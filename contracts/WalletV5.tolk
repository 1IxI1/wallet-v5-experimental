import "@stdlib/gas-payments"
import "c5-register-validation"
import "errors"
import "messages"
import "storage"

contract WalletV5 {
    author: "The Tolk Team"
    version: "5.2"
    description: "Based on wallet v5r1, added public key rotation"
    storage: Storage
    incomingMessages: AllowedMessageToWalletV5
    incomingExternal: AllowedExternalMessageToWalletV5
}

const SIZE_SIGNATURE = 512

@inline_ref
fun processExtraActions(extraActions: SnakedExtraActions, isExtension: bool) {
    while (true) {
        val action = lazy ExtraAction.fromSlice(extraActions);
        match (action) {
            AddExtensionExtraAction => {
                val (extensionWorkchain, extensionAddrHash) = action.addr.getWorkchainAndHash();
                val myWorkchain = contract.getAddress().getWorkchain();
                assert (myWorkchain == extensionWorkchain) throw Errors.ExtensionWrongWorkchain;

                var storage = lazy Storage.load();
                val inserted = storage.extensions.addIfNotExists(extensionAddrHash, true);
                assert (inserted) throw Errors.AddExtension;
                storage.save();
            }

            RemoveExtensionExtraAction => {
                val (extensionWorkchain, extensionAddrHash) = action.addr.getWorkchainAndHash();
                val myWorkchain = contract.getAddress().getWorkchain();
                assert (myWorkchain == extensionWorkchain) throw Errors.ExtensionWrongWorkchain;

                var storage = lazy Storage.load();
                val removed = storage.extensions.delete(extensionAddrHash);
                assert (removed) throw Errors.RemoveExtension;
                if (!storage.isSignatureAllowed) {
                    assert (
                        !storage.extensions.isEmpty()
                    ) throw Errors.RemoveLastExtensionWhenSignatureDisabled;
                }
                storage.save();
            }

            SetSignatureAllowedExtraAction => {
                assert (isExtension) throw Errors.OnlyExtensionCanChangeSignatureMode;

                var storage = lazy Storage.load();
                assert (
                    storage.isSignatureAllowed != action.allowSignature
                ) throw Errors.ThisSignatureModeAlreadySet;
                if (!action.allowSignature) {
                    assert (
                        !storage.extensions.isEmpty()
                    ) throw Errors.DisableSignatureWhenExtensionsIsEmpty;
                }
                storage.isSignatureAllowed = action.allowSignature;
                storage.save();
            }

            ChangeKeyExtraAction => {
                // extensions can't change public key
                assert (!isExtension) throw Errors.OnlyOwnerCanChangeKey;

                val rotation = action.rotation.load();

                var storage = lazy Storage.load();
                assert (storage.publicKey != rotation.newPublicKey) throw Errors.NewKeyMustDiffer;
                assert (!storage.wasKeyChanged) throw Errors.PublicKeyWasAlreadyChanged;

                // a message "change key" is signed by two keys:
                // 1) signature of the message itself (old key)
                // 2) a special "proof" signed by a new private key
                val (myWorkchain, myAddrHash) = contract.getAddress().getWorkchainAndHash();
                val expectedPayload = KeyRotationProofPayload {
                    walletWorkchain: myWorkchain,
                    walletAddrHash: myAddrHash,
                };
                assert (
                    isSliceSignatureValid(
                        expectedPayload.toCell().beginParse(),
                        rotation.proof as slice,
                        rotation.newPublicKey,
                    )
                ) throw Errors.NewKeySignatureIsInvalid;

                storage.publicKey = rotation.newPublicKey;
                storage.wasKeyChanged = true;
                storage.save();

                // `lazy fromSlice` does not advance `extraActions`, so skip `Cell<KeyRotation>` manually
                // to make `getNext()` below consume a next ref (next ExtraAction)
                extraActions.skipAny<cell>();
            }

            else => throw Errors.UnsupportedAction,
        }
        if (!extraActions.hasNext()) {
            return;
        }
        extraActions = extraActions.getNext();
    }
}

fun processActions(
    outActions: OutActionsCell?,
    hasExtraActions: bool,
    extraActions: SnakedExtraActions,
    isExternal: bool,
    isExtension: bool,
) {
    if (outActions != null) {
        // Simply set the C5 register with all pre-computed actions after verification:
        setTvmRegisterC5(outActions.verifyC5Actions(isExternal));
    }
    if (hasExtraActions) {
        processExtraActions(extraActions, isExtension);
    }
}

type AllowedMessageToWalletV5 = ExtensionActionRequest | InternalSignedRequest

type AllowedExternalMessageToWalletV5 = ExternalSignedRequest

fun onExternalMessage(inMsgBody: slice) {
    val signature = inMsgBody.getLastBits(SIZE_SIGNATURE);
    val signedSlice = inMsgBody.removeLastBits(SIZE_SIGNATURE);

    val msg = AllowedExternalMessageToWalletV5.fromSlice(
        signedSlice,
        { throwIfOpcodeDoesNotMatch: Errors.InvalidMessageOperation },
    );

    checkMigrations();
    var storage = lazy Storage.load();

    assert (
        isSignatureValid(signedSlice.hash(), signature, storage.publicKey)
    ) throw Errors.InvalidSignature;
    assert (
        storage.isSignatureAllowed | storage.extensions.isEmpty()
    ) throw Errors.SignatureDisabled;
    assert (msg.seqno == storage.seqno) throw Errors.InvalidSeqno;
    assert (msg.walletId == storage.subwalletId) throw Errors.InvalidWalletId;
    assert (msg.validUntil > blockchain.now()) throw Errors.Expired;

    acceptExternalMessage();

    // Store and commit the seqno increment to prevent replays even if the subsequent requests fail.
    storage.isSignatureAllowed = true;
    storage.seqno += 1;
    storage.save();

    commitContractDataAndActions();
    processActions(msg.outActions, msg.hasExtraActions, msg.extraActions, true, false);
}

@on_bounced_policy("manual")
fun onInternalMessage(in: InMessage) {
    val msg = lazy AllowedMessageToWalletV5.fromSlice(in.body);

    match (msg) {
        InternalSignedRequest => {
            val bodyLongEnough = in.body.remainingBitsCount() >= SIZE_SIGNATURE + 128;
            if (!bodyLongEnough) {
                return; // don't try to parse it (it will fail), just ignore
            }

            val signature = in.body.getLastBits(SIZE_SIGNATURE);
            val signedSlice = in.body.removeLastBits(SIZE_SIGNATURE);

            checkMigrations();
            var storage = lazy Storage.load();
            if (!isSignatureValid(signedSlice.hash(), signature, storage.publicKey)) {
                return;
            }

            assert (
                storage.isSignatureAllowed | storage.extensions.isEmpty()
            ) throw Errors.SignatureDisabled;
            assert (msg.seqno == storage.seqno) throw Errors.InvalidSeqno;
            assert (msg.walletId == storage.subwalletId) throw Errors.InvalidWalletId;
            assert (msg.validUntil > blockchain.now()) throw Errors.Expired;

            // Store and commit the seqno increment to prevent replays even if the subsequent requests fail.
            storage.isSignatureAllowed = true;
            storage.seqno += 1;
            storage.save();

            processActions(msg.outActions, msg.hasExtraActions, msg.extraActions, false, false);
        }

        ExtensionActionRequest => {
            val (senderWorkchain, senderAddrHash) = in.senderAddress.getWorkchainAndHash();
            val myWorkchain = contract.getAddress().getWorkchain();
            if (myWorkchain != senderWorkchain) {
                return;
            }

            checkMigrations();
            val storage = lazy Storage.load();
            if (!storage.extensions.exists(senderAddrHash)) {
                // Note that some random contract may have deposited funds with this prefix,
                // so we accept the funds silently instead of throwing an error (wallet v4 does the same).
                return;
            }

            processActions(msg.outActions, msg.hasExtraActions, msg.extraActions, false, true);
        }

        else => {
            // if opcode is strange or body is empty at all (for instance, bounced messages)
            // just ignore, do not throw
        }
    }
}

get fun is_signature_allowed(): bool {
    checkMigrations();
    val storage = lazy Storage.load();
    return storage.isSignatureAllowed;
}

get fun seqno(): int {
    checkMigrations();
    val storage = lazy Storage.load();
    return storage.seqno;
}

get fun get_subwallet_id(): int {
    checkMigrations();
    val storage = lazy Storage.load();
    return storage.subwalletId;
}

get fun get_public_key(): int {
    checkMigrations();
    val storage = lazy Storage.load();
    return storage.publicKey;
}

// Returns raw dictionary (or null if empty) where keys are address hashes. Workchains of extensions are same with wallet smart contract workchain
get fun get_extensions(): map<uint256, bool> {
    checkMigrations();
    val storage = lazy Storage.load();
    return storage.extensions;
}

// The version header as PERSISTED in c4 — deliberately unchecked, so an
// unmigrated account can be told apart from a migrated one.
get fun data_version(): int {
    return contract.getData().beginParse().preloadUint(32);
}

get fun migration_count(): int {
    checkMigrations();
    val storage = lazy Storage.load();
    return storage.migrationCount;
}

get fun last_migration_at(): int {
    checkMigrations();
    val storage = lazy Storage.load();
    return storage.lastMigrationAt;
}
