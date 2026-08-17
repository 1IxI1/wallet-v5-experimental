import "@acton/crypto"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "../contracts/errors"
import "../contracts/messages"
import "../contracts/storage"
import "../wrappers/WalletV5.gen"
import "../wrappers/utils"

// ChangeKeyExtraAction (0x05) rotates the wallet's public key. Two signatures authorize it:
// the request carrying the action is signed by the CURRENT key, like any signed request, and
// the action itself carries a proof of possession — a signature by the NEW key over
// `"KEY_ROTATION" || walletAddress` — so the owner cannot rotate to a key nobody holds, and a
// proof made for one wallet is worthless against another.
//
// The seqno/walletId/validUntil header is checked the same way as any other signed
// request; those paths are covered in wallet-v5-internal.test.tolk.

/// A request body carrying nothing but a rotation to `newKey`. `proofKey` produces the proof
/// of possession — it is `newKey` in the honest case, and something else when a test breaks
/// exactly that.
fun rotationActions(
    walletV5: WalletV5,
    newKey: KeyPair,
    proofKey: KeyPair? = null,
): ActionsList {
    if (proofKey == null) {
        proofKey = newKey;
    }
    var extraActions: array<ExtraAction> = [];
    extraActions.push(changeKeyAction(walletV5.address, newKey.publicKey, proofKey.privateKey));
    return ActionsList {
        outActions: [],
        extraActions,
    };
}

fun deployWalletWithSubwallet(keyPair: KeyPair, subwalletId: int): (WalletV5, Treasury) {
    return deployWallet(Storage {
        isSignatureAllowed: true,
        seqno: 0,
        subwalletId,
        publicKey: keyPair.publicKey,
        extensions: [],
        wasKeyChanged: false,
    });
}

get fun `test w5 change-key: rotates the key and the new key takes over`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (walletV5, _) = deployWalletWithKey(oldKey);

    val receipt = walletV5.sendExternalSigned(
        createExternalSignedBody(
            oldKey,
            DEFAULT_SUBWALLET_ID,
            0,
            rotationActions(walletV5, newKey),
        ),
    )!;

    expect(receipt).toHaveTx({ exitCode: 0 });
    expect(walletV5.getPublicKey()).toEqual(newKey.publicKey);
    expect(walletV5.getSeqno()).toEqual(1);

    // The rotation is what authorization actually follows afterwards: the old key can no
    // longer spend, the new one can.
    val receiver = randomAddress("receiver");
    val forwardValue = ton("0.001");
    var outActions: array<SendAction> = [];
    outActions.push(sendMsgAction(receiver, forwardValue));
    val actions = ActionsList {
        outActions,
        extraActions: [],
    };

    val stale = walletV5.sendExternalSigned(
        createExternalSignedBody(oldKey, DEFAULT_SUBWALLET_ID, 1, actions),
    );
    expect(stale == null).toBeTrue();

    val transfer = walletV5.sendExternalSigned(
        createExternalSignedBody(newKey, DEFAULT_SUBWALLET_ID, 1, actions),
    )!;
    expect(transfer).toHaveTx({ from: walletV5.address, to: receiver, value: forwardValue });
    expect(walletV5.getSeqno()).toEqual(2);
}

get fun `test w5 change-key: the key can be rotated only once`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val thirdKey = crypto.generateKeyPair();
    val (walletV5, _) = deployWalletWithKey(oldKey);

    walletV5.sendExternalSigned(
        createExternalSignedBody(
            oldKey,
            DEFAULT_SUBWALLET_ID,
            0,
            rotationActions(walletV5, newKey),
        ),
    );
    expect(walletV5.getPublicKey()).toEqual(newKey.publicKey);

    // Signed by the key the wallet now holds, with a flawless proof for the third key — the
    // latch set by the first rotation is what refuses it.
    val receipt = walletV5.sendExternalSigned(
        createExternalSignedBody(
            newKey,
            DEFAULT_SUBWALLET_ID,
            1,
            rotationActions(walletV5, thirdKey),
        ),
    )!;

    expect(receipt).toHaveTx({ exitCode: Errors.PublicKeyWasAlreadyChanged });
    expect(walletV5.getPublicKey()).toEqual(newKey.publicKey);
}

get fun `test w5 change-key: a refused rotation does not burn the one allowed rotation`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (walletV5, _) = deployWalletWithKey(oldKey);

    // Proof made by the wrong key: the action throws, so the latch must stay unset.
    walletV5.sendExternalSigned(
        createExternalSignedBody(
            oldKey,
            DEFAULT_SUBWALLET_ID,
            0,
            rotationActions(walletV5, newKey, oldKey),
        ),
    );
    expect(walletV5.getPublicKey()).toEqual(oldKey.publicKey);

    // The owner retries with a correct proof and still gets their rotation.
    val receipt = walletV5.sendExternalSigned(
        createExternalSignedBody(
            oldKey,
            DEFAULT_SUBWALLET_ID,
            1,
            rotationActions(walletV5, newKey),
        ),
    )!;

    expect(receipt).toHaveTx({ exitCode: 0 });
    expect(walletV5.getPublicKey()).toEqual(newKey.publicKey);
}

get fun `test w5 change-key: rotates alongside a transfer in the same request`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (walletV5, _) = deployWalletWithKey(oldKey);

    // The action shares the request with out actions and another extra action, so the snake
    // walker has to step over the rotation's own ref to reach the next node.
    val extension = randomAddress("extension");
    val receiver = randomAddress("receiver");
    val forwardValue = ton("0.001");

    var outActions: array<SendAction> = [];
    outActions.push(sendMsgAction(receiver, forwardValue));
    var extraActions: array<ExtraAction> = [];
    extraActions.push(changeKeyAction(walletV5.address, newKey.publicKey, newKey.privateKey));
    extraActions.push(AddExtensionExtraAction { addr: extension });

    val receipt = walletV5.sendExternalSigned(
        createExternalSignedBody(
            oldKey,
            DEFAULT_SUBWALLET_ID,
            0,
            ActionsList { outActions, extraActions },
        ),
    )!;

    expect(receipt).toHaveTx({ from: walletV5.address, to: receiver, value: forwardValue });
    expect(walletV5.getPublicKey()).toEqual(newKey.publicKey);

    val (_, extensionHash) = extension.getWorkchainAndHash();
    expect(walletV5.getExtensions().exists(extensionHash)).toBeTrue();
}

get fun `test w5 change-key: rotates through an internal signed request too`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (walletV5, deployer) = deployWalletWithKey(oldKey);

    // Internally signed requests are authorized by the very same key, so they may rotate it.
    val receipt = walletV5.sendSignedBody(
        deployer.address,
        createSignedBody(oldKey, DEFAULT_SUBWALLET_ID, 0, rotationActions(walletV5, newKey)),
        { value: ton("0.1") },
    );

    expect(receipt).toHaveSuccessfulTx({ from: deployer.address, to: walletV5.address });
    expect(walletV5.getPublicKey()).toEqual(newKey.publicKey);
    expect(walletV5.getSeqno()).toEqual(1);
}

get fun `test w5 change-key: a rotation the new key did not sign is rejected`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (walletV5, _) = deployWalletWithKey(oldKey);

    // Proof of possession made by the old key instead of the new one.
    val receipt = walletV5.sendExternalSigned(
        createExternalSignedBody(
            oldKey,
            DEFAULT_SUBWALLET_ID,
            0,
            rotationActions(walletV5, newKey, oldKey),
        ),
    )!;

    expect(receipt).toHaveTx({ exitCode: Errors.NewKeySignatureIsInvalid });
    expect(walletV5.getPublicKey()).toEqual(oldKey.publicKey);
    // The request itself was authentic, so the seqno was committed before the rotation
    // was refused — the failed attempt is not replayable.
    expect(walletV5.getSeqno()).toEqual(1);
}

get fun `test w5 change-key: rotating to the same key is rejected`() {
    val keyPair = crypto.generateKeyPair();
    val (walletV5, _) = deployWalletWithKey(keyPair);

    val receipt = walletV5.sendExternalSigned(
        createExternalSignedBody(
            keyPair,
            DEFAULT_SUBWALLET_ID,
            0,
            rotationActions(walletV5, keyPair),
        ),
    )!;

    expect(receipt).toHaveTx({ exitCode: Errors.NewKeyMustDiffer });
    expect(walletV5.getPublicKey()).toEqual(keyPair.publicKey);
}

get fun `test w5 change-key: an extension cannot rotate the key`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (walletV5, deployer) = deployWalletWithKey(oldKey);

    addExtensionSigned(walletV5, deployer.address, deployer.address, oldKey, 0);

    // The extension is trusted for every other extra action and its proof of possession is
    // flawless — the wallet still refuses, because rotating the key is the owner's alone.
    val receipt = walletV5.sendExtensionActionBody(
        deployer.address,
        rotationActions(walletV5, newKey),
        0,
        { value: ton("0.1") },
    );

    expect(receipt).toHaveTx({
        from: deployer.address,
        to: walletV5.address,
        exitCode: Errors.OnlyOwnerCanChangeKey,
    });
    expect(walletV5.getPublicKey()).toEqual(oldKey.publicKey);
}

get fun `test w5 change-key: a request the current key did not sign is rejected`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val attackerKey = crypto.generateKeyPair();
    val (walletV5, _) = deployWalletWithKey(oldKey);

    // A flawless proof of possession is not enough: the request must also be signed by the
    // key the wallet currently holds. Rejected before accept_message, so nothing lands.
    val honest = createExternalSignedBody(
        oldKey,
        DEFAULT_SUBWALLET_ID,
        0,
        rotationActions(walletV5, newKey),
    );
    val forged = ExternalSignedBody {
        payload: honest.payload,
        signature: crypto.sign(attackerKey.privateKey, honest.payload.toCell()) as bytes64,
    };

    expect(walletV5.sendExternalSigned(forged) == null).toBeTrue();
    expect(walletV5.getPublicKey()).toEqual(oldKey.publicKey);
    expect(walletV5.getSeqno()).toEqual(0);
}

get fun `test w5 change-key: a proof made for one wallet is rejected by another`() {
    val sharedKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();

    // One key, two wallets differing only by subwallet id — a normal W5 client setup.
    val (walletA, _) = deployWalletWithSubwallet(sharedKey, DEFAULT_SUBWALLET_ID);
    val (walletB, _) = deployWalletWithSubwallet(sharedKey, DEFAULT_SUBWALLET_ID + 1);

    // A's rotation, proof and all, re-addressed to B and re-signed for it. The owner can redo
    // the outer signature themselves, but the proof commits to A's address, so B refuses it —
    // rotating B needs a proof the new key holder makes for B.
    val forA = rotationActions(walletA, newKey);
    val receipt = walletB.sendExternalSigned(
        createExternalSignedBody(sharedKey, DEFAULT_SUBWALLET_ID + 1, 0, forA),
    )!;

    expect(receipt).toHaveTx({ exitCode: Errors.NewKeySignatureIsInvalid });
    expect(walletB.getPublicKey()).toEqual(sharedKey.publicKey);

    // The very same proof is still the right one for A.
    walletA.sendExternalSigned(
        createExternalSignedBody(sharedKey, DEFAULT_SUBWALLET_ID, 0, forA),
    );
    expect(walletA.getPublicKey()).toEqual(newKey.publicKey);
}
