import "@acton/build"
import "@acton/crypto"
import "@acton/emulation/config"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "../contracts/errors"
import "../contracts/storage"
import "../wrappers/WalletV5.gen"
import "../wrappers/utils"

// Data-version migrations through the config-code stub. The wallet's account
// code is the 18-byte loader; the real code (this build, DATA_VERSION = v2)
// sits in ConfigParam(228). Wallets whose c4 carries an older version header
// get migrated by checkMigrations() on the first execution that touches them —
// the deploy message itself is already such a touch.

fun deployWalletWithData(data: cell): (WalletV5, Treasury) {
    val deployer = testing.treasury("deployer");
    val stateInit = ContractState {
        code: WalletV5.deployCodeConfigStub(),
        data,
    };
    val address = AutoDeployAddress { stateInit }.calculateAddress();
    val wallet = WalletV5 {
        address,
        stateInit,
        toShard: null,
    };
    val deployResult = wallet.deploy(deployer.address, { value: ton("5"), bounce: false });
    return (wallet, deployer);
}

fun v1Data(keyPair: KeyPair, seqno: int, extensions: ExtensionsDict): cell {
    return StorageV1 {
        version: DATA_VERSION_1,
        isSignatureAllowed: true,
        seqno,
        subwalletId: DEFAULT_SUBWALLET_ID,
        publicKey: keyPair.publicKey,
        extensions,
        wasKeyChanged: false,
    }.toCell();
}

get fun `test migration: v1 data is migrated by the deploy touch`() {
    val keyPair = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithData(v1Data(keyPair, 5, []));

    // the deploy internal already ran checkMigrations -> c4 is v2 now
    expect(net.runGetMethod<int>(wallet.address, "data_version")).toEqual(DATA_VERSION_2);
    expect(net.runGetMethod<int>(wallet.address, "migration_count")).toEqual(1);
    // v1 fields survived the migration intact
    expect(wallet.getSeqno()).toEqual(5);
    expect(wallet.getPublicKey()).toEqual(keyPair.publicKey);
    expect(wallet.isSignatureAllowed()).toEqual(true);
}

get fun `test migration: external continues seqno after migration`() {
    val keyPair = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithData(v1Data(keyPair, 7, []));
    val receiver = testing.treasury("receiver");

    val body = createExternalSignedBody(
        keyPair,
        DEFAULT_SUBWALLET_ID,
        7, // the seqno carried over from the v1 data
        ActionsList {
            outActions: [sendMsgAction(receiver.address, ton("1"))],
            extraActions: [],
        },
    );
    val txs = wallet.sendExternalSigned(body);
    expect(txs).toBeNotNull();
    expect(txs!).toHaveTx({ from: wallet.address, to: receiver.address, value: ton("1") });

    expect(wallet.getSeqno()).toEqual(8);
    // still exactly ONE migration: the second touch found DATA_VERSION and did nothing
    expect(net.runGetMethod<int>(wallet.address, "migration_count")).toEqual(1);
    expect(net.runGetMethod<int>(wallet.address, "data_version")).toEqual(DATA_VERSION_2);
}

get fun `test migration: extensions dict survives`() {
    val keyPair = crypto.generateKeyPair();
    val extension = testing.treasury("extension");
    val (_, extensionHash) = extension.address.getWorkchainAndHash();
    var extensions: ExtensionsDict = [];
    extensions.addIfNotExists(extensionHash, true);

    val (wallet, _) = deployWalletWithData(v1Data(keyPair, 0, extensions));

    val migrated = wallet.getExtensionsArray();
    expect(migrated).toHaveLength(1);
    expect(migrated.get(0)).toEqual(extension.address);
}

get fun `test migration: v2-born wallet never migrates`() {
    val keyPair = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithKey(keyPair);

    expect(net.runGetMethod<int>(wallet.address, "data_version")).toEqual(DATA_VERSION_2);
    expect(net.runGetMethod<int>(wallet.address, "migration_count")).toEqual(0);
}

get fun `test migration: unknown data version is rejected`() {
    val keyPair = crypto.generateKeyPair();
    val badData = StorageV1 {
        version: (DATA_MAGIC << 8) | 0xff,
        isSignatureAllowed: true,
        seqno: 0,
        subwalletId: DEFAULT_SUBWALLET_ID,
        publicKey: keyPair.publicKey,
        extensions: [],
        wasKeyChanged: false,
    }.toCell();

    val deployer = testing.treasury("deployer");
    val stateInit = ContractState {
        code: WalletV5.deployCodeConfigStub(),
        data: badData,
    };
    val address = AutoDeployAddress { stateInit }.calculateAddress();
    val wallet = WalletV5 {
        address,
        stateInit,
        toShard: null,
    };
    val deployResult = wallet.deploy(deployer.address, { value: ton("5"), bounce: false });

    expect(deployResult).toHaveTx({ to: wallet.address, exitCode: Errors.UnknownDataVersion });
}

// Not a migration per se, but THE upgrade lever end to end: the wallet's brain
// is whatever ConfigParam(228) holds right now.
get fun `test upgrade lever: dropping the config param bricks, restoring revives`() {
    val keyPair = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithKey(keyPair);
    val receiver = testing.treasury("receiver");

    // works with the code in place
    val body0 = createExternalSignedBody(
        keyPair,
        DEFAULT_SUBWALLET_ID,
        0,
        ActionsList {
            outActions: [sendMsgAction(receiver.address, ton("0.1"))],
            extraActions: [],
        },
    );
    expect(wallet.sendExternalSigned(body0)).toBeNotNull();
    expect(wallet.getSeqno()).toEqual(1);

    // pull the code out from under it: empty cell -> BLESSed empty continuation
    // -> implicit RET without ACCEPT -> every external is rejected
    var config = testing.getConfig();
    config.setParamRaw(CONFIG_CODE_PARAM_IDX, createEmptyCell());
    expect(testing.setConfig(config)).toEqual(true);

    val body1 = createExternalSignedBody(
        keyPair,
        DEFAULT_SUBWALLET_ID,
        1,
        ActionsList {
            outActions: [sendMsgAction(receiver.address, ton("0.1"))],
            extraActions: [],
        },
    );
    expect(wallet.sendExternalSigned(body1)).toBeNull();

    // restore the code -> same address comes back to life, seqno intact
    var config2 = testing.getConfig();
    config2.setParamRaw(CONFIG_CODE_PARAM_IDX, build("WalletV5"));
    expect(testing.setConfig(config2)).toEqual(true);

    expect(wallet.sendExternalSigned(body1)).toBeNotNull();
    expect(wallet.getSeqno()).toEqual(2);
}
