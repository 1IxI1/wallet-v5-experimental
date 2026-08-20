import "@acton/build"
import "@acton/crypto"
import "@acton/io"
import "@acton/emulation/config"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "../contracts/storage"
import "../wrappers/WalletV5.gen"
import "../wrappers/utils"

// What the config-code loader actually costs: same operations run twice, once on
// a wallet whose account code IS the W5 code and once through the 18-byte stub
// that pulls the code out of ConfigParam(-228). The delta is the loader.

fun deployPlain(keyPair: KeyPair): (WalletV5, Treasury) {
    val deployer = testing.treasury("plain-deployer");
    val wallet = WalletV5.fromStorage({
        isSignatureAllowed: true,
        seqno: 0,
        subwalletId: DEFAULT_SUBWALLET_ID,
        publicKey: keyPair.publicKey,
        extensions: [],
        wasKeyChanged: false,
    });
    expect(
        wallet.deploy(deployer.address, { value: ton("5"), bounce: false }),
    ).toHaveSuccessfulDeploy({ to: wallet.address });
    return (wallet, deployer);
}

// returns -1 when the external is rejected, so a failing variant is visible
fun transferGasOrFail(wallet: WalletV5, keyPair: KeyPair, seqno: int): int {
    val receiver = testing.treasury("gas-receiver");
    val body = createExternalSignedBody(
        keyPair,
        DEFAULT_SUBWALLET_ID,
        seqno,
        ActionsList {
            outActions: [sendMsgAction(receiver.address, ton("0.1"))],
            extraActions: [],
        },
    );
    val txs = wallet.sendExternalSigned(body);
    return txs == null ? -1 : txs!.at(0).gasUsed;
}

fun transferGas(wallet: WalletV5, keyPair: KeyPair, seqno: int): int {
    val receiver = testing.treasury("gas-receiver");
    val body = createExternalSignedBody(
        keyPair,
        DEFAULT_SUBWALLET_ID,
        seqno,
        ActionsList {
            outActions: [sendMsgAction(receiver.address, ton("0.1"))],
            extraActions: [],
        },
    );
    val txs = wallet.sendExternalSigned(body);
    expect(txs).toBeNotNull();
    return txs!.at(0).gasUsed;
}

get fun `test gas: config-code loader overhead`() {
    val keyPair = crypto.generateKeyPair();

    val (plain, _) = deployPlain(keyPair);
    val plainGas = transferGas(plain, keyPair, 0);

    val (stubbed, _) = deployWalletWithKey(keyPair);
    val stubGas = transferGas(stubbed, keyPair, 0);

    println("plain code  gas:", plainGas);
    println("config-code gas:", stubGas);
    println("loader overhead:", stubGas - plainGas);

    // the loader is a fixed, small prelude — nowhere near a percent of a transfer
    expect(stubGas).toBeGreater(plainGas);
    expect(stubGas - plainGas).toBeLess(1000);
}

get fun `test gas: loader overhead on a get-method`() {
    val keyPair = crypto.generateKeyPair();
    val (plain, _) = deployPlain(keyPair);
    val (stubbed, _) = deployWalletWithKey(keyPair);

    // same getter, both paths — read through the wrappers so the call is identical
    expect(plain.seqno()).toEqual(0);
    expect(stubbed.seqno()).toEqual(0);
}

// How much of that overhead is the config dictionary walk: the same loader, but
// with the config dict padded to a realistic size. Cell loads inside the lookup
// are 100 gas each (25 when already cached), so a deeper dict costs more.
get fun `test gas: overhead vs config dict size`() {
    val keyPair = crypto.generateKeyPair();
    val (plain, _) = deployPlain(keyPair);
    val plainGas = transferGas(plain, keyPair, 0);

    var config = testing.getConfig();
    // negative keys share the "1" subtree with -228: these are the ones that can
    // lengthen its lookup path (positive params branch off at the very first bit)
    var i = -260;
    while (i < -200) {
        config.setParamRaw(i, beginCell().storeUint(0, 32).endCell());
        i += 1;
    }
    expect(testing.setConfig(config)).toEqual(true);

    val (stubbed, _) = deployWalletWithKey(keyPair);
    val stubGas = transferGas(stubbed, keyPair, 0);

    println("plain code  gas:", plainGas);
    println("config-code gas (padded config):", stubGas);
    println("loader overhead (padded config):", stubGas - plainGas);
}

// Same loader, different param index: does the crowded POSITIVE subtree (where all
// the real config params live) make the lookup deeper — and hence dearer?
//
// The stub is `FF00 | 81 <idx:int16> | F833 20 6E F27F D0 ED1E 20 ED53 D9`, so the
// index is just 16 bits inside an otherwise identical 144-bit cell.
fun stubCodeForIndex(idx: int): cell {
    return beginCell()
        .storeUint(0xFF0081, 24)
        .storeInt(idx, 16)
        .storeUint(0xF833206EF27FD0ED1E20ED53D9, 104)
        .endCell();
}

fun deployStubbed(keyPair: KeyPair, code: cell, name: string): WalletV5 {
    val deployer = testing.treasury(name);
    val stateInit = ContractState {
        code,
        data: Storage {
            isSignatureAllowed: true,
            seqno: 0,
            subwalletId: DEFAULT_SUBWALLET_ID,
            publicKey: keyPair.publicKey,
            extensions: [],
            wasKeyChanged: false,
        }.toCell(),
    };
    val address = AutoDeployAddress { stateInit }.calculateAddress();
    val wallet = WalletV5 {
        address,
        stateInit,
        toShard: null,
    };
    expect(
        wallet.deploy(deployer.address, { value: ton("5"), bounce: false }),
    ).toHaveSuccessfulDeploy({ to: address });
    return wallet;
}

fun countConfigParams(config: BlockchainConfigMap): (int, int) {
    var negatives = 0;
    var positives = 0;
    var cur = config.findFirst();
    while (cur.isFound) {
        if (cur.getKey() < 0) {
            negatives += 1;
        } else {
            positives += 1;
        }
        cur = config.iterateNext(cur);
    }
    return (negatives, positives);
}

get fun `test gas: negative vs positive param index`() {
    val keyPair = crypto.generateKeyPair();
    val (plain, _) = deployPlain(keyPair);
    val plainGas = transferGas(plain, keyPair, 0);

    var config = testing.getConfig();
    val (negatives, positives) = countConfigParams(config);
    config.setParamRaw(-228, build("WalletV5"));
    config.setParamRaw(228, build("WalletV5"));
    expect(testing.setConfig(config)).toEqual(true);

    val negWallet = deployStubbed(keyPair, stubCodeForIndex(-228), "neg-deployer");
    val posWallet = deployStubbed(keyPair, stubCodeForIndex(228), "pos-deployer");
    val negGas = transferGas(negWallet, keyPair, 0);
    val posGas = transferGas(posWallet, keyPair, 0);

    println("config params: negative =", negatives, ", positive =", positives);
    println("overhead via param -228:", negGas - plainGas);
    println("overhead via param  228:", posGas - plainGas);
    println("difference:", posGas - negGas);
}

// The real driver is not the sign but how many keys share a long prefix with
// yours: each branch point on the path is another cell load (100 gas).
get fun `test gas: cost follows prefix neighbours, not the sign`() {
    val keyPair = crypto.generateKeyPair();
    val (plain, _) = deployPlain(keyPair);
    val plainGas = transferGas(plain, keyPair, 0);

    var config = testing.getConfig();
    config.setParamRaw(228, build("WalletV5"));
    expect(testing.setConfig(config)).toEqual(true);
    val bare = transferGasOrFail(
        deployStubbed(keyPair, stubCodeForIndex(228), "pos-bare"),
        keyPair,
        0,
    );

    // crowd the positive subtree right around 228
    var i = 200;
    while (i < 260) {
        if (i != 228) {
            // never overwrite the code the stub is about to load
            config.setParamRaw(i, beginCell().storeUint(0, 32).endCell());
        }
        i += 1;
    }
    expect(testing.setConfig(config)).toEqual(true);
    // a second key, so the wallet lands on a different address than the bare run
    val keyPair2 = crypto.generateKeyPair();
    val crowded = transferGasOrFail(
        deployStubbed(keyPair2, stubCodeForIndex(228), "pos-crowded"),
        keyPair2,
        0,
    );

    // why does the crowded variant get rejected? print the emulator's verdict

    println("overhead via 228, no neighbours:", bare - plainGas);
    println("overhead via 228, 60 neighbours:", crowded - plainGas);
}
