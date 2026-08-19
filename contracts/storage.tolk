import "errors"

type ExtensionsDict = map<uint256, bool>

// --- data versioning ---------------------------------------------------------
// The first 32 bits of c4 are a version header: 0xdada00 (magic) | version:8.
// The version a build writes/expects is hardcoded below; the code itself ships
// in ConfigParam(228), so the code and its expected data version upgrade
// atomically with one set-config. checkMigrations() runs at the start of every
// execution and lifts c4 to the current layout, one version per stage, when it
// finds an older one.
const DATA_MAGIC = 0xdada00
const DATA_VERSION_1 = (DATA_MAGIC << 8) | 1 // 0xdada0001
const DATA_VERSION_2 = (DATA_MAGIC << 8) | 2 // 0xdada0002
const DATA_VERSION_3 = (DATA_MAGIC << 8) | 3 // 0xdada0003

// what THIS build writes and expects
const DATA_VERSION = DATA_VERSION_3

// v1 layout: the original w5.2 fields behind the header
struct StorageV1 {
    version: uint32
    isSignatureAllowed: bool
    seqno: uint32
    subwalletId: uint32
    publicKey: uint256
    extensions: ExtensionsDict
    wasKeyChanged: bool
}

// v2 layout: v1 + migrationCount
struct StorageV2 {
    version: uint32
    isSignatureAllowed: bool
    seqno: uint32
    subwalletId: uint32
    publicKey: uint256
    extensions: ExtensionsDict
    wasKeyChanged: bool
    migrationCount: uint32
}

// current (v3) layout
struct Storage {
    version: uint32 = DATA_VERSION
    isSignatureAllowed: bool
    seqno: uint32
    subwalletId: uint32
    publicKey: uint256
    extensions: ExtensionsDict // from address hash to true
    wasKeyChanged: bool
    // v2: how many times this data cell has been migrated to a newer layout
    migrationCount: uint32 = 0
    // v3: unixtime of the last applied migration (0 = born on the current layout)
    lastMigrationAt: uint32 = 0
}

fun Storage.load(): Storage {
    return Storage.fromCell(contract.getData());
}

fun Storage.save(self) {
    contract.setData(self.toCell());
}

// Migrate c4 to the current layout if an older version sits there. Staged: each
// branch lifts the data exactly one version and falls through to the next.
// Writing c4 is also fine in get-method contexts: it is not persisted, but every
// later Storage.load() in the same execution sees the migrated view.
fun checkMigrations() {
    var version = contract.getData().beginParse().preloadUint(32);
    if (version == DATA_VERSION) {
        return;
    }

    if (version == DATA_VERSION_1) {
        val old = StorageV1.fromCell(contract.getData());
        contract.setData(
            StorageV2 {
                version: DATA_VERSION_2,
                isSignatureAllowed: old.isSignatureAllowed,
                seqno: old.seqno,
                subwalletId: old.subwalletId,
                publicKey: old.publicKey,
                extensions: old.extensions,
                wasKeyChanged: old.wasKeyChanged,
                migrationCount: 1,
            }.toCell(),
        );
        version = DATA_VERSION_2;
    }

    if (version == DATA_VERSION_2) {
        val old = StorageV2.fromCell(contract.getData());
        Storage {
            isSignatureAllowed: old.isSignatureAllowed,
            seqno: old.seqno,
            subwalletId: old.subwalletId,
            publicKey: old.publicKey,
            extensions: old.extensions,
            wasKeyChanged: old.wasKeyChanged,
            migrationCount: old.migrationCount + 1,
            lastMigrationAt: blockchain.now(),
        }.save();
        version = DATA_VERSION_3;
    }

    if (version != DATA_VERSION) {
        throw Errors.UnknownDataVersion;
    }
}
