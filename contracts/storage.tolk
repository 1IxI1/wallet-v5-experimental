import "errors"

type ExtensionsDict = map<uint256, bool>

// --- data versioning ---------------------------------------------------------
// The first 32 bits of c4 are a version header: 0xdada00 (magic) | version:8.
// The version a build writes/expects is hardcoded below; the code itself ships
// in ConfigParam(-228), so the code and its expected data version upgrade
// atomically with one set-config.
//
// Migration is LAZY: checkMigrations() guards the storage loads, not the entry
// points, so an execution that never reads c4 (a plain incoming transfer, the
// deploy message) neither pays for the check nor migrates. The first operation
// that does read the storage lifts it, one version per stage.
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

// Guard in front of every storage load. INLINED on purpose: as a plain function it
// costs ~440 gas of CALLDICT (the call walks the contract's method dictionary)
// before doing any work. Inlined, the hot path is a peek at the 32-bit header plus
// a compare — and it deliberately does NOT parse the struct, because old data is
// SHORTER and parsing the current layout would underflow before we learn the
// version. Callers keep using `lazy Storage.load()` afterwards, which is what makes
// the load itself cheap.
@inline
fun checkMigrations() {
    if (contract.getData().beginParse().preloadUint(32) != DATA_VERSION) {
        migrateData();
    }
}

// Cold path: lift c4 to the current layout, one version per stage, and return the
// migrated struct. Deliberately NOT inlined — it must not bloat every call site.
// Writing c4 is also fine in get-method contexts: it is not persisted, but every
// later load in the same execution sees the migrated view.
fun migrateData() {
    var version = contract.getData().beginParse().preloadUint(32);

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
        return;
    }

    throw Errors.UnknownDataVersion;
}
