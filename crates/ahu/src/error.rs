use thiserror::Error;

#[derive(Debug, Error)]
pub enum AhuError {
    #[error("invalid magic: expected AHU1, got {found:02x?}")]
    BadMagic { found: [u8; 4] },

    #[error("unsupported format version {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },

    #[error(
        "header field out of bounds: {field} offset {offset} + length {length} exceeds file size {file_size}"
    )]
    HeaderOutOfBounds {
        field: &'static str,
        offset: u64,
        length: u64,
        file_size: u64,
    },

    #[error("manifest CBOR decode error: {0}")]
    ManifestDecode(String),

    #[error("manifest field missing or invalid: {0}")]
    ManifestField(String),

    #[error("seal validation failed: {0}")]
    SealInvalid(String),

    #[error("index digest mismatch: expected {expected}, got {actual}")]
    IndexDigestMismatch { expected: String, actual: String },

    #[error("data digest mismatch: expected {expected}, got {actual}")]
    DataDigestMismatch { expected: String, actual: String },

    #[error("index not sorted: record {index} key {key} >= next key {next_key}")]
    IndexNotSorted {
        index: usize,
        key: String,
        next_key: String,
    },

    #[error("duplicate entry key at index {index}: {key}")]
    DuplicateEntryKey { index: usize, key: String },

    #[error("index section size {size} is not a multiple of record size {record_size}")]
    IndexSizeMismatch { size: u64, record_size: usize },

    #[error("epoch rollback: scope {scope} epoch {epoch} <= high-water {high_water}")]
    EpochRollback {
        scope: String,
        epoch: u64,
        high_water: u64,
    },

    #[error("continuity break: prev_manifest_digest mismatch for scope {scope}")]
    ContinuityBreak { scope: String },

    #[error("delta requires base_manifest_digest")]
    DeltaMissingBase,

    #[error("fork detected: prev_manifest_digest does not match recorded digest for {scope}")]
    ForkDetected { scope: String },

    #[error("entry at index offset {offset} length {length} exceeds data section")]
    EntryOutOfBounds { offset: u64, length: u32 },

    #[error("reserved field not zero at index record {index}")]
    ReservedNotZero { index: usize },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("bundle write error: {0}")]
    Write(String),

    #[error("invalid bundle operation: {0}")]
    InvalidOperation(String),
}

pub type Result<T> = std::result::Result<T, AhuError>;
