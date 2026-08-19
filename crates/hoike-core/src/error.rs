use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("empty OCSP request")]
    EmptyRequest,

    #[error("request too large: {size} bytes (max {max})")]
    RequestTooLarge { size: usize, max: usize },

    #[error("empty request list in OCSPRequest")]
    EmptyRequestList,

    #[error("DER parse error in {context}: {detail}")]
    DerParse {
        context: &'static str,
        detail: String,
    },

    #[error("GET path decode error: {0}")]
    GetDecode(String),

    #[error("no matching CA scope for CertID")]
    NoMatchingScope,

    #[error("bundle error: {0}")]
    Bundle(#[from] ahu::AhuError),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("epoch rollback: scope {scope} epoch {epoch} <= high-water {high_water}")]
    EpochRollback {
        scope: String,
        epoch: u64,
        high_water: u64,
    },

    #[error(
        "epoch jump too large: scope {scope} epoch {epoch} jumps {jump} from high-water {high_water} (max allowed: {max_jump})"
    )]
    EpochJumpTooLarge {
        scope: String,
        epoch: u64,
        high_water: u64,
        jump: u64,
        max_jump: u64,
    },

    #[error("fork detected: prev_manifest_digest mismatch for scope {scope}")]
    ForkDetected { scope: String },

    #[error("state store error: {0}")]
    StateStore(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
