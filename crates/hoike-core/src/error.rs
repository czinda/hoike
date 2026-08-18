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

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
