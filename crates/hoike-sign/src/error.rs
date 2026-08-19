use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignError {
    #[error("DER encoding error: {0}")]
    Der(#[from] der::Error),

    #[error("OCSP builder error: {0}")]
    OcspBuilder(String),

    #[error("signing error: {0}")]
    Signing(String),

    #[error("CRL parse error: {0}")]
    CrlParse(String),

    #[error("bundle build error: {0}")]
    Bundle(#[from] ahu::AhuError),

    #[error("PKCS#11 error: {0}")]
    Pkcs11(String),

    #[error("key loading error: {0}")]
    KeyLoad(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SignError>;

impl From<x509_ocsp::builder::Error> for SignError {
    fn from(e: x509_ocsp::builder::Error) -> Self {
        SignError::OcspBuilder(e.to_string())
    }
}
