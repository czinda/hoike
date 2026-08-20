pub mod crl;
#[cfg(feature = "dogtag-sync")]
pub mod dogtag_sync;
pub mod error;
pub mod generate;
pub mod keyfile;
pub mod live;
pub mod ml_dsa_bridge;
#[cfg(feature = "pkcs11")]
pub mod pkcs11;
pub mod rotation;
pub mod source;

pub use crl::CrlSource;
#[cfg(feature = "dogtag-sync")]
pub use dogtag_sync::{DogtagSyncConfig, DogtagSyncSource};
pub use error::{Result, SignError};
pub use generate::datetime_to_epoch;
pub use generate::{CertIdCompat, GenerationConfig, produce_bundle};
pub use keyfile::{demo_ecdsa_p256_key, load_ecdsa_p256_key};
pub use live::{LiveCertStatus, extract_status_from_response, sign_live_response};
pub use ml_dsa_bridge::{
    ML_DSA_44_OID, ML_DSA_65_OID, ML_DSA_87_OID, MlDsaSignatureBytes, MlDsaSigner,
    ml_dsa_44_signer, ml_dsa_65_signer, ml_dsa_87_signer, ml_dsa_signature_size,
};
#[cfg(feature = "pkcs11")]
pub use pkcs11::{Pkcs11Config, Pkcs11EcdsaSignature, Pkcs11Signer, Pkcs11SignerBridge};
pub use rotation::{
    CertInfo, RotationStatus, check_and_log_rotation, check_rotation_needed, format_cert_info,
    run_rotation_command,
};
pub use source::{
    CaIdentity, CertificateStatus, Epoch, RevocationSource, StatusChange, StatusSnapshot,
};
