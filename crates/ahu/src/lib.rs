pub mod bundle;
pub mod error;
pub mod header;
pub mod index;
pub mod manifest;
pub mod mmap_bundle;
pub mod seal;
pub mod verify;

pub use bundle::{Bundle, BundleBuilder};
pub use error::{AhuError, Result};
pub use header::FileHeader;
pub use index::{
    IndexFlags, IndexRecord, compute_entry_key,
    ALG_DISC_DEFAULT, ALG_DISC_ML_DSA_44, ALG_DISC_ML_DSA_65, ALG_DISC_ML_DSA_87,
};
pub use manifest::{
    BundleType, CaScope, Completeness, Compression, CompressionAlgorithm, Continuity, Integrity,
    Manifest, ResponderId, ResponderIdType, Shard, Window,
};
pub use mmap_bundle::MmapBundle;
pub use verify::{VerifyResult, check_epochs, manifest_digest, verify_structure};
#[cfg(feature = "seal-verify")]
pub use seal::{SealVerification, verify_seal};
