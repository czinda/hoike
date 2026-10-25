//! Shared bundle integrity, seal trust, and scope authorization policy.
//!
//! Admission is read-only. Freshness, rollback checks, and installation belong
//! to the caller.

use ahu::{Bundle, BundleType, CompressionAlgorithm, SealVerification};
use der::{Decode, DecodePem, Encode};
use tracing::{info, warn};

use crate::config::StorageConfig;
use crate::error::{CoreError, Result};

#[derive(Debug, PartialEq, Eq)]
pub enum AdmissionTrust {
    Authenticated { signer_sha256: String },
    UnauthenticatedDemo,
}

/// Verify structure, digests, the CMS seal, and configured scope restrictions.
///
/// Decoded manifest fields must match the encoded manifest used for CMS
/// verification; structural verification binds them before policy checks.
///
/// Requires explicit signer pins or CA anchors, even when demo admission is
/// enabled. Certificate validity is checked at `now` (Unix seconds). Empty scope
/// authorizations impose no additional restriction on trusted signers.
pub fn authenticate_bundle(
    bundle: &Bundle,
    storage: &StorageConfig,
    now: u64,
) -> Result<SealVerification> {
    verify_structure(bundle)?;
    let has_trust_anchors = storage
        .seal_trust_anchors
        .as_ref()
        .is_some_and(|v| !v.is_empty());
    let has_pins = !storage.seal_signer_pins.is_empty();
    if !has_trust_anchors && !has_pins {
        return Err(CoreError::Config(
            if storage.seal_authorizations.is_empty() {
                "bundle authentication requires seal_signer_pins or seal_trust_anchors".into()
            } else {
                "seal_authorizations requires trust anchors or explicit signer pins".into()
            },
        ));
    }
    if bundle.seal_bytes.is_empty() {
        return Err(CoreError::Config(
            "seal trust configured but bundle has no seal".into(),
        ));
    }

    let read_certs = |paths: &[std::path::PathBuf]| -> Result<Vec<Vec<u8>>> {
        let mut anchors = Vec::new();
        for path in paths {
            let bytes = std::fs::read(path).map_err(|e| {
                CoreError::Config(format!(
                    "cannot read seal trust anchor {}: {e}",
                    path.display()
                ))
            })?;
            let cert = if bytes.starts_with(b"-----BEGIN") {
                x509_cert::Certificate::from_pem(&bytes)
            } else {
                x509_cert::Certificate::from_der(&bytes)
            }
            .map_err(|e| {
                CoreError::Config(format!("invalid seal trust anchor {}: {e}", path.display()))
            })?;
            anchors.push(
                cert.to_der()
                    .map_err(|e| CoreError::Config(e.to_string()))?,
            );
        }
        Ok(anchors)
    };
    let anchors = read_certs(storage.seal_trust_anchors.as_deref().unwrap_or(&[]))?;
    let pins = read_certs(&storage.seal_signer_pins)?;
    let verification = if has_pins {
        ahu::verify_seal_with_pins(&bundle.manifest_bytes, &bundle.seal_bytes, &pins, now).or_else(
            |pin_error| {
                if has_trust_anchors {
                    ahu::verify_seal_with_anchors(
                        &bundle.manifest_bytes,
                        &bundle.seal_bytes,
                        &anchors,
                        now,
                    )
                } else {
                    Err(pin_error)
                }
            },
        )
    } else {
        ahu::verify_seal_with_anchors(&bundle.manifest_bytes, &bundle.seal_bytes, &anchors, now)
    }
    .map_err(|e| CoreError::Config(format!("seal verification failed: {e}")))?;
    if !storage.seal_authorizations.is_empty() {
        for scope in &bundle.manifest.ca_scopes {
            if !storage.seal_authorizations.iter().any(|auth| {
                auth.producer_id == bundle.manifest.producer_id
                    && auth
                        .issuer_key_hash
                        .eq_ignore_ascii_case(&hex::encode(&scope.issuer_key_hash))
                    && auth
                        .signer_sha256
                        .eq_ignore_ascii_case(&verification.signer_sha256)
            }) {
                return Err(CoreError::Config(
                    "seal signer is not authorized for producer/CA scope".into(),
                ));
            }
        }
    }
    info!(signer = %verification.signer_sha256, "CMS seal authenticated against configured trust policy");
    Ok(verification)
}

/// Validate that a bundle matches the serving profile this responder
/// supports: a full, uncompressed bundle (design §S3).
///
/// The ahu *format* can represent delta bundles, tombstones, Zstd
/// compression, and delta-chain metadata; this responder implements none of
/// the runtime machinery those require (no delta overlays, no decompression,
/// no chain tracking). Admission therefore rejects them before any durable
/// state changes. A valid seal does not change this: use
/// [`authenticate_bundle`] to inspect an authenticated delta, and
/// materialize deltas into a full, uncompressed bundle (`ahu apply`) before
/// serving them.
pub fn validate_serving_profile(bundle: &Bundle) -> Result<()> {
    let reject = |reason: &str| {
        Err(CoreError::Config(format!(
            "unsupported serving profile: {reason}"
        )))
    };
    if bundle.manifest.bundle_type != BundleType::Full {
        return reject("delta bundle; materialize it into a full bundle before serving");
    }
    match &bundle.manifest.compression {
        None => {}
        Some(compression) => {
            if compression.algorithm != CompressionAlgorithm::None {
                return reject("compressed bundle; serve an uncompressed bundle instead");
            }
            if compression.dictionary_digest.is_some() {
                return reject("compression dictionary; serve an uncompressed bundle instead");
            }
        }
    }
    if bundle.index.iter().any(|record| record.is_tombstone()) {
        return reject("tombstone in a full bundle; tombstones only apply to deltas");
    }
    if bundle.manifest.continuity.base_manifest_digest.is_some() {
        return reject("full bundle naming a base manifest");
    }
    if bundle.manifest.continuity.chain_length != 0 {
        return reject("full bundle with nonzero chain_length");
    }
    Ok(())
}

/// Admit a bundle under the configured trust policy, or for explicitly enabled
/// unauthenticated demo serving. Configured trust always takes precedence.
///
/// Admission also enforces the supported serving profile regardless of trust
/// mode: a correctly sealed delta or compressed bundle is inspectable but not
/// servable.
pub fn admit_bundle(bundle: &Bundle, storage: &StorageConfig, now: u64) -> Result<AdmissionTrust> {
    validate_serving_profile(bundle)?;
    if storage.allow_unauthenticated_bundles
        && storage.seal_signer_pins.is_empty()
        && storage
            .seal_trust_anchors
            .as_ref()
            .is_none_or(|v| v.is_empty())
        && storage.seal_authorizations.is_empty()
    {
        verify_structure(bundle)?;
        warn!(
            target: "audit",
            event = "bundle_admission",
            trust = "unauthenticated_demo",
            producer = %bundle.manifest.producer_id,
            "UNAUTHENTICATED DEMO bundle admitted; CMS seal not verified"
        );
        return Ok(AdmissionTrust::UnauthenticatedDemo);
    }

    let verification = authenticate_bundle(bundle, storage, now)?;
    Ok(AdmissionTrust::Authenticated {
        signer_sha256: verification.signer_sha256,
    })
}

fn verify_structure(bundle: &Bundle) -> Result<()> {
    let result = ahu::verify_structure(bundle)?;
    for warning in &result.warnings {
        warn!(warning, "bundle verification warning");
    }
    Ok(())
}
