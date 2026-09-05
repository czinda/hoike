use sha2::{Digest, Sha256};

use crate::bundle::Bundle;
use crate::error::{AhuError, Result};
use crate::index::validate_sort_order;

/// Results of bundle verification.
#[derive(Debug)]
pub struct VerifyResult {
    pub header_ok: bool,
    pub manifest_ok: bool,
    pub index_digest_ok: bool,
    pub data_digest_ok: bool,
    pub sort_order_ok: bool,
    pub entry_bounds_ok: bool,
    pub seal_present: bool,
    pub entry_count_matches: bool,
    pub warnings: Vec<String>,
}

/// Verify a bundle's structural integrity.
///
/// This checks everything *except* the CMS seal signature (which requires
/// a trust anchor) and individual OCSP response signatures (which are
/// expensive at scale and optional per §3.1 of the spec).
pub fn verify_structure(bundle: &Bundle) -> Result<VerifyResult> {
    let mut result = VerifyResult {
        header_ok: true,
        manifest_ok: true,
        index_digest_ok: false,
        data_digest_ok: false,
        sort_order_ok: false,
        entry_bounds_ok: true,
        seal_present: !bundle.seal_bytes.is_empty(),
        entry_count_matches: false,
        warnings: Vec::new(),
    };

    // Verify index digest.
    let mut index_bytes = Vec::new();
    for record in &bundle.index {
        record.write_to(&mut index_bytes)?;
    }
    let computed_index_digest: [u8; 32] = Sha256::digest(&index_bytes).into();
    result.index_digest_ok = computed_index_digest == bundle.manifest.integrity.index_digest;
    if !result.index_digest_ok {
        return Err(AhuError::IndexDigestMismatch {
            expected: hex::encode(bundle.manifest.integrity.index_digest),
            actual: hex::encode(computed_index_digest),
        });
    }

    // Verify data digest.
    let computed_data_digest: [u8; 32] = Sha256::digest(&bundle.data).into();
    result.data_digest_ok = computed_data_digest == bundle.manifest.integrity.data_digest;
    if !result.data_digest_ok {
        return Err(AhuError::DataDigestMismatch {
            expected: hex::encode(bundle.manifest.integrity.data_digest),
            actual: hex::encode(computed_data_digest),
        });
    }

    // Verify sort order.
    validate_sort_order(&bundle.index)?;
    result.sort_order_ok = true;

    // Verify entry count.
    result.entry_count_matches = bundle.index.len() as u64 == bundle.manifest.entry_count;
    if !result.entry_count_matches {
        result.warnings.push(format!(
            "entry_count in manifest ({}) does not match index record count ({})",
            bundle.manifest.entry_count,
            bundle.index.len()
        ));
    }

    // Verify entry bounds (each record's offset+length within the data section).
    for record in &bundle.index {
        if record.is_tombstone() {
            continue;
        }
        if bundle.entry_bytes(record).is_none() {
            result.entry_bounds_ok = false;
            return Err(AhuError::EntryOutOfBounds {
                offset: record.data_offset,
                length: record.data_length,
            });
        }
    }

    // Check for delta-specific requirements.
    if bundle.manifest.bundle_type == crate::manifest::BundleType::Delta
        && bundle.manifest.continuity.base_manifest_digest.is_none()
    {
        return Err(AhuError::DeltaMissingBase);
    }

    // Warn about missing seal.
    if !result.seal_present {
        result.warnings.push("seal section is empty".into());
    }

    Ok(result)
}

/// Compute the SHA-256 digest of the manifest bytes.
pub fn manifest_digest(manifest_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(manifest_bytes).into()
}

/// Check epoch high-water marks. Returns errors for any rollback attempt.
pub fn check_epochs(
    bundle: &Bundle,
    high_water_marks: &std::collections::HashMap<(String, Vec<u8>), u64>,
) -> Result<()> {
    for scope in &bundle.manifest.ca_scopes {
        let key = (
            bundle.manifest.producer_id.clone(),
            scope.issuer_key_hash.clone(),
        );
        if let Some(&hw) = high_water_marks.get(&key) {
            if scope.epoch <= hw {
                return Err(AhuError::EpochRollback {
                    scope: hex::encode(&scope.issuer_key_hash),
                    epoch: scope.epoch,
                    high_water: hw,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::BundleBuilder;
    use crate::manifest::*;
    use sha2::Sha256;
    use uuid::Uuid;

    fn test_manifest() -> Manifest {
        Manifest {
            format_version: 1,
            bundle_id: Uuid::nil(),
            producer_id: "test".into(),
            created_at: 1700000000,
            bundle_type: BundleType::Full,
            ca_scopes: vec![CaScope {
                hash_algorithm: vec![0x01],
                issuer_name_hash: vec![0xAA; 32],
                issuer_key_hash: vec![0xBB; 32],
                epoch: 5,
                responder_id: ResponderId {
                    id_type: ResponderIdType::ByKey,
                    value: vec![0xCC; 20],
                },
                responder_chain: None,
                signature_algorithm: vec![0x02],
                completeness: Completeness::AuthoritativeComplete,
            }],
            window: Window {
                produced_at: 1700000000,
                this_update_min: 1700000000,
                next_update_min: 1700086400,
                next_update_max: 1700093600,
            },
            integrity: Integrity {
                index_digest: [0; 32],
                data_digest: [0; 32],
            },
            entry_count: 0,
            continuity: Continuity {
                prev_manifest_digest: None,
                base_manifest_digest: None,
                chain_length: 0,
            },
            shard: None,
            compression: None,
            extensions: None,
        }
    }

    #[test]
    fn verify_valid_bundle() {
        let mut builder = BundleBuilder::new(test_manifest());
        builder.add_entry([0xAA; 32], b"response".to_vec());

        let bytes = builder.build(|m| Ok(Sha256::digest(m).to_vec())).unwrap();

        let bundle = Bundle::from_bytes(&bytes).unwrap();
        let result = verify_structure(&bundle).unwrap();
        assert!(result.index_digest_ok);
        assert!(result.data_digest_ok);
        assert!(result.sort_order_ok);
        assert!(result.entry_bounds_ok);
        assert!(result.entry_count_matches);
    }

    #[test]
    fn epoch_rollback_rejected() {
        let mut builder = BundleBuilder::new(test_manifest());
        builder.add_entry([0xAA; 32], b"response".to_vec());

        let bytes = builder.build(|m| Ok(Sha256::digest(m).to_vec())).unwrap();

        let bundle = Bundle::from_bytes(&bytes).unwrap();

        let mut hw = std::collections::HashMap::new();
        hw.insert(("test".to_string(), vec![0xBB; 32]), 5);

        let err = check_epochs(&bundle, &hw).unwrap_err();
        assert!(matches!(err, AhuError::EpochRollback { .. }));
    }
}
