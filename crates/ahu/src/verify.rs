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
/// The decoded manifest must agree with the encoded manifest before its
/// digests or metadata can be used by a caller.
pub fn verify_structure(bundle: &Bundle) -> Result<VerifyResult> {
    let manifest = crate::manifest::Manifest::from_cbor(&bundle.manifest_bytes)?;
    // Bundle exposes both representations publicly. Compare their normalized
    // encodings so accepted CBOR encodings and NaN extension values remain
    // usable, without allowing unsigned changes to the decoded fields. CMS
    // verification still authenticates the original manifest_bytes verbatim.
    if manifest.to_cbor() != bundle.manifest.to_cbor() {
        return Err(AhuError::ManifestField(
            "decoded manifest does not match manifest bytes".into(),
        ));
    }

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
    result.index_digest_ok = computed_index_digest == manifest.integrity.index_digest;
    if !result.index_digest_ok {
        return Err(AhuError::IndexDigestMismatch {
            expected: hex::encode(manifest.integrity.index_digest),
            actual: hex::encode(computed_index_digest),
        });
    }

    // Verify data digest.
    let computed_data_digest: [u8; 32] = Sha256::digest(&bundle.data).into();
    result.data_digest_ok = computed_data_digest == manifest.integrity.data_digest;
    if !result.data_digest_ok {
        return Err(AhuError::DataDigestMismatch {
            expected: hex::encode(manifest.integrity.data_digest),
            actual: hex::encode(computed_data_digest),
        });
    }

    // Verify sort order.
    validate_sort_order(&bundle.index)?;
    result.sort_order_ok = true;

    // Verify entry count.
    result.entry_count_matches = bundle.index.len() as u64 == manifest.entry_count;
    if !result.entry_count_matches {
        result.warnings.push(format!(
            "entry_count in manifest ({}) does not match index record count ({})",
            manifest.entry_count,
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
    if manifest.bundle_type == crate::manifest::BundleType::Delta
        && manifest.continuity.base_manifest_digest.is_none()
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

    fn bundle_with_manifest(manifest: Manifest) -> Bundle {
        let mut builder = BundleBuilder::new(manifest);
        builder.add_entry([0xAA; 32], b"response".to_vec());
        Bundle::from_bytes(&builder.build(|m| Ok(Sha256::digest(m).to_vec())).unwrap()).unwrap()
    }

    #[test]
    fn verify_rejects_payload_and_decoded_digest_mismatches() {
        let valid = bundle_with_manifest(test_manifest());
        for section in ["data", "index"] {
            let mut bundle = Bundle::from_bytes(&valid.to_bytes().unwrap()).unwrap();
            match section {
                "data" => {
                    bundle.data[0] ^= 1;
                    bundle.manifest.integrity.data_digest = Sha256::digest(&bundle.data).into();
                }
                "index" => {
                    bundle.index[0].entry_key[0] ^= 1;
                    let mut index = Vec::new();
                    bundle.index[0].write_to(&mut index).unwrap();
                    bundle.manifest.integrity.index_digest = Sha256::digest(&index).into();
                }
                _ => unreachable!(),
            }
            assert_eq!(bundle.manifest_bytes, valid.manifest_bytes);
            let result = verify_structure(&bundle);
            assert!(
                matches!(result, Err(AhuError::ManifestField(_))),
                "modified {section} accepted with an unsigned decoded digest: {result:?}"
            );
        }
    }

    #[test]
    fn verify_rejects_decoded_metadata_mismatches() {
        let valid = bundle_with_manifest(test_manifest());
        for field in ["producer", "scope", "epoch", "window", "entry_count"] {
            let mut bundle = Bundle::from_bytes(&valid.to_bytes().unwrap()).unwrap();
            match field {
                "producer" => bundle.manifest.producer_id = "other".into(),
                "scope" => bundle.manifest.ca_scopes[0].issuer_key_hash[0] ^= 1,
                "epoch" => bundle.manifest.ca_scopes[0].epoch += 1,
                "window" => bundle.manifest.window.next_update_min += 1,
                "entry_count" => bundle.manifest.entry_count += 1,
                _ => unreachable!(),
            }
            assert_eq!(bundle.manifest_bytes, valid.manifest_bytes);
            let result = verify_structure(&bundle);
            assert!(
                matches!(result, Err(AhuError::ManifestField(_))),
                "decoded {field} mismatch accepted: {result:?}"
            );
        }
    }

    #[test]
    fn verify_accepts_equivalent_manifest_encoding() {
        let mut bundle = bundle_with_manifest(test_manifest());
        let mut value: ciborium::Value =
            ciborium::from_reader(bundle.manifest_bytes.as_slice()).unwrap();
        let ciborium::Value::Map(ref mut entries) = value else {
            panic!("test manifest must be a map");
        };
        entries.reverse();
        bundle.manifest_bytes.clear();
        ciborium::into_writer(&value, &mut bundle.manifest_bytes).unwrap();

        let parsed = Bundle::from_bytes(&bundle.to_bytes().unwrap()).unwrap();
        assert_eq!(parsed.manifest, bundle.manifest);
        assert_ne!(parsed.manifest_bytes, parsed.manifest.to_cbor());
        verify_structure(&parsed).unwrap();
    }

    #[test]
    fn verify_accepts_parsed_nan_extensions_but_rejects_changed_values() {
        let mut manifest = test_manifest();
        manifest.extensions = Some(vec![("test".into(), ciborium::Value::Float(f64::NAN))]);
        let mut bundle = bundle_with_manifest(manifest);
        // Manifest's derived PartialEq is non-reflexive for NaN. A consistently
        // parsed extension must still be accepted by structural verification.
        verify_structure(&bundle).unwrap();
        bundle.manifest.extensions.as_mut().unwrap()[0].1 = ciborium::Value::Float(0.0);
        let result = verify_structure(&bundle);
        assert!(
            matches!(result, Err(AhuError::ManifestField(_))),
            "changed decoded extension accepted: {result:?}"
        );
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
