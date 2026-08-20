use der::Encode;
use der::asn1::{Null, OctetString};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use signature::Signer;
use spki::{AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding};
use x509_ocsp::builder::OcspResponseBuilder;
use x509_ocsp::{CertId, CertStatus, OcspGeneralizedTime, ResponderId, SingleResponse};

use ahu::{
    BundleBuilder, BundleType, Completeness, Continuity, Integrity, Manifest,
    ResponderId as AhuResponderId, ResponderIdType, Window,
};

use crate::error::{Result, SignError};
use crate::source::{CaIdentity, CertificateStatus, StatusSnapshot};

#[derive(Debug, Clone)]
pub struct GenerationConfig {
    pub producer_id: String,
    pub epoch: u64,
    pub validity_secs: u64,
    pub jitter_secs: u64,
    pub certid_compat: CertIdCompat,
    pub completeness: Completeness,
    /// Number of SingleResponse elements per signed BasicOCSPResponse.
    /// 1 = one signature per certificate (default).
    /// >1 = batch N certificates under one signature, amortizing signature cost.
    pub bucket_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertIdCompat {
    Sha256Only,
    Sha1Only,
    Dual,
}

impl Default for GenerationConfig {
    fn default() -> Self {
        GenerationConfig {
            producer_id: "hoike-signer".into(),
            epoch: 1,
            validity_secs: 86400,
            jitter_secs: 7200,
            certid_compat: CertIdCompat::Dual,
            completeness: Completeness::Partial,
            bucket_size: 1,
        }
    }
}

pub fn produce_bundle<S, Sig>(
    ca: &CaIdentity,
    snapshot: &StatusSnapshot,
    config: &GenerationConfig,
    signer: &mut S,
    seal_fn: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
) -> Result<Vec<u8>>
where
    S: Signer<Sig> + DynSignatureAlgorithmIdentifier,
    Sig: SignatureBitStringEncoding,
{
    let now = snapshot.this_update;
    let next_update_base = now + config.validity_secs;
    let produced_at = ocsp_time(now)?;

    let issuer_name_hash_sha256 = Sha256::digest(&ca.issuer_name_der);
    let issuer_key_hash_sha256 = Sha256::digest(&ca.issuer_key_bytes);
    let issuer_name_hash_sha1 = Sha1::digest(&ca.issuer_name_der);
    let issuer_key_hash_sha1 = Sha1::digest(&ca.issuer_key_bytes);

    let responder_key_hash = Sha1::digest(&ca.issuer_key_bytes);
    let responder_id =
        ResponderId::ByKey(OctetString::new(responder_key_hash.to_vec()).map_err(SignError::Der)?);

    let sha256_oid = const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    let sha1_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

    let mut ca_scopes = vec![ahu::CaScope {
        hash_algorithm: sha256_oid.as_bytes().to_vec(),
        issuer_name_hash: issuer_name_hash_sha256.to_vec(),
        issuer_key_hash: issuer_key_hash_sha256.to_vec(),
        epoch: config.epoch,
        responder_id: AhuResponderId {
            id_type: ResponderIdType::ByKey,
            value: responder_key_hash.to_vec(),
        },
        responder_chain: None,
        signature_algorithm: vec![],
        completeness: config.completeness,
    }];

    // Dual and Sha1Only modes produce SHA-1 CertID entries; register a SHA-1
    // ca_scope so the router can route requests with SHA-1 issuer hashes.
    if matches!(
        config.certid_compat,
        CertIdCompat::Dual | CertIdCompat::Sha1Only
    ) {
        ca_scopes.push(ahu::CaScope {
            hash_algorithm: sha1_oid.as_bytes().to_vec(),
            issuer_name_hash: issuer_name_hash_sha1.to_vec(),
            issuer_key_hash: issuer_key_hash_sha1.to_vec(),
            epoch: config.epoch,
            responder_id: AhuResponderId {
                id_type: ResponderIdType::ByKey,
                value: responder_key_hash.to_vec(),
            },
            responder_chain: None,
            signature_algorithm: vec![],
            completeness: config.completeness,
        });
    }

    // For Sha256Only, remove the SHA-256 scope if only SHA-1 is wanted —
    // but Sha256Only should keep just the SHA-256 scope (already the default).

    let manifest = Manifest {
        format_version: 1,
        bundle_id: uuid::Uuid::nil(),
        producer_id: config.producer_id.clone(),
        created_at: now,
        bundle_type: BundleType::Full,
        ca_scopes,
        window: Window {
            produced_at: now,
            this_update_min: now,
            next_update_min: next_update_base,
            next_update_max: next_update_base + config.jitter_secs,
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
    };

    let mut builder = BundleBuilder::new(manifest);
    let this_update = ocsp_time(now)?;

    // Prepare all entries: (entry_keys, cert_id(s), single_response(s)) per serial
    struct PreparedEntry {
        entry_keys: Vec<[u8; 32]>,
        single_responses: Vec<SingleResponse>,
    }

    let mut prepared: Vec<PreparedEntry> = Vec::with_capacity(snapshot.entries.len());

    for (serial, status) in &snapshot.entries {
        let cert_status = match status {
            CertificateStatus::Good => CertStatus::good(),
            CertificateStatus::Revoked {
                revocation_time,
                reason,
            } => {
                let revoked_info = x509_ocsp::RevokedInfo {
                    revocation_time: ocsp_time(*revocation_time)?,
                    revocation_reason: *reason,
                };
                CertStatus::revoked(revoked_info)
            }
        };

        let serial_number =
            x509_cert::serial_number::SerialNumber::new(serial).map_err(SignError::Der)?;

        let entry_key_jitter = {
            let mut h = Sha256::new();
            h.update(serial);
            let d: [u8; 32] = h.finalize().into();
            let frac = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) as u64;
            (frac * config.jitter_secs) / u32::MAX as u64
        };
        let next_update_time = next_update_base + entry_key_jitter;
        let next_update = ocsp_time(next_update_time)?;

        match config.certid_compat {
            CertIdCompat::Sha256Only => {
                let cert_id = build_certid(
                    sha256_oid,
                    &issuer_name_hash_sha256,
                    &issuer_key_hash_sha256,
                    serial_number,
                )?;
                let certid_der = cert_id.to_der().map_err(SignError::Der)?;
                let entry_key: [u8; 32] = Sha256::digest(&certid_der).into();
                let single = SingleResponse::new(cert_id, cert_status, this_update)
                    .with_next_update(next_update);
                prepared.push(PreparedEntry {
                    entry_keys: vec![entry_key],
                    single_responses: vec![single],
                });
            }
            CertIdCompat::Sha1Only => {
                let cert_id = build_certid(
                    sha1_oid,
                    &issuer_name_hash_sha1,
                    &issuer_key_hash_sha1,
                    serial_number,
                )?;
                let certid_der = cert_id.to_der().map_err(SignError::Der)?;
                let entry_key: [u8; 32] = Sha256::digest(&certid_der).into();
                let single = SingleResponse::new(cert_id, cert_status, this_update)
                    .with_next_update(next_update);
                prepared.push(PreparedEntry {
                    entry_keys: vec![entry_key],
                    single_responses: vec![single],
                });
            }
            CertIdCompat::Dual => {
                let cert_id_sha256 = build_certid(
                    sha256_oid,
                    &issuer_name_hash_sha256,
                    &issuer_key_hash_sha256,
                    serial_number.clone(),
                )?;
                let cert_id_sha1 = build_certid(
                    sha1_oid,
                    &issuer_name_hash_sha1,
                    &issuer_key_hash_sha1,
                    serial_number,
                )?;
                let ek256: [u8; 32] =
                    Sha256::digest(&cert_id_sha256.to_der().map_err(SignError::Der)?).into();
                let ek1: [u8; 32] =
                    Sha256::digest(&cert_id_sha1.to_der().map_err(SignError::Der)?).into();

                let single_sha256 = SingleResponse::new(cert_id_sha256, cert_status, this_update)
                    .with_next_update(next_update);
                let single_sha1 = SingleResponse::new(cert_id_sha1, cert_status, this_update)
                    .with_next_update(next_update);

                prepared.push(PreparedEntry {
                    entry_keys: vec![ek256, ek1],
                    single_responses: vec![single_sha256, single_sha1],
                });
            }
        }
    }

    // Group entries into buckets and sign
    let bucket_size = config.bucket_size.max(1);
    for bucket in prepared.chunks(bucket_size) {
        let mut response_builder = OcspResponseBuilder::new(responder_id.clone());
        let mut all_keys: Vec<[u8; 32]> = Vec::new();

        for entry in bucket {
            for single in &entry.single_responses {
                response_builder = response_builder.with_single_response(single.clone());
            }
            all_keys.extend_from_slice(&entry.entry_keys);
        }

        let ocsp_response = response_builder
            .sign(signer, None, produced_at)
            .map_err(SignError::from)?;
        let response_der = ocsp_response.to_der().map_err(SignError::Der)?;

        add_shared_entries(&mut builder, &all_keys, response_der);
    }

    builder
        .build(|manifest_bytes| {
            seal_fn(manifest_bytes).map_err(|e| ahu::AhuError::Write(e.to_string()))
        })
        .map_err(SignError::Bundle)
}

fn build_certid(
    hash_oid: const_oid::ObjectIdentifier,
    name_hash: &[u8],
    key_hash: &[u8],
    serial: x509_cert::serial_number::SerialNumber,
) -> Result<CertId> {
    Ok(CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: hash_oid,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(name_hash.to_vec()).map_err(SignError::Der)?,
        issuer_key_hash: OctetString::new(key_hash.to_vec()).map_err(SignError::Der)?,
        serial_number: serial,
    })
}

/// Add multiple entry keys all pointing to the same response blob.
/// Pairs consecutive keys via add_dual_entry so ALIAS dedup stores the
/// data once. An odd key out gets a regular add_entry (one extra data copy
/// per bucket — negligible vs the signature amortization savings).
fn add_shared_entries(builder: &mut BundleBuilder, keys: &[[u8; 32]], response_der: Vec<u8>) {
    match keys.len() {
        0 => {}
        1 => {
            builder.add_entry(keys[0], response_der);
        }
        2 => {
            builder.add_dual_entry(keys[0], keys[1], response_der);
        }
        _ => {
            let mut i = 0;
            while i + 1 < keys.len() {
                builder.add_dual_entry(keys[i], keys[i + 1], response_der.clone());
                i += 2;
            }
            if i < keys.len() {
                builder.add_entry(keys[i], response_der);
            }
        }
    }
}

pub fn ocsp_time(epoch_secs: u64) -> Result<OcspGeneralizedTime> {
    let dt = epoch_to_datetime(epoch_secs)?;
    Ok(OcspGeneralizedTime::from(dt))
}

pub fn epoch_to_datetime(secs: u64) -> Result<der::DateTime> {
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = (time_of_day / 3600) as u8;
    let minutes = ((time_of_day % 3600) / 60) as u8;
    let seconds = (time_of_day % 60) as u8;

    let (year, month, day) = days_to_ymd(days);
    der::DateTime::new(year as u16, month as u8, day as u8, hours, minutes, seconds)
        .map_err(SignError::Der)
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::CertificateStatus;
    use der::{Decode, Encode};
    use p256::ecdsa::SigningKey;
    use std::collections::BTreeMap;
    use x509_cert::ext::pkix::CrlReason;

    fn test_signing_key() -> SigningKey {
        let secret = [1u8; 32];
        SigningKey::from_bytes((&secret).into()).unwrap()
    }

    fn test_snapshot() -> StatusSnapshot {
        let mut entries = BTreeMap::new();
        entries.insert(vec![42u8], CertificateStatus::Good);
        entries.insert(
            vec![100u8],
            CertificateStatus::Revoked {
                revocation_time: 1700000000,
                reason: Some(CrlReason::KeyCompromise),
            },
        );
        entries.insert(vec![0x01, 0x00], CertificateStatus::Good);

        StatusSnapshot {
            entries,
            this_update: 1700000000,
            next_update: Some(1700086400),
        }
    }

    fn test_ca() -> CaIdentity {
        CaIdentity {
            label: "test-ca".into(),
            issuer_name_der: b"CN=Test CA,O=Hoike Test".to_vec(),
            issuer_key_bytes: b"test-ca-public-key-bytes".to_vec(),
        }
    }

    #[test]
    fn produce_sha256_only_bundle() {
        let ca = test_ca();
        let snapshot = test_snapshot();
        let config = GenerationConfig {
            certid_compat: CertIdCompat::Sha256Only,
            ..Default::default()
        };
        let mut key = test_signing_key();

        let bundle_bytes = produce_bundle::<_, p256::ecdsa::DerSignature>(
            &ca,
            &snapshot,
            &config,
            &mut key,
            |m| Ok(Sha256::digest(m).to_vec()),
        )
        .unwrap();

        let bundle = ahu::Bundle::from_bytes(&bundle_bytes).unwrap();
        let result = ahu::verify_structure(&bundle).unwrap();
        assert!(result.index_digest_ok);
        assert!(result.data_digest_ok);
        assert!(result.sort_order_ok);
        assert_eq!(bundle.manifest.entry_count, 3);
    }

    #[test]
    fn produce_dual_certid_bundle() {
        let ca = test_ca();
        let snapshot = test_snapshot();
        let config = GenerationConfig {
            certid_compat: CertIdCompat::Dual,
            ..Default::default()
        };
        let mut key = test_signing_key();

        let bundle_bytes = produce_bundle::<_, p256::ecdsa::DerSignature>(
            &ca,
            &snapshot,
            &config,
            &mut key,
            |m| Ok(Sha256::digest(m).to_vec()),
        )
        .unwrap();

        let bundle = ahu::Bundle::from_bytes(&bundle_bytes).unwrap();
        let result = ahu::verify_structure(&bundle).unwrap();
        assert!(result.index_digest_ok);
        assert!(result.data_digest_ok);
        // 3 certs × 2 CertIDs each = 6 index records
        assert_eq!(bundle.manifest.entry_count, 6);
    }

    #[test]
    fn round_trip_lookup() {
        let ca = test_ca();
        let snapshot = test_snapshot();
        let config = GenerationConfig {
            certid_compat: CertIdCompat::Sha256Only,
            ..Default::default()
        };
        let mut key = test_signing_key();

        let bundle_bytes = produce_bundle::<_, p256::ecdsa::DerSignature>(
            &ca,
            &snapshot,
            &config,
            &mut key,
            |m| Ok(Sha256::digest(m).to_vec()),
        )
        .unwrap();

        let bundle = ahu::Bundle::from_bytes(&bundle_bytes).unwrap();

        let sha256_oid = const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
        let name_hash = Sha256::digest(&ca.issuer_name_der);
        let key_hash = Sha256::digest(&ca.issuer_key_bytes);
        let serial = x509_cert::serial_number::SerialNumber::new(&[42u8]).unwrap();
        let cert_id = build_certid(sha256_oid, &name_hash, &key_hash, serial).unwrap();
        let certid_der = cert_id.to_der().unwrap();
        let entry_key: [u8; 32] = Sha256::digest(&certid_der).into();

        let response = bundle
            .lookup(&entry_key)
            .expect("entry for serial 42 not found");
        assert!(!response.is_empty());

        let ocsp_resp = <x509_ocsp::OcspResponse as Decode>::from_der(response)
            .expect("invalid OCSP response DER");
        assert_eq!(
            ocsp_resp.response_status,
            x509_ocsp::OcspResponseStatus::Successful
        );
    }

    fn large_snapshot(n: usize) -> StatusSnapshot {
        let mut entries = BTreeMap::new();
        for i in 0..n {
            let serial = (i as u32 + 1).to_be_bytes().to_vec();
            if i % 5 == 0 {
                entries.insert(
                    serial,
                    CertificateStatus::Revoked {
                        revocation_time: 1700000000,
                        reason: Some(CrlReason::Unspecified),
                    },
                );
            } else {
                entries.insert(serial, CertificateStatus::Good);
            }
        }
        StatusSnapshot {
            entries,
            this_update: 1700000000,
            next_update: Some(1700086400),
        }
    }

    #[test]
    fn batching_bucket_5_produces_correct_bundle() {
        let ca = test_ca();
        let snapshot = large_snapshot(10);
        let config = GenerationConfig {
            certid_compat: CertIdCompat::Sha256Only,
            bucket_size: 5,
            ..Default::default()
        };
        let mut key = test_signing_key();

        let bundle_bytes = produce_bundle::<_, p256::ecdsa::DerSignature>(
            &ca,
            &snapshot,
            &config,
            &mut key,
            |m| Ok(Sha256::digest(m).to_vec()),
        )
        .unwrap();

        let bundle = ahu::Bundle::from_bytes(&bundle_bytes).unwrap();
        let result = ahu::verify_structure(&bundle).unwrap();
        assert!(result.index_digest_ok);
        assert!(result.data_digest_ok);
        assert!(result.sort_order_ok);
        // 10 entries, each with its own index record
        assert_eq!(bundle.manifest.entry_count, 10);
    }

    #[test]
    fn batching_preserves_lookup() {
        let ca = test_ca();
        let snapshot = large_snapshot(20);
        let config = GenerationConfig {
            certid_compat: CertIdCompat::Sha256Only,
            bucket_size: 5,
            ..Default::default()
        };
        let mut key = test_signing_key();

        let bundle_bytes = produce_bundle::<_, p256::ecdsa::DerSignature>(
            &ca,
            &snapshot,
            &config,
            &mut key,
            |m| Ok(Sha256::digest(m).to_vec()),
        )
        .unwrap();

        let bundle = ahu::Bundle::from_bytes(&bundle_bytes).unwrap();

        let sha256_oid = const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
        let name_hash = Sha256::digest(&ca.issuer_name_der);
        let key_hash_val = Sha256::digest(&ca.issuer_key_bytes);

        // Verify every entry can be looked up and returns valid OCSP DER
        for i in 0..20u32 {
            let serial_bytes = (i + 1).to_be_bytes().to_vec();
            let serial = x509_cert::serial_number::SerialNumber::new(&serial_bytes).unwrap();
            let cert_id = build_certid(sha256_oid, &name_hash, &key_hash_val, serial).unwrap();
            let certid_der = cert_id.to_der().unwrap();
            let entry_key: [u8; 32] = Sha256::digest(&certid_der).into();

            let response = bundle
                .lookup(&entry_key)
                .unwrap_or_else(|| panic!("entry for serial {} not found", i + 1));
            assert!(!response.is_empty(), "empty response for serial {}", i + 1);

            let ocsp_resp = <x509_ocsp::OcspResponse as Decode>::from_der(response)
                .unwrap_or_else(|e| panic!("invalid DER for serial {}: {e}", i + 1));
            assert_eq!(
                ocsp_resp.response_status,
                x509_ocsp::OcspResponseStatus::Successful
            );
        }
    }

    #[test]
    fn batching_reduces_data_size() {
        let ca = test_ca();
        let snapshot = large_snapshot(50);
        let mut key = test_signing_key();

        // Unbatched
        let config_1 = GenerationConfig {
            certid_compat: CertIdCompat::Sha256Only,
            bucket_size: 1,
            ..Default::default()
        };
        let unbatched = produce_bundle::<_, p256::ecdsa::DerSignature>(
            &ca,
            &snapshot,
            &config_1,
            &mut key,
            |m| Ok(Sha256::digest(m).to_vec()),
        )
        .unwrap();

        // Batched with bucket_size=10
        let config_10 = GenerationConfig {
            certid_compat: CertIdCompat::Sha256Only,
            bucket_size: 10,
            ..Default::default()
        };
        let batched = produce_bundle::<_, p256::ecdsa::DerSignature>(
            &ca,
            &snapshot,
            &config_10,
            &mut key,
            |m| Ok(Sha256::digest(m).to_vec()),
        )
        .unwrap();

        // Batched should be smaller (fewer signatures)
        assert!(
            batched.len() < unbatched.len(),
            "batched ({}) should be smaller than unbatched ({})",
            batched.len(),
            unbatched.len()
        );
    }
}
