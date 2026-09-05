use std::collections::BTreeMap;

use hoike_sign::{
    CaIdentity, CertIdCompat, CertificateStatus, GenerationConfig, MlDsaSignatureBytes,
    StatusSnapshot, ml_dsa_44_signer, ml_dsa_65_signer, ml_dsa_87_signer, produce_bundle,
};
use sha2::{Digest, Sha256};
use x509_cert::ext::pkix::CrlReason;

fn test_ca() -> CaIdentity {
    CaIdentity {
        label: "pq-test-ca".into(),
        issuer_name_der: b"CN=PQ Test CA,O=Hoike PQC Test".to_vec(),
        issuer_key_bytes: b"pq-test-ca-public-key-bytes".to_vec(),
    }
}

fn test_snapshot(count: usize) -> StatusSnapshot {
    let now = hoike_sign::source::unix_now().unwrap();
    let mut entries = BTreeMap::new();
    for i in 0..count {
        let serial = vec![(i >> 8) as u8, (i & 0xFF) as u8];
        if i % 5 == 0 {
            entries.insert(
                serial,
                CertificateStatus::Revoked {
                    revocation_time: 1700000000,
                    reason: Some(CrlReason::KeyCompromise),
                },
            );
        } else {
            entries.insert(serial, CertificateStatus::Good);
        }
    }
    StatusSnapshot {
        entries,
        this_update: now,
        next_update: Some(now + 86400),
    }
}

#[test]
fn produce_ml_dsa_44_bundle() {
    let ca = test_ca();
    let snapshot = test_snapshot(10);
    let config = GenerationConfig {
        certid_compat: CertIdCompat::Sha256Only,
        ..Default::default()
    };
    let mut signer = ml_dsa_44_signer(&[42u8; 32]);

    let bundle_bytes = produce_bundle::<_, MlDsaSignatureBytes>(
        &ca,
        &snapshot,
        &config,
        &mut signer,
        |m| Ok(Sha256::digest(m).to_vec()),
        None,
    )
    .unwrap();

    let bundle = ahu::Bundle::from_bytes(&bundle_bytes).unwrap();
    let result = ahu::verify_structure(&bundle).unwrap();
    assert!(result.index_digest_ok);
    assert!(result.data_digest_ok);
    assert!(result.sort_order_ok);
    assert_eq!(bundle.manifest.entry_count, 10);

    println!(
        "ML-DSA-44 bundle: {} bytes, {} entries, avg {} bytes/entry",
        bundle_bytes.len(),
        bundle.manifest.entry_count,
        bundle_bytes.len() / bundle.manifest.entry_count as usize
    );
}

#[test]
fn produce_ml_dsa_65_bundle() {
    let ca = test_ca();
    let snapshot = test_snapshot(10);
    let config = GenerationConfig {
        certid_compat: CertIdCompat::Sha256Only,
        ..Default::default()
    };
    let mut signer = ml_dsa_65_signer(&[43u8; 32]);

    let bundle_bytes = produce_bundle::<_, MlDsaSignatureBytes>(
        &ca,
        &snapshot,
        &config,
        &mut signer,
        |m| Ok(Sha256::digest(m).to_vec()),
        None,
    )
    .unwrap();

    let bundle = ahu::Bundle::from_bytes(&bundle_bytes).unwrap();
    let result = ahu::verify_structure(&bundle).unwrap();
    assert!(result.index_digest_ok);
    assert_eq!(bundle.manifest.entry_count, 10);

    println!(
        "ML-DSA-65 bundle: {} bytes, {} entries, avg {} bytes/entry",
        bundle_bytes.len(),
        bundle.manifest.entry_count,
        bundle_bytes.len() / bundle.manifest.entry_count as usize
    );
}

#[test]
fn produce_ml_dsa_87_bundle() {
    let ca = test_ca();
    let snapshot = test_snapshot(5);
    let config = GenerationConfig {
        certid_compat: CertIdCompat::Sha256Only,
        ..Default::default()
    };
    let mut signer = ml_dsa_87_signer(&[44u8; 32]);

    let bundle_bytes = produce_bundle::<_, MlDsaSignatureBytes>(
        &ca,
        &snapshot,
        &config,
        &mut signer,
        |m| Ok(Sha256::digest(m).to_vec()),
        None,
    )
    .unwrap();

    let bundle = ahu::Bundle::from_bytes(&bundle_bytes).unwrap();
    let result = ahu::verify_structure(&bundle).unwrap();
    assert!(result.index_digest_ok);
    assert_eq!(bundle.manifest.entry_count, 5);

    println!(
        "ML-DSA-87 bundle: {} bytes, {} entries, avg {} bytes/entry",
        bundle_bytes.len(),
        bundle.manifest.entry_count,
        bundle_bytes.len() / bundle.manifest.entry_count as usize
    );
}

#[test]
fn ml_dsa_response_is_valid_der() {
    let ca = test_ca();
    let snapshot = test_snapshot(3);
    let config = GenerationConfig {
        certid_compat: CertIdCompat::Sha256Only,
        ..Default::default()
    };
    let mut signer = ml_dsa_65_signer(&[50u8; 32]);

    let bundle_bytes = produce_bundle::<_, MlDsaSignatureBytes>(
        &ca,
        &snapshot,
        &config,
        &mut signer,
        |m| Ok(Sha256::digest(m).to_vec()),
        None,
    )
    .unwrap();

    let bundle = ahu::Bundle::from_bytes(&bundle_bytes).unwrap();

    // Verify each stored response is parseable DER
    for record in &bundle.index {
        if let Some(resp_bytes) = bundle.entry_bytes(record) {
            use der::Decode;
            let ocsp_resp = x509_ocsp::OcspResponse::from_der(resp_bytes)
                .expect("stored response should be valid DER OCSPResponse");
            assert_eq!(
                ocsp_resp.response_status,
                x509_ocsp::OcspResponseStatus::Successful
            );
        }
    }
}

#[test]
fn ml_dsa_65_larger_than_ecdsa() {
    let ca = test_ca();
    let snapshot = test_snapshot(10);
    let config = GenerationConfig {
        certid_compat: CertIdCompat::Sha256Only,
        ..Default::default()
    };

    // ECDSA bundle
    let secret = [1u8; 32];
    let mut ecdsa_key = p256::ecdsa::SigningKey::from_bytes((&secret).into()).unwrap();
    let ecdsa_bytes = produce_bundle::<_, p256::ecdsa::DerSignature>(
        &ca,
        &snapshot,
        &config,
        &mut ecdsa_key,
        |m| Ok(Sha256::digest(m).to_vec()),
        None,
    )
    .unwrap();

    // ML-DSA-65 bundle
    let mut ml_signer = ml_dsa_65_signer(&[1u8; 32]);
    let ml_bytes = produce_bundle::<_, MlDsaSignatureBytes>(
        &ca,
        &snapshot,
        &config,
        &mut ml_signer,
        |m| Ok(Sha256::digest(m).to_vec()),
        None,
    )
    .unwrap();

    println!(
        "ECDSA-P256: {} bytes | ML-DSA-65: {} bytes | ratio: {:.1}x",
        ecdsa_bytes.len(),
        ml_bytes.len(),
        ml_bytes.len() as f64 / ecdsa_bytes.len() as f64
    );

    assert!(
        ml_bytes.len() > ecdsa_bytes.len(),
        "ML-DSA-65 bundle ({}) should be larger than ECDSA ({}) due to ~3.3KB signature overhead per response",
        ml_bytes.len(),
        ecdsa_bytes.len()
    );
}

#[test]
fn ml_dsa_dual_certid_bundle() {
    let ca = test_ca();
    let snapshot = test_snapshot(5);
    let config = GenerationConfig {
        certid_compat: CertIdCompat::Dual,
        ..Default::default()
    };
    let mut signer = ml_dsa_44_signer(&[55u8; 32]);

    let bundle_bytes = produce_bundle::<_, MlDsaSignatureBytes>(
        &ca,
        &snapshot,
        &config,
        &mut signer,
        |m| Ok(Sha256::digest(m).to_vec()),
        None,
    )
    .unwrap();

    let bundle = ahu::Bundle::from_bytes(&bundle_bytes).unwrap();
    let result = ahu::verify_structure(&bundle).unwrap();
    assert!(result.index_digest_ok);
    // 5 certs × 2 CertIDs each = 10 index records
    assert_eq!(bundle.manifest.entry_count, 10);
}
