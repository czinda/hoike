//! F08 regression coverage for configured seal material.
//!
//! 1. A configured seal certificate is normalized from PEM or DER to the same
//!    DER bytes; malformed input fails instead of falling back.
//! 2. The seal key/certificate pair is proven with a real CMS preflight seal
//!    before publication. A mismatched or expired replacement certificate
//!    fails the next signing pass — revalidated per pass, never a cached
//!    startup verdict — and preserves the previously published generation.
//!
//! Production paths go through `sign_and_write_scope`, the same orchestration
//! the background signer loop and the on-demand admin endpoint use.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use hoike_sign::source::unix_now;
use hoike_sign::{
    CaIdentity, CertificateStatus, Epoch, PersistentSources, RevocationSource, SealKey,
    StatusChange, StatusSnapshot, load_seal_certificate, sign_and_write_scope,
    validate_seal_materials,
};

fn current_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn key(seed: u8) -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
}

/// Synthetic snapshot source with a fresh validity window (no live directory
/// or CRL needed). Injected into the persistent-source map, which
/// `sign_and_write_scope` resolves before consulting `ca.source`.
struct MockSource(Vec<(Vec<u8>, CertificateStatus)>);

impl RevocationSource for MockSource {
    fn snapshot(&self, _ca: &CaIdentity) -> hoike_sign::Result<StatusSnapshot> {
        let now = unix_now()?;
        Ok(StatusSnapshot {
            entries: self.0.iter().cloned().collect(),
            this_update: now,
            next_update: Some(now + 86400),
            ..Default::default()
        })
    }
    fn changes_since(
        &self,
        _ca: &CaIdentity,
        _since: Epoch,
    ) -> hoike_sign::Result<Vec<StatusChange>> {
        Ok(vec![])
    }
    fn supports_streaming(&self) -> bool {
        false
    }
    fn is_authoritative_complete(&self) -> bool {
        false
    }
}

/// Re-issue `generate_seal_cert`'s certificate for `key` with an explicit
/// validity window, so production checks run against fresh material rather
/// than the generator's historic fixed window.
fn reissued_certificate(key: &p256::ecdsa::SigningKey, not_before: u64, not_after: u64) -> Vec<u8> {
    use der::{Decode, Encode};
    use signature::Signer;
    let mut cert =
        x509_cert::Certificate::from_der(&hoike_sign::generate_seal_cert(key).unwrap()).unwrap();
    let time = |secs: u64| {
        x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_unix_duration(std::time::Duration::from_secs(secs)).unwrap(),
        )
    };
    cert.tbs_certificate.validity = x509_cert::time::Validity {
        not_before: time(not_before),
        not_after: time(not_after),
    };
    let sig: p256::ecdsa::DerSignature = key.sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = der::asn1::BitString::from_bytes(sig.as_bytes()).unwrap();
    cert.to_der().unwrap()
}

/// Write a standard PEM certificate (LF line endings, 64-column base64) —
/// the encoding an operator's real file and the serving-side pin loader use.
fn write_pem(path: &Path, der: &[u8]) {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    std::fs::write(path, pem).unwrap();
}

/// Write the same certificate as a messier PEM with CRLF line endings,
/// whitespace padding around the base64, and a trailing blank line. The
/// signer-side normalizer must tolerate this ordinary variation.
fn write_pem_with_whitespace(path: &Path, der: &[u8]) {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\r\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str("  ");
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push_str(" \r\n");
    }
    pem.push_str("-----END CERTIFICATE-----\r\n\r\n");
    std::fs::write(path, pem).unwrap();
}

struct Fixture {
    config: hoike_core::Config,
    sources: PersistentSources,
    bundle_path: PathBuf,
}

/// Configure a real signer scope around the given seal key and certificate
/// file, with the same certificate pinned for admission. State is initialized
/// explicitly (F04) and the revocation source is injected directly.
fn production_fixture(dir: &Path, seal_key: &p256::ecdsa::SigningKey, seal_cert: &Path) -> Fixture {
    use p256::pkcs8::EncodePrivateKey;
    let key_path = dir.join("seal-key.p8");
    std::fs::write(&key_path, seal_key.to_pkcs8_der().unwrap().as_bytes()).unwrap();
    let bundle_path = dir.join("test.ahu");
    let config_path = dir.join("hoike.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
[server]
[storage]
bundle_dir = "{dir}/bundles"
state_db = "{dir}/state"
seal_signer_pins = ["{cert}"]

[[ca]]
label = "test"
issuer_name_der_b64 = "bmFtZQ=="
issuer_key_bytes_b64 = "a2V5"
bundle_file = "{bundle}"
seal_key = "{key}"
seal_cert = "{cert}"

[ca.signing_key]
type = "demo"
"#,
            dir = dir.display(),
            cert = seal_cert.display(),
            bundle = bundle_path.display(),
            key = key_path.display(),
        ),
    )
    .unwrap();
    let config = hoike_core::Config::from_file(&config_path).unwrap();
    hoike_core::StateStore::initialize(&config.storage.state_db.join("state.json")).unwrap();

    let mut sources: PersistentSources = HashMap::new();
    sources.insert(
        "test".to_string(),
        Box::new(MockSource(vec![(vec![0x01], CertificateStatus::Good)])),
    );
    Fixture {
        config,
        sources,
        bundle_path,
    }
}

/// F08: the same certificate configured as PEM (with ordinary line endings
/// and whitespace) and as DER must normalize to identical DER bytes, survive
/// real configured production, and produce a seal the pinned loader accepts.
/// Malformed input must fail, never fall back.
#[test]
fn configured_pem_and_der_seal_certificates_are_equivalent() {
    let dir = tempfile::tempdir().unwrap();
    let now = current_time();
    let seal_key = key(0x07);
    let cert_der = reissued_certificate(&seal_key, now - 60, now + 86400);
    let der_path = dir.path().join("seal-signer.der");
    let pem_path = dir.path().join("seal-signer.pem");
    let messy_pem_path = dir.path().join("seal-signer-messy.pem");
    std::fs::write(&der_path, &cert_der).unwrap();
    write_pem(&pem_path, &cert_der);
    write_pem_with_whitespace(&messy_pem_path, &cert_der);

    // Normalization: both configured encodings yield the same DER bytes —
    // including a PEM with CRLF endings and whitespace padding.
    assert_eq!(
        load_seal_certificate(&pem_path).unwrap(),
        load_seal_certificate(&der_path).unwrap()
    );
    assert_eq!(load_seal_certificate(&messy_pem_path).unwrap(), cert_der);
    assert_eq!(load_seal_certificate(&pem_path).unwrap(), cert_der);

    // Malformed input fails: garbage DER, invalid base64 in PEM, a wrong PEM
    // label, and truncated DER must all be rejected.
    let garbage = dir.path().join("garbage.der");
    std::fs::write(&garbage, b"not a certificate").unwrap();
    assert!(load_seal_certificate(&garbage).is_err());
    let bad_b64 = dir.path().join("bad-b64.pem");
    std::fs::write(
        &bad_b64,
        "-----BEGIN CERTIFICATE-----\r\n!!!!\r\n-----END CERTIFICATE-----\r\n",
    )
    .unwrap();
    assert!(load_seal_certificate(&bad_b64).is_err());
    let wrong_label = dir.path().join("wrong-label.pem");
    write_pem(&wrong_label, &cert_der);
    let mislabeled = std::fs::read_to_string(&wrong_label)
        .unwrap()
        .replace("CERTIFICATE", "PRIVATE KEY");
    std::fs::write(&wrong_label, mislabeled).unwrap();
    assert!(load_seal_certificate(&wrong_label).is_err());
    let truncated = dir.path().join("truncated.der");
    std::fs::write(&truncated, &cert_der[..cert_der.len() - 5]).unwrap();
    assert!(load_seal_certificate(&truncated).is_err());

    // The pair preflight accepts the matching certificate at `now`.
    assert!(validate_seal_materials(&SealKey::EcdsaP256(seal_key.clone()), &cert_der, now).is_ok());

    // Real configured production must produce a seal accepted by the pinned
    // loader for BOTH encodings — not just equivalent decoded bytes.
    let mut fingerprints = Vec::new();
    for (encoding, cert_path) in [("pem", &pem_path), ("der", &der_path)] {
        let prod_dir = tempfile::tempdir().unwrap();
        let fixture = production_fixture(prod_dir.path(), &seal_key, cert_path);
        let signed = sign_and_write_scope(&fixture.config, &fixture.sources, &fixture.config.ca[0])
            .unwrap_or_else(|e| panic!("{encoding} seal certificate must sign: {e}"));
        assert_eq!(signed.epoch, 1, "first pass derives epoch 1");
        let bundle = ahu::Bundle::from_file(&fixture.bundle_path).unwrap();
        let verification =
            hoike_core::admission::authenticate_bundle(&bundle, &fixture.config.storage, now)
                .unwrap_or_else(|e| {
                    panic!("{encoding} seal certificate must be admitted by the pinned loader: {e}")
                });
        fingerprints.push(verification.signer_sha256);
    }
    assert_eq!(
        fingerprints[0], fingerprints[1],
        "both encodings must seal as the same pinned signer"
    );
}

/// F08/F07-adjacent: a configured seal certificate for a different key than
/// the configured seal key must fail the preflight before publication, and
/// the previously published generation must remain untouched.
#[test]
fn seal_pair_mismatch_fails_before_publication() {
    let dir = tempfile::tempdir().unwrap();
    let now = current_time();
    let seal_key = key(0x07);
    let other_key = key(0x08);
    let other_cert = reissued_certificate(&other_key, now - 60, now + 86400);

    // The pair proof itself must reject a certificate for an unrelated key.
    assert!(
        validate_seal_materials(&SealKey::EcdsaP256(seal_key.clone()), &other_cert, now).is_err()
    );

    // First pass with matching material publishes a generation.
    let cert_path = dir.path().join("seal-signer.pem");
    write_pem(
        &cert_path,
        &reissued_certificate(&seal_key, now - 60, now + 86400),
    );
    let fixture = production_fixture(dir.path(), &seal_key, &cert_path);
    sign_and_write_scope(&fixture.config, &fixture.sources, &fixture.config.ca[0]).unwrap();
    let prior_bytes = std::fs::read(&fixture.bundle_path).unwrap();

    // Replace the certificate with one for an unrelated key. The next signing
    // pass — the same path on-demand signing and post-rotation reloads take —
    // must revalidate and fail before publication.
    write_pem(&cert_path, &other_cert);
    let err = sign_and_write_scope(&fixture.config, &fixture.sources, &fixture.config.ca[0])
        .expect_err("mismatched seal pair must fail the signing pass");
    assert!(
        err.to_lowercase().contains("seal"),
        "error must identify the seal material: {err}"
    );

    // The previously published generation is untouched.
    assert_eq!(std::fs::read(&fixture.bundle_path).unwrap(), prior_bytes);
}

/// F08: a replacement seal certificate that is expired at `now` must be
/// rejected by the preflight (validity is checked per pass, not cached), and
/// the previously published generation must remain untouched.
#[test]
fn replacement_expired_seal_certificate_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let now = current_time();
    let seal_key = key(0x07);
    let expired_cert = reissued_certificate(&seal_key, now - 7200, now - 3600);

    // Matching key, but the certificate is outside its validity period.
    assert!(
        validate_seal_materials(&SealKey::EcdsaP256(seal_key.clone()), &expired_cert, now).is_err()
    );

    // First pass with fresh matching material publishes a generation.
    let cert_path = dir.path().join("seal-signer.der");
    std::fs::write(
        &cert_path,
        reissued_certificate(&seal_key, now - 60, now + 86400),
    )
    .unwrap();
    let fixture = production_fixture(dir.path(), &seal_key, &cert_path);
    sign_and_write_scope(&fixture.config, &fixture.sources, &fixture.config.ca[0]).unwrap();
    let prior_bytes = std::fs::read(&fixture.bundle_path).unwrap();

    // Swap in the expired replacement; the next pass must fail.
    std::fs::write(&cert_path, &expired_cert).unwrap();
    let err = sign_and_write_scope(&fixture.config, &fixture.sources, &fixture.config.ca[0])
        .expect_err("expired seal certificate must fail the signing pass");
    assert!(
        err.to_lowercase().contains("seal"),
        "error must identify the seal material: {err}"
    );

    assert_eq!(std::fs::read(&fixture.bundle_path).unwrap(), prior_bytes);
}
