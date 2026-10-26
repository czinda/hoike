//! F07/F08 regression coverage for configured seal material.
//!
//! 1. A configured seal certificate is normalized from PEM or DER to the same
//!    DER bytes; malformed input fails instead of falling back.
//! 2. The seal key/certificate pair is proven with a real CMS preflight seal
//!    before publication. A mismatched or expired replacement certificate
//!    fails the next signing pass — revalidated per pass, never a cached
//!    startup verdict — and preserves the previously published generation.
//! 3. Production requires a complete, persistent seal pair (F07): implicit
//!    OCSP-key reuse and non-demo ephemeral fallback are removed, a
//!    half-configured pair always errors, demo generates a distinct
//!    ephemeral pair only with no seal inputs, and the same public key is
//!    rejected as both OCSP signing key and seal key even through different
//!    file names.
//!
//! Production paths go through `sign_and_write_scope`, the same orchestration
//! the background signer loop and the on-demand admin endpoint use.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use hoike_sign::orchestrate::load_seal_materials;
use hoike_sign::source::unix_now;
use hoike_sign::{
    CaIdentity, CertificateStatus, Epoch, PersistentSources, RevocationSource, SealKey,
    StatusChange, StatusSnapshot, ensure_distinct_ecdsa_seal_key, load_seal_certificate,
    sign_and_write_scope, validate_seal_materials,
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

// ── F07: explicit production seal pair and loaded-key separation ──────────

/// How a fixture configures its OCSP signing key.
enum SigningStyle {
    /// A persistent PKCS#8 file key (production shape).
    File(p256::ecdsa::SigningKey),
    /// The ephemeral demo key.
    Demo,
}

/// Configure a signer scope with an explicit signing-key style and optional
/// seal inputs, mirroring `production_fixture` (pinned admission, injected
/// source, explicit state initialization).
fn signer_fixture(
    dir: &Path,
    signing: SigningStyle,
    seal_key_file: Option<&Path>,
    seal_cert_file: Option<&Path>,
    seal_cert_pin: Option<&Path>,
) -> Fixture {
    let bundle_path = dir.join("test.ahu");
    let config_path = dir.join("hoike.toml");
    let signing_table = match &signing {
        SigningStyle::File(key) => {
            let key_path = dir.join("ocsp-key.p8");
            use p256::pkcs8::EncodePrivateKey;
            std::fs::write(&key_path, key.to_pkcs8_der().unwrap().as_bytes()).unwrap();
            format!(
                "[ca.signing_key]\ntype = \"file\"\npath = \"{}\"\n",
                key_path.display()
            )
        }
        SigningStyle::Demo => "[ca.signing_key]\ntype = \"demo\"\n".to_string(),
    };
    let mut seal_lines = String::new();
    if let Some(path) = seal_key_file {
        seal_lines.push_str(&format!("seal_key = \"{}\"\n", path.display()));
    }
    if let Some(path) = seal_cert_file {
        seal_lines.push_str(&format!("seal_cert = \"{}\"\n", path.display()));
    }
    // Pin the seal certificate for admission when one is configured.
    let pins = match seal_cert_pin {
        Some(path) => format!("seal_signer_pins = [\"{}\"]\n", path.display()),
        None => "allow_unauthenticated_bundles = true\n".to_string(),
    };
    std::fs::write(
        &config_path,
        format!(
            r#"
[server]
[storage]
bundle_dir = "{dir}/bundles"
state_db = "{dir}/state"
{pins}

[[ca]]
label = "test"
issuer_name_der_b64 = "bmFtZQ=="
issuer_key_bytes_b64 = "a2V5"
bundle_file = "{bundle}"
{seal_lines}
{signing_table}
"#,
            dir = dir.display(),
            bundle = bundle_path.display(),
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

/// F07: production (persistent signing key) requires a complete persistent
/// seal pair. Neither input, or exactly one of the two, must fail before
/// anything is produced or published.
#[test]
fn production_requires_a_complete_seal_pair() {
    let dir = tempfile::tempdir().unwrap();
    let now = current_time();
    let seal_key = key(0x07);
    let seal_key_path = dir.path().join("seal-key.p8");
    use p256::pkcs8::EncodePrivateKey;
    std::fs::write(&seal_key_path, seal_key.to_pkcs8_der().unwrap().as_bytes()).unwrap();
    let seal_cert_path = dir.path().join("seal-signer.der");
    std::fs::write(
        &seal_cert_path,
        reissued_certificate(&seal_key, now - 60, now + 86400),
    )
    .unwrap();

    let cases: [(&str, Option<&Path>, Option<&Path>); 3] = [
        ("neither", None, None),
        ("seal key only", Some(&seal_key_path), None),
        ("seal cert only", None, Some(&seal_cert_path)),
    ];
    for (name, seal_key_file, seal_cert_file) in cases {
        let case_dir = tempfile::tempdir().unwrap();
        let fixture = signer_fixture(
            case_dir.path(),
            SigningStyle::File(key(0x09)),
            seal_key_file,
            seal_cert_file,
            Some(&seal_cert_path),
        );
        let production_without_seal_pair = fixture.config.ca[0].clone();
        assert!(
            load_seal_materials(&production_without_seal_pair).is_err(),
            "{name}: the loader must refuse to invent production seal material"
        );
        let err = sign_and_write_scope(&fixture.config, &fixture.sources, &fixture.config.ca[0])
            .expect_err(&format!(
                "{name}: production must require a complete seal pair"
            ));
        assert!(
            err.to_lowercase().contains("seal"),
            "{name}: error must identify the seal material: {err}"
        );
        assert!(
            !fixture.bundle_path.exists(),
            "{name}: nothing may be published on a failed pass"
        );
    }

    // A complete pair with the same fixture shape succeeds (control).
    let ok_dir = tempfile::tempdir().unwrap();
    let fixture = signer_fixture(
        ok_dir.path(),
        SigningStyle::File(key(0x09)),
        Some(&seal_key_path),
        Some(&seal_cert_path),
        Some(&seal_cert_path),
    );
    sign_and_write_scope(&fixture.config, &fixture.sources, &fixture.config.ca[0])
        .unwrap_or_else(|e| panic!("complete seal pair must sign: {e}"));
    assert!(fixture.bundle_path.exists());
}

/// F07: the same public key must be rejected as both the OCSP signing key and
/// the seal key even when configured through different file names (copy and
/// symlink aliases), and the previously published generation must survive.
/// The separation proof is asserted directly for software P-256 signers, the
/// bridge-shaped software signer, and (under the pkcs11 feature) the real
/// PKCS#11 bridge signature type.
#[test]
fn same_public_key_under_different_paths_is_rejected() {
    let ocsp_key = key(0x09);
    let independent_seal = SealKey::EcdsaP256(key(0x07));
    let same_key_seal = SealKey::EcdsaP256(ocsp_key.clone());

    // Software P-256 signer: same key rejected, independent key accepted.
    assert!(
        ensure_distinct_ecdsa_seal_key::<_, p256::ecdsa::DerSignature>(&ocsp_key, &same_key_seal)
            .is_err(),
        "the same key must be rejected as both OCSP signer and seal key"
    );
    assert!(
        ensure_distinct_ecdsa_seal_key::<_, p256::ecdsa::DerSignature>(
            &ocsp_key,
            &independent_seal
        )
        .is_ok(),
        "an independent seal key must be accepted"
    );

    // Bridge-shaped software signer with real ECDSA DER bytes.
    let bridge = SoftwareEcdsaBridge {
        key: ocsp_key.clone(),
        behavior: BridgeBehavior::Sign,
    };
    assert!(
        ensure_distinct_ecdsa_seal_key::<_, BridgeEcdsaSignature>(&bridge, &same_key_seal).is_err(),
        "the same key through the bridge shape must be rejected"
    );
    assert!(
        ensure_distinct_ecdsa_seal_key::<_, BridgeEcdsaSignature>(&bridge, &independent_seal)
            .is_ok(),
        "an independent seal key must be accepted through the bridge shape"
    );

    // The real PKCS#11 bridge signature type, software-backed.
    #[cfg(feature = "pkcs11")]
    {
        assert!(
            ensure_distinct_ecdsa_seal_key::<_, hoike_sign::Pkcs11EcdsaSignature>(
                &bridge,
                &same_key_seal
            )
            .is_err(),
            "the same key through the PKCS#11 bridge signature type must be rejected"
        );
        assert!(
            ensure_distinct_ecdsa_seal_key::<_, hoike_sign::Pkcs11EcdsaSignature>(
                &bridge,
                &independent_seal
            )
            .is_ok(),
            "an independent seal key must be accepted through the PKCS#11 bridge \
             signature type"
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let now = current_time();
    let seal_key = key(0x07);

    let seal_key_path = dir.path().join("seal-key.p8");
    let seal_cert_path = dir.path().join("seal-signer.der");
    use p256::pkcs8::EncodePrivateKey;
    std::fs::write(&seal_key_path, seal_key.to_pkcs8_der().unwrap().as_bytes()).unwrap();
    std::fs::write(
        &seal_cert_path,
        reissued_certificate(&seal_key, now - 60, now + 86400),
    )
    .unwrap();

    // First pass with genuinely independent material publishes a generation.
    let fixture = signer_fixture(
        dir.path(),
        SigningStyle::File(ocsp_key.clone()),
        Some(&seal_key_path),
        Some(&seal_cert_path),
        Some(&seal_cert_path),
    );
    sign_and_write_scope(&fixture.config, &fixture.sources, &fixture.config.ca[0]).unwrap();
    let prior_bytes = std::fs::read(&fixture.bundle_path).unwrap();

    // Replace the seal key file with the OCSP signing key material under the
    // same (and an additional symlinked) path — same public key, different
    // file names. The seal certificate is replaced to match, so the pair
    // itself is valid and only the OCSP/seal key separation can reject it.
    let ocsp_material = ocsp_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    std::fs::write(&seal_key_path, &ocsp_material).unwrap();
    let alias = dir.path().join("seal-alias.p8");
    std::fs::write(&alias, &ocsp_material).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&alias, dir.path().join("seal-link.p8")).unwrap();
    let reused_cert = reissued_certificate(&ocsp_key, now - 60, now + 86400);
    std::fs::write(&seal_cert_path, &reused_cert).unwrap();
    let link = dir.path().join("seal-link.p8");

    let err = sign_and_write_scope(&fixture.config, &fixture.sources, &fixture.config.ca[0])
        .expect_err("the same public key must be rejected as both OCSP and seal key");
    assert!(
        err.to_lowercase().contains("seal"),
        "error must identify the seal material: {err}"
    );
    assert_eq!(
        std::fs::read(&fixture.bundle_path).unwrap(),
        prior_bytes,
        "previously published generation must be untouched"
    );

    // Same rejection when the reused key is addressed through a symlink
    // alias — the check is on loaded keys, not path names. (The state
    // directory is already initialized, so this goes through the loader
    // rather than a second full fixture.)
    #[cfg(unix)]
    {
        let mut aliased = fixture.config.ca[0].clone();
        aliased.seal_key = Some(link);
        let err = load_seal_materials(&aliased)
            .err()
            .or_else(|| {
                // The pair itself is valid, so only the separation proof at
                // the loaded-signer boundary can reject it.
                sign_and_write_scope(&fixture.config, &fixture.sources, &aliased).err()
            })
            .expect("same key through a symlink alias must be rejected");
        assert!(
            err.to_lowercase().contains("seal"),
            "error must identify the seal material: {err}"
        );
    }
}

/// F07: explicit demo mode generates a *distinct* ephemeral seal pair only
/// when neither seal input is supplied; a half-specified demo pair is always
/// an error, and the generated seal key is never the demo OCSP key.
#[test]
fn demo_generates_distinct_seal_material() {
    let dir = tempfile::tempdir().unwrap();
    let now = current_time();
    let seal_key = key(0x07);
    let seal_key_path = dir.path().join("seal-key.p8");
    use p256::pkcs8::EncodePrivateKey;
    std::fs::write(&seal_key_path, seal_key.to_pkcs8_der().unwrap().as_bytes()).unwrap();
    let seal_cert_path = dir.path().join("seal-signer.der");
    std::fs::write(
        &seal_cert_path,
        reissued_certificate(&seal_key, now - 60, now + 86400),
    )
    .unwrap();

    // Neither input in demo mode: a distinct ephemeral pair is generated.
    let fixture = signer_fixture(dir.path(), SigningStyle::Demo, None, None, None);
    let (demo_seal, demo_cert) = load_seal_materials(&fixture.config.ca[0])
        .expect("demo mode with no seal inputs must generate ephemeral seal material");
    let SealKey::EcdsaP256(demo_seal_key) = &demo_seal else {
        panic!("demo seal material must be ECDSA P-256");
    };
    let demo_ocsp = hoike_sign::demo_ecdsa_p256_key();
    assert_ne!(
        demo_seal_key.verifying_key(),
        demo_ocsp.verifying_key(),
        "demo seal key must be distinct from the demo OCSP key"
    );
    assert!(
        validate_seal_materials(&demo_seal, &demo_cert, now).is_ok(),
        "generated demo seal pair must pass its own preflight"
    );
    // A second load generates fresh material — never a fixed historic key.
    let (second_seal, _) = load_seal_materials(&fixture.config.ca[0]).unwrap();
    let SealKey::EcdsaP256(second_key) = &second_seal else {
        panic!("demo seal material must be ECDSA P-256");
    };
    assert_ne!(
        second_key.verifying_key(),
        demo_seal_key.verifying_key(),
        "ephemeral demo seal keys must be freshly generated, not a fixed key"
    );

    // Full demo production succeeds end to end.
    sign_and_write_scope(&fixture.config, &fixture.sources, &fixture.config.ca[0])
        .unwrap_or_else(|e| panic!("demo production must sign: {e}"));

    // A half-specified pair is always an error, even in demo mode.
    for (name, seal_key_file, seal_cert_file) in [
        ("demo seal key only", Some(seal_key_path.as_path()), None),
        ("demo seal cert only", None, Some(seal_cert_path.as_path())),
    ] {
        let case_dir = tempfile::tempdir().unwrap();
        let fixture = signer_fixture(
            case_dir.path(),
            SigningStyle::Demo,
            seal_key_file,
            seal_cert_file,
            Some(&seal_cert_path),
        );
        assert!(
            load_seal_materials(&fixture.config.ca[0]).is_err(),
            "{name}: a half-configured pair must always error"
        );
        let err = sign_and_write_scope(&fixture.config, &fixture.sources, &fixture.config.ca[0])
            .expect_err(&format!("{name}: a half-configured pair must always error"));
        assert!(
            err.to_lowercase().contains("seal"),
            "{name}: error must identify the seal material: {err}"
        );
    }
}

// ── F07: the OCSP/seal key-separation proof at the signer boundary ─────────

/// A software-backed signer with the same trait shape as the PKCS#11 ECDSA
/// bridge: `signature::Signer<Sig>` where `Sig` carries DER ECDSA bytes
/// through the spki 0.7 bit-string encoding. Real ECDSA bytes, no HSM.
struct SoftwareEcdsaBridge {
    key: p256::ecdsa::SigningKey,
    behavior: BridgeBehavior,
}

enum BridgeBehavior {
    Sign,
    /// Fail inside the signer (e.g. HSM error) — the preflight must fail.
    FailSigning,
    /// Produce bytes that are not a valid DER ECDSA signature.
    GarbageBytes,
}

impl signature::Signer<BridgeEcdsaSignature> for SoftwareEcdsaBridge {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<BridgeEcdsaSignature, signature::Error> {
        use signature::SignatureEncoding;
        match self.behavior {
            BridgeBehavior::Sign => {
                let sig: p256::ecdsa::DerSignature = self.key.try_sign(msg)?;
                Ok(BridgeEcdsaSignature(sig.to_vec()))
            }
            BridgeBehavior::FailSigning => Err(signature::Error::new()),
            BridgeBehavior::GarbageBytes => Ok(BridgeEcdsaSignature(b"not a signature".to_vec())),
        }
    }
}

/// DER ECDSA signature wrapper with the same trait surface as
/// `hoike_sign::Pkcs11EcdsaSignature` (signature v2 encoding + spki 0.7
/// bit-string encoding).
#[derive(Clone)]
struct BridgeEcdsaSignature(Vec<u8>);

impl signature::SignatureEncoding for BridgeEcdsaSignature {
    type Repr = Vec<u8>;
}

impl TryFrom<&[u8]> for BridgeEcdsaSignature {
    type Error = signature::Error;
    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        Ok(BridgeEcdsaSignature(bytes.to_vec()))
    }
}

impl AsRef<[u8]> for BridgeEcdsaSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<BridgeEcdsaSignature> for Vec<u8> {
    fn from(sig: BridgeEcdsaSignature) -> Vec<u8> {
        sig.0
    }
}

impl spki::SignatureBitStringEncoding for BridgeEcdsaSignature {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        der::asn1::BitString::from_bytes(&self.0)
    }
}

#[cfg(feature = "pkcs11")]
impl signature::Signer<hoike_sign::Pkcs11EcdsaSignature> for SoftwareEcdsaBridge {
    fn try_sign(
        &self,
        msg: &[u8],
    ) -> std::result::Result<hoike_sign::Pkcs11EcdsaSignature, signature::Error> {
        use signature::SignatureEncoding;
        match self.behavior {
            BridgeBehavior::Sign => {
                let sig: p256::ecdsa::DerSignature = self.key.try_sign(msg)?;
                hoike_sign::Pkcs11EcdsaSignature::try_from(sig.to_vec().as_slice())
            }
            BridgeBehavior::FailSigning => Err(signature::Error::new()),
            BridgeBehavior::GarbageBytes => {
                hoike_sign::Pkcs11EcdsaSignature::try_from(&b"not a signature"[..])
            }
        }
    }
}

/// F07: signer and encoding failures fail the separation preflight — the
/// check never silently passes when it could not be performed.
#[test]
fn loaded_signer_errors_fail_separation_preflight() {
    let independent_seal = SealKey::EcdsaP256(key(0x07));

    // A failing signer (e.g. HSM error) fails the preflight.
    let failing = SoftwareEcdsaBridge {
        key: key(0x09),
        behavior: BridgeBehavior::FailSigning,
    };
    assert!(
        ensure_distinct_ecdsa_seal_key::<_, BridgeEcdsaSignature>(&failing, &independent_seal)
            .is_err(),
        "a signer error must fail the preflight"
    );

    // Bytes that are not a valid DER P-256 signature fail the preflight.
    let garbage = SoftwareEcdsaBridge {
        key: key(0x09),
        behavior: BridgeBehavior::GarbageBytes,
    };
    assert!(
        ensure_distinct_ecdsa_seal_key::<_, BridgeEcdsaSignature>(&garbage, &independent_seal)
            .is_err(),
        "an unparseable signature must fail the preflight"
    );

    // ML-DSA seal keys are algorithm-distinct from ECDSA OCSP signers.
    let ml_dsa_seal = SealKey::MlDsa65(ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(
        (&[5u8; 32]).into(),
    ));
    assert!(
        ensure_distinct_ecdsa_seal_key::<_, p256::ecdsa::DerSignature>(&key(0x09), &ml_dsa_seal)
            .is_ok(),
        "an ML-DSA seal key is distinct from any ECDSA OCSP signer by algorithm"
    );
}
