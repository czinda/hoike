//! F07 — explicit production seal pair and loaded-key separation at the real
//! one-shot `hoike sign` boundary.
//!
//! File signing without a complete `--seal-key`/`--seal-cert` pair must fail
//! before anything is written; the same key material configured as both the
//! OCSP signing key and the seal key (through different file names) must be
//! rejected; explicit `--demo-key` generates a distinct ephemeral seal pair;
//! and a failed signing run must not modify a previously written output.

use der::{Decode, Encode};
use p256::ecdsa::{DerSignature, SigningKey, signature::Signer};
use p256::pkcs8::EncodePrivateKey;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, process::Stdio};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
}

fn write_pkcs8(path: &Path, key: &SigningKey) {
    fs::write(path, key.to_pkcs8_der().unwrap().as_bytes()).unwrap();
}

/// Re-issue `generate_seal_cert`'s certificate with a fresh validity window,
/// as the repository's other synthetic fixtures do.
fn certificate(subject: &SigningKey, start: u64, end: u64) -> Vec<u8> {
    let mut cert =
        x509_cert::Certificate::from_der(&hoike_sign::generate_seal_cert(subject).unwrap())
            .unwrap();
    let time = |seconds: u64| {
        x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_unix_duration(Duration::from_secs(seconds)).unwrap(),
        )
    };
    cert.tbs_certificate.validity = x509_cert::time::Validity {
        not_before: time(start),
        not_after: time(end),
    };
    let sig: DerSignature = subject.sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = der::asn1::BitString::from_bytes(sig.as_bytes()).unwrap();
    cert.to_der().unwrap()
}

struct SignFixture {
    dir: tempfile::TempDir,
    crl: PathBuf,
    issuer: PathBuf,
    ocsp_key: PathBuf,
    seal_key: PathBuf,
    seal_cert: PathBuf,
    output: PathBuf,
}

impl SignFixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let now = now();
        // The CRL issuer is independent from the OCSP signing and seal keys.
        let issuer_key = key(0x21);
        let issuer_der = certificate(&issuer_key, now - 60, now + 86400);
        let issuer = dir.path().join("issuer.der");
        fs::write(&issuer, &issuer_der).unwrap();

        // A real signed CRL with a fresh window, issued by that certificate.
        let crl = dir.path().join("test.crl");
        let crl_der = signed_crl(&issuer_key, &issuer_der, now);
        fs::write(&crl, &crl_der).unwrap();

        // Distinct OCSP signing and seal material.
        let ocsp_key = dir.path().join("ocsp.p8");
        write_pkcs8(&ocsp_key, &key(0x31));
        let seal_key = dir.path().join("seal.p8");
        write_pkcs8(&seal_key, &key(0x37));
        let seal_cert = dir.path().join("seal-cert.der");
        fs::write(&seal_cert, certificate(&key(0x37), now - 60, now + 86400)).unwrap();

        let output = dir.path().join("out.ahu");
        Self {
            dir,
            crl,
            issuer,
            ocsp_key,
            seal_key,
            seal_cert,
            output,
        }
    }

    fn sign(&self, extra: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoike"))
            .arg("sign")
            .arg("--ca")
            .arg("test")
            .arg("--crl")
            .arg(&self.crl)
            .arg("--issuer")
            .arg(&self.issuer)
            .arg("--output")
            .arg(&self.output)
            .args(extra)
            .env_remove("RUST_LOG")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("failed to run hoike sign")
    }

    fn dir(&self) -> &Path {
        self.dir.path()
    }
}

/// Build a real ECDSA-signed CRL issued by `issuer_key`, matching the issuer
/// certificate's subject, with a fresh thisUpdate/nextUpdate window.
fn signed_crl(issuer_key: &SigningKey, issuer_der: &[u8], now: u64) -> Vec<u8> {
    use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
    let cert = x509_cert::Certificate::from_der(issuer_der).unwrap();
    let time = |seconds: u64| {
        x509_cert::time::Time::GeneralTime(
            der::asn1::GeneralizedTime::from_unix_duration(Duration::from_secs(seconds)).unwrap(),
        )
    };
    let sha256_with_ecdsa = const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    let alg = spki::AlgorithmIdentifierOwned {
        oid: sha256_with_ecdsa,
        parameters: None,
    };
    let tbs = TbsCertList {
        version: x509_cert::Version::V2,
        signature: alg.clone(),
        issuer: cert.tbs_certificate.subject.clone(),
        this_update: time(now - 1),
        next_update: Some(time(now + 3600)),
        revoked_certificates: Some(vec![RevokedCert {
            serial_number: x509_cert::serial_number::SerialNumber::new(&[42u8]).unwrap(),
            revocation_date: time(now - 60),
            crl_entry_extensions: None,
        }]),
        crl_extensions: None,
    };
    let sig: DerSignature = issuer_key.sign(&tbs.to_der().unwrap());
    let crl = CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: alg,
        signature: der::asn1::BitString::from_bytes(sig.as_bytes()).unwrap(),
    };
    crl.to_der().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// F07: one-shot file signing without a complete seal pair fails before
/// anything is produced.
#[test]
fn one_shot_missing_seal_cert_fails_before_production() {
    let fixture = SignFixture::new();
    let output = fixture.sign(&["--signing-key", fixture.ocsp_key.to_str().unwrap()]);
    let stderr = stderr(&output);
    assert!(
        !output.status.success(),
        "must fail without seal material; stderr:\n{stderr}"
    );
    assert!(stderr.to_lowercase().contains("seal"), "got: {stderr}");
    assert!(
        !fixture.output.exists(),
        "nothing may be written on a failed run"
    );
}

/// F07: a half-configured seal pair is always an error.
#[test]
fn one_shot_half_configured_seal_pair_is_rejected() {
    let fixture = SignFixture::new();
    for extra in [
        vec![
            "--signing-key",
            fixture.ocsp_key.to_str().unwrap(),
            "--seal-key",
            fixture.seal_key.to_str().unwrap(),
        ],
        vec![
            "--signing-key",
            fixture.ocsp_key.to_str().unwrap(),
            "--seal-cert",
            fixture.seal_cert.to_str().unwrap(),
        ],
    ] {
        let refs: Vec<&str> = extra.iter().map(|s| *s).collect();
        let output = fixture.sign(&refs);
        let stderr = stderr(&output);
        assert!(
            !output.status.success(),
            "half-configured pair must fail; stderr:\n{stderr}"
        );
        assert!(stderr.to_lowercase().contains("seal"), "got: {stderr}");
    }
    assert!(!fixture.output.exists());
}

/// F07: one-shot file signing with a complete, independent seal pair
/// succeeds and produces a parseable bundle.
#[test]
fn one_shot_file_signing_with_separate_pair_succeeds() {
    let fixture = SignFixture::new();
    let output = fixture.sign(&[
        "--signing-key",
        fixture.ocsp_key.to_str().unwrap(),
        "--seal-key",
        fixture.seal_key.to_str().unwrap(),
        "--seal-cert",
        fixture.seal_cert.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "signing with a separate seal pair must succeed; stderr:\n{}",
        stderr(&output)
    );
    let bytes = fs::read(&fixture.output).unwrap();
    let bundle = ahu::Bundle::from_bytes(&bytes).unwrap();
    assert!(bundle.manifest.entry_count >= 1);
}

/// F07: the same key material configured as both the OCSP signing key and
/// the seal key is rejected even through different file names, and a failed
/// run does not modify a previously written output.
#[test]
fn one_shot_same_key_under_different_paths_is_rejected() {
    let fixture = SignFixture::new();
    // Publish a good generation first.
    let good = fixture.sign(&[
        "--signing-key",
        fixture.ocsp_key.to_str().unwrap(),
        "--seal-key",
        fixture.seal_key.to_str().unwrap(),
        "--seal-cert",
        fixture.seal_cert.to_str().unwrap(),
    ]);
    assert!(good.status.success(), "control run must succeed");
    let prior = fs::read(&fixture.output).unwrap();

    // The OCSP signing key copied under a different name as the seal key,
    // with a matching seal certificate, so only key separation can reject it.
    let ocsp_material = fs::read(&fixture.ocsp_key).unwrap();
    let alias = fixture.dir().join("seal-alias.p8");
    fs::write(&alias, &ocsp_material).unwrap();
    let alias_cert = fixture.dir().join("seal-alias-cert.der");
    fs::write(
        &alias_cert,
        certificate(&key(0x31), now() - 60, now() + 86400),
    )
    .unwrap();

    let output = fixture.sign(&[
        "--signing-key",
        fixture.ocsp_key.to_str().unwrap(),
        "--seal-key",
        alias.to_str().unwrap(),
        "--seal-cert",
        alias_cert.to_str().unwrap(),
    ]);
    let stderr = stderr(&output);
    assert!(
        !output.status.success(),
        "same OCSP/seal key must be rejected; stderr:\n{stderr}"
    );
    assert!(stderr.to_lowercase().contains("seal"), "got: {stderr}");
    assert_eq!(
        fs::read(&fixture.output).unwrap(),
        prior,
        "previously written output must be untouched"
    );
}

/// F07: explicit demo signing generates a distinct ephemeral seal pair and
/// succeeds without any seal input.
#[test]
fn one_shot_demo_key_generates_distinct_seal_material() {
    let fixture = SignFixture::new();
    let output = fixture.sign(&["--demo-key"]);
    assert!(
        output.status.success(),
        "explicit demo signing must succeed; stderr:\n{}",
        stderr(&output)
    );
    let bytes = fs::read(&fixture.output).unwrap();
    let bundle = ahu::Bundle::from_bytes(&bytes).unwrap();
    assert!(bundle.manifest.entry_count >= 1);

    // Demo with a half-configured pair still fails.
    let output = fixture.sign(&[
        "--demo-key",
        "--seal-key",
        fixture.seal_key.to_str().unwrap(),
    ]);
    let stderr = stderr(&output);
    assert!(
        !output.status.success(),
        "demo half pair must fail; stderr:\n{stderr}"
    );
}

/// F07: the classical ECDSA signer of dual-algorithm production is covered
/// by the separation preflight — an explicit seal pair equal to the demo
/// classical key is rejected, an independent pair succeeds.
#[test]
fn one_shot_dual_algorithm_classical_signer_is_separation_checked() {
    let fixture = SignFixture::new();

    // Control: demo classical + demo PQ signer with an independent seal pair.
    let output = fixture.sign(&[
        "--demo-key",
        "--dual-alg",
        "ml-dsa-65",
        "--seal-key",
        fixture.seal_key.to_str().unwrap(),
        "--seal-cert",
        fixture.seal_cert.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "dual-alg with an independent seal pair must succeed; stderr:\n{}",
        stderr(&output)
    );
    let bytes = fs::read(&fixture.output).unwrap();
    assert!(
        ahu::Bundle::from_bytes(&bytes)
            .unwrap()
            .manifest
            .entry_count
            >= 1
    );

    // The fixed demo OCSP key configured as the seal key (with a matching
    // certificate, so the pair itself is valid) must be rejected by the
    // dual-algorithm classical-signer separation check.
    let demo_key = key(42);
    let demo_key_path = fixture.dir().join("demo-as-seal.p8");
    write_pkcs8(&demo_key_path, &demo_key);
    let demo_cert_path = fixture.dir().join("demo-as-seal-cert.der");
    let now = now();
    fs::write(
        &demo_cert_path,
        certificate(&demo_key, now - 60, now + 86400),
    )
    .unwrap();

    let output = fixture.sign(&[
        "--demo-key",
        "--dual-alg",
        "ml-dsa-65",
        "--seal-key",
        demo_key_path.to_str().unwrap(),
        "--seal-cert",
        demo_cert_path.to_str().unwrap(),
    ]);
    let stderr = stderr(&output);
    assert!(
        !output.status.success(),
        "dual-alg classical signer equal to the seal key must fail; stderr:\n{stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("seal"),
        "error must identify the seal material: {stderr}"
    );
}
