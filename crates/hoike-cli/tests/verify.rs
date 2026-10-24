//! F01 / A2: verdicts at the real CLI boundary, with current synthetic seals.

use ahu::{Bundle, BundleBuilder};
use der::{Decode, Encode};
use hoike_sign::{CertIdCompat, SealKey};
use p256::ecdsa::{DerSignature, SigningKey, signature::Signer};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
}

fn certificate(key: &SigningKey, start: u64, end: u64) -> Vec<u8> {
    let mut cert =
        x509_cert::Certificate::from_der(&hoike_sign::generate_seal_cert(key).unwrap()).unwrap();
    let time = |seconds| {
        x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_unix_duration(Duration::from_secs(seconds)).unwrap(),
        )
    };
    cert.tbs_certificate.validity = x509_cert::time::Validity {
        not_before: time(start),
        not_after: time(end),
    };
    let sig: DerSignature = key.sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = der::asn1::BitString::from_bytes(sig.as_bytes()).unwrap();
    cert.to_der().unwrap()
}

struct Fixture {
    dir: tempfile::TempDir,
    seal_key: SigningKey,
    seal_cert: Vec<u8>,
    bundle: Vec<u8>,
    path: PathBuf,
    config: PathBuf,
    state: PathBuf,
}

impl Fixture {
    fn new(embed_cert: bool) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(".verify-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        let now = now();
        // Seal and OCSP keys must be distinct, even in these synthetic fixtures.
        let seal_key = key(7);
        let seal_cert = certificate(&seal_key, now - 60, now + 3600);
        let mut ocsp_key = key(1);
        let responder_cert = certificate(&ocsp_key, now - 60, now + 3600);
        let ca = hoike_sign::CaIdentity {
            label: "test".into(),
            issuer_name_der: "CN=Verification Test CA"
                .parse::<x509_cert::name::Name>()
                .unwrap()
                .to_der()
                .unwrap(),
            issuer_key_bytes: ocsp_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        };
        let snapshot = hoike_sign::StatusSnapshot {
            entries: [
                (vec![42], hoike_sign::CertificateStatus::Good),
                (vec![43], hoike_sign::CertificateStatus::Good),
            ]
            .into(),
            this_update: now - 1,
            next_update: Some(now + 3600),
            ..Default::default()
        };
        let generation = hoike_sign::GenerationConfig {
            producer_id: "verify-test".into(),
            certid_compat: CertIdCompat::Sha256Only,
            validity_secs: 3600,
            jitter_secs: 0,
            ..Default::default()
        };
        let bundle = hoike_sign::produce_bundle::<_, DerSignature>(
            &ca,
            &snapshot,
            &generation,
            &mut ocsp_key,
            |m| hoike_sign::create_cms_seal(m, &SealKey::EcdsaP256(seal_key.clone()), &seal_cert),
            embed_cert.then_some(responder_cert.as_slice()),
        )
        .unwrap();
        let path = dir.path().join("test.ahu");
        std::fs::write(&path, &bundle).unwrap();
        std::fs::write(dir.path().join("signer.der"), &seal_cert).unwrap();
        let config = dir.path().join("hoike.toml");
        let state = dir.path().join("state");
        let fixture = Self {
            dir,
            seal_key,
            seal_cert,
            bundle,
            path,
            config,
            state,
        };
        fixture.configure("seal_signer_pins = ['signer.der']", true);
        fixture
    }

    fn configure(&self, policy: &str, explicit_ca: bool) {
        // The subprocess works in this directory. An implicit hoike.toml is
        // deliberately present to catch accidental configuration discovery.
        let ca = if explicit_ca {
            "\n[[ca]]\nlabel = 'test'\n"
        } else {
            ""
        };
        std::fs::write(
            &self.config,
            format!("[server]\nmode = 'edge'\n[storage]\nbundle_dir = '.'\nstate_db = 'state'\n{policy}\n{ca}"),
        )
        .unwrap();
    }

    fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ahu"))
            .current_dir(self.dir.path())
            .args(args)
            .output()
            .unwrap()
    }

    fn verify(&self, entries: bool) -> Output {
        let mut args = vec!["verify", "test.ahu", "--config", "hoike.toml"];
        if entries {
            args.push("--entries");
        }
        self.cli(&args)
    }

    fn check(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoike"))
            .current_dir(self.dir.path())
            .args(["check", "--config", "hoike.toml"])
            .env("RUST_LOG", "error")
            .output()
            .unwrap()
    }

    fn write(&self, bundle: &Bundle) {
        std::fs::write(&self.path, bundle.to_bytes().unwrap()).unwrap();
    }

    fn reseal(&self, bundle: &mut Bundle) {
        bundle.manifest_bytes = bundle.manifest.to_cbor();
        bundle.seal_bytes = hoike_sign::create_cms_seal(
            &bundle.manifest_bytes,
            &SealKey::EcdsaP256(self.seal_key.clone()),
            &self.seal_cert,
        )
        .unwrap();
    }

    fn write_entries(&self, entries: Vec<([u8; 32], Vec<u8>)>) {
        let bundle = Bundle::from_bytes(&self.bundle).unwrap();
        let mut builder = BundleBuilder::new(bundle.manifest);
        for (key, bytes) in entries {
            builder.add_entry(key, bytes);
        }
        let bytes = builder
            .build(|manifest| {
                Ok(hoike_sign::create_cms_seal(
                    manifest,
                    &SealKey::EcdsaP256(self.seal_key.clone()),
                    &self.seal_cert,
                )
                .unwrap())
            })
            .unwrap();
        std::fs::write(&self.path, bytes).unwrap();
    }

    fn scoped_policy(&self) -> String {
        let bundle = Bundle::from_bytes(&self.bundle).unwrap();
        format!(
            "seal_signer_pins = ['signer.der']\n[[storage.seal_authorizations]]\nproducer_id = 'verify-test'\nissuer_key_hash = '{}'\nsigner_sha256 = '{}'",
            hex::encode(&bundle.manifest.ca_scopes[0].issuer_key_hash),
            hex::encode(Sha256::digest(&self.seal_cert)),
        )
    }

    fn seed_state(&self) {
        // Use real committed state but absolute paths in this process; never
        // change the test runner's cwd (tests execute concurrently).
        let mut config = hoike_core::Config::from_file(&self.config).unwrap();
        config.storage.bundle_dir = self.dir.path().to_path_buf();
        config.storage.state_db = self.state.clone();
        config.storage.seal_signer_pins = vec![self.dir.path().join("signer.der")];
        drop(hoike_core::ResponderState::load(config).unwrap());
    }
}

// Include names, bytes and mtimes: rewriting identical state also violates the
// read-only contract. Include directories to catch creation/deletion of files.
type StateTree = BTreeMap<PathBuf, (SystemTime, Option<Vec<u8>>)>;

fn state_tree(root: &Path) -> StateTree {
    fn visit(root: &Path, path: &Path, result: &mut StateTree) {
        let meta = std::fs::metadata(path).unwrap();
        result.insert(
            path.strip_prefix(root).unwrap().to_path_buf(),
            (
                meta.modified().unwrap(),
                meta.is_file().then(|| std::fs::read(path).unwrap()),
            ),
        );
        if meta.is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), result);
            }
        }
    }
    let mut result = BTreeMap::new();
    if root.exists() {
        visit(root, root, &mut result);
    }
    result
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn success(output: &Output) {
    assert!(output.status.success(), "{output:?}");
}

fn auth_failure(output: &Output) {
    assert!(!output.status.success(), "{output:?}");
    assert!(
        stderr(output).contains("authentication failed"),
        "{output:?}"
    );
    assert!(
        !stdout(output).contains("Verification passed"),
        "{output:?}"
    );
}

#[test]
fn verify_requires_an_explicit_mode() {
    let f = Fixture::new(true);
    let bare = f.cli(&["verify", "test.ahu"]);
    assert!(
        !bare.status.success(),
        "bare verify claimed success: {bare:?}"
    );
    assert!(stderr(&bare).contains("--config"), "{bare:?}");
    assert!(stderr(&bare).contains("--structure-only"), "{bare:?}");
    let help = f.cli(&["verify", "--help"]);
    success(&help);
    for flag in ["--config", "--structure-only", "--entries"] {
        assert!(stdout(&help).contains(flag), "{help:?}");
    }
    for args in [
        vec!["verify", "test.ahu", "--entries"],
        vec!["verify", "test.ahu", "--structure-only", "--entries"],
        vec![
            "verify",
            "test.ahu",
            "--config",
            "hoike.toml",
            "--structure-only",
        ],
    ] {
        let output = f.cli(&args);
        assert!(!output.status.success(), "{output:?}");
        assert!(
            !stderr(&output).contains("authentication failed"),
            "{output:?}"
        );
    }
    assert!(!f.state.exists());
}

#[test]
fn verify_rejects_corrupt_or_untrusted_cms() {
    let f = Fixture::new(true);
    let good = f.verify(false);
    success(&good);
    assert!(stdout(&good).contains("authenticated"), "{good:?}");
    assert!(
        stdout(&good).contains("Installation eligibility not checked."),
        "{good:?}"
    );
    assert!(
        stdout(&good).contains(&hex::encode(Sha256::digest(&f.seal_cert))),
        "{good:?}"
    );
    assert!(!f.state.exists(), "verification created state");

    f.seed_state();
    let before = state_tree(&f.state);
    success(&f.verify(false));
    let mut corrupt = Bundle::from_bytes(&f.bundle).unwrap();
    *corrupt.seal_bytes.last_mut().unwrap() ^= 1;
    f.write(&corrupt);
    auth_failure(&f.verify(false));

    let other_key = key(8);
    let other_cert = certificate(&other_key, now() - 60, now() + 3600);
    corrupt.seal_bytes = hoike_sign::create_cms_seal(
        &corrupt.manifest_bytes,
        &SealKey::EcdsaP256(other_key),
        &other_cert,
    )
    .unwrap();
    f.write(&corrupt);
    auth_failure(&f.verify(false));
    corrupt.seal_bytes.clear();
    f.write(&corrupt);
    auth_failure(&f.verify(false));

    // Explicit demo admission does not authorize an authenticated CLI verdict.
    std::fs::write(&f.path, &f.bundle).unwrap();
    f.configure("allow_unauthenticated_bundles = true", true);
    auth_failure(&f.verify(false));
    assert_eq!(state_tree(&f.state), before);
}

#[test]
fn verify_rejects_expired_certificates_and_unauthorized_scopes() {
    let f = Fixture::new(true);
    f.configure(&f.scoped_policy(), true);
    success(&f.verify(false));
    for field in ["producer", "issuer"] {
        let mut wrong = Bundle::from_bytes(&f.bundle).unwrap();
        if field == "producer" {
            wrong.manifest.producer_id = "other-producer".into();
        } else {
            wrong.manifest.ca_scopes[0].issuer_key_hash = vec![0xEE; 32];
        }
        f.reseal(&mut wrong);
        f.write(&wrong);
        let output = f.verify(false);
        auth_failure(&output);
        assert!(stderr(&output).contains("not authorized"), "{output:?}");
    }
    let expired = certificate(&f.seal_key, now() - 7200, now() - 60);
    std::fs::write(f.dir.path().join("expired.der"), &expired).unwrap();
    f.configure("seal_signer_pins = ['expired.der']", true);
    let mut bundle = Bundle::from_bytes(&f.bundle).unwrap();
    bundle.seal_bytes = hoike_sign::create_cms_seal(
        &bundle.manifest_bytes,
        &SealKey::EcdsaP256(f.seal_key.clone()),
        &expired,
    )
    .unwrap();
    f.write(&bundle);
    let output = f.verify(false);
    auth_failure(&output);
    assert!(
        stderr(&output).contains("outside validity period"),
        "{output:?}"
    );
    assert!(!f.state.exists());
}

#[test]
fn structure_only_never_claims_authentication() {
    let f = Fixture::new(true);
    let mut bundle = Bundle::from_bytes(&f.bundle).unwrap();
    for seal in [bundle.seal_bytes.clone(), vec![0xAA; 32], vec![]] {
        bundle.seal_bytes = seal;
        f.write(&bundle);
        let output = f.cli(&["verify", "test.ahu", "--structure-only"]);
        success(&output);
        assert!(
            stdout(&output)
                .lines()
                .any(|s| s == "Structure valid; authenticity not checked."),
            "{output:?}"
        );
        assert!(
            !stdout(&output).contains("Verification passed"),
            "{output:?}"
        );
        assert!(!stdout(&output).contains("authenticated"), "{output:?}");
    }
    // A digest failure and a malformed file must not yield even structural success.
    bundle.data[0] ^= 1;
    f.write(&bundle);
    let corrupt = f.cli(&["verify", "test.ahu", "--structure-only"]);
    assert!(!corrupt.status.success(), "{corrupt:?}");
    assert!(!stdout(&corrupt).contains("Structure valid"), "{corrupt:?}");
    std::fs::write(&f.path, b"not an ahu bundle").unwrap();
    let malformed = f.verify(false);
    assert!(!malformed.status.success(), "{malformed:?}");
    assert!(
        !stderr(&malformed).contains("authentication failed"),
        "{malformed:?}"
    );
    assert!(!f.state.exists());
}

#[test]
fn entries_rejects_unchecked_successful_responses() {
    let f = Fixture::new(false);
    success(&f.verify(false));
    let output = f.verify(true);
    assert!(
        !output.status.success(),
        "unchecked entries claimed success: {output:?}"
    );
    assert!(
        stdout(&output).contains("no embedded responder cert"),
        "{output:?}"
    );
    assert!(
        stderr(&output).contains("entry signature verification incomplete"),
        "{output:?}"
    );
    assert!(
        !stdout(&output).contains("Verification passed"),
        "{output:?}"
    );
    assert!(!f.state.exists());

    // Checking one signature must not hide another successful response that
    // cannot be checked. Removing certs does not change signed responseData.
    let mixed = Fixture::new(true);
    let bundle = Bundle::from_bytes(&mixed.bundle).unwrap();
    let mut response = x509_ocsp::OcspResponse::from_der(bundle.entry_at(0).unwrap()).unwrap();
    let bytes = response.response_bytes.as_mut().unwrap();
    let mut basic = x509_ocsp::BasicOcspResponse::from_der(bytes.response.as_bytes()).unwrap();
    basic.certs = None;
    bytes.response = der::asn1::OctetString::new(basic.to_der().unwrap()).unwrap();
    mixed.write_entries(vec![
        (bundle.index[0].entry_key, response.to_der().unwrap()),
        (
            bundle.index[1].entry_key,
            bundle.entry_at(1).unwrap().to_vec(),
        ),
    ]);
    let output = mixed.verify(true);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        stdout(&output).contains("Verified:         1"),
        "{output:?}"
    );
    assert!(
        stdout(&output).contains("Unchecked:        1"),
        "{output:?}"
    );
    assert!(
        stderr(&output).contains("entry signature verification incomplete"),
        "{output:?}"
    );
}

#[test]
fn entries_report_unsigned_errors_separately_and_verify_embedded_keys() {
    let f = Fixture::new(true);
    let bundle = Bundle::from_bytes(&f.bundle).unwrap();
    // Protocol-defined unsigned OCSP error responses do not count as signatures.
    f.write_entries(vec![
        (
            bundle.index[0].entry_key,
            bundle.entry_at(0).unwrap().to_vec(),
        ),
        ([0xFF; 32], vec![0x30, 0x03, 0x0A, 0x01, 0x06]),
    ]);
    let output = f.verify(true);
    success(&output);
    assert!(
        stdout(&output).contains("Verified:         1"),
        "{output:?}"
    );
    assert!(
        stdout(&output).contains("Unsigned errors:  1"),
        "{output:?}"
    );
    assert!(
        stdout(&output).contains("responder-chain trust not checked"),
        "{output:?}"
    );

    // A real successful response with a corrupt signature is still a failure,
    // even after a trusted producer sealed its bytes.
    let mut response = x509_ocsp::OcspResponse::from_der(bundle.entry_at(0).unwrap()).unwrap();
    let response_bytes = response.response_bytes.as_mut().unwrap();
    let mut basic =
        x509_ocsp::BasicOcspResponse::from_der(response_bytes.response.as_bytes()).unwrap();
    let mut sig = basic.signature.raw_bytes().to_vec();
    *sig.last_mut().unwrap() ^= 1;
    basic.signature = der::asn1::BitString::from_bytes(&sig).unwrap();
    response_bytes.response = der::asn1::OctetString::new(basic.to_der().unwrap()).unwrap();
    f.write_entries(vec![(
        bundle.index[0].entry_key,
        response.to_der().unwrap(),
    )]);
    let output = f.verify(true);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        stderr(&output).contains("entry signature verification failed"),
        "{output:?}"
    );
}

#[test]
fn entries_rejects_malformed_responses_instead_of_counting_them_as_unsigned_errors() {
    let f = Fixture::new(true);
    let bundle = Bundle::from_bytes(&f.bundle).unwrap();
    let mut response = x509_ocsp::OcspResponse::from_der(bundle.entry_at(0).unwrap()).unwrap();
    // Error responses cannot carry responseBytes, even if those bytes contain
    // an otherwise valid signature. Unknown status values are invalid too.
    response.response_status = x509_ocsp::OcspResponseStatus::Unauthorized;
    for malformed in [
        response.to_der().unwrap(),
        vec![0x30, 0x03, 0x0A, 0x01, 0x04],
        b"not DER".to_vec(),
    ] {
        f.write_entries(vec![(bundle.index[0].entry_key, malformed)]);
        let output = f.verify(true);
        assert!(!output.status.success(), "{output:?}");
        assert!(
            stdout(&output).contains("Verified:         0"),
            "{output:?}"
        );
        assert!(
            stdout(&output).contains("Unsigned errors:  0"),
            "{output:?}"
        );
        assert!(
            stderr(&output).contains("entry signature verification failed"),
            "{output:?}"
        );
    }
}

#[test]
fn verify_rejects_entry_count_mismatches() {
    let f = Fixture::new(true);
    let mut bundle = Bundle::from_bytes(&f.bundle).unwrap();
    bundle.manifest.entry_count += 1;
    f.reseal(&mut bundle);
    f.write(&bundle);
    for output in [
        f.verify(false),
        f.cli(&["verify", "test.ahu", "--structure-only"]),
    ] {
        assert!(!output.status.success(), "{output:?}");
        assert!(stderr(&output).contains("entry count"), "{output:?}");
        assert!(!stdout(&output).contains("Structure valid"), "{output:?}");
    }
    assert!(!f.state.exists());
}

#[test]
fn check_authenticates_without_creating_or_changing_state() {
    let f = Fixture::new(true);
    let output = f.check();
    success(&output);
    assert!(!f.state.exists(), "hoike check created state");
    assert!(stdout(&output).contains("authenticated"), "{output:?}");
    assert!(
        stdout(&output).contains("Installation eligibility not checked."),
        "{output:?}"
    );
    f.seed_state();
    let before = state_tree(&f.state);
    let mut next = Bundle::from_bytes(&f.bundle).unwrap();
    next.manifest.ca_scopes[0].epoch = 2;
    f.reseal(&mut next);
    f.write(&next);
    success(&f.check());
    assert_eq!(
        state_tree(&f.state),
        before,
        "check installed a newer generation"
    );
    *next.seal_bytes.last_mut().unwrap() ^= 1;
    f.write(&next);
    let output = f.check();
    assert!(
        !output.status.success(),
        "check hid a bad candidate with recovery: {output:?}"
    );
    assert_eq!(state_tree(&f.state), before);
}

#[test]
fn check_demo_is_explicit_and_configured_trust_cannot_downgrade() {
    let f = Fixture::new(true);
    f.configure("", true);
    let no_trust = f.check();
    assert!(!no_trust.status.success(), "{no_trust:?}");
    f.configure("allow_unauthenticated_bundles = true", true);
    let mut corrupt = Bundle::from_bytes(&f.bundle).unwrap();
    *corrupt.seal_bytes.last_mut().unwrap() ^= 1;
    f.write(&corrupt);
    let demo = f.check();
    success(&demo);
    assert!(
        stdout(&demo).contains("Unauthenticated demo admission; authenticity not checked."),
        "{demo:?}"
    );
    assert!(!stdout(&demo).contains("All checks passed"), "{demo:?}");
    f.configure(
        "allow_unauthenticated_bundles = true\nseal_signer_pins = ['signer.der']",
        true,
    );
    let configured = f.check();
    assert!(!configured.status.success(), "{configured:?}");
    assert!(!f.state.exists());
}

#[test]
fn check_uses_configured_bundle_selection_and_nonce_validation() {
    let f = Fixture::new(true);
    // A higher-epoch untrusted bundle cannot divert an explicit [[ca]] path.
    let mut other = Bundle::from_bytes(&f.bundle).unwrap();
    other.manifest.ca_scopes[0].epoch = 20;
    f.reseal(&mut other);
    *other.seal_bytes.last_mut().unwrap() ^= 1;
    std::fs::write(f.dir.path().join("other.ahu"), other.to_bytes().unwrap()).unwrap();
    success(&f.check());
    let explicit = std::fs::read_to_string(&f.config).unwrap();
    std::fs::write(
        &f.config,
        format!("{explicit}\nbundle_file = 'other.ahu'\n"),
    )
    .unwrap();
    assert!(
        !f.check().status.success(),
        "explicit bundle_file must take precedence"
    );
    // Legacy discovery still selects the highest epoch, then authenticates it.
    f.configure("seal_signer_pins = ['signer.der']", false);
    assert!(!f.check().status.success());
    f.configure("seal_signer_pins = ['signer.der']", true);
    let original = std::fs::read_to_string(&f.config).unwrap();
    for nonce in ["live", "forward", "unknown"] {
        std::fs::write(&f.config, format!("{original}\nnonce_policy = '{nonce}'\n")).unwrap();
        let output = f.check();
        assert!(!output.status.success(), "{nonce}: {output:?}");
    }
    assert!(!f.state.exists());
}
