//! F05 / S5 — offline, recoverable authenticated import at the real CLI
//! boundary.
//!
//! `hoike import --bundle PATH --ca LABEL --config PATH` is an offline
//! installation: it always authenticates under the configured trust policy
//! (the demo serving flag never bypasses this), resolves the destination
//! from the selected CA label, fails promptly while a server holds the
//! writer lock, and never suggests SIGHUP — completion instructs the
//! operator to start the server.

use base64::Engine;
use der::{Decode, Encode};
use p256::ecdsa::{DerSignature, SigningKey, signature::Signer};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{fs, net::TcpListener};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
}

fn certificate(subject: &SigningKey, start: u64, end: u64) -> Vec<u8> {
    let mut cert =
        x509_cert::Certificate::from_der(&hoike_sign::generate_seal_cert(subject).unwrap())
            .unwrap();
    let time = |seconds| {
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

struct Fixture {
    dir: tempfile::TempDir,
    /// Configuration path; the subprocesses take it as `--config hoike.toml`
    /// relative to `dir`, so the field is kept for the fixture's own use.
    #[allow(dead_code)]
    config: PathBuf,
    state: PathBuf,
    port: u16,
    seal_key: SigningKey,
    seal_cert: Vec<u8>,
    issuer_name_der: Vec<u8>,
    issuer_key_bytes: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let now = now();
        // Seal and OCSP keys are distinct, even in synthetic fixtures.
        let seal_key = key(7);
        let seal_cert = certificate(&seal_key, now - 60, now + 3600);
        let ocsp_key = key(1);
        let issuer_name_der = "CN=Import Test CA"
            .parse::<x509_cert::name::Name>()
            .unwrap()
            .to_der()
            .unwrap();
        let issuer_key_bytes = ocsp_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        fs::write(dir.path().join("signer.der"), &seal_cert).unwrap();
        // Reserve an ephemeral port so failures are attributed correctly.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let config = dir.path().join("hoike.toml");
        fs::write(
            &config,
            format!(
                "[server]\nmode = 'edge'\nlisten = '127.0.0.1:{port}'\n[storage]\nbundle_dir = \
                 'bundles'\nstate_db = 'state'\nseal_signer_pins = ['signer.der']\n[[ca]]\nlabel \
                 = 'test'\n"
            ),
        )
        .unwrap();
        let state = dir.path().join("state");
        Self {
            dir,
            config,
            state,
            port,
            seal_key,
            seal_cert,
            issuer_name_der,
            issuer_key_bytes,
        }
    }

    /// A real signed, CMS-sealed bundle; serial 42 is `good` or `revoked`.
    fn bundle(&self, epoch: u64, revoked: bool) -> Vec<u8> {
        let now = now();
        let mut ocsp_key = key(1);
        let ca = hoike_sign::CaIdentity {
            label: "test".into(),
            issuer_name_der: self.issuer_name_der.clone(),
            issuer_key_bytes: self.issuer_key_bytes.clone(),
        };
        let status = if revoked {
            hoike_sign::CertificateStatus::Revoked {
                revocation_time: now - 1,
                reason: None,
            }
        } else {
            hoike_sign::CertificateStatus::Good
        };
        let snapshot = hoike_sign::StatusSnapshot {
            entries: [(vec![42], status)].into(),
            this_update: now - 1,
            next_update: Some(now + 3600),
            ..Default::default()
        };
        let generation = hoike_sign::GenerationConfig {
            producer_id: "import-test".into(),
            epoch,
            certid_compat: hoike_sign::CertIdCompat::Sha256Only,
            validity_secs: 3600,
            jitter_secs: 0,
            ..Default::default()
        };
        let seal_key = hoike_sign::SealKey::EcdsaP256(self.seal_key.clone());
        let seal_cert = self.seal_cert.clone();
        hoike_sign::produce_bundle::<_, DerSignature>(
            &ca,
            &snapshot,
            &generation,
            &mut ocsp_key,
            move |m| hoike_sign::create_cms_seal(m, &seal_key, &seal_cert),
            None,
        )
        .unwrap()
    }

    /// Same structure, but sealed by a signer nobody trusts.
    fn untrusted_bundle(&self, epoch: u64) -> Vec<u8> {
        let now = now();
        let wrong = key(8);
        let wrong_cert = certificate(&wrong, now - 60, now + 3600);
        let mut ocsp_key = key(2);
        let ca = hoike_sign::CaIdentity {
            label: "test".into(),
            issuer_name_der: self.issuer_name_der.clone(),
            issuer_key_bytes: ocsp_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        };
        let snapshot = hoike_sign::StatusSnapshot {
            entries: [(vec![42], hoike_sign::CertificateStatus::Good)].into(),
            this_update: now - 1,
            next_update: Some(now + 3600),
            ..Default::default()
        };
        let generation = hoike_sign::GenerationConfig {
            producer_id: "import-test".into(),
            epoch,
            certid_compat: hoike_sign::CertIdCompat::Sha256Only,
            validity_secs: 3600,
            jitter_secs: 0,
            ..Default::default()
        };
        hoike_sign::produce_bundle::<_, DerSignature>(
            &ca,
            &snapshot,
            &generation,
            &mut ocsp_key,
            |m| hoike_sign::create_cms_seal(m, &hoike_sign::SealKey::EcdsaP256(wrong), &wrong_cert),
            None,
        )
        .unwrap()
    }

    fn init_state(&self) {
        hoike_core::StateStore::initialize(&self.state.join("state.json")).unwrap();
    }

    fn hoike(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoike"))
            .current_dir(self.dir.path())
            .args(args)
            .env("RUST_LOG", "error")
            .output()
            .unwrap()
    }

    fn write_incoming(&self, name: &str, bytes: &[u8]) -> String {
        fs::write(self.dir.path().join(name), bytes).unwrap();
        name.to_string()
    }

    fn import(&self, bundle: &str, ca: &str) -> Output {
        self.hoike(&[
            "import",
            "--bundle",
            bundle,
            "--ca",
            ca,
            "--config",
            "hoike.toml",
        ])
    }

    fn spawn_serve(&self) -> Child {
        Command::new(env!("CARGO_BIN_EXE_hoike"))
            .current_dir(self.dir.path())
            .args(["serve", "--config", "hoike.toml"])
            .env("RUST_LOG", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    fn wait_listening(&self, child: &mut Child) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("server exited before listening: {status}");
            }
            if TcpStream::connect_timeout(
                &SocketAddr::from(([127, 0, 0, 1], self.port)),
                Duration::from_millis(200),
            )
            .is_ok()
            {
                return;
            }
            assert!(Instant::now() < deadline, "server did not start listening");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn query(&self) -> Output {
        let b64 = base64::engine::general_purpose::STANDARD;
        self.hoike(&[
            "query",
            "--url",
            &format!("http://127.0.0.1:{}", self.port),
            "--serial",
            "2a",
            "--issuer-name-b64",
            &b64.encode(&self.issuer_name_der),
            "--issuer-key-b64",
            &b64.encode(&self.issuer_key_bytes),
        ])
    }

    fn destination(&self) -> PathBuf {
        self.dir.path().join("bundles/test.ahu")
    }

    fn high_water(&self) -> Option<u64> {
        let raw = fs::read_to_string(self.state.join("state.json")).ok()?;
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        value["high_water_marks"]
            .as_object()?
            .values()
            .filter_map(|v| v.as_u64())
            .max()
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_no_sighup(output: &Output) {
    let text = format!("{}{}", stdout(output), stderr(output));
    assert!(
        !text.contains("SIGHUP"),
        "import must never suggest SIGHUP: {text}"
    );
}

#[test]
fn import_requires_a_label_and_rejects_unknown_labels() {
    let f = Fixture::new();
    f.init_state();
    let incoming = f.write_incoming("incoming.ahu", &f.bundle(1, false));

    // The CA label is required: there is no destination to select without it.
    let out = f.hoike(&["import", "--bundle", &incoming, "--config", "hoike.toml"]);
    assert!(!out.status.success(), "{out:?}");
    assert!(
        stderr(&out).to_lowercase().contains("ca"),
        "must demand --ca: {}",
        stderr(&out)
    );
    assert_no_sighup(&out);
    assert!(!f.destination().exists());

    let out = f.import(&incoming, "no-such-label");
    assert!(!out.status.success(), "{out:?}");
    assert!(
        stderr(&out).contains("unknown CA label"),
        "{}",
        stderr(&out)
    );
    assert!(!f.destination().exists());
}

#[test]
fn import_rejects_untrusted_input_without_changes() {
    let f = Fixture::new();
    f.init_state();
    let trusted = f.bundle(1, false);
    let incoming = f.write_incoming("incoming.ahu", &trusted);
    let out = f.import(&incoming, "test");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert_no_sighup(&out);
    assert_eq!(fs::read(f.destination()).unwrap(), trusted);
    let committed_state = fs::read(f.state.join("state.json")).unwrap();

    let bad = f.write_incoming("incoming-bad.ahu", &f.untrusted_bundle(2));
    let out = f.import(&bad, "test");
    assert!(!out.status.success(), "{out:?}");
    assert!(
        stderr(&out).contains("seal verification failed"),
        "{}",
        stderr(&out)
    );
    assert_no_sighup(&out);
    assert_eq!(fs::read(f.destination()).unwrap(), trusted);
    assert_eq!(
        fs::read(f.state.join("state.json")).unwrap(),
        committed_state
    );
}

#[test]
fn import_requires_initialized_state() {
    let f = Fixture::new();
    let incoming = f.write_incoming("incoming.ahu", &f.bundle(1, false));
    let out = f.import(&incoming, "test");
    assert!(!out.status.success(), "{out:?}");
    assert!(
        stderr(&out).contains("init-state"),
        "must point at explicit initialization: {}",
        stderr(&out)
    );
    assert!(
        !f.state.join("state.json").exists(),
        "import must never initialize state implicitly"
    );
    assert!(!f.destination().exists());
}

#[test]
fn import_rejects_active_writer_and_force() {
    let f = Fixture::new();
    f.init_state();
    let first_bytes = f.bundle(1, false);
    let first = f.write_incoming("incoming.ahu", &first_bytes);
    let out = f.import(&first, "test");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));

    let mut server = f.spawn_serve();
    f.wait_listening(&mut server);

    // A running server holds the exclusive writer lock: offline import
    // fails promptly instead of racing it.
    let second = f.write_incoming("incoming-2.ahu", &f.bundle(2, true));
    let out = f.import(&second, "test");
    assert!(!out.status.success(), "{out:?}");
    assert!(
        stderr(&out).contains("lock"),
        "exclusion error must identify the writer lock: {}",
        stderr(&out)
    );
    assert_no_sighup(&out);

    // There is no --force escape hatch anymore.
    let out = f.hoike(&[
        "import",
        "--bundle",
        &second,
        "--ca",
        "test",
        "--config",
        "hoike.toml",
        "--force",
    ]);
    assert!(!out.status.success(), "{out:?}");
    assert!(
        stderr(&out).contains("unexpected argument"),
        "--force must be rejected by the parser: {}",
        stderr(&out)
    );

    server.kill().unwrap();
    server.wait().unwrap();

    assert_eq!(
        f.high_water(),
        Some(1),
        "the excluded import changed nothing"
    );
    assert_eq!(
        fs::read(f.destination()).unwrap(),
        first_bytes,
        "the excluded import changed nothing"
    );
}

#[test]
fn import_offline_install_and_restart_serves_selected_generation() {
    let f = Fixture::new();
    f.init_state();

    let first = f.bundle(1, false);
    let incoming = f.write_incoming("incoming.ahu", &first);
    let out = f.import(&incoming, "test");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert!(
        stdout(&out).contains("hoike serve"),
        "completion must instruct the operator to start the server: {}",
        stdout(&out)
    );
    assert_no_sighup(&out);
    assert_eq!(fs::read(f.destination()).unwrap(), first);

    let mut server = f.spawn_serve();
    f.wait_listening(&mut server);
    let query = f.query();
    assert!(query.status.success(), "{:?}", stderr(&query));
    assert!(
        stdout(&query).contains("Status: GOOD"),
        "{}{}",
        stdout(&query),
        stderr(&query)
    );
    server.kill().unwrap();
    server.wait().unwrap();

    // Offline import of the next generation while the server is stopped.
    let second = f.write_incoming("incoming-2.ahu", &f.bundle(2, true));
    let out = f.import(&second, "test");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert_no_sighup(&out);
    assert_eq!(f.high_water(), Some(2));

    // Restarting serves the selected generation, not the previous one.
    let mut server = f.spawn_serve();
    f.wait_listening(&mut server);
    let query = f.query();
    assert!(query.status.success(), "{:?}", stderr(&query));
    assert!(
        stdout(&query).contains("Status: REVOKED"),
        "restart must serve the imported generation: {}{}",
        stdout(&query),
        stderr(&query)
    );
    server.kill().unwrap();
    server.wait().unwrap();
}

#[test]
fn import_reports_committed_warning_when_publication_fails_and_retry_repairs() {
    let f = Fixture::new();
    f.init_state();
    let first = f.write_incoming("incoming.ahu", &f.bundle(1, false));
    assert!(f.import(&first, "test").status.success());

    // Make the configured path unreplaceable: the installation commits, but
    // the post-commit publication of the convenience path fails.
    let destination = f.destination();
    fs::remove_file(&destination).unwrap();
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("occupied"), b"old").unwrap();

    let second_bytes = f.bundle(2, true);
    let second = f.write_incoming("incoming-2.ahu", &second_bytes);
    let out = f.import(&second, "test");
    assert!(
        out.status.success(),
        "a post-commit publication failure is committed, not an error: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("WARNING") && stderr(&out).contains("committed"),
        "the operator must learn the installation committed: {}",
        stderr(&out)
    );
    assert_no_sighup(&out);
    assert_eq!(
        f.high_water(),
        Some(2),
        "the descriptor commit is the installation commit point"
    );

    // Retrying the identical import repairs the path.
    fs::remove_dir_all(&destination).unwrap();
    let out = f.import(&second, "test");
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));
    assert!(
        !stderr(&out).contains("WARNING"),
        "repaired publication must not warn: {}",
        stderr(&out)
    );
    assert_eq!(fs::read(&destination).unwrap(), second_bytes);
    assert_eq!(f.high_water(), Some(2));
}
