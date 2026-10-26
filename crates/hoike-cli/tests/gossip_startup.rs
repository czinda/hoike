//! F09 / S7 — explicit gossip authentication policy at the real CLI boundary.
//!
//! An enabled gossip section with unusable key material must abort `hoike
//! serve` instead of warning-and-continuing with unauthenticated broadcasts.
//! A disabled section requires no key material at all. A correctly configured
//! node whose gossip peers are unreachable (a partitioned gossip plane) must
//! keep serving OCSP locally — SWIM packet loss never stops the data plane.
//! `hoike check` reports the effective authentication mode and fails on the
//! same invalid configurations that would abort startup.

use base64::Engine;
use der::{Decode, Encode};
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use p256::ecdsa::{DerSignature, SigningKey, signature::Signer};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
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

/// Write an Ed25519 gossip identity (PKCS#8 private + SPKI public PEM) under
/// `dir`; returns the two paths.
fn write_gossip_identity(dir: &Path, name: &str, seed: u8) -> (PathBuf, PathBuf) {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let priv_path = dir.join(format!("{name}.ed25519.p8"));
    let pub_path = dir.join(format!("{name}.ed25519.pub.pem"));
    let priv_pem = signing.to_pkcs8_pem(Default::default()).unwrap();
    fs::write(&priv_path, priv_pem.as_str()).unwrap();
    let pub_pem = signing
        .verifying_key()
        .to_public_key_pem(Default::default())
        .unwrap();
    fs::write(&pub_path, pub_pem).unwrap();
    (priv_path, pub_path)
}

struct Fixture {
    dir: tempfile::TempDir,
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
        let issuer_name_der = "CN=Gossip Startup Test CA"
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
        fs::write(
            dir.path().join("hoike.toml"),
            format!(
                "[server]\nmode = 'edge'\nlisten = '127.0.0.1:{port}'\n[storage]\nbundle_dir = \
                 'bundles'\nstate_db = 'state'\nseal_signer_pins = ['signer.der']\n[[ca]]\nlabel \
                 = 'test'\n"
            ),
        )
        .unwrap();
        Self {
            dir,
            port,
            seal_key,
            seal_cert,
            issuer_name_der,
            issuer_key_bytes,
        }
    }

    /// A real signed, CMS-sealed bundle with serial 0x2a `good`.
    fn bundle(&self) -> Vec<u8> {
        let now = now();
        let mut ocsp_key = key(1);
        let ca = hoike_sign::CaIdentity {
            label: "test".into(),
            issuer_name_der: self.issuer_name_der.clone(),
            issuer_key_bytes: self.issuer_key_bytes.clone(),
        };
        let snapshot = hoike_sign::StatusSnapshot {
            entries: [(vec![42], hoike_sign::CertificateStatus::Good)].into(),
            this_update: now - 1,
            next_update: Some(now + 3600),
            ..Default::default()
        };
        let generation = hoike_sign::GenerationConfig {
            producer_id: "gossip-startup-test".into(),
            epoch: 1,
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

    /// Initialize state and install the bundle, so `serve` has valid work.
    fn install_bundle(&self) {
        let init = self.hoike(&["init-state", "--config", "hoike.toml"]);
        assert!(init.status.success(), "{init:?}");
        fs::write(self.dir.path().join("incoming.ahu"), self.bundle()).unwrap();
        let import = self.hoike(&[
            "import",
            "--bundle",
            "incoming.ahu",
            "--ca",
            "test",
            "--config",
            "hoike.toml",
        ]);
        assert!(import.status.success(), "{import:?}");
    }

    /// A copy of the base config with a `[gossip]` section appended.
    fn with_gossip(&self, name: &str, gossip: &str) -> PathBuf {
        let path = self.dir.path().join(format!("gossip-{name}.toml"));
        let base = fs::read_to_string(self.dir.path().join("hoike.toml")).unwrap();
        fs::write(&path, format!("{base}\n{gossip}")).unwrap();
        path
    }

    fn hoike(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hoike"))
            .current_dir(self.dir.path())
            .args(args)
            .env("RUST_LOG", "error")
            .output()
            .unwrap()
    }

    fn spawn_serve(&self, config: &Path) -> Child {
        Command::new(env!("CARGO_BIN_EXE_hoike"))
            .current_dir(self.dir.path())
            .args(["serve", "--config", &config.to_string_lossy()])
            .env("RUST_LOG", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    fn is_listening(&self) -> bool {
        TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], self.port)),
            Duration::from_millis(200),
        )
        .is_ok()
    }

    fn wait_listening(&self, child: &mut Child) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("server exited before listening: {status}");
            }
            if self.is_listening() {
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
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// F09: an enabled gossip section whose key material cannot be loaded is a
/// fatal startup error — the process must exit nonzero and never accept OCSP
/// traffic, not warn-and-continue with unauthenticated broadcasts.
#[test]
fn enabled_gossip_key_failure_aborts_startup() {
    let f = Fixture::new();
    f.install_bundle();
    // auth_mode defaults to "required"; the identity key does not exist.
    let config = f.with_gossip(
        "missing-key",
        "[gossip]\nenabled = true\nbind = '127.0.0.1:0'\nnode_name = 'edge-01'\n\
         identity_key = 'does-not-exist.p8'\n",
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_hoike"))
        .current_dir(f.dir.path())
        .args(["serve", "--config", &config.to_string_lossy()])
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                !status.success(),
                "missing configured gossip identity key must abort startup"
            );
            break;
        }
        assert!(
            !f.is_listening(),
            "serve continued (and served OCSP) despite unusable gossip key material"
        );
        assert!(
            Instant::now() < deadline,
            "serve neither exited nor listened"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        !output.status.success(),
        "missing configured gossip identity key must abort startup"
    );
    let text = stderr(&output);
    assert!(
        text.contains("gossip"),
        "error must identify gossip: {text}"
    );
}

/// F09: a disabled gossip section never loads key material, so unusable paths
/// in a disabled section are not startup errors.
#[test]
fn disabled_gossip_requires_no_key_material() {
    let f = Fixture::new();
    f.install_bundle();
    let config = f.with_gossip(
        "disabled",
        "[gossip]\nenabled = false\nbind = '127.0.0.1:0'\nnode_name = 'edge-01'\n\
         identity_key = 'does-not-exist.p8'\n[gossip.peer_identities]\n\
         edge-02 = 'also-missing.pub.pem'\n",
    );

    let mut child = f.spawn_serve(&config);
    f.wait_listening(&mut child);
    child.kill().unwrap();
    child.wait().unwrap();
}

/// F09: a correctly configured required-mode node whose gossip peers are all
/// unreachable (a partitioned gossip plane) still serves valid local OCSP
/// responses — SWIM packet loss never stops the data plane.
#[test]
fn partitioned_gossip_peers_never_stop_ocsp_serving() {
    let f = Fixture::new();
    f.install_bundle();
    let (identity, public) = write_gossip_identity(f.dir.path(), "edge-01", 11);
    let config = f.with_gossip(
        "partitioned",
        &format!(
            "[gossip]\nenabled = true\nbind = '127.0.0.1:0'\nnode_name = 'edge-01'\n\
             auth_mode = 'required'\nidentity_key = '{}'\nseeds = ['127.0.0.1:1']\n\
             [gossip.peer_identities]\nedge-01 = '{}'\n",
            identity.display(),
            public.display()
        ),
    );
    assert!(identity.is_file() && public.is_file());

    let mut child = f.spawn_serve(&config);
    f.wait_listening(&mut child);

    // Leave the gossip plane partitioned for several SWIM probe periods while
    // querying: the unreachable seed must not degrade the OCSP answer.
    for _ in 0..3 {
        std::thread::sleep(Duration::from_millis(1500));
        let query = f.query();
        assert!(
            query.status.success(),
            "{}\n{}",
            stdout(&query),
            stderr(&query)
        );
        assert!(
            stdout(&query).contains("Status: GOOD"),
            "local OCSP query must succeed under gossip partition: {}",
            stdout(&query)
        );
    }
    child.kill().unwrap();
    child.wait().unwrap();
}

/// F09: `hoike check` reports the effective authentication mode (and its
/// unsigned-acceptance posture) accurately, and fails on the configurations
/// that would abort startup.
#[test]
fn check_reports_effective_gossip_auth_mode() {
    let f = Fixture::new();
    f.install_bundle();
    let (identity, public) = write_gossip_identity(f.dir.path(), "edge-01", 12);

    // Permissive rollout mode: signed traffic verified, unsigned accepted —
    // reported as such, exit 0.
    let permissive = f.with_gossip(
        "check-permissive",
        &format!(
            "[gossip]\nenabled = true\nbind = '127.0.0.1:0'\nnode_name = 'edge-01'\n\
             auth_mode = 'permissive'\nidentity_key = '{}'\n[gossip.peer_identities]\n\
             edge-01 = '{}'\n",
            identity.display(),
            public.display()
        ),
    );
    let out = f.hoike(&["check", "--config", &permissive.to_string_lossy()]);
    assert!(out.status.success(), "{}\n{}", stdout(&out), stderr(&out));
    assert!(
        stdout(&out).contains("auth_mode=permissive"),
        "check must print the effective mode: {}",
        stdout(&out)
    );
    assert!(
        stdout(&out).contains("unsigned"),
        "check must state the unsigned-acceptance posture: {}",
        stdout(&out)
    );

    // Required mode with valid material: reported as enforced, exit 0.
    let required = f.with_gossip(
        "check-required",
        &format!(
            "[gossip]\nenabled = true\nbind = '127.0.0.1:0'\nnode_name = 'edge-01'\n\
             auth_mode = 'required'\nidentity_key = '{}'\n[gossip.peer_identities]\n\
             edge-01 = '{}'\n",
            identity.display(),
            public.display()
        ),
    );
    let out = f.hoike(&["check", "--config", &required.to_string_lossy()]);
    assert!(out.status.success(), "{}\n{}", stdout(&out), stderr(&out));
    assert!(
        stdout(&out).contains("auth_mode=required"),
        "check must print the effective mode: {}",
        stdout(&out)
    );

    // Required mode with unusable key material: the same fatal configuration
    // startup would reject must fail check.
    let broken = f.with_gossip(
        "check-broken",
        "[gossip]\nenabled = true\nbind = '127.0.0.1:0'\nnode_name = 'edge-01'\n\
         auth_mode = 'required'\nidentity_key = 'does-not-exist.p8'\n",
    );
    let out = f.hoike(&["check", "--config", &broken.to_string_lossy()]);
    assert!(!out.status.success(), "check must fail: {}", stdout(&out));
    assert!(
        format!("{}{}", stdout(&out), stderr(&out)).contains("gossip"),
        "failure must identify gossip: {}{}",
        stdout(&out),
        stderr(&out)
    );

    // Unknown mode strings are configuration errors.
    let invalid = f.with_gossip(
        "check-invalid",
        "[gossip]\nenabled = true\nbind = '127.0.0.1:0'\nauth_mode = 'strict'\n",
    );
    let out = f.hoike(&["check", "--config", &invalid.to_string_lossy()]);
    assert!(!out.status.success());
}
