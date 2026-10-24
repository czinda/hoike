//! F01 / A2: exercise the authenticated admin HTTP boundary, not its handler.

use ahu::Bundle;
use der::{Decode, Encode};
use hoike_sign::{CertIdCompat, SealKey};
use p256::ecdsa::{DerSignature, SigningKey, signature::Signer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
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
    config: hoike_core::Config,
    seal_key: SigningKey,
    seal_cert: Vec<u8>,
    expired_cert: Vec<u8>,
    bundle: Vec<u8>,
}

impl Fixture {
    fn new(demo: bool) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(".verify-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        let now = now();
        let seal_key = key(7);
        let seal_cert = certificate(&seal_key, now - 60, now + 3600);
        let expired_cert = certificate(&seal_key, now - 7200, now - 60);
        let mut ocsp_key = key(1);
        let ca = hoike_sign::CaIdentity {
            label: "test".into(),
            issuer_name_der: "CN=Admin Verification CA"
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
            entries: [(vec![42], hoike_sign::CertificateStatus::Good)].into(),
            this_update: now - 1,
            next_update: Some(now + 3600),
            ..Default::default()
        };
        let generation = hoike_sign::GenerationConfig {
            producer_id: "admin-verify".into(),
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
            None,
        )
        .unwrap();
        std::fs::write(dir.path().join("test.ahu"), &bundle).unwrap();
        std::fs::write(dir.path().join("signer.der"), &seal_cert).unwrap();
        std::fs::write(dir.path().join("expired.der"), &expired_cert).unwrap();
        let parsed = Bundle::from_bytes(&bundle).unwrap();
        let policy = if demo {
            String::new()
        } else {
            format!(
                "seal_signer_pins = ['{dir}/signer.der', '{dir}/expired.der']\n[[storage.seal_authorizations]]\nproducer_id = 'admin-verify'\nissuer_key_hash = '{}'\nsigner_sha256 = '{}'",
                hex::encode(&parsed.manifest.ca_scopes[0].issuer_key_hash),
                hex::encode(Sha256::digest(&seal_cert)),
                dir = dir.path().display(),
            )
        };
        // Synthetic test-only bcrypt credential shared with the existing e2e
        // login tests: test-password, cost 4. Use the real login/RBAC path.
        let config_text = format!(
            r#"
[server]
mode = 'edge'
[server.admin]
[[server.admin.operators]]
name = 'op'
password_hash = '$2y$04$DM3Fnh2MyUkSAP1Q5Rk4/eyX2w.VlF4vWTGcTvhex.StxDFv7HzWq'
role = 'operator'
[[server.admin.operators]]
name = 'viewer'
password_hash = '$2y$04$DM3Fnh2MyUkSAP1Q5Rk4/eyX2w.VlF4vWTGcTvhex.StxDFv7HzWq'
role = 'viewer'
[storage]
bundle_dir = '{dir}'
state_db = '{dir}/state'
allow_unauthenticated_bundles = true
{policy}
[[ca]]
label = 'test'
"#,
            dir = dir.path().display()
        );
        let config_path = dir.path().join("hoike.toml");
        std::fs::write(&config_path, config_text).unwrap();
        let config = hoike_core::Config::from_file(&config_path).unwrap();
        Self {
            dir,
            config,
            seal_key,
            seal_cert,
            expired_cert,
            bundle,
        }
    }

    fn candidate(&self) -> Bundle {
        let mut bundle = Bundle::from_bytes(&self.bundle).unwrap();
        bundle.manifest.ca_scopes[0].epoch = 2;
        self.reseal(&mut bundle);
        bundle
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
}

struct Server {
    client: reqwest::Client,
    base: String,
    token: String,
    task: tokio::task::JoinHandle<()>,
    responder: std::sync::Arc<hoike_core::ResponderState>,
}

impl Server {
    async fn start(f: &Fixture) -> Self {
        let responder = hoike_core::ResponderState::load(f.config.clone()).unwrap();
        let state = hoike_server::AppState::new(responder, f.config.clone());
        let responder = state.responder.clone();
        let app = hoike_server::build_admin_router_standalone(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/api/admin", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let mut server = Self {
            client,
            base,
            token: String::new(),
            task,
            responder,
        };
        server.token = server.login("op").await;
        server
    }

    async fn login(&self, name: &str) -> String {
        let response = self
            .client
            .post(format!("{}/session", self.base))
            .header("Content-Type", "application/json")
            .body(format!(r#"{{"name":"{name}","password":"test-password"}}"#))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let json: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        json["session_token"].as_str().unwrap().to_owned()
    }

    async fn upload(&self, operation: &str, bytes: Vec<u8>, token: Option<&str>) -> (u16, Value) {
        let mut request = self
            .client
            .post(format!("{}/bundles/{operation}", self.base))
            .header("Content-Type", "application/octet-stream")
            .body(bytes);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let json = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        (status, json)
    }

    async fn verify(&self, bundle: &Bundle) -> Value {
        let (status, json) = self
            .upload("verify", bundle.to_bytes().unwrap(), Some(&self.token))
            .await;
        assert_eq!(status, 200, "{json}");
        json
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

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
    visit(root, root, &mut result);
    result
}

fn failed_verdict(json: &Value) {
    assert_eq!(json["overall_ok"], false, "{json}");
    assert_eq!(json["trust_status"], "failed", "{json}");
    assert!(
        json["trust_error"].as_str().is_some_and(|s| !s.is_empty()),
        "{json}"
    );
    assert!(json["signer_sha256"].is_null(), "{json}");
    for field in [
        "header_ok",
        "manifest_ok",
        "index_digest_ok",
        "data_digest_ok",
        "sort_order_ok",
        "entry_bounds_ok",
        "entry_count_matches",
    ] {
        assert_eq!(json[field], true, "{field}: {json}");
    }
}

#[tokio::test]
async fn admin_verify_uses_running_trust_policy() {
    let f = Fixture::new(false);
    let server = Server::start(&f).await;
    let before = state_tree(&f.config.storage.state_db);
    let scopes = server.responder.scope_info();
    let mut corrupt = f.candidate();
    *corrupt.seal_bytes.last_mut().unwrap() ^= 1;
    let bad = server.verify(&corrupt).await;
    failed_verdict(&bad);
    assert_eq!(bad["seal_present"], true);

    // Runtime policy is already loaded: verification must not discover or
    // reload a configuration file from disk or accept the upload as policy.
    std::fs::write(f.dir.path().join("hoike.toml"), b"not TOML").unwrap();
    let good = server.verify(&f.candidate()).await;
    assert_eq!(good["overall_ok"], true, "{good}");
    assert_eq!(good["trust_status"], "authenticated", "{good}");
    assert!(good["trust_error"].is_null(), "{good}");
    assert_eq!(
        good["signer_sha256"],
        hex::encode(Sha256::digest(&f.seal_cert))
    );

    let other_key = key(8);
    let other_cert = certificate(&other_key, now() - 60, now() + 3600);
    let mut untrusted = f.candidate();
    untrusted.seal_bytes = hoike_sign::create_cms_seal(
        &untrusted.manifest_bytes,
        &SealKey::EcdsaP256(other_key),
        &other_cert,
    )
    .unwrap();
    failed_verdict(&server.verify(&untrusted).await);
    untrusted.seal_bytes.clear();
    let unsigned = server.verify(&untrusted).await;
    failed_verdict(&unsigned);
    assert_eq!(unsigned["seal_present"], false);

    for field in ["producer", "issuer"] {
        let mut wrong = f.candidate();
        if field == "producer" {
            wrong.manifest.producer_id = "other".into();
        } else {
            wrong.manifest.ca_scopes[0].issuer_key_hash = vec![0xEE; 32];
        }
        f.reseal(&mut wrong);
        let verdict = server.verify(&wrong).await;
        failed_verdict(&verdict);
        assert!(
            verdict["trust_error"]
                .as_str()
                .unwrap()
                .contains("not authorized"),
            "{verdict}"
        );
    }
    let mut expired = f.candidate();
    expired.seal_bytes = hoike_sign::create_cms_seal(
        &expired.manifest_bytes,
        &SealKey::EcdsaP256(f.seal_key.clone()),
        &f.expired_cert,
    )
    .unwrap();
    let verdict = server.verify(&expired).await;
    failed_verdict(&verdict);
    assert!(
        verdict["trust_error"]
            .as_str()
            .unwrap()
            .contains("outside validity period"),
        "{verdict}"
    );
    assert_eq!(state_tree(&f.config.storage.state_db), before);
    assert_eq!(server.responder.scope_info(), scopes);
    assert_eq!(
        std::fs::read(f.dir.path().join("test.ahu")).unwrap(),
        f.bundle
    );
}

#[tokio::test]
async fn admin_demo_mode_cannot_claim_authentication() {
    let f = Fixture::new(true);
    let server = Server::start(&f).await;
    let before = state_tree(&f.config.storage.state_db);
    failed_verdict(&server.verify(&f.candidate()).await);
    let (status, inspection) = server
        .upload("inspect", f.bundle.clone(), Some(&server.token))
        .await;
    assert_eq!(status, 200);
    assert_eq!(inspection["seal_present"], true);
    assert!(inspection.get("trust_status").is_none());
    assert_eq!(state_tree(&f.config.storage.state_db), before);
}

#[tokio::test]
async fn admin_verify_distinguishes_malformed_input_and_enforces_rbac() {
    let f = Fixture::new(false);
    let server = Server::start(&f).await;
    let before = state_tree(&f.config.storage.state_db);
    let mut damaged = f.candidate();
    damaged.data[0] ^= 1;
    for bytes in [b"not an ahu bundle".to_vec(), damaged.to_bytes().unwrap()] {
        let (status, json) = server.upload("verify", bytes, Some(&server.token)).await;
        assert_eq!(status, 400, "{json}");
        assert!(json["detail"].is_string(), "{json}");
        assert!(
            json.get("trust_status").is_none(),
            "malformed input is not a trust verdict: {json}"
        );
    }
    // Entry-count mismatch is a reported structural flag (not a parse error).
    // Even a trusted signature cannot turn that result into overall success.
    let mut wrong_count = f.candidate();
    wrong_count.manifest.entry_count += 1;
    f.reseal(&mut wrong_count);
    let json = server.verify(&wrong_count).await;
    assert_eq!(json["entry_count_matches"], false, "{json}");
    assert_eq!(json["overall_ok"], false, "{json}");
    let (status, _) = server.upload("verify", f.bundle.clone(), None).await;
    assert_eq!(status, 401);
    let viewer = server.login("viewer").await;
    let (status, _) = server
        .upload("verify", f.bundle.clone(), Some(&viewer))
        .await;
    assert_eq!(status, 403);
    assert_eq!(state_tree(&f.config.storage.state_db), before);
}
