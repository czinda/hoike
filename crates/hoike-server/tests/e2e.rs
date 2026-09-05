fn current_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
use ahu::{
    BundleBuilder, BundleType, CaScope, Completeness, Continuity, Integrity, Manifest, ResponderId,
    ResponderIdType, Window,
};
use der::Encode;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x509_ocsp::{CertId, OcspRequest, Request, TbsRequest};

fn build_certid(serial: u64) -> CertId {
    build_certid_for_ca(serial, b"CN=Test CA,O=Hoike Test", b"test-ca-public-key")
}

fn build_certid_for_ca(serial: u64, issuer_name: &[u8], issuer_key: &[u8]) -> CertId {
    use const_oid::ObjectIdentifier;
    use der::asn1::OctetString;

    let sha256_oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

    let issuer_name_hash = Sha256::digest(issuer_name);
    let issuer_key_hash = Sha256::digest(issuer_key);

    let serial_bytes = serial.to_be_bytes();
    let start = serial_bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let serial_trimmed = &serial_bytes[start..];

    CertId {
        hash_algorithm: spki::AlgorithmIdentifier {
            oid: sha256_oid,
            parameters: None,
        },
        issuer_name_hash: OctetString::new(issuer_name_hash.to_vec()).unwrap(),
        issuer_key_hash: OctetString::new(issuer_key_hash.to_vec()).unwrap(),
        serial_number: x509_cert::serial_number::SerialNumber::new(serial_trimmed).unwrap(),
    }
}

fn build_ocsp_request(cert_id: &CertId) -> Vec<u8> {
    let request = Request {
        req_cert: cert_id.clone(),
        single_request_extensions: None,
    };

    let tbs = TbsRequest {
        version: Default::default(),
        requestor_name: None,
        request_list: vec![request],
        request_extensions: None,
    };

    let ocsp_req = OcspRequest {
        tbs_request: tbs,
        optional_signature: None,
    };

    ocsp_req.to_der().expect("OCSPRequest encode failed")
}

fn build_bundle_for_ca(issuer_name: &[u8], issuer_key: &[u8], entries: &[(u64, &[u8])]) -> Vec<u8> {
    let manifest = Manifest {
        format_version: 1,
        bundle_id: Uuid::nil(),
        producer_id: "e2e-test".into(),
        created_at: current_time() - 1,
        bundle_type: BundleType::Full,
        ca_scopes: vec![CaScope {
            hash_algorithm: vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            issuer_name_hash: Sha256::digest(issuer_name).to_vec(),
            issuer_key_hash: Sha256::digest(issuer_key).to_vec(),
            epoch: 1,
            responder_id: ResponderId {
                id_type: ResponderIdType::ByKey,
                value: vec![0xCC; 20],
            },
            responder_chain: None,
            signature_algorithm: vec![0x02],
            completeness: Completeness::AuthoritativeComplete,
        }],
        window: Window {
            produced_at: current_time() - 1,
            this_update_min: current_time() - 1,
            next_update_min: current_time() + 86400,
            next_update_max: current_time() + 93600,
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

    for (serial, response_bytes) in entries {
        let cert_id = build_certid_for_ca(*serial, issuer_name, issuer_key);
        let certid_der = cert_id.to_der().unwrap();
        let entry_key: [u8; 32] = Sha256::digest(&certid_der).into();
        builder.add_entry(entry_key, response_bytes.to_vec());
    }

    builder
        .build(|m| Ok(Sha256::digest(m).to_vec()))
        .expect("build failed")
}

fn build_test_bundle_with_real_certids(entries: &[(u64, &[u8])]) -> Vec<u8> {
    let manifest = Manifest {
        format_version: 1,
        bundle_id: Uuid::nil(),
        producer_id: "e2e-test".into(),
        created_at: current_time() - 1,
        bundle_type: BundleType::Full,
        ca_scopes: vec![CaScope {
            hash_algorithm: vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            issuer_name_hash: Sha256::digest(b"CN=Test CA,O=Hoike Test").to_vec(),
            issuer_key_hash: Sha256::digest(b"test-ca-public-key").to_vec(),
            epoch: 1,
            responder_id: ResponderId {
                id_type: ResponderIdType::ByKey,
                value: vec![0xCC; 20],
            },
            responder_chain: None,
            signature_algorithm: vec![0x02],
            completeness: Completeness::AuthoritativeComplete,
        }],
        window: Window {
            produced_at: current_time() - 1,
            this_update_min: current_time() - 1,
            next_update_min: current_time() + 86400,
            next_update_max: current_time() + 93600,
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

    for (serial, response_bytes) in entries {
        let cert_id = build_certid(*serial);
        let certid_der = cert_id.to_der().unwrap();
        let entry_key: [u8; 32] = Sha256::digest(&certid_der).into();
        builder.add_entry(entry_key, response_bytes.to_vec());
    }

    builder
        .build(|m| Ok(Sha256::digest(m).to_vec()))
        .expect("build failed")
}

async fn start_test_server(bundle_bytes: Vec<u8>) -> (u16, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let bundle_path = dir.path().join("test.ahu");
    std::fs::write(&bundle_path, &bundle_bytes).unwrap();

    let config_toml = format!(
        r#"
[server]
mode = "edge"
listen = "127.0.0.1:0"
max_request = 8192

[storage]
bundle_dir = "{dir}"
state_db = "{dir}/state"

[[ca]]
label = "test"
bundle_file = "{bundle}"
"#,
        dir = dir.path().display(),
        bundle = bundle_path.display(),
    );

    let config_path = dir.path().join("hoike.toml");
    std::fs::write(&config_path, &config_toml).unwrap();

    let config = hoike_core::Config::from_file(&config_path).unwrap();
    let state = hoike_core::ResponderState::load(config.clone()).unwrap();
    let app_state = hoike_server::AppState::new(state, config);
    let app = hoike_server::build_router(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (port, dir)
}

#[tokio::test]
async fn post_request_returns_matching_response() {
    let response_bytes = b"MOCK-OCSP-RESPONSE-FOR-SERIAL-42";
    let bundle_bytes = build_test_bundle_with_real_certids(&[
        (42, response_bytes),
        (100, b"MOCK-OCSP-RESPONSE-FOR-SERIAL-100"),
    ]);

    let (port, _dir) = start_test_server(bundle_bytes).await;

    let cert_id = build_certid(42);
    let request_der = build_ocsp_request(&cert_id);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .header("Content-Type", "application/ocsp-request")
        .body(request_der)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/ocsp-response"
    );

    // Success: should have ETag and Cache-Control headers.
    assert!(resp.headers().get("etag").is_some());
    assert!(resp.headers().get("cache-control").is_some());

    let body = resp.bytes().await.unwrap();
    assert_eq!(&body[..], response_bytes);
}

#[tokio::test]
async fn unknown_serial_returns_unauthorized() {
    let bundle_bytes = build_test_bundle_with_real_certids(&[(1, b"RESPONSE-1")]);
    let (port, _dir) = start_test_server(bundle_bytes).await;

    let cert_id = build_certid(999);
    let request_der = build_ocsp_request(&cert_id);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .header("Content-Type", "application/ocsp-request")
        .body(request_der)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    // unauthorized = 30 03 0A 01 06
    assert_eq!(&body[..], &[0x30, 0x03, 0x0A, 0x01, 0x06]);
}

#[tokio::test]
async fn malformed_request_returns_error() {
    let bundle_bytes = build_test_bundle_with_real_certids(&[(1, b"R")]);
    let (port, _dir) = start_test_server(bundle_bytes).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .header("Content-Type", "application/ocsp-request")
        .body(b"not-valid-der".to_vec())
        .send()
        .await
        .unwrap();

    let body = resp.bytes().await.unwrap();
    // malformedRequest = 30 03 0A 01 01
    assert_eq!(&body[..], &[0x30, 0x03, 0x0A, 0x01, 0x01]);
}

#[tokio::test]
async fn get_root_returns_malformed() {
    let bundle_bytes = build_test_bundle_with_real_certids(&[(1, b"R")]);
    let (port, _dir) = start_test_server(bundle_bytes).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(&body[..], &[0x30, 0x03, 0x0A, 0x01, 0x01]);
}

// ── Multi-CA tests ──────────────────────────────────────────────────

#[allow(clippy::type_complexity)]
async fn start_multi_ca_server(
    bundles: Vec<(&str, &[u8], &[u8], Vec<u8>)>, // (label, issuer_name, issuer_key, bundle_bytes)
) -> (u16, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();

    let mut ca_blocks = String::new();
    for (i, (label, _name, _key, bytes)) in bundles.iter().enumerate() {
        let bundle_path = dir.path().join(format!("ca{i}.ahu"));
        std::fs::write(&bundle_path, bytes).unwrap();
        ca_blocks.push_str(&format!(
            r#"
[[ca]]
label = "{label}"
bundle_file = "{path}"
"#,
            path = bundle_path.display(),
        ));
    }

    let config_toml = format!(
        r#"
[server]
mode = "edge"
listen = "127.0.0.1:0"
max_request = 8192

[storage]
bundle_dir = "{dir}"
state_db = "{dir}/state"
{ca_blocks}
"#,
        dir = dir.path().display(),
    );

    let config_path = dir.path().join("hoike.toml");
    std::fs::write(&config_path, &config_toml).unwrap();

    let config = hoike_core::Config::from_file(&config_path).unwrap();
    let state = hoike_core::ResponderState::load(config.clone()).unwrap();
    let app_state = hoike_server::AppState::new(state, config);
    let app = hoike_server::build_router(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (port, dir)
}

#[tokio::test]
async fn two_cas_route_independently() {
    let ca_a_name = b"CN=Enterprise CA A,O=Hoike";
    let ca_a_key = b"ca-a-public-key";
    let ca_b_name = b"CN=IoT CA B,O=Hoike";
    let ca_b_key = b"ca-b-public-key";

    let bundle_a = build_bundle_for_ca(
        ca_a_name,
        ca_a_key,
        &[(1, b"RESPONSE-A-SERIAL-1"), (2, b"RESPONSE-A-SERIAL-2")],
    );
    let bundle_b = build_bundle_for_ca(
        ca_b_name,
        ca_b_key,
        &[(1, b"RESPONSE-B-SERIAL-1"), (99, b"RESPONSE-B-SERIAL-99")],
    );

    let (port, _dir) = start_multi_ca_server(vec![
        ("ca-a", ca_a_name, ca_a_key, bundle_a),
        ("ca-b", ca_b_name, ca_b_key, bundle_b),
    ])
    .await;

    let client = reqwest::Client::new();

    // Request serial 1 from CA-A → should get CA-A's response
    let cert_id_a1 = build_certid_for_ca(1, ca_a_name, ca_a_key);
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .header("Content-Type", "application/ocsp-request")
        .body(build_ocsp_request(&cert_id_a1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(&body[..], b"RESPONSE-A-SERIAL-1");

    // Request serial 99 from CA-B → should get CA-B's response
    let cert_id_b99 = build_certid_for_ca(99, ca_b_name, ca_b_key);
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .header("Content-Type", "application/ocsp-request")
        .body(build_ocsp_request(&cert_id_b99))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(&body[..], b"RESPONSE-B-SERIAL-99");
}

#[tokio::test]
async fn cross_ca_miss_returns_unauthorized() {
    let ca_a_name = b"CN=CA Alpha,O=Test";
    let ca_a_key = b"alpha-key";
    let ca_b_name = b"CN=CA Beta,O=Test";
    let ca_b_key = b"beta-key";

    let bundle_a = build_bundle_for_ca(ca_a_name, ca_a_key, &[(42, b"ALPHA-42")]);
    let bundle_b = build_bundle_for_ca(ca_b_name, ca_b_key, &[(42, b"BETA-42")]);

    let (port, _dir) = start_multi_ca_server(vec![
        ("alpha", ca_a_name, ca_a_key, bundle_a),
        ("beta", ca_b_name, ca_b_key, bundle_b),
    ])
    .await;

    let client = reqwest::Client::new();

    // Request serial 42 from CA Alpha → gets ALPHA-42
    let cert_id = build_certid_for_ca(42, ca_a_name, ca_a_key);
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .header("Content-Type", "application/ocsp-request")
        .body(build_ocsp_request(&cert_id))
        .send()
        .await
        .unwrap();
    let body = resp.bytes().await.unwrap();
    assert_eq!(&body[..], b"ALPHA-42");

    // Request serial 42 from CA Beta → gets BETA-42 (not ALPHA-42)
    let cert_id = build_certid_for_ca(42, ca_b_name, ca_b_key);
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .header("Content-Type", "application/ocsp-request")
        .body(build_ocsp_request(&cert_id))
        .send()
        .await
        .unwrap();
    let body = resp.bytes().await.unwrap();
    assert_eq!(&body[..], b"BETA-42");

    // Request serial 999 from a non-existent CA → unauthorized
    let cert_id = build_certid_for_ca(999, b"CN=Unknown CA", b"unknown-key");
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .header("Content-Type", "application/ocsp-request")
        .body(build_ocsp_request(&cert_id))
        .send()
        .await
        .unwrap();
    let body = resp.bytes().await.unwrap();
    assert_eq!(&body[..], &[0x30, 0x03, 0x0A, 0x01, 0x06]); // unauthorized
}

// ── Nonce policy tests ──────────────────────────────────────────────

fn build_ocsp_request_with_nonce(cert_id: &CertId, nonce: &[u8]) -> Vec<u8> {
    use der::asn1::OctetString;

    let nonce_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");
    let nonce_value = OctetString::new(nonce.to_vec()).unwrap();
    let nonce_ext_value = OctetString::new(nonce_value.to_der().unwrap()).unwrap();
    let nonce_ext = x509_cert::ext::Extension {
        extn_id: nonce_oid,
        critical: false,
        extn_value: nonce_ext_value,
    };

    let request = Request {
        req_cert: cert_id.clone(),
        single_request_extensions: None,
    };

    let tbs = TbsRequest {
        version: Default::default(),
        requestor_name: None,
        request_list: vec![request],
        request_extensions: Some(vec![nonce_ext]),
    };

    let ocsp_req = OcspRequest {
        tbs_request: tbs,
        optional_signature: None,
    };

    ocsp_req
        .to_der()
        .expect("OCSPRequest with nonce encode failed")
}

#[tokio::test]
async fn nonce_ignored_serves_presigned() {
    let response_bytes = b"PRESIGNED-RESPONSE-42";
    let bundle_bytes = build_test_bundle_with_real_certids(&[(42, response_bytes)]);
    let (port, _dir) = start_test_server(bundle_bytes).await;

    let cert_id = build_certid(42);
    let nonce = [0xAA; 16]; // 16 bytes = MustAccept per RFC 9654
    let request_der = build_ocsp_request_with_nonce(&cert_id, &nonce);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .header("Content-Type", "application/ocsp-request")
        .body(request_der)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    // ignore policy: serves the pre-signed response, no nonce in it
    assert_eq!(&body[..], response_bytes);
}

#[tokio::test]
async fn forward_policy_without_url_rejected_at_startup() {
    let bundle_bytes = build_test_bundle_with_real_certids(&[(1, b"R")]);
    let dir = tempfile::tempdir().unwrap();
    let bundle_path = dir.path().join("test.ahu");
    std::fs::write(&bundle_path, &bundle_bytes).unwrap();

    let config_toml = format!(
        r#"
[server]
mode = "edge"
listen = "127.0.0.1:0"

[storage]
bundle_dir = "{dir}"
state_db = "{dir}/state"

[[ca]]
label = "bad-forward"
bundle_file = "{bundle}"
nonce_policy = "forward"
"#,
        dir = dir.path().display(),
        bundle = bundle_path.display(),
    );

    let config_path = dir.path().join("hoike.toml");
    std::fs::write(&config_path, &config_toml).unwrap();

    let config = hoike_core::Config::from_file(&config_path).unwrap();
    let msg = match hoike_core::ResponderState::load(config) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected config validation error"),
    };
    assert!(
        msg.contains("forward_to"),
        "expected forward_to error, got: {msg}"
    );
}

#[tokio::test]
async fn live_nonce_rejected_at_startup() {
    let bundle_bytes = build_test_bundle_with_real_certids(&[(1, b"R")]);
    let dir = tempfile::tempdir().unwrap();
    let bundle_path = dir.path().join("test.ahu");
    std::fs::write(&bundle_path, &bundle_bytes).unwrap();

    let config_toml = format!(
        r#"
[server]
mode = "edge"
listen = "127.0.0.1:0"

[storage]
bundle_dir = "{dir}"
state_db = "{dir}/state"

[[ca]]
label = "bad-live"
bundle_file = "{bundle}"
nonce_policy = "live"
"#,
        dir = dir.path().display(),
        bundle = bundle_path.display(),
    );

    let config_path = dir.path().join("hoike.toml");
    std::fs::write(&config_path, &config_toml).unwrap();

    let config = hoike_core::Config::from_file(&config_path).unwrap();
    let msg = match hoike_core::ResponderState::load(config) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected config validation error for nonce_policy=live"),
    };
    assert!(
        msg.contains("live") && (msg.contains("edge") || msg.contains("signing key")),
        "expected live-on-edge rejection, got: {msg}"
    );
}

#[tokio::test]
async fn invalid_nonce_policy_rejected_at_startup() {
    let bundle_bytes = build_test_bundle_with_real_certids(&[(1, b"R")]);
    let dir = tempfile::tempdir().unwrap();
    let bundle_path = dir.path().join("test.ahu");
    std::fs::write(&bundle_path, &bundle_bytes).unwrap();

    let config_toml = format!(
        r#"
[server]
mode = "edge"
listen = "127.0.0.1:0"

[storage]
bundle_dir = "{dir}"
state_db = "{dir}/state"

[[ca]]
label = "bad-policy"
bundle_file = "{bundle}"
nonce_policy = "bogus"
"#,
        dir = dir.path().display(),
        bundle = bundle_path.display(),
    );

    let config_path = dir.path().join("hoike.toml");
    std::fs::write(&config_path, &config_toml).unwrap();

    let config = hoike_core::Config::from_file(&config_path).unwrap();
    let msg = match hoike_core::ResponderState::load(config) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected config validation error"),
    };
    assert!(
        msg.contains("bogus"),
        "expected unknown policy error, got: {msg}"
    );
}

fn build_expired_bundle(entries: &[(u64, &[u8])]) -> Vec<u8> {
    let manifest = Manifest {
        format_version: 1,
        bundle_id: Uuid::nil(),
        producer_id: "e2e-test".into(),
        created_at: 1000000000,
        bundle_type: BundleType::Full,
        ca_scopes: vec![CaScope {
            hash_algorithm: vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            issuer_name_hash: Sha256::digest(b"CN=Test CA,O=Hoike Test").to_vec(),
            issuer_key_hash: Sha256::digest(b"test-ca-public-key").to_vec(),
            epoch: 1,
            responder_id: ResponderId {
                id_type: ResponderIdType::ByKey,
                value: vec![0xCC; 20],
            },
            responder_chain: None,
            signature_algorithm: vec![0x02],
            completeness: Completeness::AuthoritativeComplete,
        }],
        window: Window {
            produced_at: 1000000000,
            this_update_min: 1000000000,
            next_update_min: 1000086400, // ~2001-09-09 — long expired
            next_update_max: 1000093600,
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

    for (serial, response_bytes) in entries {
        let cert_id = build_certid(*serial);
        let certid_der = cert_id.to_der().unwrap();
        let entry_key: [u8; 32] = Sha256::digest(&certid_der).into();
        builder.add_entry(entry_key, response_bytes.to_vec());
    }

    builder
        .build(|m| Ok(Sha256::digest(m).to_vec()))
        .expect("build failed")
}

#[tokio::test]
async fn expired_bundle_returns_try_later() {
    let bundle_bytes = build_expired_bundle(&[(42, b"EXPIRED-RESPONSE")]);
    let (port, _dir) = start_test_server(bundle_bytes).await;

    let cert_id = build_certid(42);
    let request_der = build_ocsp_request(&cert_id);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .header("Content-Type", "application/ocsp-request")
        .body(request_der)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    // tryLater = 30 03 0A 01 03
    assert_eq!(
        &body[..],
        &[0x30, 0x03, 0x0A, 0x01, 0x03],
        "expired bundle should return tryLater"
    );
}

#[tokio::test]
async fn success_response_has_last_modified() {
    let response_bytes = b"MOCK-RESPONSE";
    let bundle_bytes = build_test_bundle_with_real_certids(&[(42, response_bytes)]);

    let (port, _dir) = start_test_server(bundle_bytes).await;

    let cert_id = build_certid(42);
    let request_der = build_ocsp_request(&cert_id);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .header("Content-Type", "application/ocsp-request")
        .body(request_der)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers().get("last-modified").is_some(),
        "successful response should have Last-Modified header"
    );
    let lm = resp
        .headers()
        .get("last-modified")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        lm.ends_with("GMT"),
        "Last-Modified should be HTTP-date in GMT: {lm}"
    );
}

#[tokio::test]
async fn live_nonce_signing_returns_nonce_in_response() {
    use der::Decode;
    use std::collections::BTreeMap;
    use x509_ocsp::{BasicOcspResponse, OcspResponse};

    // Build a real bundle with proper DER-encoded OCSP responses
    let issuer_name = b"CN=Live Test CA,O=Hoike Test";
    let issuer_key = b"live-test-ca-public-key";

    let ca = hoike_sign::CaIdentity {
        label: "live-test".into(),
        issuer_name_der: issuer_name.to_vec(),
        issuer_key_bytes: issuer_key.to_vec(),
    };
    let mut entries = BTreeMap::new();
    entries.insert(vec![42u8], hoike_sign::CertificateStatus::Good);
    let snapshot = hoike_sign::StatusSnapshot {
        entries,
        this_update: current_time() - 1,
        next_update: Some(current_time() + 86400),
    };
    let config = hoike_sign::GenerationConfig {
        producer_id: "live-test".into(),
        epoch: 1,
        validity_secs: 86400,
        certid_compat: hoike_sign::CertIdCompat::Sha256Only,
        completeness: ahu::Completeness::AuthoritativeComplete,
        bucket_size: 1,
        ..Default::default()
    };
    let mut key = hoike_sign::demo_ecdsa_p256_key();
    let bundle_bytes = hoike_sign::produce_bundle::<_, p256::ecdsa::DerSignature>(
        &ca,
        &snapshot,
        &config,
        &mut key,
        |m| {
            use sha2_v010::Digest as _;
            Ok(sha2_v010::Sha256::digest(m).to_vec())
        },
        None,
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let bundle_path = dir.path().join("test.ahu");
    std::fs::write(&bundle_path, &bundle_bytes).unwrap();

    // Config with nonce_policy = "live" in combined mode
    let config_toml = format!(
        r#"
[server]
mode = "combined"
listen = "127.0.0.1:0"

[storage]
bundle_dir = "{dir}"
state_db = "{dir}/state"

[[ca]]
label = "live-test"
bundle_file = "{bundle}"
nonce_policy = "live"

[ca.source]
type = "crl"
path = "{dir}/dummy.crl"

[ca.signing_key]
type = "demo"
"#,
        dir = dir.path().display(),
        bundle = bundle_path.display(),
    );

    let config_path = dir.path().join("hoike.toml");
    std::fs::write(&config_path, &config_toml).unwrap();
    std::fs::write(dir.path().join("dummy.crl"), b"").unwrap();

    let config = hoike_core::Config::from_file(&config_path).unwrap();
    let state = hoike_core::ResponderState::load(config.clone()).unwrap();

    let demo_key = hoike_sign::demo_ecdsa_p256_key();
    let live = hoike_server::LiveSignerState {
        signer: tokio::sync::Mutex::new(demo_key),
        responder_key_bytes: issuer_key.to_vec(),
        validity_secs: 86400,
        responder_cert_der: None,
    };
    let app_state = hoike_server::AppState::new(state, config).with_live_signer(live);
    let app = hoike_server::build_router(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Build a request WITH a 16-byte nonce.
    // Must use explicit NULL parameter to match produce_bundle's AlgorithmIdentifier.
    let sha256_oid = const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    let cert_id = CertId {
        hash_algorithm: spki::AlgorithmIdentifier {
            oid: sha256_oid,
            parameters: Some(der::asn1::Null.into()),
        },
        issuer_name_hash: der::asn1::OctetString::new(Sha256::digest(issuer_name).to_vec())
            .unwrap(),
        issuer_key_hash: der::asn1::OctetString::new(Sha256::digest(issuer_key).to_vec()).unwrap(),
        serial_number: x509_cert::serial_number::SerialNumber::new(&[42u8]).unwrap(),
    };
    let nonce_bytes = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];

    let nonce_ext = x509_ocsp::ext::Nonce::new(nonce_bytes.clone()).unwrap();
    use x509_cert::ext::AsExtension;
    let nonce_ext_val = nonce_ext
        .to_extension(&x509_cert::name::Name::default(), &[])
        .unwrap();

    let request = Request {
        req_cert: cert_id,
        single_request_extensions: None,
    };
    let tbs = TbsRequest {
        version: Default::default(),
        requestor_name: None,
        request_list: vec![request],
        request_extensions: Some(vec![nonce_ext_val]),
    };
    let ocsp_req = OcspRequest {
        tbs_request: tbs,
        optional_signature: None,
    };
    let request_der = ocsp_req.to_der().unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .header("Content-Type", "application/ocsp-request")
        .body(request_der)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();

    // Parse and verify nonce is in the response
    let ocsp_resp = OcspResponse::from_der(&body).unwrap();
    assert_eq!(
        ocsp_resp.response_status,
        x509_ocsp::OcspResponseStatus::Successful
    );

    let basic =
        BasicOcspResponse::from_der(ocsp_resp.response_bytes.unwrap().response.as_bytes()).unwrap();

    let resp_nonce = basic.nonce().expect("live response should contain nonce");
    assert_eq!(
        resp_nonce.0.as_bytes(),
        &nonce_bytes,
        "nonce should match request nonce"
    );
}

/// Build a minimal CRL revoking serials 42 and 100. Replicates
/// `hoike_sign::crl::tests::build_test_crl_der` (that helper is `#[cfg(test)]`
/// and thus not visible across the crate boundary). The CRL is signed by the
/// independently configured synthetic issuer and remains currently valid.
fn build_round_trip_crl_der() -> (Vec<u8>, Vec<u8>) {
    use der::Decode;
    use signature::Signer;
    let key = hoike_sign::demo_ecdsa_p256_key();
    let cert_der = hoike_sign::generate_seal_cert(&key).unwrap();
    let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();
    use der::asn1::{BitString, UtcTime};
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
    use x509_cert::time::Time;

    let now_dt =
        der::DateTime::from_unix_duration(std::time::Duration::from_secs(current_time() - 1))
            .unwrap();
    let next_dt =
        der::DateTime::from_unix_duration(std::time::Duration::from_secs(current_time() + 3600))
            .unwrap();
    let revoke_dt = der::DateTime::new(2025, 1, 10, 8, 0, 0).unwrap();

    let this_update = Time::UtcTime(UtcTime::from_date_time(now_dt).unwrap());
    let next_update = Time::UtcTime(UtcTime::from_date_time(next_dt).unwrap());
    let revoke_time = Time::UtcTime(UtcTime::from_date_time(revoke_dt).unwrap());

    let revoked_certs = vec![
        RevokedCert {
            serial_number: x509_cert::serial_number::SerialNumber::new(&[42u8]).unwrap(),
            revocation_date: revoke_time,
            crl_entry_extensions: None,
        },
        RevokedCert {
            serial_number: x509_cert::serial_number::SerialNumber::new(&[100u8]).unwrap(),
            revocation_date: revoke_time,
            crl_entry_extensions: None,
        },
    ];

    let sha256_with_ecdsa = const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    let alg = AlgorithmIdentifierOwned {
        oid: sha256_with_ecdsa,
        parameters: None,
    };

    let tbs = TbsCertList {
        version: x509_cert::Version::V2,
        signature: alg.clone(),
        issuer: cert.tbs_certificate.subject,
        this_update,
        next_update: Some(next_update),
        revoked_certificates: Some(revoked_certs),
        crl_extensions: None,
    };

    let sig: p256::ecdsa::DerSignature = key.sign(&tbs.to_der().unwrap());
    let crl = CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: alg,
        signature: BitString::from_bytes(sig.as_bytes()).unwrap(),
    };

    (crl.to_der().expect("CRL encoding failed"), cert_der)
}

/// Full Phase 2 round-trip for the on-demand signing endpoint:
/// sign an initial bundle (epoch 1) → load it (records the high-water mark) →
/// POST `/api/admin/sign/{label}` → assert the endpoint signs at epoch 2, hot-
/// reloads, and the freshly written `.ahu` on disk parses at the new epoch.
///
/// The epoch progression (1 → 2) is the correctness signal: `sign_ca_scope`
/// derives the epoch from the persisted high-water mark, so a second signing
/// pass must observe the first pass's advance rather than repeat epoch 1.
#[tokio::test]
async fn sign_endpoint_round_trip_signs_reloads_and_advances_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let crl_path = dir.path().join("test.crl");
    use base64::Engine;
    use der::Decode;
    let (crl_der, cert_der) = build_round_trip_crl_der();
    std::fs::write(&crl_path, crl_der).unwrap();
    std::fs::write(dir.path().join("issuer.der"), &cert_der).unwrap();
    let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();
    let issuer_name = base64::engine::general_purpose::STANDARD
        .encode(cert.tbs_certificate.subject.to_der().unwrap());
    let issuer_key = base64::engine::general_purpose::STANDARD.encode(
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    );
    let bundle_path = dir.path().join("round-trip-test.ahu");

    // `password_hash` below is a bcrypt hash of "test-password" (cost 4) — a
    // synthetic, test-only credential, never a real secret.
    let config_toml = format!(
        r#"
[server]
mode = "combined"
listen = "127.0.0.1:0"

[server.admin]
session_ttl_secs = 3600

[[server.admin.operators]]
name = "op"
password_hash = "$2y$04$DM3Fnh2MyUkSAP1Q5Rk4/eyX2w.VlF4vWTGcTvhex.StxDFv7HzWq"
role = "operator"

[storage]
bundle_dir = "{dir}"
state_db = "{dir}/state"

[[ca]]
label = "round-trip-test"
issuer_name_der_b64 = "{issuer_name}"
issuer_key_bytes_b64 = "{issuer_key}"
bundle_file = "{bundle}"

[ca.source]
type = "crl"
path = "{crl}"
issuer_cert = "{dir}/issuer.der"

[ca.signing_key]
type = "demo"
"#,
        dir = dir.path().display(),
        bundle = bundle_path.display(),
        crl = crl_path.display(),
    );
    let config_path = dir.path().join("hoike.toml");
    std::fs::write(&config_path, &config_toml).unwrap();

    let config = hoike_core::Config::from_file(&config_path).unwrap();

    // Persistent sources are empty here (CRL is stateless), but they still flow
    // through the same `SignerContext` mutex the endpoint locks — mirroring how
    // `run_server` wires the background loop and the admin API together.
    let sources = hoike_sign::create_persistent_sources(&config).unwrap();

    // Initial signer pass — epoch 1.
    let initial = hoike_sign::sign_and_write_all(&config, &sources).unwrap();
    assert_eq!(initial.len(), 1, "one CA has a source");
    assert_eq!(
        initial[0].epoch, 1,
        "first pass derives epoch 1 (high-water 0 + 1)"
    );
    assert_eq!(initial[0].entry_count, 2, "CRL revokes serials 42 and 100");

    // Loading the bundle records the high-water mark (epoch 1) in the state store,
    // so the next signing pass must advance to epoch 2.
    let state = hoike_core::ResponderState::load(config.clone()).unwrap();

    let ctx = hoike_server::SignerContext {
        sources: tokio::sync::Mutex::new(sources),
    };
    let app_state = hoike_server::AppState::new(state, config).with_signer_context(ctx);
    let app = hoike_server::build_router(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = reqwest::Client::new();

    // Authenticate via the real login endpoint — the `state` module is private,
    // so a `Session` cannot be fabricated in the test.
    let login_resp = client
        .post(format!("http://127.0.0.1:{port}/api/admin/session"))
        .header("Content-Type", "application/json")
        .body(r#"{"name":"op","password":"test-password"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(login_resp.status(), 200, "login should succeed");
    let login_json: serde_json::Value =
        serde_json::from_str(&login_resp.text().await.unwrap()).unwrap();
    let token = login_json["session_token"]
        .as_str()
        .expect("login response should carry a session_token")
        .to_string();

    // On-demand sign of the single scope.
    let sign_resp = client
        .post(format!(
            "http://127.0.0.1:{port}/api/admin/sign/round-trip-test"
        ))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(sign_resp.status(), 200, "sign endpoint should succeed");
    let sign_json: serde_json::Value =
        serde_json::from_str(&sign_resp.text().await.unwrap()).unwrap();
    assert_eq!(sign_json["status"], "ok");
    assert_eq!(sign_json["ca_label"], "round-trip-test");
    assert_eq!(
        sign_json["epoch"].as_u64().unwrap(),
        2,
        "endpoint sign must advance the epoch to 2"
    );
    assert_eq!(
        sign_json["entry_count"].as_u64().unwrap(),
        2,
        "re-sign sees the same two revoked serials"
    );

    // The freshly written `.ahu` on disk must reflect the advanced epoch. Epoch
    // is per-scope in the manifest; this single-CA bundle carries one scope.
    let bundle_after = ahu::Bundle::from_file(&bundle_path).unwrap();
    let scope = bundle_after
        .manifest
        .ca_scopes
        .first()
        .expect("bundle should carry one CA scope");
    assert_eq!(scope.epoch, 2, "written bundle scope should be at epoch 2");

    // A Viewer-authenticated request through the same endpoint is rejected — but
    // more importantly, an unauthenticated sign attempt must not succeed.
    let unauth = client
        .post(format!(
            "http://127.0.0.1:{port}/api/admin/sign/round-trip-test"
        ))
        .send()
        .await
        .unwrap();
    assert_ne!(
        unauth.status(),
        200,
        "unauthenticated sign must be rejected"
    );
}

fn review_rewindow(bytes: &[u8], this: u64, next: u64) -> Vec<u8> {
    let bundle = ahu::Bundle::from_bytes(bytes).unwrap();
    let mut manifest = bundle.manifest.clone();
    manifest.window.this_update_min = this;
    manifest.window.next_update_min = next;
    manifest.window.next_update_max = next;
    let mut builder = BundleBuilder::new(manifest);
    for i in 0..bundle.index.len() {
        let data = bundle.entry_at(i).unwrap();
        builder.add_entry(bundle.index[i].entry_key, data.to_vec());
    }
    builder.build(|m| Ok(Sha256::digest(m).to_vec())).unwrap()
}

#[tokio::test]
async fn expired_first_ca_does_not_block_fresh_second_ca() {
    use tower::ServiceExt;
    let dir = tempfile::tempdir().unwrap();
    let first = build_expired_bundle(&[(42, b"OLD")]);
    let second = build_bundle_for_ca(b"CA2", b"KEY2", &[(42, b"FRESH")]);
    std::fs::write(dir.path().join("a.ahu"), first).unwrap();
    std::fs::write(dir.path().join("b.ahu"), second).unwrap();
    let conf = format!(
        "[server]\nmode='edge'\n[storage]\nbundle_dir='{0}'\nstate_db='{0}/state'\n[[ca]]\nlabel='a'\nbundle_file='{0}/a.ahu'\n[[ca]]\nlabel='b'\nbundle_file='{0}/b.ahu'\n",
        dir.path().display()
    );
    let cfg: hoike_core::Config = toml::from_str(&conf).unwrap();
    let state = hoike_core::ResponderState::load(cfg.clone()).unwrap();
    let app = hoike_server::build_router(hoike_server::AppState::new(state, cfg));
    let req = build_ocsp_request(&build_certid_for_ca(42, b"CA2", b"KEY2"));
    let response = app
        .oneshot(
            axum::http::Request::post("/")
                .body(axum::body::Body::from(req))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], b"FRESH");
}

#[tokio::test]
async fn cache_lifetime_is_capped_by_remaining_validity() {
    use tower::ServiceExt;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let bytes = review_rewindow(
        &build_test_bundle_with_real_certids(&[(42, b"R")]),
        now - 86000,
        now + 10,
    );
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.ahu"), bytes).unwrap();
    let conf = format!(
        "[server]\nmode='edge'\n[storage]\nbundle_dir='{0}'\nstate_db='{0}/state'\n",
        dir.path().display()
    );
    let cfg: hoike_core::Config = toml::from_str(&conf).unwrap();
    let state = hoike_core::ResponderState::load(cfg.clone()).unwrap();
    let app = hoike_server::build_router(hoike_server::AppState::new(state, cfg));
    let req = build_ocsp_request(&build_certid(42));
    let response = app
        .oneshot(
            axum::http::Request::post("/")
                .body(axum::body::Body::from(req))
                .unwrap(),
        )
        .await
        .unwrap();
    let cc = response.headers()["cache-control"].to_str().unwrap();
    let max_age: u64 = cc
        .split(", ")
        .find_map(|item| item.strip_prefix("max-age="))
        .unwrap()
        .parse()
        .unwrap();
    assert!(max_age <= 10, "cache outlives source: {cc}");
}

#[test]
fn batched_live_responses_preserve_requested_status_and_source_window() {
    use der::Decode;
    use x509_ocsp::builder::OcspResponseBuilder;
    use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, SingleResponse};
    let now = current_time();
    let time = |t| {
        x509_ocsp::OcspGeneralizedTime(
            der::asn1::GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(t))
                .unwrap(),
        )
    };
    let first = build_certid(1);
    let requested = build_certid(2);
    for status in [
        CertStatus::unknown(),
        CertStatus::revoked(x509_ocsp::RevokedInfo {
            revocation_time: time(now - 100),
            revocation_reason: None,
        }),
    ] {
        let mut key = hoike_sign::demo_ecdsa_p256_key();
        let response = OcspResponseBuilder::new(x509_ocsp::ResponderId::ByKey(
            der::asn1::OctetString::new(vec![1; 20]).unwrap(),
        ))
        .with_single_response(
            SingleResponse::new(first.clone(), CertStatus::good(), time(now - 30))
                .with_next_update(time(now + 60)),
        )
        .with_single_response(
            SingleResponse::new(requested.clone(), status, time(now - 30))
                .with_next_update(time(now + 60)),
        )
        .sign::<_, p256::ecdsa::DerSignature>(&mut key, None, time(now))
        .unwrap()
        .to_der()
        .unwrap();
        let requested_der = requested.to_der().unwrap();
        let source = hoike_sign::live::extract_status_for_cert(&response, &requested_der).unwrap();
        assert_eq!(source.this_update, now - 30);
        assert_eq!(source.next_update, now + 60);
        assert!(
            hoike_sign::live::extract_status_for_cert(
                &response,
                &build_certid(3).to_der().unwrap()
            )
            .is_err()
        );
        let fresh =
            hoike_sign::live::sign_live_response_with_window::<_, p256::ecdsa::DerSignature>(
                &requested_der,
                source.status,
                &[7; 16],
                b"KEY",
                &mut key,
                now,
                source.this_update,
                source.next_update,
                None,
            )
            .unwrap();
        let outer = OcspResponse::from_der(&fresh).unwrap();
        let basic =
            BasicOcspResponse::from_der(outer.response_bytes.unwrap().response.as_bytes()).unwrap();
        let single = &basic.tbs_response_data.responses[0];
        assert_eq!(single.cert_id, requested);
        assert_eq!(single.cert_status, status);
        assert_eq!(single.this_update, time(now - 30));
        assert_eq!(single.next_update, Some(time(now + 60)));
        assert_eq!(basic.nonce().unwrap().0.as_bytes(), &[7; 16]);
        use signature::Verifier;
        let signature =
            p256::ecdsa::DerSignature::from_bytes(basic.signature.as_bytes().unwrap()).unwrap();
        key.verifying_key()
            .verify(&basic.tbs_response_data.to_der().unwrap(), &signature)
            .unwrap();
    }
}

#[test]
fn live_signing_rejects_stale_or_future_source() {
    let now = current_time();
    for (this, next) in [(now - 30, now), (now + 1, now + 60)] {
        assert!(
            hoike_sign::live::sign_live_response_with_window::<_, p256::ecdsa::DerSignature>(
                &build_certid(2).to_der().unwrap(),
                hoike_sign::LiveCertStatus::Good,
                &[7; 16],
                b"KEY",
                &mut hoike_sign::demo_ecdsa_p256_key(),
                now,
                this,
                next,
                None
            )
            .is_err()
        );
    }
}

fn synthetic_issued_certificate(
    subject: &p256::ecdsa::SigningKey,
    issuer: &p256::ecdsa::SigningKey,
    ca: bool,
) -> Vec<u8> {
    use der::Decode;
    use signature::Signer;
    let mut cert =
        x509_cert::Certificate::from_der(&hoike_sign::generate_seal_cert(subject).unwrap())
            .unwrap();
    let issuer_cert =
        x509_cert::Certificate::from_der(&hoike_sign::generate_seal_cert(issuer).unwrap()).unwrap();
    cert.tbs_certificate.issuer = issuer_cert.tbs_certificate.subject;
    // CMS's X.509 codec emits UTCTime for years before 2050. Sign the same
    // canonical representation that will be embedded in SignedData.
    let validity = &mut cert.tbs_certificate.validity;
    validity.not_before = x509_cert::time::Time::UtcTime(
        der::asn1::UtcTime::from_unix_duration(validity.not_before.to_unix_duration()).unwrap(),
    );
    validity.not_after = x509_cert::time::Time::UtcTime(
        der::asn1::UtcTime::from_unix_duration(validity.not_after.to_unix_duration()).unwrap(),
    );
    if ca {
        cert.tbs_certificate.extensions = Some(vec![x509_cert::ext::Extension {
            extn_id: const_oid::ObjectIdentifier::new_unwrap("2.5.29.19"),
            critical: true,
            extn_value: der::asn1::OctetString::new(vec![0x30, 0x03, 0x01, 0x01, 0xff]).unwrap(),
        }]);
    }
    let signature: p256::ecdsa::DerSignature = issuer.sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = der::asn1::BitString::from_bytes(signature.as_bytes()).unwrap();
    {
        use signature::Verifier;
        issuer
            .verifying_key()
            .verify(&cert.tbs_certificate.to_der().unwrap(), &signature)
            .unwrap();
    }
    cert.to_der().unwrap()
}

#[test]
fn responder_load_enforces_cms_integrity_anchor_and_scope_authorization() {
    let root = p256::ecdsa::SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let leaf = p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let wrong = p256::ecdsa::SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
    let anchor = synthetic_issued_certificate(&root, &root, true);
    let cert = synthetic_issued_certificate(&leaf, &root, false);
    let wrong_anchor = synthetic_issued_certificate(&wrong, &wrong, true);
    for case in [
        "valid",
        "invalid-signature",
        "wrong-anchor",
        "missing-anchor",
        "wrong-scope",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let parsed =
            ahu::Bundle::from_bytes(&build_test_bundle_with_real_certids(&[(42, b"R")])).unwrap();
        let mut builder = BundleBuilder::new(parsed.manifest.clone());
        builder.add_entry(parsed.index[0].entry_key, b"R".to_vec());
        let key = hoike_sign::SealKey::EcdsaP256(if case == "invalid-signature" {
            wrong.clone()
        } else {
            leaf.clone()
        });
        let bytes = builder
            .build(|m| {
                hoike_sign::create_cms_seal(m, &key, &cert)
                    .map_err(|e| ahu::AhuError::Write(e.to_string()))
            })
            .unwrap();
        std::fs::write(dir.path().join("test.ahu"), bytes).unwrap();
        if case != "missing-anchor" {
            std::fs::write(
                dir.path().join("anchor.der"),
                if case == "wrong-anchor" {
                    &wrong_anchor
                } else {
                    &anchor
                },
            )
            .unwrap();
        }
        let conf = format!(
            "[server]\nmode='edge'\n[storage]\nbundle_dir='{0}'\nstate_db='{0}/state'\nseal_trust_anchors=['{0}/anchor.der']\n[[storage.seal_authorizations]]\nproducer_id='{1}'\nissuer_key_hash='{2}'\nsigner_sha256='{3}'\n",
            dir.path().display(),
            if case == "wrong-scope" {
                "other-producer"
            } else {
                "e2e-test"
            },
            hex::encode(Sha256::digest(b"test-ca-public-key")),
            hex::encode(Sha256::digest(&cert))
        );
        let cfg: hoike_core::Config = toml::from_str(&conf).unwrap();
        let result = hoike_core::ResponderState::load(cfg);
        assert_eq!(
            result.is_ok(),
            case == "valid",
            "case {case}: {}",
            result.err().map(|e| e.to_string()).unwrap_or_default()
        );
    }
}

#[tokio::test]
async fn live_signers_are_selected_by_ca_and_reload_matching_material() {
    check_live_signers_by_ca(false).await;
}

#[tokio::test]
async fn default_bundle_paths_keep_ca_scope_and_live_key_together() {
    check_live_signers_by_ca(true).await;
}

async fn check_live_signers_by_ca(default_paths: bool) {
    use der::Decode;
    use signature::Verifier;
    use tower::ServiceExt;
    let dir = tempfile::tempdir().unwrap();
    let mut blocks = String::new();
    let mut identities = Vec::new();
    for n in 1..=2u8 {
        let key = p256::ecdsa::SigningKey::from_bytes((&[n; 32]).into()).unwrap();
        let name = format!("CA-{n}").into_bytes();
        let public = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let cid = build_certid_for_ca(42, &name, &public);
        let source = hoike_sign::live::sign_live_response::<_, p256::ecdsa::DerSignature>(
            &cid.to_der().unwrap(),
            hoike_sign::LiveCertStatus::Good,
            &[1; 16],
            &public,
            &mut key.clone(),
            current_time() - 1,
            300,
            None,
        )
        .unwrap();
        std::fs::write(
            dir.path().join(format!("ca-{n}.ahu")),
            build_bundle_for_ca(&name, &public, &[(42, &source)]),
        )
        .unwrap();
        let bundle_setting = if default_paths {
            String::new()
        } else {
            format!("bundle_file='{}/ca-{n}.ahu'\n", dir.path().display())
        };
        blocks.push_str(&format!("\n[[ca]]\nlabel='ca-{n}'\n{bundle_setting}nonce_policy='live'\n[ca.source]\ntype='crl'\npath='{0}/unused.crl'\n[ca.signing_key]\ntype='demo'\n",dir.path().display()));
        identities.push((key, public, cid));
    }
    let config: hoike_core::Config = toml::from_str(&format!(
        "[server]\nmode='combined'\n[storage]\nbundle_dir='{0}'\nstate_db='{0}/state'\n{blocks}",
        dir.path().display()
    ))
    .unwrap();
    let state = hoike_core::ResponderState::load(config.clone()).unwrap();
    let mut app_state = hoike_server::AppState::new(state, config);
    for (i, (key, public, _)) in identities.iter().enumerate() {
        app_state = app_state.with_live_signer_for(
            &format!("ca-{}", i + 1),
            hoike_server::LiveSignerState {
                signer: tokio::sync::Mutex::new(key.clone()),
                responder_key_bytes: public.clone(),
                validity_secs: 3600,
                responder_cert_der: None,
            },
        );
    }
    let app = hoike_server::build_router(app_state);
    for (i, (key, _, cid)) in identities.iter().enumerate() {
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::post("/")
                    .body(axum::body::Body::from(build_ocsp_request_with_nonce(
                        cid, &[7; 16],
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let outer = x509_ocsp::OcspResponse::from_der(&bytes).unwrap();
        let basic = x509_ocsp::BasicOcspResponse::from_der(
            outer.response_bytes.unwrap().response.as_bytes(),
        )
        .unwrap();
        let sig =
            p256::ecdsa::DerSignature::from_bytes(basic.signature.as_bytes().unwrap()).unwrap();
        let tbs = basic.tbs_response_data.to_der().unwrap();
        key.verifying_key().verify(&tbs, &sig).unwrap();
        assert!(
            identities[1 - i]
                .0
                .verifying_key()
                .verify(&tbs, &sig)
                .is_err()
        );
        assert_eq!(&basic.tbs_response_data.responses[0].cert_id, cid);
    }
}

#[tokio::test]
async fn configured_live_material_uses_raw_responder_key_and_refreshes_pair() {
    use der::Decode;
    use p256::pkcs8::EncodePrivateKey;
    let dir = tempfile::tempdir().unwrap();
    let config:hoike_core::config::CaConfig=toml::from_str(&format!("label='test'\nresponder_cert='{0}/cert.der'\n[signing_key]\ntype='file'\npath='{0}/key.der'\n",dir.path().display())).unwrap();
    let mut old_public = Vec::new();
    for seed in [4u8, 5] {
        let key = p256::ecdsa::SigningKey::from_bytes((&[seed; 32]).into()).unwrap();
        let cert_der = hoike_sign::generate_seal_cert(&key).unwrap();
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();
        std::fs::write(
            dir.path().join("key.der"),
            key.to_pkcs8_der().unwrap().as_bytes(),
        )
        .unwrap();
        if seed == 5 {
            assert!(
                hoike_server::LiveSignerState::from_config(&config).is_err(),
                "mixed old cert/new key must fail"
            );
        }
        std::fs::write(dir.path().join("cert.der"), &cert_der).unwrap();
        let loaded = hoike_server::LiveSignerState::from_config(&config).unwrap();
        let public = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        assert_eq!(loaded.responder_key_bytes, public);
        assert_ne!(loaded.responder_key_bytes, old_public);
        assert_eq!(
            loaded.signer.lock().await.verifying_key(),
            key.verifying_key()
        );
        old_public = public.to_vec();
    }
}

#[test]
fn missing_configured_default_bundle_never_uses_another_cas_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("other.ahu"),
        build_test_bundle_with_real_certids(&[(42, b"other-ca")]),
    )
    .unwrap();
    let config:hoike_core::Config=toml::from_str(&format!("[server]\nmode='edge'\n[storage]\nbundle_dir='{0}'\nstate_db='{0}/state'\n[[ca]]\nlabel='missing'\n",dir.path().display())).unwrap();
    assert!(hoike_core::ResponderState::load(config).is_err());
}
