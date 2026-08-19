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
        created_at: 4102444800,
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
            produced_at: 4102444800,
            this_update_min: 4102444800,
            next_update_min: 4102531200,
            next_update_max: 4102538400,
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
        created_at: 4102444800,
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
            produced_at: 4102444800,
            this_update_min: 4102444800,
            next_update_min: 4102531200,
            next_update_max: 4102538400,
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
    let state = hoike_core::ResponderState::load(config).unwrap();
    let app_state = hoike_server::AppState::new(state);
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
    let state = hoike_core::ResponderState::load(config).unwrap();
    let app_state = hoike_server::AppState::new(state);
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
        msg.contains("live") && msg.contains("not yet implemented"),
        "expected live/not-implemented error, got: {msg}"
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
