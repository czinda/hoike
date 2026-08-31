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
        this_update: 4102444800,
        next_update: Some(4102531200),
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
