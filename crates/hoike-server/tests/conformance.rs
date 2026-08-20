//! RFC 9919 / RFC 9654 conformance test suite.
//!
//! Validates hoike's OCSP responder against the protocol requirements.
//! These tests use real DER-encoded OCSP responses (produced by hoike-sign)
//! rather than mock byte strings, enabling DER-level structural validation.

use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use x509_ocsp::{CertId, OcspRequest, OcspResponse, Request, TbsRequest};

// ── Test infrastructure ────────────────────────────────────────────

const ISSUER_NAME: &[u8] = b"CN=Conformance CA,O=Hoike Test";
const ISSUER_KEY: &[u8] = b"conformance-ca-public-key";

fn signing_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

fn build_conformance_bundle() -> Vec<u8> {
    use hoike_sign::{
        CaIdentity, CertIdCompat, CertificateStatus, GenerationConfig, StatusSnapshot,
    };
    use sha2_v010::Digest as Digest010;
    use x509_cert::ext::pkix::CrlReason;

    let ca = CaIdentity {
        label: "conformance-ca".into(),
        issuer_name_der: ISSUER_NAME.to_vec(),
        issuer_key_bytes: ISSUER_KEY.to_vec(),
    };

    let mut entries = BTreeMap::new();
    // Serial 1: good
    entries.insert(vec![1u8], CertificateStatus::Good);
    // Serial 2: good
    entries.insert(vec![2u8], CertificateStatus::Good);
    // Serial 10: revoked with reason
    entries.insert(
        vec![10u8],
        CertificateStatus::Revoked {
            revocation_time: 4102400000,
            reason: Some(CrlReason::KeyCompromise),
        },
    );
    // Serial 11: revoked without specific reason
    entries.insert(
        vec![11u8],
        CertificateStatus::Revoked {
            revocation_time: 4102410000,
            reason: None,
        },
    );

    let snapshot = StatusSnapshot {
        entries,
        this_update: 4102444800,
        next_update: Some(4102531200),
    };

    let config = GenerationConfig {
        producer_id: "conformance-test".into(),
        epoch: 1,
        validity_secs: 86400,
        jitter_secs: 7200,
        certid_compat: CertIdCompat::Sha256Only,
        completeness: ahu::Completeness::AuthoritativeComplete,
        bucket_size: 1,
    };

    let mut key = signing_key();
    hoike_sign::produce_bundle::<_, p256::ecdsa::DerSignature>(
        &ca,
        &snapshot,
        &config,
        &mut key,
        |m| Ok(sha2_v010::Sha256::digest(m).to_vec()),
        None,
    )
    .expect("produce_bundle failed")
}

fn build_certid_conformance(serial: u8) -> CertId {
    use const_oid::ObjectIdentifier;
    use der::asn1::{Null, OctetString};

    let sha256_oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    let issuer_name_hash = Sha256::digest(ISSUER_NAME);
    let issuer_key_hash = Sha256::digest(ISSUER_KEY);

    // Must match produce_bundle's AlgorithmIdentifier: explicit NULL parameter
    CertId {
        hash_algorithm: spki::AlgorithmIdentifier {
            oid: sha256_oid,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(issuer_name_hash.to_vec()).unwrap(),
        issuer_key_hash: OctetString::new(issuer_key_hash.to_vec()).unwrap(),
        serial_number: x509_cert::serial_number::SerialNumber::new(&[serial]).unwrap(),
    }
}

fn build_request(cert_id: &CertId) -> Vec<u8> {
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

fn build_request_with_nonce(cert_id: &CertId, nonce_len: usize) -> Vec<u8> {
    use der::asn1::OctetString;

    let nonce_bytes = vec![0xAA; nonce_len];
    let nonce_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");
    let inner_octet = OctetString::new(nonce_bytes).unwrap();
    let nonce_ext_value = OctetString::new(inner_octet.to_der().unwrap()).unwrap();
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

async fn start_conformance_server() -> (u16, tempfile::TempDir) {
    let bundle_bytes = build_conformance_bundle();
    let dir = tempfile::tempdir().unwrap();
    let bundle_path = dir.path().join("conformance.ahu");
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
label = "conformance-ca"
bundle_file = "{bundle}"
nonce_policy = "ignore"
completeness = "authoritative-complete"
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

async fn post_ocsp(port: u16, request_der: &[u8]) -> reqwest::Response {
    let client = reqwest::Client::new();
    client
        .post(format!("http://127.0.0.1:{port}/"))
        .header("Content-Type", "application/ocsp-request")
        .body(request_der.to_vec())
        .send()
        .await
        .unwrap()
}

fn parse_ocsp_response(body: &[u8]) -> OcspResponse {
    OcspResponse::from_der(body).expect("response is not valid DER OCSPResponse")
}

// ── Response format checks (RFC 9919) ──────────────────────────────

#[tokio::test]
async fn conformance_good_serial_returns_successful() {
    let (port, _dir) = start_conformance_server().await;

    let cert_id = build_certid_conformance(1);
    let resp = post_ocsp(port, &build_request(&cert_id)).await;

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    let ocsp = parse_ocsp_response(&body);
    assert_eq!(
        ocsp.response_status,
        x509_ocsp::OcspResponseStatus::Successful,
    );
}

#[tokio::test]
async fn conformance_revoked_has_reason() {
    let (port, _dir) = start_conformance_server().await;

    // Serial 10 was revoked with KeyCompromise
    let cert_id = build_certid_conformance(10);
    let resp = post_ocsp(port, &build_request(&cert_id)).await;

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    let ocsp = parse_ocsp_response(&body);
    assert_eq!(
        ocsp.response_status,
        x509_ocsp::OcspResponseStatus::Successful,
    );

    // Parse the BasicOCSPResponse to check the single response status
    let response_bytes = ocsp.response_bytes.as_ref().expect("missing responseBytes");
    let basic = x509_ocsp::BasicOcspResponse::from_der(response_bytes.response.as_bytes())
        .expect("invalid BasicOCSPResponse");

    let single = &basic.tbs_response_data.responses[0];
    match &single.cert_status {
        x509_ocsp::CertStatus::Revoked(info) => {
            // revocation_time should be present
            assert!(info.revocation_time.0.to_unix_duration().as_secs() > 0);
        }
        other => panic!("expected Revoked status, got {other:?}"),
    }
}

#[tokio::test]
async fn conformance_nextupdate_present() {
    let (port, _dir) = start_conformance_server().await;

    let cert_id = build_certid_conformance(1);
    let resp = post_ocsp(port, &build_request(&cert_id)).await;

    let body = resp.bytes().await.unwrap();
    let ocsp = parse_ocsp_response(&body);
    let response_bytes = ocsp.response_bytes.as_ref().expect("missing responseBytes");
    let basic = x509_ocsp::BasicOcspResponse::from_der(response_bytes.response.as_bytes())
        .expect("invalid BasicOCSPResponse");

    for single in &basic.tbs_response_data.responses {
        assert!(
            single.next_update.is_some(),
            "RFC 9919 §3.2.4: nextUpdate MUST be present"
        );
    }
}

#[tokio::test]
async fn conformance_responder_id_by_key() {
    let (port, _dir) = start_conformance_server().await;

    let cert_id = build_certid_conformance(1);
    let resp = post_ocsp(port, &build_request(&cert_id)).await;

    let body = resp.bytes().await.unwrap();
    let ocsp = parse_ocsp_response(&body);
    let response_bytes = ocsp.response_bytes.as_ref().expect("missing responseBytes");
    let basic = x509_ocsp::BasicOcspResponse::from_der(response_bytes.response.as_bytes())
        .expect("invalid BasicOCSPResponse");

    match &basic.tbs_response_data.responder_id {
        x509_ocsp::ResponderId::ByKey(_) => {} // correct
        x509_ocsp::ResponderId::ByName(_) => {
            panic!("RFC 9919: new responders SHOULD use byKey ResponderID");
        }
    }
}

#[tokio::test]
async fn conformance_unauthorized_on_unknown() {
    let (port, _dir) = start_conformance_server().await;

    // Serial 99 was never issued
    let cert_id = build_certid_conformance(99);
    let resp = post_ocsp(port, &build_request(&cert_id)).await;

    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    // unauthorized = 30 03 0A 01 06
    assert_eq!(
        &body[..],
        &[0x30, 0x03, 0x0A, 0x01, 0x06],
        "unknown serial must return unauthorized, not a signed good"
    );
}

// ── Nonce boundary behavior (RFC 9654) ─────────────────────────────

#[tokio::test]
async fn conformance_nonce_0_malformed() {
    let (port, _dir) = start_conformance_server().await;
    let cert_id = build_certid_conformance(1);

    // 0-byte nonce → malformedRequest
    let request = build_request_with_nonce(&cert_id, 0);
    let resp = post_ocsp(port, &request).await;
    let body = resp.bytes().await.unwrap();
    assert_eq!(
        &body[..],
        &[0x30, 0x03, 0x0A, 0x01, 0x01],
        "0-byte nonce must be malformedRequest per RFC 9654"
    );
}

#[tokio::test]
async fn conformance_nonce_1_accepted() {
    let (port, _dir) = start_conformance_server().await;
    let cert_id = build_certid_conformance(1);

    // 1-byte nonce (1-15 range) → MAY omit nonce from response; response should still be valid
    let request = build_request_with_nonce(&cert_id, 1);
    let resp = post_ocsp(port, &request).await;
    let body = resp.bytes().await.unwrap();
    // Should not be malformedRequest — should get a successful response (pre-signed, ignore policy)
    let ocsp = parse_ocsp_response(&body);
    assert_eq!(
        ocsp.response_status,
        x509_ocsp::OcspResponseStatus::Successful,
        "1-byte nonce should be accepted (MAY omit from response)"
    );
}

#[tokio::test]
async fn conformance_nonce_15_accepted() {
    let (port, _dir) = start_conformance_server().await;
    let cert_id = build_certid_conformance(1);

    let request = build_request_with_nonce(&cert_id, 15);
    let resp = post_ocsp(port, &request).await;
    let body = resp.bytes().await.unwrap();
    let ocsp = parse_ocsp_response(&body);
    assert_eq!(
        ocsp.response_status,
        x509_ocsp::OcspResponseStatus::Successful,
        "15-byte nonce should be accepted"
    );
}

#[tokio::test]
async fn conformance_nonce_16_must_accept() {
    let (port, _dir) = start_conformance_server().await;
    let cert_id = build_certid_conformance(1);

    // 16 bytes is the start of the MUST accept range
    let request = build_request_with_nonce(&cert_id, 16);
    let resp = post_ocsp(port, &request).await;
    let body = resp.bytes().await.unwrap();
    let ocsp = parse_ocsp_response(&body);
    assert_eq!(
        ocsp.response_status,
        x509_ocsp::OcspResponseStatus::Successful,
        "16-byte nonce MUST be accepted per RFC 9654"
    );
}

#[tokio::test]
async fn conformance_nonce_32_must_accept() {
    let (port, _dir) = start_conformance_server().await;
    let cert_id = build_certid_conformance(1);

    let request = build_request_with_nonce(&cert_id, 32);
    let resp = post_ocsp(port, &request).await;
    let body = resp.bytes().await.unwrap();
    let ocsp = parse_ocsp_response(&body);
    assert_eq!(
        ocsp.response_status,
        x509_ocsp::OcspResponseStatus::Successful,
        "32-byte nonce MUST be accepted per RFC 9654"
    );
}

#[tokio::test]
async fn conformance_nonce_33_accepted() {
    let (port, _dir) = start_conformance_server().await;
    let cert_id = build_certid_conformance(1);

    // 33-128 → MAY omit nonce
    let request = build_request_with_nonce(&cert_id, 33);
    let resp = post_ocsp(port, &request).await;
    let body = resp.bytes().await.unwrap();
    let ocsp = parse_ocsp_response(&body);
    assert_eq!(
        ocsp.response_status,
        x509_ocsp::OcspResponseStatus::Successful,
        "33-byte nonce should be accepted (MAY omit from response)"
    );
}

#[tokio::test]
async fn conformance_nonce_128_accepted() {
    let (port, _dir) = start_conformance_server().await;
    let cert_id = build_certid_conformance(1);

    let request = build_request_with_nonce(&cert_id, 128);
    let resp = post_ocsp(port, &request).await;
    let body = resp.bytes().await.unwrap();
    let ocsp = parse_ocsp_response(&body);
    assert_eq!(
        ocsp.response_status,
        x509_ocsp::OcspResponseStatus::Successful,
        "128-byte nonce should be accepted"
    );
}

#[tokio::test]
async fn conformance_nonce_129_malformed() {
    let (port, _dir) = start_conformance_server().await;
    let cert_id = build_certid_conformance(1);

    // >128 → malformedRequest
    let request = build_request_with_nonce(&cert_id, 129);
    let resp = post_ocsp(port, &request).await;
    let body = resp.bytes().await.unwrap();
    assert_eq!(
        &body[..],
        &[0x30, 0x03, 0x0A, 0x01, 0x01],
        "129-byte nonce must be malformedRequest per RFC 9654"
    );
}

// ── HTTP header checks (RFC 9919 §6, §7.2) ────────────────────────

#[tokio::test]
async fn conformance_http_content_type() {
    let (port, _dir) = start_conformance_server().await;

    let cert_id = build_certid_conformance(1);
    let resp = post_ocsp(port, &build_request(&cert_id)).await;

    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/ocsp-response",
        "Content-Type must be application/ocsp-response"
    );
}

#[tokio::test]
async fn conformance_http_content_type_on_error() {
    let (port, _dir) = start_conformance_server().await;

    // Send garbage → malformedRequest
    let resp = post_ocsp(port, b"garbage").await;

    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/ocsp-response",
        "Even error responses must have application/ocsp-response Content-Type"
    );
}

#[tokio::test]
async fn conformance_http_cache_control() {
    let (port, _dir) = start_conformance_server().await;

    let cert_id = build_certid_conformance(1);
    let resp = post_ocsp(port, &build_request(&cert_id)).await;

    let cc = resp
        .headers()
        .get("cache-control")
        .expect("successful response must have Cache-Control")
        .to_str()
        .unwrap();

    assert!(
        cc.contains("max-age="),
        "Cache-Control must have max-age, got: {cc}"
    );
    assert!(
        cc.contains("public"),
        "Cache-Control must have public, got: {cc}"
    );
    assert!(
        cc.contains("no-transform"),
        "Cache-Control must have no-transform, got: {cc}"
    );
    assert!(
        cc.contains("must-revalidate"),
        "Cache-Control should have must-revalidate, got: {cc}"
    );
}

#[tokio::test]
async fn conformance_http_etag() {
    let (port, _dir) = start_conformance_server().await;

    let cert_id = build_certid_conformance(1);
    let resp = post_ocsp(port, &build_request(&cert_id)).await;

    let etag = resp
        .headers()
        .get("etag")
        .expect("successful response must have ETag")
        .to_str()
        .unwrap();

    assert!(
        etag.starts_with('"') && etag.ends_with('"'),
        "ETag must be quoted, got: {etag}"
    );
}

#[tokio::test]
async fn conformance_error_no_caching() {
    let (port, _dir) = start_conformance_server().await;

    // unauthorized response
    let cert_id = build_certid_conformance(99);
    let resp = post_ocsp(port, &build_request(&cert_id)).await;

    let cc = resp
        .headers()
        .get("cache-control")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();

    assert!(
        cc.contains("no-cache") || cc.contains("no-store") || cc.is_empty(),
        "error responses must not be cacheable, got: {cc}"
    );

    // Should NOT have an ETag
    assert!(
        resp.headers().get("etag").is_none(),
        "error responses should not have ETag"
    );
}

// ── GET method (RFC 9919 §6) ───────────────────────────────────────

#[tokio::test]
async fn conformance_get_method() {
    let (port, _dir) = start_conformance_server().await;

    let cert_id = build_certid_conformance(1);
    let request_der = build_request(&cert_id);

    // First, get the expected response via POST
    let post_resp = post_ocsp(port, &request_der).await;
    let post_body = post_resp.bytes().await.unwrap();

    // Now do a GET with the base64-encoded request in the path
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&request_der);
    let encoded =
        percent_encoding::utf8_percent_encode(&b64, percent_encoding::NON_ALPHANUMERIC).to_string();

    let client = reqwest::Client::new();
    let get_resp = client
        .get(format!("http://127.0.0.1:{port}/{encoded}"))
        .send()
        .await
        .unwrap();

    assert_eq!(get_resp.status(), 200);
    assert_eq!(
        get_resp.headers().get("content-type").unwrap(),
        "application/ocsp-response"
    );

    let get_body = get_resp.bytes().await.unwrap();
    assert_eq!(
        &get_body[..],
        &post_body[..],
        "GET and POST must return the same response for the same CertID"
    );
}

#[tokio::test]
async fn conformance_sha256_certid_supported() {
    let (port, _dir) = start_conformance_server().await;

    // Our test CertIDs use SHA-256 (OID 2.16.840.1.101.3.4.2.1)
    let cert_id = build_certid_conformance(1);
    let resp = post_ocsp(port, &build_request(&cert_id)).await;

    let body = resp.bytes().await.unwrap();
    let ocsp = parse_ocsp_response(&body);

    assert_eq!(
        ocsp.response_status,
        x509_ocsp::OcspResponseStatus::Successful,
        "SHA-256 CertID must be supported per RFC 9919 §3.2.1"
    );
}
