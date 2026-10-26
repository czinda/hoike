//! Per-CA forwarding trust-root tests (October audit F10, design S8).
//!
//! Each test starts a real loopback TLS listener backed by a fresh synthetic
//! P-256 CA/leaf chain with a `localhost` SAN, then proves that the forwarding
//! client built for a configured `forward_ca` trusts exactly that CA's root —
//! and no other CA's root and no mismatched hostname. No invalid-certificate
//! or invalid-hostname acceptance is ever enabled. Gated on the `tls` feature
//! because the upstream listeners reuse the production server-side TLS
//! configuration path (`hoike_server::tls::server_config`).
#![cfg(feature = "tls")]

use axum::http::StatusCode;
use axum::routing::{get, post};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use signature::Signer;
use tower::ServiceExt;

fn current_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn pem_wrap(tag: &str, der_bytes: &[u8]) -> String {
    use base64::Engine as _;
    format!(
        "-----BEGIN {tag}-----\n{}\n-----END {tag}-----\n",
        base64::engine::general_purpose::STANDARD.encode(der_bytes)
    )
}

/// Issue a fresh certificate for `subject_key` under `issuer_key`, following
/// the repository's ephemeral-key test style: start from hoike-sign's
/// self-signed template, re-bind issuer/validity, add the requested
/// extensions, and sign the TBS with the issuer key. The issuer's own
/// certificate is regenerated from the same key so subject/issuer DN matching
/// holds for path building.
fn issue(
    subject_key: &p256::ecdsa::SigningKey,
    issuer_key: &p256::ecdsa::SigningKey,
    is_ca: bool,
    dns_san: Option<&str>,
) -> Vec<u8> {
    let mut cert =
        x509_cert::Certificate::from_der(&hoike_sign::generate_seal_cert(subject_key).unwrap())
            .unwrap();
    let issuer_cert =
        x509_cert::Certificate::from_der(&hoike_sign::generate_seal_cert(issuer_key).unwrap())
            .unwrap();
    cert.tbs_certificate.issuer = issuer_cert.tbs_certificate.subject;
    let now = current_time();
    let time = |seconds| {
        x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_unix_duration(std::time::Duration::from_secs(seconds))
                .unwrap(),
        )
    };
    cert.tbs_certificate.validity = x509_cert::time::Validity {
        not_before: time(now - 300),
        not_after: time(now + 86400),
    };
    let mut exts = Vec::new();
    if is_ca {
        // basicConstraints CA:TRUE, critical (DER).
        exts.push(x509_cert::ext::Extension {
            extn_id: const_oid::ObjectIdentifier::new_unwrap("2.5.29.19"),
            critical: true,
            extn_value: der::asn1::OctetString::new(vec![0x30, 0x03, 0x01, 0x01, 0xff]).unwrap(),
        });
    } else {
        // extendedKeyUsage: serverAuth — a real TLS server certificate; some
        // verifiers require it even though rustls's webpki does not.
        let eku = vec![const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1")];
        exts.push(x509_cert::ext::Extension {
            extn_id: const_oid::ObjectIdentifier::new_unwrap("2.5.29.37"),
            critical: false,
            extn_value: der::asn1::OctetString::new(eku.to_der().unwrap()).unwrap(),
        });
    }
    if let Some(dns) = dns_san {
        // subjectAltName dNSName — SEQUENCE OF GeneralName with one dNSName
        // ([2] IMPLICIT IA5String). rustls requires a SAN for hostname checks;
        // there is no CN fallback.
        let names = vec![x509_cert::ext::pkix::name::GeneralName::DnsName(
            der::asn1::Ia5String::new(dns).unwrap(),
        )];
        exts.push(x509_cert::ext::Extension {
            extn_id: const_oid::ObjectIdentifier::new_unwrap("2.5.29.17"),
            critical: false,
            extn_value: der::asn1::OctetString::new(names.to_der().unwrap()).unwrap(),
        });
    }
    cert.tbs_certificate.extensions = Some(exts);
    let signature: p256::ecdsa::DerSignature =
        issuer_key.sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = der::asn1::BitString::from_bytes(signature.as_bytes()).unwrap();
    cert.to_der().unwrap()
}

struct SyntheticCa {
    key: p256::ecdsa::SigningKey,
    cert_der: Vec<u8>,
}

fn synthetic_ca(seed: u8) -> SyntheticCa {
    let key = p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap();
    let cert_der = issue(&key, &key, true, None);
    SyntheticCa { key, cert_der }
}

fn synthetic_leaf(ca: &SyntheticCa, seed: u8, dns: &str) -> (p256::ecdsa::SigningKey, Vec<u8>) {
    let key = p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap();
    let cert_der = issue(&key, &ca.key, false, Some(dns));
    (key, cert_der)
}

/// A loopback TLS upstream bound before the returned handle, so the URL is
/// live by construction (no bind race).
struct Upstream {
    url: String,
    _server: tokio::task::JoinHandle<()>,
}

async fn spawn_tls_upstream(
    leaf_cert_der: Vec<u8>,
    leaf_key: p256::ecdsa::SigningKey,
    router: axum::Router,
) -> Upstream {
    use p256::pkcs8::EncodePrivateKey;
    // server_config reads the files synchronously; the tempdir is dropped
    // before the server task runs, so nothing depends on it afterwards.
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, pem_wrap("CERTIFICATE", &leaf_cert_der)).unwrap();
    std::fs::write(
        &key_path,
        pem_wrap("PRIVATE KEY", leaf_key.to_pkcs8_der().unwrap().as_bytes()),
    )
    .unwrap();
    let config = hoike_server::tls::server_config(&cert_path, &key_path, None).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let rustls_config =
        axum_server::tls_rustls::RustlsConfig::from_config(std::sync::Arc::new(config));
    let server = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, rustls_config)
            .serve(router.into_make_service())
            .await
            .unwrap();
    });
    Upstream {
        url: format!("https://localhost:{port}/"),
        _server: server,
    }
}

fn ok_router() -> axum::Router {
    axum::Router::new().route("/", get(|| async { "ok" }).post(|| async { "ok" }))
}

/// Write a minimal configuration with one `[[ca]]` entry per tuple
/// (label, forward_to, optional forward_ca path). `demo_admission` mirrors
/// the e2e transport fixtures: mocked bundle seals are only loadable under
/// explicit demo admission.
fn write_config(
    dir: &std::path::Path,
    cas: &[(&str, &str, Option<std::path::PathBuf>)],
    demo_admission: bool,
) -> hoike_core::Config {
    let mut toml_text = format!(
        "[server]\nmode = 'edge'\n[storage]\nbundle_dir = '{}'\nstate_db = '{}/state'\n",
        dir.display(),
        dir.display()
    );
    if demo_admission {
        toml_text.push_str("allow_unauthenticated_bundles = true\n");
    }
    for (label, forward_to, forward_ca) in cas {
        toml_text.push_str(&format!(
            "\n[[ca]]\nlabel = '{label}'\nnonce_policy = 'forward'\nforward_to = '{forward_to}'\n"
        ));
        if let Some(path) = forward_ca {
            toml_text.push_str(&format!("forward_ca = '{}'\n", path.display()));
        }
    }
    let path = dir.join("hoike.toml");
    std::fs::write(&path, toml_text).unwrap();
    hoike_core::Config::from_file(&path).unwrap()
}

fn write_ca_pem(dir: &std::path::Path, name: &str, ca: &SyntheticCa) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, pem_wrap("CERTIFICATE", &ca.cert_der)).unwrap();
    path
}

#[tokio::test]
async fn configured_private_root_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let ca_a = synthetic_ca(1);
    let (leaf_key, leaf_cert) = synthetic_leaf(&ca_a, 2, "localhost");
    let upstream = spawn_tls_upstream(leaf_cert, leaf_key, ok_router()).await;
    let ca_pem = write_ca_pem(dir.path(), "ca-a.pem", &ca_a);

    let config = write_config(dir.path(), &[("a", &upstream.url, Some(ca_pem))], false);
    let clients = hoike_server::build_forward_clients(&config).unwrap();
    let client_a = clients.get("a").expect("forwarding CA has a client");
    assert!(client_a.get(&upstream.url).send().await.is_ok());
}

#[tokio::test]
async fn private_roots_are_isolated_per_ca() {
    let dir = tempfile::tempdir().unwrap();
    let ca_a = synthetic_ca(1);
    let ca_b = synthetic_ca(3);
    let (leaf_key_a, leaf_cert_a) = synthetic_leaf(&ca_a, 2, "localhost");
    let (leaf_key_b, leaf_cert_b) = synthetic_leaf(&ca_b, 4, "localhost");
    let upstream_a = spawn_tls_upstream(leaf_cert_a, leaf_key_a, ok_router()).await;
    let upstream_b = spawn_tls_upstream(leaf_cert_b, leaf_key_b, ok_router()).await;
    let ca_pem_a = write_ca_pem(dir.path(), "ca-a.pem", &ca_a);
    let ca_pem_b = write_ca_pem(dir.path(), "ca-b.pem", &ca_b);

    let config = write_config(
        dir.path(),
        &[
            ("a", &upstream_a.url, Some(ca_pem_a)),
            ("b", &upstream_b.url, Some(ca_pem_b)),
        ],
        false,
    );
    let clients = hoike_server::build_forward_clients(&config).unwrap();
    let client_a = clients.get("a").expect("CA a has a client");
    let client_b = clients.get("b").expect("CA b has a client");

    // Both upstreams share the hostname "localhost"; only the pinned root
    // distinguishes them. Each client validates only its own CA's chain.
    assert!(client_a.get(&upstream_a.url).send().await.is_ok());
    assert!(client_b.get(&upstream_b.url).send().await.is_ok());
    assert!(client_b.get(&upstream_a.url).send().await.is_err());
    assert!(client_a.get(&upstream_b.url).send().await.is_err());
}

#[tokio::test]
async fn wrong_hostname_and_wrong_root_reject() {
    let dir = tempfile::tempdir().unwrap();
    let ca_a = synthetic_ca(1);
    let ca_b = synthetic_ca(3);
    let (leaf_key_a, leaf_cert_a) = synthetic_leaf(&ca_a, 2, "localhost");
    // Signed by CA A (so the chain would validate) but with a SAN that does
    // not match the "localhost" URL — hostname checking must reject it.
    let (wrong_host_key, wrong_host_cert) = synthetic_leaf(&ca_a, 5, "other.example");
    let upstream_a = spawn_tls_upstream(leaf_cert_a, leaf_key_a, ok_router()).await;
    let wrong_host_upstream =
        spawn_tls_upstream(wrong_host_cert, wrong_host_key, ok_router()).await;
    let ca_pem_a = write_ca_pem(dir.path(), "ca-a.pem", &ca_a);
    let ca_pem_b = write_ca_pem(dir.path(), "ca-b.pem", &ca_b);

    let config = write_config(
        dir.path(),
        &[
            ("a", &upstream_a.url, Some(ca_pem_a)),
            ("b", &upstream_a.url, Some(ca_pem_b)),
        ],
        false,
    );
    let clients = hoike_server::build_forward_clients(&config).unwrap();
    let client_a = clients.get("a").expect("CA a has a client");
    let client_b = clients.get("b").expect("CA b has a client");

    assert!(client_a.get(&upstream_a.url).send().await.is_ok());
    // Wrong root: CA b's client does not trust CA A's chain.
    assert!(client_b.get(&upstream_a.url).send().await.is_err());
    // Wrong hostname: correct root, but the certificate names another host.
    assert!(client_a.get(&wrong_host_upstream.url).send().await.is_err());
}

#[test]
fn invalid_root_configuration_fails_startup() {
    let dir = tempfile::tempdir().unwrap();
    let ca_a = synthetic_ca(1);
    let ca_pem_a = write_ca_pem(dir.path(), "ca-a.pem", &ca_a);

    let https = "https://localhost:1/";
    let http = "http://localhost:1/";

    // Unreadable CA file.
    let config = write_config(
        dir.path(),
        &[("a", https, Some(dir.path().join("missing.pem")))],
        false,
    );
    let err = hoike_server::build_forward_clients(&config).unwrap_err();
    assert!(err.contains("forward_ca"), "got: {err}");

    // Present but empty (zero parseable certificates).
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, b"").unwrap();
    let config = write_config(dir.path(), &[("a", https, Some(empty.clone()))], false);
    let err = hoike_server::build_forward_clients(&config).unwrap_err();
    assert!(err.contains("no certificates"), "got: {err}");

    // Malformed PEM body.
    let garbage = dir.path().join("garbage.pem");
    std::fs::write(
        &garbage,
        b"-----BEGIN CERTIFICATE-----\n!!! not base64 !!!\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let config = write_config(dir.path(), &[("a", https, Some(garbage))], false);
    assert!(hoike_server::build_forward_clients(&config).is_err());

    // A configured forward_ca on a cleartext (or otherwise non-HTTPS) target
    // is a configuration error even with forward_insecure's escape hatch,
    // because pinned roots are meaningless without TLS.
    let config = write_config(dir.path(), &[("a", http, Some(ca_pem_a.clone()))], false);
    let err = hoike_server::build_forward_clients(&config).unwrap_err();
    assert!(err.contains("https"), "got: {err}");

    // Duplicate labels must reject rather than silently overwrite one CA's
    // trust policy with another's.
    let config = write_config(
        dir.path(),
        &[
            ("dup", https, Some(ca_pem_a.clone())),
            ("dup", https, Some(ca_pem_a)),
        ],
        false,
    );
    let err = hoike_server::build_forward_clients(&config).unwrap_err();
    assert!(err.contains("duplicate"), "got: {err}");

    // A non-forwarding CA does not require a client and does not fail
    // construction: only CAs with a forward_to get one.
    let mut toml_text = format!(
        "[server]\nmode = 'edge'\n[storage]\nbundle_dir = '{}'\nstate_db = '{}/state'\n",
        dir.path().display(),
        dir.path().display()
    );
    toml_text.push_str("\n[[ca]]\nlabel = 'plain'\nnonce_policy = 'ignore'\n");
    let path = dir.path().join("plain.toml");
    std::fs::write(&path, toml_text).unwrap();
    let config = hoike_core::Config::from_file(&path).unwrap();
    let clients = hoike_server::build_forward_clients(&config).unwrap();
    assert!(!clients.contains_key("plain"));
}

// ── The actual OCSP forwarding handler over an authenticated upstream ──

const FWD_ISSUER_NAME: &[u8] = b"CN=Forward CA,O=Hoike Test";
const FWD_ISSUER_KEY: &[u8] = b"forward-ca-public-key";

fn build_certid(serial: u64) -> x509_ocsp::CertId {
    let sha256_oid = const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    let issuer_name_hash = Sha256::digest(FWD_ISSUER_NAME);
    let issuer_key_hash = Sha256::digest(FWD_ISSUER_KEY);
    let serial_bytes = serial.to_be_bytes();
    let start = serial_bytes.iter().position(|&b| b != 0).unwrap_or(7);
    x509_ocsp::CertId {
        hash_algorithm: spki::AlgorithmIdentifier {
            oid: sha256_oid,
            parameters: None,
        },
        issuer_name_hash: der::asn1::OctetString::new(issuer_name_hash.to_vec()).unwrap(),
        issuer_key_hash: der::asn1::OctetString::new(issuer_key_hash.to_vec()).unwrap(),
        serial_number: x509_cert::serial_number::SerialNumber::new(&serial_bytes[start..]).unwrap(),
    }
}

fn build_ocsp_request_with_nonce(cert_id: &x509_ocsp::CertId, nonce: &[u8]) -> Vec<u8> {
    use x509_ocsp::{OcspRequest, Request, TbsRequest};

    let nonce_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");
    let nonce_value = der::asn1::OctetString::new(nonce.to_vec()).unwrap();
    let nonce_ext_value = der::asn1::OctetString::new(nonce_value.to_der().unwrap()).unwrap();
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
    OcspRequest {
        tbs_request: tbs,
        optional_signature: None,
    }
    .to_der()
    .unwrap()
}

fn build_forward_bundle() -> Vec<u8> {
    use ahu::{
        BundleBuilder, BundleType, CaScope, Completeness, Continuity, Integrity, Manifest,
        ResponderId, ResponderIdType, Window,
    };
    use uuid::Uuid;

    let now = current_time();
    let manifest = Manifest {
        format_version: 1,
        bundle_id: Uuid::nil(),
        producer_id: "forward-tls-test".into(),
        created_at: now - 1,
        bundle_type: BundleType::Full,
        ca_scopes: vec![CaScope {
            hash_algorithm: vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            issuer_name_hash: Sha256::digest(FWD_ISSUER_NAME).to_vec(),
            issuer_key_hash: Sha256::digest(FWD_ISSUER_KEY).to_vec(),
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
            produced_at: now - 1,
            this_update_min: now - 1,
            next_update_min: now + 86400,
            next_update_max: now + 93600,
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
    let cert_id = build_certid(42);
    let entry_key: [u8; 32] = Sha256::digest(cert_id.to_der().unwrap()).into();
    builder.add_entry(entry_key, b"PRESIGNED-PLACEHOLDER".to_vec());
    builder
        .build(|m| Ok(Sha256::digest(m).to_vec()))
        .expect("build failed")
}

/// The full request path — router, nonce dispatch, per-CA client selection,
/// TLS handshake under the pinned root, and upstream response validation —
/// with one authenticated upstream OCSP response.
#[tokio::test]
async fn forwarding_handler_serves_authenticated_upstream_response() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("fwd.ahu"), build_forward_bundle()).unwrap();

    // A real signed, nonce-bearing OCSP response from the upstream signer.
    let nonce = [0xAB; 16];
    let cert_id = build_certid(42);
    let now = current_time();
    let mut upstream_signer = hoike_sign::demo_ecdsa_p256_key();
    let upstream_response =
        hoike_sign::live::sign_live_response_with_window::<_, p256::ecdsa::DerSignature>(
            &cert_id.to_der().unwrap(),
            hoike_sign::LiveCertStatus::Good,
            &nonce,
            b"UPSTREAM-KEY",
            &mut upstream_signer,
            now,
            now - 30,
            now + 3600,
            None,
        )
        .unwrap();

    let expected_upstream_response = upstream_response.clone();
    let upstream_router = axum::Router::new().route(
        "/",
        post(move || {
            let body = upstream_response.clone();
            async move {
                (
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "application/ocsp-response",
                    )],
                    body,
                )
            }
        }),
    );
    let ca = synthetic_ca(1);
    let (leaf_key, leaf_cert) = synthetic_leaf(&ca, 2, "localhost");
    let upstream = spawn_tls_upstream(leaf_cert, leaf_key, upstream_router).await;
    let ca_pem = write_ca_pem(dir.path(), "ca.pem", &ca);

    let config = write_config(dir.path(), &[("fwd", &upstream.url, Some(ca_pem))], true);
    hoike_core::StateStore::initialize(&config.storage.state_db.join("state.json")).unwrap();
    let guard = std::sync::Arc::new(
        hoike_core::StateDirectoryLock::acquire(&config.storage.state_db).unwrap(),
    );
    let responder = hoike_core::ResponderState::load(config.clone(), guard).unwrap();
    let app_state = hoike_server::AppState::new(responder, config).unwrap();
    let app = hoike_server::build_router(app_state);

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/")
        .header("content-type", "application/ocsp-request")
        .body(axum::body::Body::from(build_ocsp_request_with_nonce(
            &cert_id, &nonce,
        )))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap(),
        "application/ocsp-response"
    );
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CACHE_CONTROL)
            .unwrap(),
        "no-cache, no-store"
    );
    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    assert_eq!(&body[..], &expected_upstream_response[..]);
}
