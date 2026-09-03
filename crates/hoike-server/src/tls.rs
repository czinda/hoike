//! Server-side TLS for hoike's management listeners (admin API, web UI, metrics).
//!
//! Scope is deliberate: TLS terminates on the *management* surfaces only. The
//! OCSP data plane (`server.listen`) stays plaintext HTTP — OCSP responses are
//! CMS/signature-authenticated end to end (RFC 6960 / NIAP PPCA
//! FCO_NRO_EXT.2), so a transport wrapper there would add cost without adding a
//! security property. The management surfaces, by contrast, carry operator
//! credentials and session cookies and require a trusted path (FTP_TRP.1).
//!
//! Crypto is pinned to the **aws-lc-rs** provider for FIPS alignment (NIAP TLS
//! Functional Package). The `ServerConfig` is built with an *explicit* provider
//! rather than the process default, so it is unaffected by whichever provider
//! reqwest's client-side rustls happens to pull in.

use hoike_core::config::TlsConfig;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig};

/// Build a rustls `ServerConfig` from PEM cert/key files, optionally requiring
/// client certificates (mutual TLS) when `client_ca` is present.
///
/// TLS 1.2 is the floor and TLS 1.3 is offered (TLS Functional Package v1.1);
/// the aws-lc-rs provider supplies the ciphersuites.
pub fn server_config(
    cert: &Path,
    key: &Path,
    client_ca: Option<&Path>,
) -> Result<ServerConfig, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let certs = load_certs(cert)?;
    let key = load_key(key)?;

    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| format!("TLS protocol version setup failed: {e}"))?;

    let config = match client_ca {
        Some(ca_path) => {
            // Mutual TLS (FCS_TLSS_EXT.2): clients must present a certificate
            // chaining to one of the configured anchors.
            let mut roots = RootCertStore::empty();
            for anchor in load_certs(ca_path)? {
                roots.add(anchor).map_err(|e| {
                    format!("adding client CA anchor from {}: {e}", ca_path.display())
                })?;
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            )
            .build()
            .map_err(|e| format!("building client-cert verifier: {e}"))?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
        }
        None => {
            // Server-auth TLS only (FCS_TLSS_EXT.1); authentication is handled by
            // the existing bcrypt/RBAC login over the encrypted channel.
            builder.with_no_client_auth().with_single_cert(certs, key)
        }
    }
    .map_err(|e| format!("loading server certificate/key: {e}"))?;

    Ok(config)
}

/// Convenience wrapper that builds a `ServerConfig` from a `TlsConfig`.
pub fn server_config_from(tls: &TlsConfig) -> Result<ServerConfig, String> {
    server_config(&tls.cert, &tls.key, tls.client_ca.as_deref())
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("opening certificate file {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("parsing certificates from {}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("no certificates found in {}", path.display()));
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("opening private key file {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("parsing private key from {}: {e}", path.display()))?
        .ok_or_else(|| format!("no private key found in {}", path.display()))
}

/// Serve an axum `Router` over TLS on `addr`, blocking until the listener exits.
///
/// Uses `axum-server`'s rustls acceptor so we don't hand-roll a
/// `tokio_rustls::TlsAcceptor` accept loop. Mirrors the plaintext
/// `axum::serve(TcpListener, router)` shape used elsewhere.
pub async fn serve_router_tls(
    addr: &str,
    router: axum::Router,
    tls: &TlsConfig,
) -> std::io::Result<()> {
    let sock: SocketAddr = addr.parse().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{addr}: {e}"))
    })?;
    let config = server_config_from(tls)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config));
    axum_server::bind_rustls(sock, rustls_config)
        .serve(router.into_make_service())
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // A self-signed P-256 cert + PKCS#8 key pair generated for the test only.
    // Produced with: openssl ecparam -genkey -name prime256v1 | openssl pkcs8
    // -topk8 -nocrypt, then a self-signed cert over it. Embedded so the test is
    // hermetic (no external fixtures, matching the repo's ephemeral-key style).
    fn write_tmp(contents: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn rejects_missing_cert_file() {
        let err = server_config(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
            None,
        )
        .unwrap_err();
        assert!(err.contains("opening certificate file"), "got: {err}");
    }

    #[test]
    fn rejects_empty_cert_pem() {
        let cert = write_tmp(b"not a pem\n");
        let key = write_tmp(b"not a pem\n");
        let err = server_config(cert.path(), key.path(), None).unwrap_err();
        assert!(err.contains("no certificates found"), "got: {err}");
    }
}
