//! RFC 4533 Content Synchronization (syncrepl) source adapter for 389 DS.
//!
//! Connects to Dogtag PKI's 389 Directory Server backend and synchronizes
//! the certificate repository via LDAP syncrepl.  The first call performs
//! a full **refresh** (one-time enumeration of every `certificateRecord`).
//! Subsequent calls send the stored **sync cookie** so 389 DS returns only
//! entries that changed — making steady-state cost proportional to issuance
//! and revocation rate, not population size.
//!
//! The sync cookie is checkpointed to disk after each successful snapshot.
//! On restart, the cookie is loaded and sent to 389 DS; if it is stale or
//! rejected, the adapter falls back to a full refresh automatically.
//!
//! # 389 DS certificate repository schema
//!
//! Each certificate issued by a Dogtag CA is stored as an LDAP entry under
//! `ou=certificateRepository,ou=ca,o=<instance>-CA` with object class
//! `certificateRecord`.  Relevant attributes:
//!
//! | Attribute         | Example                     | Meaning                   |
//! |-------------------|-----------------------------|---------------------------|
//! | `cn`              | `42`                        | Serial (decimal string)   |
//! | `serialno`        | `0x2a`                      | Serial (hex with prefix)  |
//! | `certStatus`      | `VALID` / `REVOKED`         | Current status            |
//! | `revokedOn`       | `1719878400000`             | Revocation epoch (ms)     |
//! | `revReason`       | `1`                         | CRL reason code           |
//!
//! # Sync protocol controls (RFC 4533)
//!
//! | OID                          | Name              | Direction |
//! |------------------------------|-------------------|-----------|
//! | `1.3.6.1.4.1.4203.1.9.1.1`  | Sync Request      | → server  |
//! | `1.3.6.1.4.1.4203.1.9.1.2`  | Sync State         | ← server  |
//! | `1.3.6.1.4.1.4203.1.9.1.3`  | Sync Done          | ← server  |

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use tracing::{debug, info, warn};
use x509_cert::ext::pkix::CrlReason;

use crate::error::{Result, SignError};
use crate::source::{
    CaIdentity, CertificateStatus, Epoch, RevocationSource, SerialBytes, StatusChange,
    StatusSnapshot,
};

// ── Sync Request Control (RFC 4533 §2.2) ────────────────────────────────

const SYNC_REQUEST_OID: &str = "1.3.6.1.4.1.4203.1.9.1.1";
const _SYNC_STATE_OID: &str = "1.3.6.1.4.1.4203.1.9.1.2";
const SYNC_DONE_OID: &str = "1.3.6.1.4.1.4203.1.9.1.3";

/// Encode the BER value for a Sync Request Control.
///
/// ```text
/// syncRequestValue ::= SEQUENCE {
///     mode          ENUMERATED { refreshOnly(1), refreshAndPersist(3) },
///     cookie        syncCookie OPTIONAL,
///     reloadHint    BOOLEAN DEFAULT FALSE
/// }
/// ```
fn encode_sync_request(mode: u8, cookie: Option<&[u8]>) -> Vec<u8> {
    let mut inner = Vec::new();

    // mode — ENUMERATED (tag 0x0a, length 1, value)
    inner.push(0x0a);
    inner.push(0x01);
    inner.push(mode);

    // cookie — OCTET STRING (tag 0x04) if present
    if let Some(c) = cookie {
        inner.push(0x04);
        ber_encode_length(c.len(), &mut inner);
        inner.extend_from_slice(c);
    }

    // Wrap in SEQUENCE (tag 0x30)
    let mut out = Vec::with_capacity(inner.len() + 4);
    out.push(0x30);
    ber_encode_length(inner.len(), &mut out);
    out.extend(inner);
    out
}

/// Encode a BER definite length.
fn ber_encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// Parse a Sync Done Control value to extract the cookie.
///
/// ```text
/// syncDoneValue ::= SEQUENCE {
///     cookie     syncCookie OPTIONAL,
///     refreshDeletes BOOLEAN DEFAULT FALSE
/// }
/// ```
fn parse_sync_done_cookie(ber: &[u8]) -> Option<Vec<u8>> {
    // SEQUENCE tag
    if ber.first() != Some(&0x30) {
        return None;
    }
    let (seq_body, _) = ber_read_tl(&ber[1..])?;

    // First element: if tag 0x04 (OCTET STRING), it's the cookie
    if seq_body.first() == Some(&0x04) {
        let (cookie_bytes, _) = ber_read_tl(&seq_body[1..])?;
        return Some(cookie_bytes.to_vec());
    }
    None
}

/// Read a BER TL (tag already consumed) and return (value_slice, rest).
fn ber_read_tl(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.is_empty() {
        return None;
    }
    let (len, hdr_size) = if data[0] < 0x80 {
        (data[0] as usize, 1)
    } else if data[0] == 0x81 {
        if data.len() < 2 {
            return None;
        }
        (data[1] as usize, 2)
    } else if data[0] == 0x82 {
        if data.len() < 3 {
            return None;
        }
        (((data[1] as usize) << 8) | data[2] as usize, 3)
    } else {
        return None;
    };
    let body = data.get(hdr_size..hdr_size + len)?;
    let rest = data.get(hdr_size + len..)?;
    Some((body, rest))
}

// ── Configuration ────────────────────────────────────────────────────────

/// Configuration for the Dogtag syncrepl source adapter.
#[derive(Debug, Clone)]
pub struct DogtagSyncConfig {
    /// LDAP URL, e.g. `ldap://ds-iot.cert-lab.local:3389`
    pub ldap_url: String,
    /// Search base, e.g. `ou=certificateRepository,ou=ca,o=pki-iot-ca-CA`
    pub base_dn: String,
    /// Bind DN, e.g. `cn=Directory Manager`
    pub bind_dn: String,
    /// Bind password (resolved from env or config)
    pub bind_password: String,
    /// Path to persist the sync cookie between restarts
    pub cookie_path: PathBuf,
    /// LDAP filter for certificate records
    pub filter: String,
    /// Transport security: `"ldaps"`, `"starttls"`, or `"none"` (FTP_ITC.1).
    pub tls: String,
    /// Optional PEM CA bundle to validate the directory server certificate.
    pub ca_cert: Option<PathBuf>,
}

impl DogtagSyncConfig {
    /// Attributes to request from 389 DS.
    fn attrs() -> Vec<&'static str> {
        vec!["cn", "serialno", "certStatus", "revokedOn", "revReason"]
    }
}

/// Open an `LdapConn` honoring the configured transport security (FTP_ITC.1).
///
/// - `"starttls"` sets `set_starttls(true)` so TLS is negotiated *before* the
///   bind — the bind password never crosses in cleartext.
/// - `"ldaps"` relies on an `ldaps://` URL scheme for implicit TLS.
/// - `"none"` (default) is plaintext, retained for backward compatibility.
///
/// When `ca_cert` is set, the directory server certificate is validated against
/// exactly that PEM anchor (via a rustls `ClientConfig` on the aws-lc-rs
/// provider); otherwise the platform trust store is used.
fn connect(ldap_url: &str, tls: &str, ca_cert: Option<&Path>) -> Result<LdapConn> {
    let mut settings = LdapConnSettings::new();

    match tls {
        "starttls" => settings = settings.set_starttls(true),
        "ldaps" => {
            if !ldap_url.starts_with("ldaps://") {
                return Err(SignError::Config(format!(
                    "dogtag-sync tls=\"ldaps\" requires an ldaps:// URL, got {ldap_url}"
                )));
            }
        }
        "none" => {}
        other => {
            return Err(SignError::Config(format!(
                "dogtag-sync: invalid tls mode {other:?} (expected ldaps|starttls|none)"
            )));
        }
    }

    if let Some(ca_path) = ca_cert {
        settings = settings.set_config(Arc::new(client_config_with_ca(ca_path)?));
    }

    LdapConn::with_settings(settings, ldap_url)
        .map_err(|e| SignError::Config(format!("LDAP connect {ldap_url}: {e}")))
}

/// Build a rustls `ClientConfig` that trusts only the certificates in `ca_path`.
///
/// Pinned to the aws-lc-rs provider explicitly so it is independent of whatever
/// process-default provider other components installed.
fn client_config_with_ca(ca_path: &Path) -> Result<rustls::ClientConfig> {
    let file = std::fs::File::open(ca_path)
        .map_err(|e| SignError::Config(format!("opening LDAP CA {}: {e}", ca_path.display())))?;
    let mut reader = std::io::BufReader::new(file);
    let mut roots = rustls::RootCertStore::empty();
    let mut added = 0usize;
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.map_err(|e| {
            SignError::Config(format!("parsing LDAP CA {}: {e}", ca_path.display()))
        })?;
        roots
            .add(cert)
            .map_err(|e| SignError::Config(format!("adding LDAP CA anchor: {e}")))?;
        added += 1;
    }
    if added == 0 {
        return Err(SignError::Config(format!(
            "no certificates found in LDAP CA {}",
            ca_path.display()
        )));
    }

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| SignError::Config(format!("LDAP TLS protocol setup: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

// ── Source adapter ───────────────────────────────────────────────────────

/// Syncrepl-backed revocation source for 389 DS certificate repositories.
///
/// Maintains an in-memory snapshot of the full certificate population.
/// Each call to [`snapshot()`] performs a syncrepl refresh-only pass:
/// on the first call, 389 DS sends every entry; on subsequent calls,
/// only entries that changed since the stored cookie.
pub struct DogtagSyncSource {
    config: DogtagSyncConfig,
    /// Accumulated snapshot from all syncrepl passes.
    entries: Arc<Mutex<BTreeMap<SerialBytes, CertificateStatus>>>,
    /// Sync cookie from the last successful refresh.
    cookie: Arc<Mutex<Option<Vec<u8>>>>,
    /// Epoch counter — incremented each successful refresh.
    epoch: Mutex<u64>,
}

impl DogtagSyncSource {
    /// Create a new source, loading any persisted cookie from disk.
    pub fn new(config: DogtagSyncConfig) -> Self {
        let cookie = load_cookie(&config.cookie_path);
        if cookie.is_some() {
            info!(
                cookie_path = %config.cookie_path.display(),
                "loaded sync cookie from checkpoint"
            );
        }

        DogtagSyncSource {
            config,
            entries: Arc::new(Mutex::new(BTreeMap::new())),
            cookie: Arc::new(Mutex::new(cookie)),
            epoch: Mutex::new(0),
        }
    }

    /// Execute one syncrepl refresh-only pass against 389 DS.
    ///
    /// If a cookie is available, sends it so the server returns only
    /// changes.  If the cookie is stale (server rejects it), retries
    /// without a cookie for a full refresh.
    fn refresh(&self) -> Result<u64> {
        let cookie_for_request = self.cookie.lock().unwrap().clone();

        let changed = match self.do_sync(cookie_for_request.as_deref()) {
            Ok(n) => n,
            Err(e) => {
                if cookie_for_request.is_some() {
                    warn!(
                        error = %e,
                        "syncrepl with cookie failed — retrying full refresh"
                    );
                    // Full refresh (no cookie)
                    self.do_sync(None)?
                } else {
                    return Err(e);
                }
            }
        };

        // Bump epoch
        let mut epoch = self.epoch.lock().unwrap();
        *epoch += 1;
        let ep = *epoch;

        info!(epoch = ep, changed, "syncrepl refresh complete");
        Ok(changed)
    }

    /// Perform the actual LDAP syncrepl search.
    ///
    /// Runs on a dedicated thread because `LdapConn` creates its own tokio
    /// runtime internally, which panics if called from within an existing
    /// runtime (hoike's axum server).
    fn do_sync(&self, cookie: Option<&[u8]>) -> Result<u64> {
        let ldap_url = self.config.ldap_url.clone();
        let bind_dn = self.config.bind_dn.clone();
        let bind_password = self.config.bind_password.clone();
        let base_dn = self.config.base_dn.clone();
        let filter = self.config.filter.clone();
        let tls = self.config.tls.clone();
        let ca_cert = self.config.ca_cert.clone();
        let cookie_owned = cookie.map(|c| c.to_vec());
        let entries = self.entries.clone();
        let cookie_state = self.cookie.clone();
        let cookie_path = self.config.cookie_path.clone();

        let handle = std::thread::spawn(move || -> Result<u64> {
            Self::do_sync_inner(
                &ldap_url,
                &bind_dn,
                &bind_password,
                &base_dn,
                &filter,
                &tls,
                ca_cert.as_deref(),
                cookie_owned.as_deref(),
                &entries,
                &cookie_state,
                &cookie_path,
            )
        });

        handle
            .join()
            .unwrap_or_else(|e| Err(SignError::Config(format!("LDAP thread panicked: {e:?}"))))
    }

    #[allow(clippy::too_many_arguments)]
    fn do_sync_inner(
        ldap_url: &str,
        bind_dn: &str,
        bind_password: &str,
        base_dn: &str,
        filter: &str,
        tls: &str,
        ca_cert: Option<&Path>,
        cookie: Option<&[u8]>,
        entries: &Mutex<BTreeMap<SerialBytes, CertificateStatus>>,
        cookie_state: &Mutex<Option<Vec<u8>>>,
        cookie_path: &Path,
    ) -> Result<u64> {
        let mut conn = connect(ldap_url, tls, ca_cert)?;

        conn.simple_bind(bind_dn, bind_password)
            .map_err(|e| SignError::Config(format!("LDAP bind as {bind_dn}: {e}")))?
            .success()
            .map_err(|e| SignError::Config(format!("LDAP bind failed: {e}")))?;

        // Build sync request control (refreshOnly = 1)
        let sync_value = encode_sync_request(1, cookie);
        let sync_control = ldap3::controls::RawControl {
            ctype: SYNC_REQUEST_OID.to_string(),
            crit: true,
            val: Some(sync_value),
        };

        let (results, ldap_result) = conn
            .with_controls(vec![sync_control])
            .search(base_dn, Scope::Subtree, filter, DogtagSyncConfig::attrs())
            .map_err(|e| SignError::Config(format!("LDAP search: {e}")))?
            .success()
            .map_err(|e| SignError::Config(format!("LDAP search result: {e}")))?;

        let mut entries_guard = entries.lock().unwrap();
        let mut changed = 0u64;

        for result_entry in results {
            let se = SearchEntry::construct(result_entry);
            if let Some((serial, status)) = parse_cert_entry(&se) {
                entries_guard.insert(serial, status);
                changed += 1;
            }
        }

        // Extract sync cookie from the result controls (Sync Done Control)
        for ctrl in &ldap_result.ctrls {
            let raw = &ctrl.1;
            if raw.ctype == SYNC_DONE_OID {
                if let Some(ref val) = raw.val {
                    if let Some(new_cookie) = parse_sync_done_cookie(val) {
                        debug!(
                            cookie_len = new_cookie.len(),
                            "received sync cookie from 389 DS"
                        );
                        *cookie_state.lock().unwrap() = Some(new_cookie.clone());
                        save_cookie(cookie_path, &new_cookie);
                    }
                }
            }
        }

        conn.unbind()
            .map_err(|e| SignError::Config(format!("LDAP unbind: {e}")))?;

        info!(
            changed,
            total = entries_guard.len(),
            had_cookie = cookie.is_some(),
            "syncrepl pass complete"
        );

        Ok(changed)
    }
}

impl RevocationSource for DogtagSyncSource {
    fn snapshot(&self, _ca: &CaIdentity) -> Result<StatusSnapshot> {
        self.refresh()?;

        let entries = self.entries.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(StatusSnapshot {
            entries: entries.clone(),
            this_update: now,
            next_update: Some(now + 86400), // 24h default, overridden by GenerationConfig
        })
    }

    fn changes_since(&self, _ca: &CaIdentity, _since: Epoch) -> Result<Vec<StatusChange>> {
        // For now, fall back to a full snapshot diff.
        // A future `refreshAndPersist` implementation would accumulate
        // changes from the persist stream and return them here.
        let entries = self.entries.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(entries
            .iter()
            .map(|(serial, status)| StatusChange {
                serial: serial.clone(),
                status: status.clone(),
                timestamp: now,
            })
            .collect())
    }

    fn supports_streaming(&self) -> bool {
        true
    }
}

// ── Entry parsing ────────────────────────────────────────────────────────

/// Parse a `certificateRecord` LDAP entry into a serial and status.
fn parse_cert_entry(entry: &SearchEntry) -> Option<(SerialBytes, CertificateStatus)> {
    // Serial: prefer `cn` (decimal) — Dogtag's `serialno` is also decimal
    // (despite the name, it is NOT hex unless prefixed with 0x).
    let serial_bytes = entry
        .attrs
        .get("cn")
        .and_then(|v| v.first())
        .and_then(|dec| parse_decimal_serial(dec))
        .or_else(|| {
            entry
                .attrs
                .get("serialno")
                .and_then(|v| v.first())
                .and_then(|s| {
                    if s.starts_with("0x") || s.starts_with("0X") {
                        parse_hex_serial(s)
                    } else {
                        parse_decimal_serial(s)
                    }
                })
        })?;

    // Status
    let status_str = entry
        .attrs
        .get("certStatus")
        .and_then(|v| v.first())
        .map(|s| s.as_str())
        .unwrap_or("VALID");

    let status = match status_str {
        "REVOKED" | "REVOKED_EXPIRED" => {
            let revocation_time = entry
                .attrs
                .get("revokedOn")
                .and_then(|v| v.first())
                .and_then(|s| s.parse::<u64>().ok())
                .map(|ms| ms / 1000) // Dogtag stores ms, we use seconds
                .unwrap_or(0);

            let reason = entry
                .attrs
                .get("revReason")
                .and_then(|v| v.first())
                .and_then(|s| s.parse::<u32>().ok())
                .and_then(crl_reason_from_u32);

            CertificateStatus::Revoked {
                revocation_time,
                reason,
            }
        }
        "VALID" => CertificateStatus::Good,
        "EXPIRED" | "INVALID" => {
            tracing::debug!(
                serial = hex::encode(&serial_bytes),
                status = status_str,
                "skipping non-active certificate"
            );
            return None;
        }
        other => {
            tracing::warn!(
                serial = hex::encode(&serial_bytes),
                status = other,
                "unknown Dogtag certStatus — skipping (never map unknown to Good)"
            );
            return None;
        }
    };

    Some((serial_bytes, status))
}

/// Parse a hex serial like `0x2a` or `2a` into bytes.
fn parse_hex_serial(hex: &str) -> Option<SerialBytes> {
    let hex = hex
        .strip_prefix("0x")
        .or(hex.strip_prefix("0X"))
        .unwrap_or(hex);
    // Pad to even length
    let hex = if hex.len() % 2 != 0 {
        format!("0{hex}")
    } else {
        hex.to_string()
    };
    hex::decode(&hex).ok()
}

/// Parse a decimal serial string into big-endian bytes.
fn parse_decimal_serial(dec: &str) -> Option<SerialBytes> {
    let n: u128 = dec.parse().ok()?;
    if n == 0 {
        return Some(vec![0]);
    }
    let bytes = n.to_be_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(15);
    Some(bytes[first_nonzero..].to_vec())
}

/// Map a Dogtag revocation reason integer to a `CrlReason`.
fn crl_reason_from_u32(code: u32) -> Option<CrlReason> {
    match code {
        0 => Some(CrlReason::Unspecified),
        1 => Some(CrlReason::KeyCompromise),
        2 => Some(CrlReason::CaCompromise),
        3 => Some(CrlReason::AffiliationChanged),
        4 => Some(CrlReason::Superseded),
        5 => Some(CrlReason::CessationOfOperation),
        6 => Some(CrlReason::CertificateHold),
        8 => Some(CrlReason::RemoveFromCRL),
        9 => Some(CrlReason::PrivilegeWithdrawn),
        10 => Some(CrlReason::AaCompromise),
        _ => None,
    }
}

// ── Cookie persistence ───────────────────────────────────────────────────

fn load_cookie(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

fn save_cookie(path: &Path, cookie: &[u8]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(path, cookie) {
        warn!(path = %path.display(), error = %e, "failed to checkpoint sync cookie");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_serial_with_prefix() {
        assert_eq!(parse_hex_serial("0x2a"), Some(vec![0x2a]));
        assert_eq!(parse_hex_serial("0X2A"), Some(vec![0x2a]));
    }

    #[test]
    fn parse_hex_serial_without_prefix() {
        assert_eq!(parse_hex_serial("ff01"), Some(vec![0xff, 0x01]));
    }

    #[test]
    fn parse_hex_serial_odd_length() {
        assert_eq!(parse_hex_serial("0xabc"), Some(vec![0x0a, 0xbc]));
    }

    #[test]
    fn parse_decimal_serial_basic() {
        assert_eq!(parse_decimal_serial("42"), Some(vec![42]));
        assert_eq!(parse_decimal_serial("256"), Some(vec![1, 0]));
    }

    #[test]
    fn crl_reason_mapping() {
        assert_eq!(crl_reason_from_u32(1), Some(CrlReason::KeyCompromise));
        assert_eq!(crl_reason_from_u32(4), Some(CrlReason::Superseded));
        assert_eq!(crl_reason_from_u32(99), None);
    }

    #[test]
    fn encode_sync_request_no_cookie() {
        let data = encode_sync_request(1, None);
        // SEQUENCE { ENUMERATED(1) }
        assert_eq!(data[0], 0x30); // SEQUENCE
        assert_eq!(data[2], 0x0a); // ENUMERATED tag
        assert_eq!(data[4], 0x01); // refreshOnly
    }

    #[test]
    fn encode_sync_request_with_cookie() {
        let cookie = b"test-cookie";
        let data = encode_sync_request(1, Some(cookie));
        assert_eq!(data[0], 0x30); // SEQUENCE
        assert_eq!(data[2], 0x0a); // ENUMERATED tag
        assert_eq!(data[4], 0x01); // refreshOnly
        assert_eq!(data[5], 0x04); // OCTET STRING tag
    }

    #[test]
    fn parse_sync_done_cookie_roundtrip() {
        let cookie = b"session-cookie-12345";
        // Build a minimal Sync Done Control value: SEQUENCE { OCTET STRING(cookie) }
        let mut ber = vec![0x30]; // SEQUENCE
        let inner_len = 2 + cookie.len(); // tag + length + value
        ber.push(inner_len as u8);
        ber.push(0x04); // OCTET STRING
        ber.push(cookie.len() as u8);
        ber.extend_from_slice(cookie);

        let parsed = parse_sync_done_cookie(&ber);
        assert_eq!(parsed, Some(cookie.to_vec()));
    }

    #[test]
    fn connect_rejects_invalid_tls_mode() {
        let err = connect("ldap://ds.example:389", "bogus", None).unwrap_err();
        assert!(
            matches!(err, SignError::Config(m) if m.contains("invalid tls mode")),
            "expected invalid-tls-mode config error"
        );
    }

    #[test]
    fn connect_ldaps_requires_ldaps_scheme() {
        // tls="ldaps" over a plaintext ldap:// URL is a configuration error and
        // must be caught before any bind is attempted.
        let err = connect("ldap://ds.example:389", "ldaps", None).unwrap_err();
        assert!(
            matches!(err, SignError::Config(m) if m.contains("requires an ldaps:// URL")),
            "expected ldaps-scheme config error"
        );
    }

    #[test]
    fn client_config_rejects_empty_ca_pem() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, b"not a pem\n").unwrap();
        let err = client_config_with_ca(f.path()).unwrap_err();
        assert!(
            matches!(err, SignError::Config(m) if m.contains("no certificates found")),
            "expected empty-CA config error"
        );
    }
}
