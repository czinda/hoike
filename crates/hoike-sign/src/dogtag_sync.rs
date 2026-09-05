//! RFC 4533 Content Synchronization (syncrepl) source adapter for 389 DS.
//!
//! Connects to Dogtag PKI's 389 Directory Server backend and synchronizes
//! the certificate repository via LDAP syncrepl.  The first call performs
//! a full **refresh** (one-time enumeration of every `certificateRecord`).
//! Subsequent calls send the stored **sync cookie** so 389 DS returns only
//! entries that changed — making steady-state cost proportional to issuance
//! and revocation rate, not population size.
//!
//! Snapshot and cookie are checkpointed together after a complete refresh.
//! Each checkpoint is bound to its source/CA and atomically replaced. Legacy
//! cookie-only state is ignored; only syncRefreshRequired triggers a full retry.
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

/// Encode through ldap3's RFC 4533 control implementation.
fn encode_sync_request(_mode: u8, cookie: Option<&[u8]>) -> Vec<u8> {
    let control: ldap3::controls::RawControl = ldap3::controls::SyncRequest {
        mode: ldap3::controls::RefreshMode::RefreshOnly,
        cookie: cookie.map(<[u8]>::to_vec),
        reload_hint: false,
    }
    .into();
    control.val.expect("SyncRequest always encodes a value")
}

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

/// One coherent source-bound snapshot and RFC 4533 resume position.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
struct Checkpoint {
    version: u32,
    binding: String,
    cookie: Option<Vec<u8>>,
    records: BTreeMap<String, StoredRecord>,
    complete: bool,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct StoredRecord {
    serial: Vec<u8>,
    revoked: Option<(u64, Option<u32>)>,
    #[serde(default)]
    excluded: bool,
}
impl StoredRecord {
    fn status(&self) -> CertificateStatus {
        match self.revoked {
            None => CertificateStatus::Good,
            Some((revocation_time, reason)) => CertificateStatus::Revoked {
                revocation_time,
                reason: reason.and_then(crl_reason_from_u32),
            },
        }
    }
}

impl Checkpoint {
    fn apply_entry(
        &mut self,
        state: ldap3::controls::SyncState,
        record: Option<StoredRecord>,
        present: &mut std::collections::BTreeSet<String>,
    ) -> Result<()> {
        use ldap3::controls::EntryState;
        if state.entry_uuid.len() != 16 {
            return Err(SignError::Config("invalid sync UUID".into()));
        }
        let id = hex::encode(state.entry_uuid);
        if state.cookie.is_some() {
            self.cookie = state.cookie;
        }
        match state.state {
            EntryState::Delete => {
                self.records.remove(&id);
            }
            EntryState::Present => {
                if !self.records.contains_key(&id) {
                    return Err(SignError::Config(
                        "present UUID absent from checkpoint".into(),
                    ));
                }
                present.insert(id);
            }
            EntryState::Add | EntryState::Modify => {
                let record = record
                    .ok_or_else(|| SignError::Config("sync update has no parsed record".into()))?;
                present.insert(id.clone());
                self.records.insert(id, record);
            }
        }
        Ok(())
    }
    fn finish(
        &mut self,
        present: &std::collections::BTreeSet<String>,
        refresh_deletes: bool,
    ) -> Result<()> {
        if !refresh_deletes {
            self.records.retain(|id, _| present.contains(id));
        }
        let mut serials = std::collections::BTreeSet::new();
        for record in self.records.values() {
            if !serials.insert(&record.serial) {
                return Err(SignError::Config(
                    "duplicate certificate serial in source".into(),
                ));
            }
        }
        self.complete = true;
        Ok(())
    }
}

pub struct DogtagSyncSource {
    config: DogtagSyncConfig,
    state: Mutex<Checkpoint>,
}

impl DogtagSyncSource {
    pub fn new(config: DogtagSyncConfig) -> Self {
        Self {
            config,
            state: Mutex::new(Checkpoint::default()),
        }
    }

    fn binding(&self, ca: &CaIdentity) -> String {
        use sha2::{Digest, Sha256};
        let material = serde_json::to_vec(&(
            &self.config.ldap_url,
            &self.config.base_dn,
            &self.config.filter,
            &self.config.bind_dn,
            &self.config.tls,
            &self.config.ca_cert,
            DogtagSyncConfig::attrs(),
            &ca.issuer_name_der,
            &ca.issuer_key_bytes,
        ))
        .expect("serializable source identity");
        hex::encode(Sha256::digest(material))
    }

    fn checkpoint_path(&self, binding: &str) -> PathBuf {
        let mut path = self.config.cookie_path.as_os_str().to_os_string();
        path.push(format!(".{binding}.json"));
        PathBuf::from(path)
    }

    fn refresh(&self, ca: &CaIdentity) -> Result<Checkpoint> {
        let binding = self.binding(ca);
        let path = self.checkpoint_path(&binding);
        // Serialize refreshes and publish only after the complete checkpoint is durable.
        let mut current = self
            .state
            .lock()
            .map_err(|_| SignError::Config("source state lock poisoned".into()))?;
        if current.binding != binding {
            *current = load_checkpoint(&path, &binding).unwrap_or(Checkpoint {
                version: 1,
                binding: binding.clone(),
                ..Default::default()
            });
        }
        let candidate = current.clone();
        let cfg = self.config.clone();
        let result = std::thread::spawn(move || Self::do_sync(&cfg, candidate))
            .join()
            .map_err(|_| SignError::Config("malformed LDAP synchronization response".into()))?;
        let staged = match result {
            Ok(value) => value,
            Err(SignError::Config(message)) if message == "syncRefreshRequired" => {
                let cfg = self.config.clone();
                let fresh = Checkpoint {
                    version: 1,
                    binding,
                    ..Default::default()
                };
                std::thread::spawn(move || Self::do_sync(&cfg, fresh))
                    .join()
                    .map_err(|_| {
                        SignError::Config("malformed LDAP synchronization response".into())
                    })??
            }
            Err(err) => return Err(err),
        };
        save_checkpoint(&path, &staged)?;
        *current = staged.clone();
        Ok(staged)
    }

    fn do_sync(config: &DogtagSyncConfig, mut staged: Checkpoint) -> Result<Checkpoint> {
        use ldap3::controls::{EntryState, SyncDone, SyncInfo, SyncState, parse_syncinfo};
        let mut conn = connect(&config.ldap_url, &config.tls, config.ca_cert.as_deref())?;
        conn.simple_bind(&config.bind_dn, &config.bind_password)
            .map_err(|e| SignError::Config(format!("LDAP bind: {e}")))?
            .success()
            .map_err(|e| SignError::Config(format!("LDAP bind: {e}")))?;
        if staged.cookie.is_none() {
            staged.records.clear();
            staged.complete = false;
        }
        let control = ldap3::controls::RawControl {
            ctype: SYNC_REQUEST_OID.into(),
            crit: true,
            val: Some(encode_sync_request(1, staged.cookie.as_deref())),
        };
        let mut search = conn
            .with_controls(vec![control])
            .streaming_search(
                &config.base_dn,
                Scope::Subtree,
                &config.filter,
                DogtagSyncConfig::attrs(),
            )
            .map_err(|e| SignError::Config(format!("LDAP search: {e}")))?;
        let mut present = std::collections::BTreeSet::new();
        while let Some(raw) = search
            .next()
            .map_err(|e| SignError::Config(format!("LDAP stream: {e}")))?
        {
            if raw.is_intermediate() {
                match parse_syncinfo(raw) {
                    SyncInfo::NewCookie(cookie) => staged.cookie = Some(cookie),
                    SyncInfo::RefreshDelete { cookie, .. }
                    | SyncInfo::RefreshPresent { cookie, .. } => {
                        if cookie.is_some() {
                            staged.cookie = cookie;
                        }
                    }
                    SyncInfo::SyncIdSet {
                        cookie,
                        refresh_deletes,
                        sync_uuids,
                    } => {
                        if cookie.is_some() {
                            staged.cookie = cookie;
                        }
                        for uuid in sync_uuids {
                            if uuid.len() != 16 {
                                return Err(SignError::Config("invalid sync UUID".into()));
                            }
                            let id = hex::encode(uuid);
                            if refresh_deletes {
                                staged.records.remove(&id);
                            } else {
                                present.insert(id);
                            }
                        }
                    }
                }
                continue;
            }
            let controls: Vec<_> = raw
                .1
                .iter()
                .filter(|c| c.1.ctype == _SYNC_STATE_OID)
                .collect();
            if controls.len() != 1 {
                return Err(SignError::Config(
                    "missing or duplicate Sync State control".into(),
                ));
            }
            let state = controls[0].1.parse::<SyncState>();
            let record = if matches!(state.state, EntryState::Add | EntryState::Modify) {
                parse_cert_entry(&SearchEntry::construct(raw))?
            } else {
                None
            };
            staged.apply_entry(state, record, &mut present)?;
        }
        let result = search.result();
        if result.rc == 4096 {
            return Err(SignError::Config("syncRefreshRequired".into()));
        }
        let result = result
            .success()
            .map_err(|e| SignError::Config(format!("LDAP search completion: {e}")))?;
        let done: Vec<_> = result
            .ctrls
            .iter()
            .filter(|c| c.1.ctype == SYNC_DONE_OID)
            .collect();
        if done.len() != 1 {
            return Err(SignError::Config(
                "missing or duplicate Sync Done control".into(),
            ));
        }
        let done = done[0].1.parse::<SyncDone>();
        if done.cookie.is_some() {
            staged.cookie = done.cookie;
        }
        staged.finish(&present, done.refresh_deletes)?;
        let _ = conn.unbind();
        Ok(staged)
    }
}

impl RevocationSource for DogtagSyncSource {
    fn snapshot(&self, ca: &CaIdentity) -> Result<StatusSnapshot> {
        let state = self.refresh(ca)?;
        let now = crate::source::unix_now()?;
        Ok(StatusSnapshot {
            entries: state
                .records
                .values()
                .filter(|r| !r.excluded)
                .map(|r| (r.serial.clone(), r.status()))
                .collect(),
            this_update: now,
            next_update: Some(
                now.checked_add(86400)
                    .ok_or_else(|| SignError::Config("source clock overflow".into()))?,
            ),
        })
    }
    fn changes_since(&self, ca: &CaIdentity, _since: Epoch) -> Result<Vec<StatusChange>> {
        let snapshot = self.snapshot(ca)?;
        Ok(snapshot
            .entries
            .into_iter()
            .map(|(serial, status)| StatusChange {
                serial,
                status,
                timestamp: snapshot.this_update,
            })
            .collect())
    }
    fn supports_streaming(&self) -> bool {
        false
    }
    fn is_authoritative_complete(&self) -> bool {
        self.state.lock().map(|s| s.complete).unwrap_or(false)
    }
}

// ── Entry parsing ────────────────────────────────────────────────────────

/// Parse a `certificateRecord` LDAP entry into a serial and status.
fn parse_cert_entry(entry: &SearchEntry) -> Result<Option<StoredRecord>> {
    let attr = |name: &str| {
        entry
            .attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .and_then(|(_, values)| {
                if values.len() == 1 {
                    values.first().map(String::as_str)
                } else {
                    None
                }
            })
    };
    let serial = attr("cn")
        .and_then(parse_decimal_serial)
        .or_else(|| {
            attr("serialno").and_then(|s| {
                if s.starts_with("0x") || s.starts_with("0X") {
                    parse_hex_serial(s)
                } else {
                    parse_decimal_serial(s)
                }
            })
        })
        .ok_or_else(|| SignError::Config("missing or invalid certificate serial".into()))?;
    let status =
        attr("certStatus").ok_or_else(|| SignError::Config("missing certificate status".into()))?;
    let revoked = match status {
        "VALID" => None,
        "INVALID" | "EXPIRED" => {
            return Ok(Some(StoredRecord {
                serial,
                revoked: None,
                excluded: true,
            }));
        }
        "REVOKED" | "REVOKED_EXPIRED" => {
            let time = attr("revokedOn")
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or_else(|| SignError::Config("missing or invalid revocation time".into()))?
                / 1000;
            let reason = attr("revReason")
                .map(|s| {
                    s.parse::<u32>()
                        .ok()
                        .filter(|v| crl_reason_from_u32(*v).is_some())
                        .ok_or_else(|| SignError::Config("invalid revocation reason".into()))
                })
                .transpose()?;
            Some((time, reason))
        }
        _ => return Err(SignError::Config("unknown certificate status".into())),
    };
    Ok(Some(StoredRecord {
        serial,
        revoked,
        excluded: false,
    }))
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
    if hex.len() > 40 || hex.is_empty() {
        return None;
    }
    let bytes = hex::decode(&hex).ok()?;
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    Some(bytes[first..].to_vec())
}

/// Parse a decimal serial string into big-endian bytes.
fn parse_decimal_serial(dec: &str) -> Option<SerialBytes> {
    if dec.is_empty() || dec.len() > 49 || !dec.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let n = num_bigint::BigUint::parse_bytes(dec.as_bytes(), 10)?;
    let bytes = n.to_bytes_be();
    if bytes.len() > 20 {
        None
    } else if bytes.is_empty() {
        Some(vec![0])
    } else {
        Some(bytes)
    }
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

fn load_checkpoint(path: &Path, binding: &str) -> Option<Checkpoint> {
    let state: Checkpoint = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    (state.version == 1 && state.binding == binding && state.complete).then_some(state)
}

fn save_checkpoint(path: &Path, state: &Checkpoint) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|e| SignError::Config(format!("checkpoint directory: {e}")))?;
    let temp = parent.join(format!(".hoike-sync-{}.tmp", uuid::Uuid::now_v7()));
    let write = || -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|e| SignError::Config(format!("checkpoint create: {e}")))?;
        serde_json::to_writer(&mut file, state)
            .map_err(|e| SignError::Config(format!("checkpoint encode: {e}")))?;
        file.flush()
            .and_then(|_| file.sync_all())
            .map_err(|e| SignError::Config(format!("checkpoint sync: {e}")))?;
        std::fs::rename(&temp, path)
            .map_err(|e| SignError::Config(format!("checkpoint replace: {e}")))?;
        std::fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|e| SignError::Config(format!("checkpoint directory sync: {e}")))?;
        Ok(())
    };
    let result = write();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
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
    #[test]
    fn large_serials_are_supported_and_bounded() {
        assert_eq!(
            parse_decimal_serial("340282366920938463463374607431768211456"),
            Some([vec![1], vec![0; 16]].concat())
        );
        assert!(
            parse_decimal_serial("1461501637330902918203684832716283019655932542976").is_none()
        );
        assert!(parse_decimal_serial("-1").is_none());
        assert_eq!(parse_hex_serial("0x0001"), Some(vec![1]));
    }
    #[test]
    fn missing_status_is_never_good_and_invalid_is_explicit() {
        let mut entry = SearchEntry {
            dn: "cn=42".into(),
            attrs: [("cn".into(), vec!["42".into()])].into(),
            bin_attrs: Default::default(),
        };
        assert!(parse_cert_entry(&entry).is_err());
        entry
            .attrs
            .insert("certStatus".into(), vec!["INVALID".into()]);
        assert!(parse_cert_entry(&entry).unwrap().unwrap().excluded);
        entry
            .attrs
            .insert("certStatus".into(), vec!["VALID".into()]);
        assert!(!parse_cert_entry(&entry).unwrap().unwrap().excluded);
    }
    #[test]
    fn checkpoint_restores_population_and_rejects_foreign_or_legacy_cookie() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint");
        let state = Checkpoint {
            version: 1,
            binding: "source-a".into(),
            cookie: Some(vec![1, 2]),
            complete: true,
            records: [(
                "uuid".into(),
                StoredRecord {
                    serial: vec![42],
                    revoked: Some((1, Some(1))),
                    excluded: false,
                },
            )]
            .into(),
        };
        save_checkpoint(&path, &state).unwrap();
        let read = load_checkpoint(&path, "source-a").unwrap();
        assert_eq!(read.cookie, state.cookie);
        assert_eq!(read.records.len(), 1);
        assert!(matches!(
            read.records["uuid"].status(),
            CertificateStatus::Revoked { .. }
        ));
        assert!(load_checkpoint(&path, "source-b").is_none());
        std::fs::write(&path, b"legacy-cookie").unwrap();
        assert!(load_checkpoint(&path, "source-a").is_none());
    }

    #[test]
    fn sync_reducer_deletes_replaces_and_prunes_only_staged_state() {
        use ldap3::controls::{EntryState, SyncState};
        let record = |n| StoredRecord {
            serial: vec![n],
            revoked: None,
            excluded: false,
        };
        let mut initial = Checkpoint::default();
        initial.records.insert(hex::encode([1; 16]), record(1));
        initial.records.insert(hex::encode([2; 16]), record(2));
        let mut staged = initial.clone();
        let mut present = Default::default();
        staged
            .apply_entry(
                SyncState {
                    state: EntryState::Delete,
                    entry_uuid: vec![1; 16],
                    cookie: None,
                },
                None,
                &mut present,
            )
            .unwrap();
        assert_eq!(staged.records.len(), 1);
        assert_eq!(initial.records.len(), 2);
        staged
            .apply_entry(
                SyncState {
                    state: EntryState::Modify,
                    entry_uuid: vec![2; 16],
                    cookie: None,
                },
                Some(StoredRecord {
                    excluded: true,
                    ..record(2)
                }),
                &mut present,
            )
            .unwrap();
        assert!(staged.records.values().all(|r| r.excluded));
        staged
            .apply_entry(
                SyncState {
                    state: EntryState::Present,
                    entry_uuid: vec![2; 16],
                    cookie: None,
                },
                None,
                &mut present,
            )
            .unwrap();
        staged.finish(&present, false).unwrap();
        assert_eq!(staged.records.len(), 1);
        let mut staged = initial.clone();
        staged
            .apply_entry(
                SyncState {
                    state: EntryState::Present,
                    entry_uuid: vec![1; 16],
                    cookie: None,
                },
                None,
                &mut std::collections::BTreeSet::new(),
            )
            .unwrap();
        staged
            .finish(&[hex::encode([1; 16])].into(), false)
            .unwrap();
        assert_eq!(staged.records.len(), 1);
        assert_eq!(initial.records.len(), 2);
    }
}
