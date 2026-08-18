use std::collections::BTreeMap;
use x509_cert::ext::pkix::CrlReason;

use crate::error::Result;

pub type Epoch = u64;
pub type SerialBytes = Vec<u8>;

#[derive(Debug, Clone)]
pub enum CertificateStatus {
    Good,
    Revoked {
        revocation_time: u64,
        reason: Option<CrlReason>,
    },
}

#[derive(Debug, Clone)]
pub struct StatusSnapshot {
    pub entries: BTreeMap<SerialBytes, CertificateStatus>,
    pub this_update: u64,
    pub next_update: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct StatusChange {
    pub serial: SerialBytes,
    pub status: CertificateStatus,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct CaIdentity {
    pub label: String,
    pub issuer_name_der: Vec<u8>,
    pub issuer_key_bytes: Vec<u8>,
}

pub trait RevocationSource: Send + Sync {
    fn snapshot(&self, ca: &CaIdentity) -> Result<StatusSnapshot>;
    fn changes_since(&self, ca: &CaIdentity, since: Epoch) -> Result<Vec<StatusChange>>;
    fn supports_streaming(&self) -> bool;
}
