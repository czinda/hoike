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
    /// True only when the source has established complete positive issuance.
    fn is_authoritative_complete(&self) -> bool {
        false
    }
}

impl StatusSnapshot {
    /// Validate source evidence at a supplied clock instant, returning its hard expiry.
    pub fn validate_at(&self, now: u64) -> Result<u64> {
        let end = self
            .next_update
            .ok_or_else(|| crate::error::SignError::Config("source has no nextUpdate".into()))?;
        if self.this_update > now || end <= now || end <= self.this_update {
            return Err(crate::error::SignError::Config(
                "source validity is expired, future-dated or inconsistent".into(),
            ));
        }
        Ok(end)
    }
}

pub fn unix_now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| crate::error::SignError::Config("clock is before Unix epoch".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn freshness_boundaries() {
        let mut s = StatusSnapshot {
            entries: BTreeMap::new(),
            this_update: 10,
            next_update: Some(20),
        };
        assert_eq!(s.validate_at(10).unwrap(), 20);
        assert!(s.validate_at(9).is_err());
        assert!(s.validate_at(20).is_err());
        s.next_update = None;
        assert!(s.validate_at(11).is_err());
    }
}
