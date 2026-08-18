use der::Decode;
use std::collections::BTreeMap;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::CrlReason;

use crate::error::{Result, SignError};
use crate::source::{CaIdentity, CertificateStatus, Epoch, RevocationSource, StatusChange, StatusSnapshot};

pub struct CrlSource {
    crl: CertificateList,
}

impl CrlSource {
    pub fn from_der(data: Vec<u8>) -> Result<Self> {
        let crl = CertificateList::from_der(&data)
            .map_err(|e| SignError::CrlParse(format!("failed to parse CRL DER: {e}")))?;
        Ok(CrlSource { crl })
    }

    pub fn from_pem(pem_text: &str) -> Result<Self> {
        let der_data = pem_to_der(pem_text)?;
        Self::from_der(der_data)
    }
}

impl RevocationSource for CrlSource {
    fn snapshot(&self, _ca: &CaIdentity) -> Result<StatusSnapshot> {
        let crl = &self.crl;
        let mut entries = BTreeMap::new();

        if let Some(revoked_certs) = &crl.tbs_cert_list.revoked_certificates {
            for rc in revoked_certs {
                let serial = rc.serial_number.as_bytes().to_vec();

                let reason = rc.crl_entry_extensions.as_ref().and_then(|exts| {
                    exts.iter()
                        .find(|ext| ext.extn_id == CrlReason::OID)
                        .and_then(|ext| CrlReason::from_der(ext.extn_value.as_bytes()).ok())
                });

                let revocation_time = time_to_epoch(rc.revocation_date);

                entries.insert(
                    serial,
                    CertificateStatus::Revoked {
                        revocation_time,
                        reason,
                    },
                );
            }
        }

        let this_update = time_to_epoch(crl.tbs_cert_list.this_update);
        let next_update = crl.tbs_cert_list.next_update.map(time_to_epoch);

        Ok(StatusSnapshot {
            entries,
            this_update,
            next_update,
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
}

fn time_to_epoch(time: x509_cert::time::Time) -> u64 {
    let dt = match time {
        x509_cert::time::Time::UtcTime(t) => t.to_date_time(),
        x509_cert::time::Time::GeneralTime(t) => t.to_date_time(),
    };
    datetime_to_epoch(dt)
}

fn datetime_to_epoch(dt: der::DateTime) -> u64 {
    let year = dt.year() as u64;
    let month = dt.month() as u64;
    let day = dt.day() as u64;
    let hour = dt.hour() as u64;
    let minutes = dt.minutes() as u64;
    let seconds = dt.seconds() as u64;

    // Approximate calculation — good enough for OCSP validity windows
    let mut days: u64 = 0;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    let mdays = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += mdays[m as usize] as u64;
        if m == 2 && is_leap(year) {
            days += 1;
        }
    }
    days += day - 1;
    days * 86400 + hour * 3600 + minutes * 60 + seconds
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let mut collecting = false;
    let mut found_end = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        if line.starts_with("-----BEGIN") {
            collecting = true;
            continue;
        }
        if line.starts_with("-----END") {
            found_end = true;
            break;
        }
        if collecting {
            b64.push_str(line.trim());
        }
    }
    if !collecting {
        return Err(SignError::CrlParse("PEM has no BEGIN marker".into()));
    }
    if !found_end {
        return Err(SignError::CrlParse(
            "PEM is truncated: found BEGIN but no END marker".into(),
        ));
    }
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| SignError::CrlParse(format!("PEM base64 decode: {e}")))
}

use const_oid::AssociatedOid;

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_crl_der() -> Vec<u8> {
        use der::Encode;
        use x509_cert::crl::{CertificateList, TbsCertList, RevokedCert};
        use x509_cert::name::RdnSequence;
        use x509_cert::time::Time;
        use der::asn1::UtcTime;
        use spki::AlgorithmIdentifierOwned;
        use der::asn1::BitString;

        let now_dt = der::DateTime::new(2025, 1, 15, 12, 0, 0).unwrap();
        let next_dt = der::DateTime::new(2025, 1, 16, 12, 0, 0).unwrap();
        let revoke_dt = der::DateTime::new(2025, 1, 10, 8, 0, 0).unwrap();

        let this_update = Time::UtcTime(UtcTime::from_date_time(now_dt).unwrap());
        let next_update = Time::UtcTime(UtcTime::from_date_time(next_dt).unwrap());
        let revoke_time = Time::UtcTime(UtcTime::from_date_time(revoke_dt).unwrap());

        let serial_42 = x509_cert::serial_number::SerialNumber::new(&[42u8]).unwrap();
        let serial_100 = x509_cert::serial_number::SerialNumber::new(&[100u8]).unwrap();

        let revoked_certs = vec![
            RevokedCert {
                serial_number: serial_42,
                revocation_date: revoke_time,
                crl_entry_extensions: None,
            },
            RevokedCert {
                serial_number: serial_100,
                revocation_date: revoke_time,
                crl_entry_extensions: None,
            },
        ];

        let sha256_with_ecdsa = const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

        let tbs = TbsCertList {
            version: x509_cert::Version::V2,
            signature: AlgorithmIdentifierOwned {
                oid: sha256_with_ecdsa,
                parameters: None,
            },
            issuer: RdnSequence::default(),
            this_update,
            next_update: Some(next_update),
            revoked_certificates: Some(revoked_certs),
            crl_extensions: None,
        };

        let crl = CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: sha256_with_ecdsa,
                parameters: None,
            },
            signature: BitString::from_bytes(&[0u8; 64]).unwrap(),
        };

        crl.to_der().expect("CRL encoding failed")
    }

    #[test]
    fn parse_crl_extracts_revoked_serials() {
        let crl_der = build_test_crl_der();
        let source = CrlSource::from_der(crl_der).unwrap();

        let ca = CaIdentity {
            label: "test".into(),
            issuer_name_der: vec![],
            issuer_key_bytes: vec![],
        };

        let snapshot = source.snapshot(&ca).unwrap();
        assert_eq!(snapshot.entries.len(), 2);

        assert!(matches!(
            snapshot.entries.get(&vec![42u8]),
            Some(CertificateStatus::Revoked { .. })
        ));
        assert!(matches!(
            snapshot.entries.get(&vec![100u8]),
            Some(CertificateStatus::Revoked { .. })
        ));
        assert!(snapshot.entries.get(&vec![1u8]).is_none());
    }
}
