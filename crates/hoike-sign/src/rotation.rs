use der::{Decode, DecodePem};
use tracing::{error, info, warn};
use x509_cert::Certificate;

use crate::error::{Result, SignError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStatus {
    Ok { expires_in_secs: u64 },
    RenewSoon { expires_in_secs: u64 },
    Expired,
}

pub fn parse_certificate(bytes: &[u8]) -> der::Result<Certificate> {
    if bytes.starts_with(b"-----BEGIN") {
        Certificate::from_pem(bytes)
    } else {
        Certificate::from_der(bytes)
    }
}

pub fn check_rotation_needed(cert_der: &[u8], renew_before_secs: u64) -> Result<RotationStatus> {
    let cert = parse_certificate(cert_der)
        .map_err(|e| SignError::Config(format!("failed to parse responder certificate: {e}")))?;

    let not_after = cert.tbs_certificate.validity.not_after;
    let not_after_epoch = time_to_epoch(not_after);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if now >= not_after_epoch {
        return Ok(RotationStatus::Expired);
    }

    let expires_in_secs = not_after_epoch - now;

    if expires_in_secs <= renew_before_secs {
        Ok(RotationStatus::RenewSoon { expires_in_secs })
    } else {
        Ok(RotationStatus::Ok { expires_in_secs })
    }
}

pub fn check_and_log_rotation(
    ca_label: &str,
    cert_der: &[u8],
    renew_before_secs: u64,
) -> Result<RotationStatus> {
    let status = check_rotation_needed(cert_der, renew_before_secs)?;

    match &status {
        RotationStatus::Ok { expires_in_secs } => {
            let days = expires_in_secs / 86400;
            info!(
                ca = ca_label,
                expires_in_days = days,
                "OCSP signing certificate valid"
            );
        }
        RotationStatus::RenewSoon { expires_in_secs } => {
            let days = expires_in_secs / 86400;
            let hours = (expires_in_secs % 86400) / 3600;
            warn!(
                ca = ca_label,
                expires_in_days = days,
                expires_in_hours = hours,
                "OCSP signing certificate approaching expiry — rotation needed"
            );
        }
        RotationStatus::Expired => {
            error!(
                ca = ca_label,
                "OCSP signing certificate has EXPIRED — responses will be rejected by clients"
            );
        }
    }

    Ok(status)
}

pub fn run_rotation_command(ca_label: &str, command: &str) -> std::result::Result<(), String> {
    info!(ca = ca_label, command, "executing rotation command");

    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .map_err(|e| format!("failed to execute rotation command: {e}"))?;

    if output.status.success() {
        info!(ca = ca_label, "rotation command completed successfully");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(
            ca = ca_label,
            exit_code = output.status.code().unwrap_or(-1),
            stderr = %stderr,
            "rotation command failed"
        );
        Err(format!(
            "rotation command exited with {}: {}",
            output.status,
            stderr.trim()
        ))
    }
}

pub fn format_cert_info(cert_der: &[u8]) -> std::result::Result<CertInfo, String> {
    let cert =
        parse_certificate(cert_der).map_err(|e| format!("failed to parse certificate: {e}"))?;

    let tbs = &cert.tbs_certificate;

    let not_before = time_to_epoch(tbs.validity.not_before);
    let not_after = time_to_epoch(tbs.validity.not_after);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let has_ocsp_signing = tbs
        .extensions
        .as_ref()
        .and_then(|exts| {
            exts.iter()
                .find(|ext| ext.extn_id == const_oid::ObjectIdentifier::new_unwrap("2.5.29.37"))
        })
        .map(|ext| {
            ext.extn_value
                .as_bytes()
                .windows(9)
                .any(|w| w == [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x09])
                || ext
                    .extn_value
                    .as_bytes()
                    .windows(8)
                    .any(|w| w == [43, 6, 1, 5, 5, 7, 3, 9])
        })
        .unwrap_or(false);

    Ok(CertInfo {
        subject: format!("{}", tbs.subject),
        issuer: format!("{}", tbs.issuer),
        not_before,
        not_after,
        is_expired: now >= not_after,
        days_remaining: if now < not_after {
            (not_after - now) / 86400
        } else {
            0
        },
        has_ocsp_signing_eku: has_ocsp_signing,
    })
}

#[derive(Debug)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: u64,
    pub not_after: u64,
    pub is_expired: bool,
    pub days_remaining: u64,
    pub has_ocsp_signing_eku: bool,
}

fn time_to_epoch(time: x509_cert::time::Time) -> u64 {
    let dt = match time {
        x509_cert::time::Time::UtcTime(t) => t.to_date_time(),
        x509_cert::time::Time::GeneralTime(t) => t.to_date_time(),
    };
    crate::generate::datetime_to_epoch(dt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;

    fn build_test_cert(not_before_dt: der::DateTime, not_after_dt: der::DateTime) -> Vec<u8> {
        use der::asn1::BitString;
        use spki::AlgorithmIdentifierOwned;
        use x509_cert::name::RdnSequence;
        use x509_cert::time::Time;

        let sha256_ecdsa = const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

        let nb = Time::UtcTime(der::asn1::UtcTime::from_date_time(not_before_dt).unwrap());
        let na = Time::UtcTime(der::asn1::UtcTime::from_date_time(not_after_dt).unwrap());

        let tbs = x509_cert::TbsCertificate {
            version: x509_cert::Version::V3,
            serial_number: x509_cert::serial_number::SerialNumber::new(&[1]).unwrap(),
            signature: AlgorithmIdentifierOwned {
                oid: sha256_ecdsa,
                parameters: None,
            },
            issuer: RdnSequence::default(),
            validity: x509_cert::time::Validity {
                not_before: nb,
                not_after: na,
            },
            subject: RdnSequence::default(),
            subject_public_key_info: spki::SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: sha256_ecdsa,
                    parameters: None,
                },
                subject_public_key: BitString::from_bytes(&[0u8; 65]).unwrap(),
            },
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: sha256_ecdsa,
                parameters: None,
            },
            signature: BitString::from_bytes(&[0u8; 64]).unwrap(),
        };

        cert.to_der().expect("cert encode failed")
    }

    #[test]
    fn rotation_check_ok() {
        let not_before = der::DateTime::new(2026, 1, 1, 0, 0, 0).unwrap();
        let not_after = der::DateTime::new(2027, 6, 1, 0, 0, 0).unwrap();
        let cert_der = build_test_cert(not_before, not_after);

        let status = check_rotation_needed(&cert_der, 604800).unwrap();
        assert!(
            matches!(status, RotationStatus::Ok { .. }),
            "cert valid until 2027 should be Ok"
        );
    }

    #[test]
    fn rotation_check_expired() {
        let not_before = der::DateTime::new(2020, 1, 1, 0, 0, 0).unwrap();
        let not_after = der::DateTime::new(2021, 1, 1, 0, 0, 0).unwrap();
        let cert_der = build_test_cert(not_before, not_after);

        let status = check_rotation_needed(&cert_der, 604800).unwrap();
        assert_eq!(status, RotationStatus::Expired);
    }

    #[test]
    fn rotation_check_renew_soon() {
        let not_before = der::DateTime::new(2026, 1, 1, 0, 0, 0).unwrap();
        let not_after = der::DateTime::new(2030, 1, 1, 0, 0, 0).unwrap();
        let cert_der = build_test_cert(not_before, not_after);

        // Threshold of 10 years — cert expires within threshold so triggers RenewSoon
        let ten_years_secs = 365 * 24 * 3600 * 10;
        let status = check_rotation_needed(&cert_der, ten_years_secs).unwrap();
        assert!(
            matches!(status, RotationStatus::RenewSoon { .. }),
            "cert within huge threshold should be RenewSoon, got {status:?}"
        );
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn pem_and_der_have_identical_rotation_status_and_invalid_cert_fails() {
        let key = crate::SealKey::EcdsaP256(crate::demo_ecdsa_p256_key());
        let cert = crate::generate_seal_cert_for_key(&key).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&cert);
        let lines = encoded
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let pem = format!("-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n");
        assert_eq!(
            check_rotation_needed(&cert, u64::MAX).unwrap(),
            check_rotation_needed(pem.as_bytes(), u64::MAX).unwrap()
        );
        assert!(check_rotation_needed(b"broken", 3600).is_err());
    }
}
