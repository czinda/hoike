//! On-demand OCSP response signing with a client-supplied nonce.
//!
//! Used by `nonce_policy = "live"` on signer/combined nodes. The signer
//! already has the certificate's status (from the loaded bundle) and the
//! signing key — it re-signs a fresh response with the nonce embedded,
//! without round-tripping to the CA.

use der::asn1::OctetString;
use der::{Decode, Encode};
use sha1::Sha1;
use sha2::Digest;
use signature::Signer;
use spki::{DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding};
use x509_ocsp::builder::OcspResponseBuilder;
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspGeneralizedTime, OcspResponse, ResponderId,
    SingleResponse, ext::Nonce,
};

use crate::error::{Result, SignError};
use crate::generate::ocsp_time;

/// Certificate status for live signing.
#[derive(Debug, Clone)]
pub enum LiveCertStatus {
    Good,
    Revoked {
        revocation_time: u64,
        reason: Option<x509_cert::ext::pkix::CrlReason>,
    },
}

/// Sign a fresh OCSP response on demand with the client's nonce embedded.
///
/// This is the hot path for `nonce_policy = "live"`. It builds a
/// `BasicOCSPResponse` containing one `SingleResponse` for the requested
/// CertID, adds the nonce as a response extension, and signs it.
#[allow(clippy::too_many_arguments)]
pub fn sign_live_response<S, Sig>(
    cert_id_der: &[u8],
    status: LiveCertStatus,
    nonce_bytes: &[u8],
    responder_key_bytes: &[u8],
    signer: &mut S,
    now: u64,
    validity_secs: u64,
    responder_cert_der: Option<&[u8]>,
) -> Result<Vec<u8>>
where
    S: Signer<Sig> + DynSignatureAlgorithmIdentifier,
    Sig: SignatureBitStringEncoding,
{
    let cert_id = CertId::from_der(cert_id_der).map_err(SignError::Der)?;

    let cert_status = match status {
        LiveCertStatus::Good => CertStatus::good(),
        LiveCertStatus::Revoked {
            revocation_time,
            reason,
        } => {
            let revoked_info = x509_ocsp::RevokedInfo {
                revocation_time: ocsp_time(revocation_time)?,
                revocation_reason: reason,
            };
            CertStatus::revoked(revoked_info)
        }
    };

    let this_update = ocsp_time(now)?;
    let next_update = ocsp_time(now + validity_secs)?;
    let produced_at = ocsp_time(now)?;

    let single =
        SingleResponse::new(cert_id, cert_status, this_update).with_next_update(next_update);

    let responder_key_hash = Sha1::digest(responder_key_bytes);
    let responder_id =
        ResponderId::ByKey(OctetString::new(responder_key_hash.to_vec()).map_err(SignError::Der)?);

    let nonce = Nonce::new(nonce_bytes.to_vec()).map_err(SignError::Der)?;

    let builder = OcspResponseBuilder::new(responder_id)
        .with_single_response(single)
        .with_extension(nonce)
        .map_err(|e| SignError::OcspBuilder(e.to_string()))?;

    let certs = responder_cert_der
        .map(|c| {
            let cert = x509_cert::Certificate::from_der(c).map_err(SignError::Der)?;
            Ok::<_, SignError>(vec![cert])
        })
        .transpose()?;
    let ocsp_response = builder
        .sign(signer, certs, produced_at)
        .map_err(SignError::from)?;

    ocsp_response.to_der().map_err(SignError::Der)
}

/// Extract the CertStatus from a pre-signed OCSPResponse's first SingleResponse.
///
/// Used to determine the certificate's status from the bundle before
/// re-signing with a nonce.
pub fn extract_status_from_response(response_der: &[u8]) -> Result<LiveCertStatus> {
    let ocsp_resp = OcspResponse::from_der(response_der).map_err(SignError::Der)?;

    let response_bytes = ocsp_resp
        .response_bytes
        .as_ref()
        .ok_or_else(|| SignError::OcspBuilder("no responseBytes in stored response".into()))?;

    let basic =
        BasicOcspResponse::from_der(response_bytes.response.as_bytes()).map_err(SignError::Der)?;

    let single = basic
        .tbs_response_data
        .responses
        .first()
        .ok_or_else(|| SignError::OcspBuilder("no SingleResponse in stored response".into()))?;

    match &single.cert_status {
        CertStatus::Good(_) => Ok(LiveCertStatus::Good),
        CertStatus::Revoked(info) => {
            let revocation_time = generalized_time_to_epoch(&info.revocation_time);
            Ok(LiveCertStatus::Revoked {
                revocation_time,
                reason: info.revocation_reason,
            })
        }
        CertStatus::Unknown(_) => Ok(LiveCertStatus::Good),
    }
}

fn generalized_time_to_epoch(gt: &OcspGeneralizedTime) -> u64 {
    let dt = gt.0.to_date_time();
    let year = dt.year() as u64;
    let month = dt.month() as u64;
    let day = dt.day() as u64;
    let hour = dt.hour() as u64;
    let minutes = dt.minutes() as u64;
    let seconds = dt.seconds() as u64;

    let mut days: u64 = 0;
    for y in 1970..year {
        days += if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
            366
        } else {
            365
        };
    }
    let mdays = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += mdays[m as usize] as u64;
        if m == 2 && ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0) {
            days += 1;
        }
    }
    days += day - 1;
    days * 86400 + hour * 3600 + minutes * 60 + seconds
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;
    use p256::ecdsa::SigningKey;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes((&[1u8; 32]).into()).unwrap()
    }

    #[test]
    fn sign_live_good_with_nonce() {
        let sha256_oid = const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
        let cert_id = CertId {
            hash_algorithm: spki::AlgorithmIdentifierOwned {
                oid: sha256_oid,
                parameters: Some(der::asn1::Null.into()),
            },
            issuer_name_hash: OctetString::new(vec![0xAA; 32]).unwrap(),
            issuer_key_hash: OctetString::new(vec![0xBB; 32]).unwrap(),
            serial_number: x509_cert::serial_number::SerialNumber::new(&[42u8]).unwrap(),
        };
        let cert_id_der = cert_id.to_der().unwrap();

        let nonce = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];

        let mut key = test_key();
        let resp_der = sign_live_response::<_, p256::ecdsa::DerSignature>(
            &cert_id_der,
            LiveCertStatus::Good,
            &nonce,
            &[0xBB; 32],
            &mut key,
            1700000000,
            86400,
            None,
        )
        .unwrap();

        let resp = OcspResponse::from_der(&resp_der).unwrap();
        assert_eq!(
            resp.response_status,
            x509_ocsp::OcspResponseStatus::Successful
        );

        let basic =
            BasicOcspResponse::from_der(resp.response_bytes.unwrap().response.as_bytes()).unwrap();

        // Verify nonce is in the response
        let resp_nonce = basic.nonce().expect("response should contain nonce");
        assert_eq!(resp_nonce.0.as_bytes(), &nonce);
    }

    #[test]
    fn sign_live_revoked_with_nonce() {
        let sha256_oid = const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
        let cert_id = CertId {
            hash_algorithm: spki::AlgorithmIdentifierOwned {
                oid: sha256_oid,
                parameters: Some(der::asn1::Null.into()),
            },
            issuer_name_hash: OctetString::new(vec![0xAA; 32]).unwrap(),
            issuer_key_hash: OctetString::new(vec![0xBB; 32]).unwrap(),
            serial_number: x509_cert::serial_number::SerialNumber::new(&[100u8]).unwrap(),
        };
        let cert_id_der = cert_id.to_der().unwrap();

        let nonce = vec![0xAA; 16];

        let mut key = test_key();
        let resp_der = sign_live_response::<_, p256::ecdsa::DerSignature>(
            &cert_id_der,
            LiveCertStatus::Revoked {
                revocation_time: 1699900000,
                reason: Some(x509_cert::ext::pkix::CrlReason::KeyCompromise),
            },
            &nonce,
            &[0xBB; 32],
            &mut key,
            1700000000,
            86400,
            None,
        )
        .unwrap();

        let resp = OcspResponse::from_der(&resp_der).unwrap();
        assert_eq!(
            resp.response_status,
            x509_ocsp::OcspResponseStatus::Successful
        );
    }

    #[test]
    fn extract_status_round_trip() {
        let sha256_oid = const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
        let cert_id = CertId {
            hash_algorithm: spki::AlgorithmIdentifierOwned {
                oid: sha256_oid,
                parameters: Some(der::asn1::Null.into()),
            },
            issuer_name_hash: OctetString::new(vec![0xAA; 32]).unwrap(),
            issuer_key_hash: OctetString::new(vec![0xBB; 32]).unwrap(),
            serial_number: x509_cert::serial_number::SerialNumber::new(&[42u8]).unwrap(),
        };
        let cert_id_der = cert_id.to_der().unwrap();

        let mut key = test_key();
        let resp_der = sign_live_response::<_, p256::ecdsa::DerSignature>(
            &cert_id_der,
            LiveCertStatus::Good,
            &[0xFF; 16],
            &[0xBB; 32],
            &mut key,
            1700000000,
            86400,
            None,
        )
        .unwrap();

        let extracted = extract_status_from_response(&resp_der).unwrap();
        assert!(matches!(extracted, LiveCertStatus::Good));
    }
}
