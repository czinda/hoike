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
use x509_cert::Certificate as CertificateForLive;

/// Certificate status for live signing.
#[derive(Debug, Clone)]
pub enum LiveCertStatus {
    Good,
    Unknown,
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
    let next = now
        .checked_add(validity_secs)
        .ok_or_else(|| SignError::Config("live validity overflow".into()))?;
    sign_live_response_with_window(
        cert_id_der,
        status,
        nonce_bytes,
        responder_key_bytes,
        signer,
        now,
        now,
        next,
        responder_cert_der,
    )
}

/// Sign only within the authenticated source window; producedAt is signing time,
/// thisUpdate remains the time the source actually established the status.
#[allow(clippy::too_many_arguments)]
pub fn sign_live_response_with_window<S, Sig>(
    cert_id_der: &[u8],
    status: LiveCertStatus,
    nonce_bytes: &[u8],
    responder_key_bytes: &[u8],
    signer: &mut S,
    now: u64,
    source_this_update: u64,
    source_next_update: u64,
    responder_cert_der: Option<&[u8]>,
) -> Result<Vec<u8>>
where
    S: Signer<Sig> + DynSignatureAlgorithmIdentifier,
    Sig: SignatureBitStringEncoding,
{
    if source_this_update > now
        || source_next_update <= now
        || source_next_update <= source_this_update
    {
        return Err(SignError::Config(
            "live source is not currently valid".into(),
        ));
    }
    let mut next_update_epoch = source_next_update;
    if let Some(bytes) = responder_cert_der {
        let cert = CertificateForLive::from_der(bytes).map_err(SignError::Der)?;
        let validity = &cert.tbs_certificate.validity;
        let before = validity.not_before.to_unix_duration().as_secs();
        let after = validity.not_after.to_unix_duration().as_secs();
        if now < before || now >= after {
            return Err(SignError::Config(
                "responder certificate is not currently valid".into(),
            ));
        }
        next_update_epoch = next_update_epoch.min(after);
    }
    let cert_id = CertId::from_der(cert_id_der).map_err(SignError::Der)?;

    let cert_status = match status {
        LiveCertStatus::Good => CertStatus::good(),
        LiveCertStatus::Unknown => CertStatus::unknown(),
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

    let this_update = ocsp_time(source_this_update)?;
    let next_update = ocsp_time(next_update_epoch)?;
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

/// Validated software-key material, shared by startup and rotation.
pub struct LiveSigningMaterial {
    pub key: p256::ecdsa::SigningKey,
    pub responder_key_bytes: Vec<u8>,
    pub responder_cert_der: Option<Vec<u8>>,
}

pub fn load_live_material(
    ca: &hoike_core::config::CaConfig,
) -> std::result::Result<LiveSigningMaterial, String> {
    use hoike_core::config::SigningKeyConfig;
    let key = match &ca.signing_key {
        Some(SigningKeyConfig::File { path }) => {
            crate::load_ecdsa_p256_key(path).map_err(|e| e.to_string())?
        }
        Some(SigningKeyConfig::Demo) => crate::demo_ecdsa_p256_key(),
        _ => return Err("live signing requires an ECDSA file or explicit demo key".into()),
    };
    let cert_der = crate::orchestrate::load_responder_cert(ca)?;
    let responder_key_bytes = if let Some(bytes) = &cert_der {
        let cert = CertificateForLive::from_der(bytes).map_err(|e| e.to_string())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        if now
            < cert
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs()
            || now
                >= cert
                    .tbs_certificate
                    .validity
                    .not_after
                    .to_unix_duration()
                    .as_secs()
        {
            return Err("live responder certificate is outside its validity period".into());
        }
        let bytes = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| "responder public key has unused bits".to_string())?;
        let certificate_key =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes).map_err(|e| e.to_string())?;
        if certificate_key != *key.verifying_key() {
            return Err("live signing key does not match responder certificate".into());
        }
        bytes.to_vec()
    } else {
        let bytes = crate::orchestrate::decode_issuer_key(ca)?;
        if !matches!(ca.signing_key, Some(SigningKeyConfig::Demo)) {
            let issuer_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes)
                .map_err(|e| format!("CA-direct issuer key: {e}"))?;
            if issuer_key != *key.verifying_key() {
                return Err("CA-direct signing key does not match issuer key".into());
            }
        }
        bytes
    };
    Ok(LiveSigningMaterial {
        key,
        responder_key_bytes,
        responder_cert_der: cert_der,
    })
}

/// Status and authenticated freshness from exactly one matching SingleResponse.
pub struct LiveResponseSource {
    pub status: LiveCertStatus,
    pub this_update: u64,
    pub next_update: u64,
}

pub fn extract_status_for_cert(
    response_der: &[u8],
    cert_id_der: &[u8],
) -> Result<LiveResponseSource> {
    let requested = CertId::from_der(cert_id_der).map_err(SignError::Der)?;
    let basic = parse_basic(response_der)?;
    let mut matches = basic
        .tbs_response_data
        .responses
        .iter()
        .filter(|r| r.cert_id == requested);
    let single = matches
        .next()
        .ok_or_else(|| SignError::OcspBuilder("requested CertID absent from response".into()))?;
    if matches.next().is_some() {
        return Err(SignError::OcspBuilder(
            "ambiguous duplicate CertID in response".into(),
        ));
    }
    let next = single
        .next_update
        .as_ref()
        .ok_or_else(|| SignError::OcspBuilder("live source requires nextUpdate".into()))?;
    Ok(LiveResponseSource {
        status: status_from_single(single),
        this_update: generalized_time_to_epoch(&single.this_update),
        next_update: generalized_time_to_epoch(next),
    })
}

fn parse_basic(response_der: &[u8]) -> Result<BasicOcspResponse> {
    let response = OcspResponse::from_der(response_der).map_err(SignError::Der)?;
    if response.response_status != x509_ocsp::OcspResponseStatus::Successful {
        return Err(SignError::OcspBuilder(
            "source OCSP response was not successful".into(),
        ));
    }
    let bytes = response
        .response_bytes
        .ok_or_else(|| SignError::OcspBuilder("missing responseBytes".into()))?;
    if bytes.response_type.to_string() != "1.3.6.1.5.5.7.48.1.1" {
        return Err(SignError::OcspBuilder("unsupported response type".into()));
    }
    BasicOcspResponse::from_der(bytes.response.as_bytes()).map_err(SignError::Der)
}

fn status_from_single(single: &SingleResponse) -> LiveCertStatus {
    match &single.cert_status {
        CertStatus::Good(_) => LiveCertStatus::Good,
        CertStatus::Unknown(_) => LiveCertStatus::Unknown,
        CertStatus::Revoked(info) => LiveCertStatus::Revoked {
            revocation_time: generalized_time_to_epoch(&info.revocation_time),
            reason: info.revocation_reason,
        },
    }
}

/// Diagnostic compatibility API. Batched sources require explicit CertID selection.
pub fn extract_status_from_response(response_der: &[u8]) -> Result<LiveCertStatus> {
    let basic = parse_basic(response_der)?;
    if basic.tbs_response_data.responses.len() != 1 {
        return Err(SignError::OcspBuilder(
            "CertID required for a batched response".into(),
        ));
    }
    Ok(status_from_single(&basic.tbs_response_data.responses[0]))
}

fn generalized_time_to_epoch(gt: &OcspGeneralizedTime) -> u64 {
    gt.0.to_unix_duration().as_secs()
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
