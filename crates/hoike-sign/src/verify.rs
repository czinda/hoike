//! OCSP response signature verification.
//!
//! Verifies the signature on a DER-encoded `OcspResponse` by parsing the
//! `BasicOcspResponse`, extracting the signer's public key from the embedded
//! certificate chain, and dispatching to the correct verifier based on the
//! `signatureAlgorithm` OID.

use der::{Decode, Encode};
use x509_ocsp::{BasicOcspResponse, OcspResponse, OcspResponseStatus};

use crate::error::{Result, SignError};
use crate::ml_dsa_bridge::{ML_DSA_44_OID, ML_DSA_65_OID, ML_DSA_87_OID};

const ECDSA_WITH_SHA256_OID: &str = "1.2.840.10045.4.3.2";

/// Verify the signature on a DER-encoded `OcspResponse`.
///
/// Extracts the `BasicOcspResponse`, re-encodes the `tbsResponseData` to DER,
/// and verifies the signature using the public key from the first embedded
/// certificate. Returns `Ok(())` if the signature is valid.
pub fn verify_ocsp_response_signature(response_der: &[u8]) -> Result<()> {
    let ocsp_resp =
        OcspResponse::from_der(response_der).map_err(|e| SignError::Verify(format!("parse OcspResponse: {e}")))?;

    if ocsp_resp.response_status != OcspResponseStatus::Successful {
        return Ok(());
    }

    let response_bytes = ocsp_resp
        .response_bytes
        .ok_or_else(|| SignError::Verify("successful response has no responseBytes".into()))?;

    let basic = BasicOcspResponse::from_der(response_bytes.response.as_bytes())
        .map_err(|e| SignError::Verify(format!("parse BasicOcspResponse: {e}")))?;

    let tbs_der = basic
        .tbs_response_data
        .to_der()
        .map_err(|e| SignError::Verify(format!("re-encode tbsResponseData: {e}")))?;

    let sig_bytes = basic.signature.raw_bytes();

    let sig_alg_oid = basic.signature_algorithm.oid.to_string();

    let pub_key_bytes = extract_public_key(&basic)?;

    match sig_alg_oid.as_str() {
        ECDSA_WITH_SHA256_OID => verify_ecdsa_p256(&tbs_der, sig_bytes, &pub_key_bytes),
        ML_DSA_44_OID => verify_ml_dsa::<ml_dsa::MlDsa44>(&tbs_der, sig_bytes, &pub_key_bytes),
        ML_DSA_65_OID => verify_ml_dsa::<ml_dsa::MlDsa65>(&tbs_der, sig_bytes, &pub_key_bytes),
        ML_DSA_87_OID => verify_ml_dsa::<ml_dsa::MlDsa87>(&tbs_der, sig_bytes, &pub_key_bytes),
        other => Err(SignError::Verify(format!("unsupported signature algorithm: {other}"))),
    }
}

fn extract_public_key(basic: &BasicOcspResponse) -> Result<Vec<u8>> {
    let cert = basic
        .certs
        .as_ref()
        .and_then(|c| c.first())
        .ok_or(SignError::NoCert)?;

    let raw = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    Ok(raw.to_vec())
}

fn verify_ecdsa_p256(tbs_der: &[u8], sig_bytes: &[u8], pub_key_bytes: &[u8]) -> Result<()> {
    use p256::ecdsa::{DerSignature, VerifyingKey};
    use signature::Verifier;

    let vk = VerifyingKey::from_sec1_bytes(pub_key_bytes)
        .map_err(|e| SignError::Verify(format!("invalid P-256 public key: {e}")))?;

    let sig = DerSignature::try_from(sig_bytes)
        .map_err(|e| SignError::Verify(format!("invalid ECDSA DER signature: {e}")))?;

    vk.verify(tbs_der, &sig)
        .map_err(|_| SignError::Verify("ECDSA-P256 signature verification failed".into()))
}

fn verify_ml_dsa<P>(tbs_der: &[u8], sig_bytes: &[u8], pub_key_bytes: &[u8]) -> Result<()>
where
    P: ml_dsa::MlDsaParams,
{
    use ml_dsa::Verifier;

    let encoded = ml_dsa::EncodedVerifyingKey::<P>::try_from(pub_key_bytes)
        .map_err(|_| SignError::Verify(format!("invalid ML-DSA public key (expected {} bytes)", std::mem::size_of::<ml_dsa::EncodedVerifyingKey<P>>())))?;

    let vk = ml_dsa::VerifyingKey::<P>::decode(&encoded);

    let sig = ml_dsa::Signature::<P>::try_from(sig_bytes)
        .map_err(|_| SignError::Verify("invalid ML-DSA signature".into()))?;

    vk.verify(tbs_der, &sig)
        .map_err(|_| SignError::Verify("ML-DSA signature verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_ecdsa_bundle_entries() {
        use crate::{
            demo_ecdsa_p256_key, generate::GenerationConfig, produce_bundle, seal::generate_seal_cert,
            source::{CaIdentity, CertificateStatus, StatusSnapshot},
        };
        use std::collections::BTreeMap;

        let mut signer = demo_ecdsa_p256_key();
        let seal_key = crate::SealKey::EcdsaP256(demo_ecdsa_p256_key());
        let seal_cert = crate::generate_seal_cert_for_key(&seal_key).unwrap();
        let responder_cert = generate_seal_cert(&signer).unwrap();

        let ca = CaIdentity {
            label: "test-ca".into(),
            issuer_name_der: b"CN=Test CA".to_vec(),
            issuer_key_bytes: vec![0x42; 32],
        };

        let mut entries = BTreeMap::new();
        entries.insert(vec![0x01], CertificateStatus::Good);
        entries.insert(vec![0x02], CertificateStatus::Good);
        let snapshot = StatusSnapshot {
            entries,
            this_update: 1700000000,
            next_update: None,
        };

        let config = GenerationConfig {
            producer_id: "test".into(),
            epoch: 1,
            ..Default::default()
        };

        let bundle_bytes = produce_bundle::<_, p256::ecdsa::DerSignature>(
            &ca, &snapshot, &config, &mut signer,
            |m| crate::create_cms_seal(m, &seal_key, &seal_cert),
            Some(&responder_cert),
        )
        .unwrap();

        let bundle = ahu::Bundle::from_bytes(&bundle_bytes).unwrap();
        let mut count = 0;
        for record in &bundle.index {
            if let Some(entry_bytes) = bundle.entry_bytes(record) {
                verify_ocsp_response_signature(entry_bytes).unwrap();
                count += 1;
            }
        }
        assert!(count >= 2);
    }

    #[test]
    fn verify_ml_dsa_signature_direct() {
        use ml_dsa::{MlDsa87, SigningKey, Signer as Signer3, Keypair};
        use ml_dsa::SignatureEncoding as SE3;

        let sk = SigningKey::<MlDsa87>::from_seed((&[42u8; 32]).into());
        let vk = sk.verifying_key();
        let msg = b"test message for ML-DSA verification";

        let sig = sk.sign(msg);
        let sig_bytes = sig.encode();
        let vk_encoded = vk.encode();

        verify_ml_dsa::<MlDsa87>(msg, sig_bytes.as_ref(), vk_encoded.as_ref()).unwrap();
    }

    #[test]
    fn verify_ml_dsa_44_signature_direct() {
        use ml_dsa::{MlDsa44, SigningKey, Signer as Signer3, Keypair};
        use ml_dsa::SignatureEncoding as SE3;

        let sk = SigningKey::<MlDsa44>::from_seed((&[1u8; 32]).into());
        let vk = sk.verifying_key();
        let msg = b"ML-DSA-44 verification test";

        let sig = sk.sign(msg);
        let sig_bytes = sig.encode();
        let vk_encoded = vk.encode();

        verify_ml_dsa::<MlDsa44>(msg, sig_bytes.as_ref(), vk_encoded.as_ref()).unwrap();
    }

    #[test]
    fn verify_wrong_message_fails() {
        use ml_dsa::{MlDsa65, SigningKey, Signer as Signer3, Keypair};
        use ml_dsa::SignatureEncoding as SE3;

        let sk = SigningKey::<MlDsa65>::from_seed((&[5u8; 32]).into());
        let vk = sk.verifying_key();

        let sig = sk.sign(b"correct message");
        let sig_bytes = sig.encode();
        let vk_encoded = vk.encode();

        let result = verify_ml_dsa::<MlDsa65>(b"wrong message", sig_bytes.as_ref(), vk_encoded.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn verify_no_embedded_cert_errors() {
        use crate::{
            demo_ecdsa_p256_key, generate::GenerationConfig, produce_bundle, seal::generate_seal_cert,
            source::{CaIdentity, CertificateStatus, StatusSnapshot},
        };
        use std::collections::BTreeMap;

        let mut signer = demo_ecdsa_p256_key();
        let seal_key = crate::SealKey::EcdsaP256(demo_ecdsa_p256_key());
        let seal_cert = crate::generate_seal_cert_for_key(&seal_key).unwrap();

        let ca = CaIdentity {
            label: "test".into(),
            issuer_name_der: b"CN=Test".to_vec(),
            issuer_key_bytes: vec![0x42; 32],
        };

        let mut entries = BTreeMap::new();
        entries.insert(vec![0x01], CertificateStatus::Good);
        let snapshot = StatusSnapshot { entries, this_update: 1700000000, next_update: None };
        let config = GenerationConfig { producer_id: "test".into(), epoch: 1, ..Default::default() };

        let bundle_bytes = produce_bundle::<_, p256::ecdsa::DerSignature>(
            &ca, &snapshot, &config, &mut signer,
            |m| crate::create_cms_seal(m, &seal_key, &seal_cert),
            None,
        ).unwrap();

        let bundle = ahu::Bundle::from_bytes(&bundle_bytes).unwrap();
        for record in &bundle.index {
            if let Some(entry_bytes) = bundle.entry_bytes(record) {
                let result = verify_ocsp_response_signature(entry_bytes);
                assert!(result.is_err());
                assert!(matches!(result.unwrap_err(), crate::error::SignError::NoCert));
            }
        }
    }
}
