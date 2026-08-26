//! CMS seal verification for ahu bundles.
//!
//! Verifies the detached CMS SignedData seal over the manifest bytes.
//! This confirms the bundle was produced by a specific signer and has
//! not been tampered with.

#[cfg(feature = "seal-verify")]
mod verify_impl {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::{Decode, Encode};
    use sha2::{Digest, Sha256};

    use crate::error::{AhuError, Result};

    const ID_SIGNED_DATA: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
    const ID_MESSAGE_DIGEST: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

    /// Result of seal verification.
    #[derive(Debug)]
    pub struct SealVerification {
        pub signature_valid: bool,
        pub digest_matches: bool,
        pub signer_subject: String,
    }

    /// Verify a CMS seal against the manifest bytes.
    ///
    /// Checks:
    /// 1. Parses as valid CMS SignedData
    /// 2. The message-digest signed attribute matches SHA-256(manifest_bytes)
    /// 3. The signature over the signed attributes is valid (ECDSA P-256)
    pub fn verify_seal(
        manifest_bytes: &[u8],
        seal_bytes: &[u8],
    ) -> Result<SealVerification> {
        if seal_bytes.is_empty() {
            return Err(AhuError::SealInvalid("seal section is empty".into()));
        }

        // Parse ContentInfo
        let content_info = ContentInfo::from_der(seal_bytes)
            .map_err(|e| AhuError::SealInvalid(format!("parse ContentInfo: {e}")))?;

        if content_info.content_type != ID_SIGNED_DATA {
            return Err(AhuError::SealInvalid(format!(
                "unexpected content type: {}",
                content_info.content_type
            )));
        }

        // Parse SignedData
        let signed_data = content_info
            .content
            .decode_as::<SignedData>()
            .map_err(|e| AhuError::SealInvalid(format!("parse SignedData: {e}")))?;

        // Must have exactly one signer
        let signer_infos = &signed_data.signer_infos.0;
        if signer_infos.is_empty() {
            return Err(AhuError::SealInvalid("no signer infos".into()));
        }
        let signer_info = &signer_infos.as_slice()[0];

        // Verify message-digest attribute matches SHA-256(manifest)
        let manifest_digest = Sha256::digest(manifest_bytes);
        let digest_matches = verify_message_digest(signer_info, &manifest_digest)?;

        if !digest_matches {
            return Err(AhuError::SealInvalid(
                "message-digest attribute does not match manifest hash".into(),
            ));
        }

        // Extract signer certificate
        let cert = extract_signer_cert(&signed_data)
            .ok_or_else(|| AhuError::SealInvalid("no signer certificate in seal".into()))?;

        let signer_subject = format!("{}", cert.tbs_certificate().subject());

        // Verify signature over signed attributes
        let signature_valid = verify_signature(signer_info, cert)?;

        Ok(SealVerification {
            signature_valid,
            digest_matches,
            signer_subject,
        })
    }

    fn verify_message_digest(
        signer_info: &cms::signed_data::SignerInfo,
        expected_digest: &[u8],
    ) -> Result<bool> {
        let attrs = signer_info
            .signed_attrs
            .as_ref()
            .ok_or_else(|| AhuError::SealInvalid("no signed attributes".into()))?;

        for attr in attrs.iter() {
            if attr.oid == ID_MESSAGE_DIGEST {
                for val in attr.values.iter() {
                    let val_der = val
                        .to_der()
                        .map_err(|e| AhuError::SealInvalid(format!("encode attr value: {e}")))?;
                    // The value is an OCTET STRING wrapping the digest
                    if let Ok(octet) = der::asn1::OctetString::from_der(&val_der) {
                        return Ok(octet.as_bytes() == expected_digest);
                    }
                }
            }
        }

        Err(AhuError::SealInvalid(
            "message-digest attribute not found".into(),
        ))
    }

    fn extract_signer_cert(
        signed_data: &SignedData,
    ) -> Option<&x509_cert::certificate::Certificate> {
        let certs = signed_data.certificates.as_ref()?;
        for choice in certs.0.iter() {
            if let cms::cert::CertificateChoices::Certificate(cert) = choice {
                return Some(cert);
            }
        }
        None
    }

    const ID_ECDSA_SHA256_V: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    const ID_ML_DSA_44_V: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
    const ID_ML_DSA_65_V: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
    const ID_ML_DSA_87_V: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

    fn verify_signature(
        signer_info: &cms::signed_data::SignerInfo,
        cert: &x509_cert::certificate::Certificate,
    ) -> Result<bool> {
        let signed_attrs = signer_info
            .signed_attrs
            .as_ref()
            .ok_or_else(|| AhuError::SealInvalid("no signed attrs for verification".into()))?;

        let attrs_der = signed_attrs
            .to_der()
            .map_err(|e| AhuError::SealInvalid(format!("encode signed attrs: {e}")))?;

        let spki = cert.tbs_certificate().subject_public_key_info();
        let pub_key_bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| AhuError::SealInvalid("no public key bits".into()))?;

        let sig_bytes = signer_info.signature.as_bytes();
        let sig_alg_oid = signer_info.signature_algorithm.oid;

        if sig_alg_oid == ID_ECDSA_SHA256_V {
            verify_ecdsa_seal(&attrs_der, sig_bytes, pub_key_bytes)
        } else if sig_alg_oid == ID_ML_DSA_44_V {
            verify_ml_dsa_seal::<ml_dsa::MlDsa44>(&attrs_der, sig_bytes, pub_key_bytes)
        } else if sig_alg_oid == ID_ML_DSA_65_V {
            verify_ml_dsa_seal::<ml_dsa::MlDsa65>(&attrs_der, sig_bytes, pub_key_bytes)
        } else if sig_alg_oid == ID_ML_DSA_87_V {
            verify_ml_dsa_seal::<ml_dsa::MlDsa87>(&attrs_der, sig_bytes, pub_key_bytes)
        } else {
            Err(AhuError::SealInvalid(format!(
                "unsupported seal signature algorithm: {sig_alg_oid}"
            )))
        }
    }

    fn verify_ecdsa_seal(attrs_der: &[u8], sig_bytes: &[u8], pub_key_bytes: &[u8]) -> Result<bool> {
        let attrs_hash = Sha256::digest(attrs_der);

        let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(pub_key_bytes)
            .map_err(|e| AhuError::SealInvalid(format!("parse P-256 public key: {e}")))?;

        let signature = p256::ecdsa::DerSignature::from_bytes(sig_bytes)
            .map_err(|e| AhuError::SealInvalid(format!("parse ECDSA signature: {e}")))?;

        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        match verifying_key.verify_prehash(&attrs_hash, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn verify_ml_dsa_seal<P>(attrs_der: &[u8], sig_bytes: &[u8], pub_key_bytes: &[u8]) -> Result<bool>
    where
        P: ml_dsa::MlDsaParams,
    {
        let encoded = ml_dsa::EncodedVerifyingKey::<P>::try_from(pub_key_bytes)
            .map_err(|_| AhuError::SealInvalid("invalid ML-DSA public key size".into()))?;
        let vk = ml_dsa::VerifyingKey::<P>::decode(&encoded);

        let sig = ml_dsa::Signature::<P>::try_from(sig_bytes)
            .map_err(|_| AhuError::SealInvalid("invalid ML-DSA signature".into()))?;

        use ml_dsa::Verifier;
        match vk.verify(attrs_der, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(feature = "seal-verify")]
pub use verify_impl::{SealVerification, verify_seal};
