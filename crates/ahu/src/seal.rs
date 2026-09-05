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
        pub signer_sha256: String,
    }

    /// Verify a CMS seal against the manifest bytes.
    ///
    /// Checks:
    /// 1. Parses as valid CMS SignedData
    /// 2. The message-digest signed attribute matches SHA-256(manifest_bytes)
    /// 3. The signature over the signed attributes is valid (ECDSA P-256)
    pub fn verify_seal(manifest_bytes: &[u8], seal_bytes: &[u8]) -> Result<SealVerification> {
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
        if signer_infos.len() != 1 {
            return Err(AhuError::SealInvalid(
                "exactly one signer is required".into(),
            ));
        }
        let signer_info = &signer_infos.as_slice()[0];
        let sha256 = der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
        if signer_info.digest_alg.oid != sha256
            || signed_data.digest_algorithms.len() != 1
            || signed_data.digest_algorithms.as_slice()[0].oid != sha256
        {
            return Err(AhuError::SealInvalid(
                "only SHA-256 digest attributes are supported".into(),
            ));
        }
        let data_oid = der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
        if signed_data.encap_content_info.econtent_type != data_oid
            || signed_data.encap_content_info.econtent.is_some()
        {
            return Err(AhuError::SealInvalid(
                "expected detached CMS data content".into(),
            ));
        }
        let content_oid = der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
        let attrs = signer_info
            .signed_attrs
            .as_ref()
            .ok_or_else(|| AhuError::SealInvalid("missing signed attributes".into()))?;
        let content_attrs: Vec<_> = attrs.iter().filter(|a| a.oid == content_oid).collect();
        if content_attrs.len() != 1
            || content_attrs[0].values.len() != 1
            || content_attrs[0].values.as_slice()[0]
                .decode_as::<der::asn1::ObjectIdentifier>()
                .ok()
                != Some(data_oid)
        {
            return Err(AhuError::SealInvalid(
                "invalid content-type attribute".into(),
            ));
        }

        // Verify message-digest attribute matches SHA-256(manifest)
        let manifest_digest = Sha256::digest(manifest_bytes);
        let digest_matches = verify_message_digest(signer_info, &manifest_digest)?;

        if !digest_matches {
            return Err(AhuError::SealInvalid(
                "message-digest attribute does not match manifest hash".into(),
            ));
        }

        // Extract signer certificate
        let cert = extract_signer_cert(&signed_data)?;

        let signer_subject = format!("{}", cert.tbs_certificate().subject());

        // Verify signature over signed attributes
        let signature_valid = verify_signature(signer_info, cert)?;
        if !signature_valid {
            return Err(AhuError::SealInvalid("invalid CMS signature".into()));
        }
        let signer_sha256 = hex::encode(Sha256::digest(
            cert.to_der()
                .map_err(|e| AhuError::SealInvalid(e.to_string()))?,
        ));

        Ok(SealVerification {
            signature_valid,
            digest_matches,
            signer_subject,
            signer_sha256,
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

        let matches: Vec<_> = attrs
            .iter()
            .filter(|a| a.oid == ID_MESSAGE_DIGEST)
            .collect();
        if matches.len() != 1 || matches[0].values.len() != 1 {
            return Err(AhuError::SealInvalid(
                "exactly one message-digest value required".into(),
            ));
        }
        let octet = matches[0].values.as_slice()[0]
            .decode_as::<der::asn1::OctetString>()
            .map_err(|e| AhuError::SealInvalid(format!("invalid digest attribute: {e}")))?;
        Ok(octet.as_bytes() == expected_digest)
    }

    fn extract_signer_cert(
        signed_data: &SignedData,
    ) -> Result<&x509_cert::certificate::Certificate> {
        use cms::signed_data::SignerIdentifier;
        use x509_cert::ext::pkix::SubjectKeyIdentifier;
        let signer = signed_data
            .signer_infos
            .0
            .as_slice()
            .first()
            .ok_or_else(|| AhuError::SealInvalid("missing signer".into()))?;
        let certs = signed_data
            .certificates
            .as_ref()
            .ok_or_else(|| AhuError::SealInvalid("missing certificates".into()))?;
        let mut found = None;
        for choice in certs.0.iter() {
            if let cms::cert::CertificateChoices::Certificate(cert) = choice {
                let tbs = cert.tbs_certificate();
                let matches = match &signer.sid {
                    SignerIdentifier::IssuerAndSerialNumber(id) => {
                        &id.issuer == tbs.issuer() && &id.serial_number == tbs.serial_number()
                    }
                    SignerIdentifier::SubjectKeyIdentifier(id) => tbs
                        .get_extension::<SubjectKeyIdentifier>()
                        .ok()
                        .flatten()
                        .is_some_and(|(_, ski)| &ski == id),
                };
                if matches {
                    if found.is_some() {
                        return Err(AhuError::SealInvalid("ambiguous signer certificate".into()));
                    }
                    found = Some(cert);
                }
            }
        }
        found.ok_or_else(|| {
            AhuError::SealInvalid("signer identifier has no matching certificate".into())
        })
    }

    /// Authenticate a seal with a deliberately bounded certificate profile:
    /// ECDSA-P256 or ML-DSA signer directly issued by a configured CA anchor,
    /// or the configured CA itself. Intermediate paths and extensions whose
    /// semantics are not implemented fail closed. This is not general PKIX.
    pub fn verify_seal_with_anchors(
        manifest: &[u8],
        seal: &[u8],
        anchors_der: &[Vec<u8>],
        now: u64,
    ) -> Result<SealVerification> {
        use x509_cert::certificate::Certificate;
        let verification = verify_seal(manifest, seal)?;
        let ci = ContentInfo::from_der(seal).map_err(|e| AhuError::SealInvalid(e.to_string()))?;
        let sd = ci
            .content
            .decode_as::<SignedData>()
            .map_err(|e| AhuError::SealInvalid(e.to_string()))?;
        let signer = extract_signer_cert(&sd)?;
        validate_cert_profile(signer, now, false)?;
        if anchors_der.is_empty() {
            return Err(AhuError::SealInvalid("no trust anchors".into()));
        }
        let anchors = anchors_der
            .iter()
            .map(|bytes| {
                Certificate::from_der(bytes)
                    .map_err(|e| AhuError::SealInvalid(format!("invalid trust anchor: {e}")))
            })
            .collect::<Result<Vec<_>>>()?;
        for anchor in &anchors {
            validate_cert_profile(anchor, now, true)?;
        }
        for anchor in &anchors {
            if signer == anchor {
                return Ok(verification);
            }
            if signer.tbs_certificate().issuer() != anchor.tbs_certificate().subject() {
                continue;
            }
            if signer.signature_algorithm() != signer.tbs_certificate().signature() {
                return Err(AhuError::SealInvalid(
                    "certificate signature algorithms disagree".into(),
                ));
            }
            let bytes = signer
                .tbs_certificate()
                .to_der()
                .map_err(|e| AhuError::SealInvalid(e.to_string()))?;
            let sig = signer.signature().as_bytes().ok_or_else(|| {
                AhuError::SealInvalid("invalid certificate signature bits".into())
            })?;
            if verify_bytes(&bytes, sig, signer.signature_algorithm().oid, anchor)? {
                return Ok(verification);
            }
        }
        Err(AhuError::SealInvalid("signer is not directly issued by a configured CA trust anchor (intermediate paths unsupported)".into()))
    }

    /// Authenticate an explicitly pinned end-entity signing certificate.
    /// Pins are exact DER certificate matches, not CA trust anchors.
    pub fn verify_seal_with_pins(
        manifest: &[u8],
        seal: &[u8],
        pins_der: &[Vec<u8>],
        now: u64,
    ) -> Result<SealVerification> {
        let verification = verify_seal(manifest, seal)?;
        let ci = ContentInfo::from_der(seal).map_err(|e| AhuError::SealInvalid(e.to_string()))?;
        let sd = ci
            .content
            .decode_as::<SignedData>()
            .map_err(|e| AhuError::SealInvalid(e.to_string()))?;
        let signer = extract_signer_cert(&sd)?;
        validate_cert_profile(signer, now, false)?;
        let signer_der = signer
            .to_der()
            .map_err(|e| AhuError::SealInvalid(e.to_string()))?;
        // Decode and canonicalize configured certificates as CMS does. The
        // X.509 codec normalizes Time encodings (including legacy demo certs).
        let pins = pins_der
            .iter()
            .map(|pin| {
                x509_cert::certificate::Certificate::from_der(pin)
                    .and_then(|cert| cert.to_der())
                    .map_err(|e| AhuError::SealInvalid(format!("invalid signer pin: {e}")))
            })
            .collect::<Result<Vec<_>>>()?;
        if !pins.iter().any(|pin| pin == &signer_der) {
            return Err(AhuError::SealInvalid(
                "signer certificate does not match an explicit pin".into(),
            ));
        }
        Ok(verification)
    }

    fn validate_cert_profile(
        cert: &x509_cert::certificate::Certificate,
        now: u64,
        ca: bool,
    ) -> Result<()> {
        use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
        let tbs = cert.tbs_certificate();
        let validity = tbs.validity();
        if now < validity.not_before.to_unix_duration().as_secs()
            || now >= validity.not_after.to_unix_duration().as_secs()
        {
            return Err(AhuError::SealInvalid(
                "certificate outside validity period".into(),
            ));
        }
        if let Some(exts) = tbs.extensions() {
            let mut seen = std::collections::HashSet::new();
            for ext in exts {
                let oid = ext.extn_id.to_string();
                if !seen.insert(oid.clone()) {
                    return Err(AhuError::SealInvalid(
                        "duplicate certificate extension".into(),
                    ));
                }
                // Reject constraints/EKU/policy extensions even when marked noncritical:
                // ignoring their scope could expand authorization.
                if !matches!(
                    oid.as_str(),
                    "2.5.29.14" | "2.5.29.15" | "2.5.29.19" | "2.5.29.35"
                ) {
                    return Err(AhuError::SealInvalid(format!(
                        "unsupported seal certificate extension {oid}"
                    )));
                }
            }
        }
        let usage = tbs
            .get_extension::<KeyUsage>()
            .map_err(|e| AhuError::SealInvalid(e.to_string()))?;
        if usage.is_some_and(|(_, ku)| {
            if ca {
                !ku.key_cert_sign()
            } else {
                !ku.digital_signature()
            }
        }) {
            return Err(AhuError::SealInvalid(
                "certificate key usage does not permit operation".into(),
            ));
        }
        if ca
            && !tbs
                .get_extension::<BasicConstraints>()
                .map_err(|e| AhuError::SealInvalid(e.to_string()))?
                .is_some_and(|(_, bc)| bc.ca)
        {
            return Err(AhuError::SealInvalid(
                "trust anchor must be a CA certificate; signer pins are a separate policy".into(),
            ));
        }
        Ok(())
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

        verify_bytes(
            &attrs_der,
            signer_info.signature.as_bytes(),
            signer_info.signature_algorithm.oid,
            cert,
        )
    }

    fn verify_bytes(
        bytes: &[u8],
        sig_bytes: &[u8],
        sig_alg_oid: der::asn1::ObjectIdentifier,
        cert: &x509_cert::certificate::Certificate,
    ) -> Result<bool> {
        let spki = cert.tbs_certificate().subject_public_key_info();
        let pub_key_bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| AhuError::SealInvalid("no public key bits".into()))?;
        if sig_alg_oid == ID_ECDSA_SHA256_V {
            let ec = der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
            let curve = der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
            if spki.algorithm.oid != ec
                || spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
                    != Some(curve)
            {
                return Err(AhuError::SealInvalid("expected P-256 key algorithm".into()));
            }
            verify_ecdsa_seal(bytes, sig_bytes, pub_key_bytes)
        } else if sig_alg_oid == ID_ML_DSA_44_V && spki.algorithm.oid == sig_alg_oid {
            verify_ml_dsa_seal::<ml_dsa::MlDsa44>(bytes, sig_bytes, pub_key_bytes)
        } else if sig_alg_oid == ID_ML_DSA_65_V && spki.algorithm.oid == sig_alg_oid {
            verify_ml_dsa_seal::<ml_dsa::MlDsa65>(bytes, sig_bytes, pub_key_bytes)
        } else if sig_alg_oid == ID_ML_DSA_87_V && spki.algorithm.oid == sig_alg_oid {
            verify_ml_dsa_seal::<ml_dsa::MlDsa87>(bytes, sig_bytes, pub_key_bytes)
        } else {
            Err(AhuError::SealInvalid(format!(
                "unsupported/mismatched signature algorithm {sig_alg_oid}"
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

    fn verify_ml_dsa_seal<P>(
        attrs_der: &[u8],
        sig_bytes: &[u8],
        pub_key_bytes: &[u8],
    ) -> Result<bool>
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
pub use verify_impl::{
    SealVerification, verify_seal, verify_seal_with_anchors, verify_seal_with_pins,
};
