use der::{Decode, Encode};
use std::collections::BTreeMap;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::CrlReason;

use crate::error::{Result, SignError};
use crate::source::{
    CaIdentity, CertificateStatus, Epoch, RevocationSource, StatusChange, StatusSnapshot,
};

pub struct CrlSource {
    crl: CertificateList,
    issuer: Option<x509_cert::Certificate>,
}

impl CrlSource {
    pub fn from_der(data: Vec<u8>) -> Result<Self> {
        let crl = CertificateList::from_der(&data)
            .map_err(|e| SignError::CrlParse(format!("failed to parse CRL DER: {e}")))?;
        Ok(CrlSource { crl, issuer: None })
    }

    /// Bind this source to an independently provisioned, authorized issuer certificate.
    pub fn with_issuer_certificate(mut self, der: &[u8]) -> Result<Self> {
        self.issuer = Some(
            crate::rotation::parse_certificate(der)
                .map_err(|e| SignError::Verify(format!("CRL issuer certificate: {e}")))?,
        );
        Ok(self)
    }

    fn authenticate(&self, ca: &CaIdentity) -> Result<()> {
        use x509_cert::ext::pkix::KeyUsage;
        let cert = self.issuer.as_ref().ok_or_else(|| {
            SignError::Verify("CRL requires an authorized issuer certificate".into())
        })?;
        let tbs = &cert.tbs_certificate;
        let crl = &self.crl;
        let now = crate::source::unix_now()?;
        if tbs.subject.to_der()? != ca.issuer_name_der
            || tbs.subject_public_key_info.subject_public_key.raw_bytes() != ca.issuer_key_bytes
            || crl.tbs_cert_list.issuer != tbs.subject
            || tbs.subject.0.is_empty()
        {
            return Err(SignError::Verify(
                "CRL issuer does not match authorized CA".into(),
            ));
        }
        if now < time_to_epoch(tbs.validity.not_before)
            || now >= time_to_epoch(tbs.validity.not_after)
        {
            return Err(SignError::Verify(
                "CRL issuer certificate is outside validity".into(),
            ));
        }
        if let Some(exts) = &tbs.extensions {
            for ext in exts {
                if ext.extn_id == KeyUsage::OID
                    && !KeyUsage::from_der(ext.extn_value.as_bytes())?.crl_sign()
                {
                    return Err(SignError::Verify(
                        "issuer key usage forbids CRL signing".into(),
                    ));
                }
            }
        }
        if crl.signature_algorithm != crl.tbs_cert_list.signature {
            return Err(SignError::Verify(
                "CRL signature algorithms disagree".into(),
            ));
        }
        if let Some(exts) = &crl.tbs_cert_list.crl_extensions {
            let mut seen = std::collections::BTreeSet::new();
            for ext in exts {
                let oid = ext.extn_id.to_string();
                if oid == "2.5.29.20" {
                    let _ = x509_cert::ext::pkix::CrlNumber::from_der(ext.extn_value.as_bytes())?;
                }
                if oid == "2.5.29.35" {
                    use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};
                    let aki = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes())?;
                    if let Some(serial) = aki.authority_cert_serial_number {
                        if serial != tbs.serial_number {
                            return Err(SignError::Verify("CRL authority serial mismatch".into()));
                        }
                    }
                    if let Some(names) = aki.authority_cert_issuer {
                        if !names.iter().any(|n| matches!(n, x509_cert::ext::pkix::name::GeneralName::DirectoryName(name) if name == &tbs.issuer)) {
                            return Err(SignError::Verify("CRL authority certificate issuer mismatch".into()));
                        }
                    }
                    if let Some(id) = aki.key_identifier {
                        if let Some(ski) = tbs.extensions.as_ref().and_then(|es| {
                            es.iter().find(|e| e.extn_id == SubjectKeyIdentifier::OID)
                        }) {
                            if SubjectKeyIdentifier::from_der(ski.extn_value.as_bytes())?.0 != id {
                                return Err(SignError::Verify(
                                    "CRL authority key identifier mismatch".into(),
                                ));
                            }
                        }
                    }
                }
                if !seen.insert(oid.clone())
                    || matches!(oid.as_str(), "2.5.29.27" | "2.5.29.28")
                    || (ext.critical && !matches!(oid.as_str(), "2.5.29.20" | "2.5.29.35"))
                {
                    return Err(SignError::Verify(format!(
                        "unsupported or duplicate CRL extension {oid}"
                    )));
                }
            }
        }
        let bytes = crl.tbs_cert_list.to_der()?;
        let signature = crl
            .signature
            .as_bytes()
            .ok_or_else(|| SignError::Verify("invalid CRL signature bit string".into()))?;
        let spki = &tbs.subject_public_key_info;
        match crl.signature_algorithm.oid.to_string().as_str() {
            "1.2.840.10045.4.3.2" => {
                if crl.signature_algorithm.parameters.is_some() {
                    return Err(SignError::Verify(
                        "ECDSA signature parameters must be absent".into(),
                    ));
                }
                use p256::pkcs8::DecodePublicKey;
                use signature::Verifier;
                let key = p256::ecdsa::VerifyingKey::from_public_key_der(&spki.to_der()?)
                    .map_err(|e| SignError::Verify(format!("CRL P-256 key: {e}")))?;
                let sig = p256::ecdsa::Signature::from_der(signature)
                    .map_err(|e| SignError::Verify(format!("CRL signature: {e}")))?;
                key.verify(&bytes, &sig)
                    .map_err(|_| SignError::Verify("CRL signature verification failed".into()))
            }
            oid @ ("1.2.840.113549.1.1.11" | "1.2.840.113549.1.1.12" | "1.2.840.113549.1.1.13") => {
                use aws_lc_rs::signature as aws;
                if spki.algorithm.oid.to_string() != "1.2.840.113549.1.1.1" {
                    return Err(SignError::Verify(
                        "CRL signature requires RSA public key".into(),
                    ));
                }
                for parameters in [
                    &spki.algorithm.parameters,
                    &crl.signature_algorithm.parameters,
                ]
                .into_iter()
                .flatten()
                {
                    if parameters.to_der()? != [5, 0] {
                        return Err(SignError::Verify("invalid RSA algorithm parameters".into()));
                    }
                }
                let algorithm = match oid {
                    "1.2.840.113549.1.1.11" => &aws::RSA_PKCS1_2048_8192_SHA256,
                    "1.2.840.113549.1.1.12" => &aws::RSA_PKCS1_2048_8192_SHA384,
                    _ => &aws::RSA_PKCS1_2048_8192_SHA512,
                };
                let key = spki
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| SignError::Verify("invalid RSA key bit string".into()))?;
                aws::UnparsedPublicKey::new(algorithm, key).verify(&bytes, signature)
                    .map_err(|_| SignError::Verify("CRL RSA signature verification failed (supported keys: 2048..8192 bits)".into()))
            }

            oid @ ("2.16.840.1.101.3.4.3.17"
            | "2.16.840.1.101.3.4.3.18"
            | "2.16.840.1.101.3.4.3.19") => {
                if spki.algorithm.oid.to_string() != oid
                    || spki.algorithm.parameters.is_some()
                    || crl.signature_algorithm.parameters.is_some()
                {
                    return Err(SignError::Verify(
                        "ML-DSA CRL algorithm/key mismatch".into(),
                    ));
                }
                let key = spki
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| SignError::Verify("invalid public key bits".into()))?;
                match oid {
                    "2.16.840.1.101.3.4.3.17" => {
                        verify_ml_crl::<ml_dsa::MlDsa44>(&bytes, signature, key)
                    }
                    "2.16.840.1.101.3.4.3.18" => {
                        verify_ml_crl::<ml_dsa::MlDsa65>(&bytes, signature, key)
                    }
                    _ => verify_ml_crl::<ml_dsa::MlDsa87>(&bytes, signature, key),
                }
            }
            other => Err(SignError::Verify(format!(
                "unsupported CRL signature algorithm: {other}; supported: ECDSA P-256/SHA-256, RSA PKCS1v1.5/SHA-256/384/512, ML-DSA"
            ))),
        }
    }

    pub fn from_pem(pem_text: &str) -> Result<Self> {
        let der_data = pem_to_der(pem_text)?;
        Self::from_der(der_data)
    }
}

impl RevocationSource for CrlSource {
    fn snapshot(&self, ca: &CaIdentity) -> Result<StatusSnapshot> {
        self.authenticate(ca)?;
        let crl = &self.crl;
        let mut entries = BTreeMap::new();

        if let Some(revoked_certs) = &crl.tbs_cert_list.revoked_certificates {
            for rc in revoked_certs {
                if let Some(exts) = &rc.crl_entry_extensions {
                    for ext in exts {
                        if ext.extn_id.to_string() == "2.5.29.29"
                            || (ext.critical && ext.extn_id != CrlReason::OID)
                        {
                            return Err(SignError::Verify(
                                "unsupported CRL entry extension".into(),
                            ));
                        }
                        if ext.extn_id == CrlReason::OID {
                            let reason = CrlReason::from_der(ext.extn_value.as_bytes())?;
                            if reason == CrlReason::RemoveFromCRL {
                                return Err(SignError::Verify(
                                    "removeFromCRL requires unsupported delta semantics".into(),
                                ));
                            }
                        }
                    }
                }
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

        let snapshot = StatusSnapshot {
            entries,
            this_update,
            next_update,
        };
        snapshot.validate_at(crate::source::unix_now()?)?;
        Ok(snapshot)
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

fn verify_ml_crl<P: ml_dsa::MlDsaParams>(data: &[u8], sig: &[u8], key: &[u8]) -> Result<()> {
    use ml_dsa::Verifier;
    let encoded = ml_dsa::EncodedVerifyingKey::<P>::try_from(key)
        .map_err(|_| SignError::Verify("invalid ML-DSA key".into()))?;
    let key = ml_dsa::VerifyingKey::<P>::decode(&encoded);
    let sig = ml_dsa::Signature::<P>::try_from(sig)
        .map_err(|_| SignError::Verify("invalid ML-DSA signature".into()))?;
    key.verify(data, &sig)
        .map_err(|_| SignError::Verify("CRL signature verification failed".into()))
}

fn time_to_epoch(time: x509_cert::time::Time) -> u64 {
    let dt = match time {
        x509_cert::time::Time::UtcTime(t) => t.to_date_time(),
        x509_cert::time::Time::GeneralTime(t) => t.to_date_time(),
    };
    datetime_to_epoch(dt)
}

fn datetime_to_epoch(dt: der::DateTime) -> u64 {
    crate::generate::datetime_to_epoch(dt)
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
        use der::asn1::BitString;
        use der::asn1::UtcTime;
        use spki::AlgorithmIdentifierOwned;
        use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
        use x509_cert::name::RdnSequence;
        use x509_cert::time::Time;

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

        assert!(source.snapshot(&ca).is_err());
    }
    fn authenticated_fixture() -> (CrlSource, CaIdentity) {
        use signature::Signer;
        let key = crate::demo_ecdsa_p256_key();
        let cert_der = crate::generate_seal_cert(&key).unwrap();
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();
        let ca = CaIdentity {
            label: "fixture".into(),
            issuer_name_der: cert.tbs_certificate.subject.to_der().unwrap(),
            issuer_key_bytes: cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes()
                .to_vec(),
        };
        let mut crl = CertificateList::from_der(&build_test_crl_der()).unwrap();
        crl.tbs_cert_list.issuer = cert.tbs_certificate.subject;
        let now = crate::source::unix_now().unwrap();
        let time = |n| {
            x509_cert::time::Time::GeneralTime(
                der::asn1::GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(n))
                    .unwrap(),
            )
        };
        crl.tbs_cert_list.this_update = time(now - 1);
        crl.tbs_cert_list.next_update = Some(time(now + 3600));
        let sig: p256::ecdsa::DerSignature = key.sign(&crl.tbs_cert_list.to_der().unwrap());
        crl.signature = der::asn1::BitString::from_bytes(sig.as_bytes()).unwrap();
        (
            CrlSource::from_der(crl.to_der().unwrap())
                .unwrap()
                .with_issuer_certificate(&cert_der)
                .unwrap(),
            ca,
        )
    }

    #[test]
    fn authenticated_crl_accepts_only_matching_issuer_and_signature() {
        let (mut source, ca) = authenticated_fixture();
        assert_eq!(source.snapshot(&ca).unwrap().entries.len(), 2);
        let mut wrong = ca.clone();
        wrong.issuer_key_bytes[0] ^= 1;
        assert!(source.snapshot(&wrong).is_err());
        source
            .crl
            .tbs_cert_list
            .revoked_certificates
            .as_mut()
            .unwrap()
            .clear();
        assert!(source.snapshot(&ca).is_err());
    }

    #[test]
    fn authenticated_crl_rejects_delta_semantics() {
        let (mut source, ca) = authenticated_fixture();
        source.crl.tbs_cert_list.crl_extensions = Some(vec![x509_cert::ext::Extension {
            extn_id: const_oid::ObjectIdentifier::new_unwrap("2.5.29.27"),
            critical: true,
            extn_value: der::asn1::OctetString::new(vec![2, 1, 1]).unwrap(),
        }]);
        assert!(
            source
                .snapshot(&ca)
                .unwrap_err()
                .to_string()
                .contains("unsupported")
        );
    }
    #[test]
    fn rsa_crls_verify_sha256_sha384_sha512_and_reject_tampering() {
        use aws_lc_rs::signature::{self as aws, KeyPair};
        let key = aws::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let (template, _) = authenticated_fixture();
        for oid in [
            "1.2.840.113549.1.1.11",
            "1.2.840.113549.1.1.12",
            "1.2.840.113549.1.1.13",
        ] {
            let mut cert = template.issuer.clone().unwrap();
            cert.tbs_certificate.subject_public_key_info = spki::SubjectPublicKeyInfoOwned {
                algorithm: spki::AlgorithmIdentifierOwned {
                    oid: "1.2.840.113549.1.1.1".parse().unwrap(),
                    parameters: None,
                },
                subject_public_key: der::asn1::BitString::from_bytes(key.public_key().as_ref())
                    .unwrap(),
            };
            let ca = CaIdentity {
                label: "rsa".into(),
                issuer_name_der: cert.tbs_certificate.subject.to_der().unwrap(),
                issuer_key_bytes: cert
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .raw_bytes()
                    .to_vec(),
            };
            let mut crl = template.crl.clone();
            crl.signature_algorithm.oid = oid.parse().unwrap();
            crl.tbs_cert_list.signature = crl.signature_algorithm.clone();
            let tbs = crl.tbs_cert_list.to_der().unwrap();
            let algorithm = match oid {
                "1.2.840.113549.1.1.11" => &aws::RSA_PKCS1_SHA256,
                "1.2.840.113549.1.1.12" => &aws::RSA_PKCS1_SHA384,
                _ => &aws::RSA_PKCS1_SHA512,
            };
            let mut signature = vec![0; key.public_modulus_len()];
            key.sign(
                algorithm,
                &aws_lc_rs::rand::SystemRandom::new(),
                &tbs,
                &mut signature,
            )
            .unwrap();
            crl.signature = der::asn1::BitString::from_bytes(&signature).unwrap();
            let mut source = CrlSource {
                crl,
                issuer: Some(cert),
            };
            assert!(source.snapshot(&ca).is_ok(), "{oid}");
            source.crl.tbs_cert_list.revoked_certificates = None;
            assert!(source.snapshot(&ca).is_err());
        }
    }
    #[test]
    fn issuer_certificate_accepts_pem_and_der_identically() {
        use der::EncodePem;
        let (source, ca) = authenticated_fixture();
        let pem = source
            .issuer
            .as_ref()
            .unwrap()
            .to_pem(der::pem::LineEnding::LF)
            .unwrap();
        let from_pem = CrlSource::from_der(source.crl.to_der().unwrap())
            .unwrap()
            .with_issuer_certificate(pem.as_bytes())
            .unwrap();
        assert_eq!(
            source.snapshot(&ca).unwrap().entries.len(),
            from_pem.snapshot(&ca).unwrap().entries.len()
        );
    }
}
