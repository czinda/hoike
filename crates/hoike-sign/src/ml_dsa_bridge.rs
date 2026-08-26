//! Bridge between ml-dsa (signature v3) and x509-ocsp (signature v2).
//!
//! `produce_bundle` requires `Signer<Sig> + DynSignatureAlgorithmIdentifier`
//! from signature v2 / spki v0.7. The ml-dsa crate implements signature v3.
//! This module wraps the v3 types to satisfy v2 trait bounds.

use ml_dsa as mldsa;

/// Wrapper around ml-dsa `SigningKey` implementing signature v2 traits.
pub struct MlDsaSigner<P: mldsa::MlDsaParams> {
    inner: mldsa::SigningKey<P>,
    sig_alg_oid: const_oid::ObjectIdentifier,
}

/// Wrapper around raw signature bytes implementing v2 `SignatureBitStringEncoding`.
#[derive(Clone)]
pub struct MlDsaSignatureBytes {
    bytes: Vec<u8>,
}

impl From<MlDsaSignatureBytes> for Vec<u8> {
    fn from(sig: MlDsaSignatureBytes) -> Vec<u8> {
        sig.bytes
    }
}

pub const ML_DSA_44_OID: &str = "2.16.840.1.101.3.4.3.17";
pub const ML_DSA_65_OID: &str = "2.16.840.1.101.3.4.3.18";
pub const ML_DSA_87_OID: &str = "2.16.840.1.101.3.4.3.19";

impl<P: mldsa::MlDsaParams> MlDsaSigner<P> {
    pub fn new(inner: mldsa::SigningKey<P>, oid_str: &str) -> Self {
        let sig_alg_oid = const_oid::ObjectIdentifier::new_unwrap(oid_str);
        MlDsaSigner { inner, sig_alg_oid }
    }
}

// ── signature v2 Signer ──────────────────────────────────────────

impl<P> signature::Signer<MlDsaSignatureBytes> for MlDsaSigner<P>
where
    P: mldsa::MlDsaParams,
    mldsa::SigningKey<P>: mldsa::Signer<mldsa::Signature<P>>,
{
    fn try_sign(&self, msg: &[u8]) -> Result<MlDsaSignatureBytes, signature::Error> {
        use mldsa::Signer as Signer3;
        let sig: mldsa::Signature<P> = self
            .inner
            .try_sign(msg)
            .map_err(|_| signature::Error::new())?;
        use mldsa::SignatureEncoding;
        let repr = sig.to_bytes();
        let slice: &[u8] = repr.as_ref();
        Ok(MlDsaSignatureBytes {
            bytes: slice.to_vec(),
        })
    }
}

// ── signature v2 SignatureEncoding ────────────────────────────────

impl signature::SignatureEncoding for MlDsaSignatureBytes {
    type Repr = Vec<u8>;
}

impl TryFrom<&[u8]> for MlDsaSignatureBytes {
    type Error = signature::Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(MlDsaSignatureBytes {
            bytes: bytes.to_vec(),
        })
    }
}

impl AsRef<[u8]> for MlDsaSignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// ── spki v0.7 SignatureBitStringEncoding ──────────────────────────

impl spki::SignatureBitStringEncoding for MlDsaSignatureBytes {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        der::asn1::BitString::from_bytes(&self.bytes)
    }
}

// ── spki v0.7 DynSignatureAlgorithmIdentifier ────────────────────

impl<P> spki::DynSignatureAlgorithmIdentifier for MlDsaSigner<P>
where
    P: mldsa::MlDsaParams,
    mldsa::SigningKey<P>: mldsa::Signer<mldsa::Signature<P>>,
{
    fn signature_algorithm_identifier(&self) -> spki::Result<spki::AlgorithmIdentifierOwned> {
        Ok(spki::AlgorithmIdentifierOwned {
            oid: self.sig_alg_oid,
            parameters: None,
        })
    }
}

// ── Constructors ─────────────────────────────────────────────────

pub fn ml_dsa_44_signer(seed: &[u8; 32]) -> MlDsaSigner<mldsa::MlDsa44> {
    let sk = mldsa::SigningKey::<mldsa::MlDsa44>::from_seed(seed.into());
    MlDsaSigner::new(sk, ML_DSA_44_OID)
}

pub fn ml_dsa_65_signer(seed: &[u8; 32]) -> MlDsaSigner<mldsa::MlDsa65> {
    let sk = mldsa::SigningKey::<mldsa::MlDsa65>::from_seed(seed.into());
    MlDsaSigner::new(sk, ML_DSA_65_OID)
}

pub fn ml_dsa_87_signer(seed: &[u8; 32]) -> MlDsaSigner<mldsa::MlDsa87> {
    let sk = mldsa::SigningKey::<mldsa::MlDsa87>::from_seed(seed.into());
    MlDsaSigner::new(sk, ML_DSA_87_OID)
}

/// Signer variant that dispatches to the correct ML-DSA parameter set.
/// Returned by [`load_ml_dsa_signer_from_pkcs8_der`] when the parameter set
/// is auto-detected from the PKCS#8 AlgorithmIdentifier OID.
pub enum MlDsaSignerVariant {
    MlDsa44(MlDsaSigner<mldsa::MlDsa44>),
    MlDsa65(MlDsaSigner<mldsa::MlDsa65>),
    MlDsa87(MlDsaSigner<mldsa::MlDsa87>),
}

impl MlDsaSignerVariant {
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::MlDsa44(_) => "ml-dsa-44",
            Self::MlDsa65(_) => "ml-dsa-65",
            Self::MlDsa87(_) => "ml-dsa-87",
        }
    }

    /// Construct a demo signer with a random seed for the given algorithm name.
    pub fn demo(sig_alg: &str) -> std::result::Result<Self, String> {
        use rand_core::RngCore;
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        match sig_alg {
            "ml-dsa-44" => Ok(Self::MlDsa44(ml_dsa_44_signer(&seed))),
            "ml-dsa-65" => Ok(Self::MlDsa65(ml_dsa_65_signer(&seed))),
            "ml-dsa-87" => Ok(Self::MlDsa87(ml_dsa_87_signer(&seed))),
            other => Err(format!("unknown ML-DSA variant: {other}")),
        }
    }

    /// Produce an ahu bundle, dispatching to the correct monomorphized
    /// `produce_bundle` instantiation based on the loaded parameter set.
    pub fn sign_bundle(
        &mut self,
        ca: &crate::source::CaIdentity,
        snapshot: &crate::source::StatusSnapshot,
        config: &crate::generate::GenerationConfig,
        seal_fn: impl FnOnce(&[u8]) -> crate::error::Result<Vec<u8>>,
        responder_cert_der: Option<&[u8]>,
    ) -> crate::error::Result<Vec<u8>> {
        match self {
            Self::MlDsa44(s) => crate::generate::produce_bundle::<_, MlDsaSignatureBytes>(
                ca, snapshot, config, s, seal_fn, responder_cert_der,
            ),
            Self::MlDsa65(s) => crate::generate::produce_bundle::<_, MlDsaSignatureBytes>(
                ca, snapshot, config, s, seal_fn, responder_cert_der,
            ),
            Self::MlDsa87(s) => crate::generate::produce_bundle::<_, MlDsaSignatureBytes>(
                ca, snapshot, config, s, seal_fn, responder_cert_der,
            ),
        }
    }
}

/// Load an ML-DSA signer from PKCS#8 DER bytes, auto-detecting the parameter set
/// from the AlgorithmIdentifier OID (RFC 9881).
pub fn load_ml_dsa_signer_from_pkcs8_der(der_bytes: &[u8]) -> Result<MlDsaSignerVariant, String> {
    use ml_dsa::pkcs8::DecodePrivateKey;

    if let Ok(sk) = mldsa::SigningKey::<mldsa::MlDsa44>::from_pkcs8_der(der_bytes) {
        return Ok(MlDsaSignerVariant::MlDsa44(MlDsaSigner::new(sk, ML_DSA_44_OID)));
    }
    if let Ok(sk) = mldsa::SigningKey::<mldsa::MlDsa65>::from_pkcs8_der(der_bytes) {
        return Ok(MlDsaSignerVariant::MlDsa65(MlDsaSigner::new(sk, ML_DSA_65_OID)));
    }
    if let Ok(sk) = mldsa::SigningKey::<mldsa::MlDsa87>::from_pkcs8_der(der_bytes) {
        return Ok(MlDsaSignerVariant::MlDsa87(MlDsaSigner::new(sk, ML_DSA_87_OID)));
    }

    Err("key does not contain a valid ML-DSA-44, ML-DSA-65, or ML-DSA-87 PKCS#8 private key".into())
}

pub fn ml_dsa_signature_size(variant: &str) -> usize {
    match variant {
        "ml-dsa-44" => 2420,
        "ml-dsa-65" => 3309,
        "ml-dsa-87" => 4627,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_dsa_44_sign_verify_size() {
        let signer = ml_dsa_44_signer(&[1u8; 32]);
        use signature::Signer;
        let sig = signer.sign(b"test message");
        assert_eq!(sig.bytes.len(), 2420);

        use spki::DynSignatureAlgorithmIdentifier;
        let alg_id = signer.signature_algorithm_identifier().unwrap();
        assert_eq!(alg_id.oid.to_string(), ML_DSA_44_OID);

        use spki::SignatureBitStringEncoding;
        let bits = sig.to_bitstring().unwrap();
        assert_eq!(bits.raw_bytes().len(), 2420);
    }

    #[test]
    fn ml_dsa_65_sign_verify_size() {
        let signer = ml_dsa_65_signer(&[2u8; 32]);
        use signature::Signer;
        let sig = signer.sign(b"test message");
        assert_eq!(sig.bytes.len(), 3309);
    }

    #[test]
    fn ml_dsa_87_sign_verify_size() {
        let signer = ml_dsa_87_signer(&[3u8; 32]);
        use signature::Signer;
        let sig = signer.sign(b"test message");
        assert_eq!(sig.bytes.len(), 4627);
    }

    #[test]
    fn ml_dsa_44_pkcs8_round_trip() {
        use ml_dsa::pkcs8::EncodePrivateKey;
        let sk = mldsa::SigningKey::<mldsa::MlDsa44>::from_seed((&[1u8; 32]).into());
        let der_doc = sk.to_pkcs8_der().expect("encode PKCS#8");
        let variant = load_ml_dsa_signer_from_pkcs8_der(der_doc.as_bytes()).unwrap();
        assert_eq!(variant.algorithm_name(), "ml-dsa-44");
    }

    #[test]
    fn ml_dsa_65_pkcs8_round_trip() {
        use ml_dsa::pkcs8::EncodePrivateKey;
        let sk = mldsa::SigningKey::<mldsa::MlDsa65>::from_seed((&[2u8; 32]).into());
        let der_doc = sk.to_pkcs8_der().expect("encode PKCS#8");
        let variant = load_ml_dsa_signer_from_pkcs8_der(der_doc.as_bytes()).unwrap();
        assert_eq!(variant.algorithm_name(), "ml-dsa-65");
    }

    #[test]
    fn ml_dsa_87_pkcs8_round_trip() {
        use ml_dsa::pkcs8::EncodePrivateKey;
        let sk = mldsa::SigningKey::<mldsa::MlDsa87>::from_seed((&[3u8; 32]).into());
        let der_doc = sk.to_pkcs8_der().expect("encode PKCS#8");
        let variant = load_ml_dsa_signer_from_pkcs8_der(der_doc.as_bytes()).unwrap();
        assert_eq!(variant.algorithm_name(), "ml-dsa-87");
    }

    #[test]
    fn ml_dsa_pkcs8_invalid_data_errors() {
        let result = load_ml_dsa_signer_from_pkcs8_der(b"not valid pkcs8");
        assert!(result.is_err());
    }

    #[test]
    fn ml_dsa_pkcs8_loaded_signer_produces_correct_signature() {
        use ml_dsa::pkcs8::EncodePrivateKey;
        let sk = mldsa::SigningKey::<mldsa::MlDsa87>::from_seed((&[42u8; 32]).into());
        let der_doc = sk.to_pkcs8_der().expect("encode PKCS#8");
        let variant = load_ml_dsa_signer_from_pkcs8_der(der_doc.as_bytes()).unwrap();
        match variant {
            MlDsaSignerVariant::MlDsa87(ref signer) => {
                use signature::Signer;
                let sig = signer.sign(b"test message");
                assert_eq!(sig.bytes.len(), 4627);
            }
            _ => panic!("expected ML-DSA-87 variant"),
        }
    }

    #[test]
    fn ml_dsa_pkcs8_deterministic_across_load() {
        use ml_dsa::pkcs8::EncodePrivateKey;
        let sk = mldsa::SigningKey::<mldsa::MlDsa87>::from_seed((&[7u8; 32]).into());
        let der_doc = sk.to_pkcs8_der().expect("encode PKCS#8");

        let seed_signer = ml_dsa_87_signer(&[7u8; 32]);
        let variant = load_ml_dsa_signer_from_pkcs8_der(der_doc.as_bytes()).unwrap();

        use signature::Signer;
        let msg = b"determinism check";
        let sig_seed = seed_signer.sign(msg);
        match variant {
            MlDsaSignerVariant::MlDsa87(ref loaded) => {
                let sig_loaded = loaded.sign(msg);
                assert_eq!(sig_seed.bytes, sig_loaded.bytes);
            }
            _ => panic!("expected ML-DSA-87"),
        }
    }
}
