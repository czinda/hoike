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
}
