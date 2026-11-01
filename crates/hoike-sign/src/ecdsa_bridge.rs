//! Bridge between ecdsa 0.17 (signature v3 / spki v0.8) and x509-ocsp
//! (signature v2 / spki v0.7), mirroring `ml_dsa_bridge.rs`.
//!
//! `produce_bundle` and the OCSP response builder require `Signer<Sig> +
//! DynSignatureAlgorithmIdentifier` from signature v2 / spki v0.7. The p256
//! 0.14 / ecdsa 0.17 line implements signature v3 traits. This module wraps
//! the v3 types to satisfy the v2 trait bounds.
//!
//! Wire compatibility: the signature is embedded as a DER BIT STRING over the
//! DER-encoded ECDSA-Sig-Value, and the algorithm identifier is
//! ecdsa-with-SHA256 (1.2.840.10045.4.3.2) with no parameters — the exact
//! encoding the PKCS#11 bridge and the previous ecdsa 0.16 native impls
//! produced.

/// OID for ecdsa-with-SHA256 (RFC 5912 / SEC 2).
pub const ECDSA_WITH_SHA256_OID: &str = "1.2.840.10045.4.3.2";

/// Wrapper around a software P-256 `SigningKey` implementing the signature
/// v2 / spki v0.7 trait set `produce_bundle` requires.
#[derive(Clone)]
pub struct EcdsaP256Signer {
    inner: p256::ecdsa::SigningKey,
}

impl EcdsaP256Signer {
    pub fn new(inner: p256::ecdsa::SigningKey) -> Self {
        Self { inner }
    }

    pub fn verifying_key(&self) -> p256::ecdsa::VerifyingKey {
        *self.inner.verifying_key()
    }
}

impl From<p256::ecdsa::SigningKey> for EcdsaP256Signer {
    fn from(inner: p256::ecdsa::SigningKey) -> Self {
        Self::new(inner)
    }
}

/// DER-encoded ECDSA-Sig-Value wrapper implementing v2
/// `SignatureBitStringEncoding`.
#[derive(Clone)]
pub struct EcdsaSignatureBytes {
    der_bytes: Vec<u8>,
}

impl From<EcdsaSignatureBytes> for Vec<u8> {
    fn from(sig: EcdsaSignatureBytes) -> Vec<u8> {
        sig.der_bytes
    }
}

impl TryFrom<&[u8]> for EcdsaSignatureBytes {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // Reject inputs that are not a valid DER ECDSA-Sig-Value.
        p256::ecdsa::DerSignature::from_bytes(bytes).map_err(|_| signature::Error::new())?;
        Ok(EcdsaSignatureBytes {
            der_bytes: bytes.to_vec(),
        })
    }
}

impl AsRef<[u8]> for EcdsaSignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.der_bytes
    }
}

// ── signature v2 Signer ──────────────────────────────────────────

impl signature::Signer<EcdsaSignatureBytes> for EcdsaP256Signer {
    fn try_sign(&self, msg: &[u8]) -> Result<EcdsaSignatureBytes, signature::Error> {
        // ecdsa 0.17 signs via signature v3 (RFC 6979 deterministic nonces).
        use p256::ecdsa::signature::Signer as SignerV3;
        let sig: p256::ecdsa::Signature =
            SignerV3::try_sign(&self.inner, msg).map_err(|_| signature::Error::new())?;
        let der = sig.to_der();
        Ok(EcdsaSignatureBytes {
            der_bytes: der.as_bytes().to_vec(),
        })
    }
}

// ── signature v2 SignatureEncoding ────────────────────────────────

impl signature::SignatureEncoding for EcdsaSignatureBytes {
    type Repr = Vec<u8>;
}

// ── spki v0.7 SignatureBitStringEncoding ──────────────────────────

impl spki::SignatureBitStringEncoding for EcdsaSignatureBytes {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        der::asn1::BitString::from_bytes(&self.der_bytes)
    }
}

// ── spki v0.7 DynSignatureAlgorithmIdentifier ────────────────────

impl spki::DynSignatureAlgorithmIdentifier for EcdsaP256Signer {
    fn signature_algorithm_identifier(&self) -> spki::Result<spki::AlgorithmIdentifierOwned> {
        Ok(spki::AlgorithmIdentifierOwned {
            oid: const_oid::ObjectIdentifier::new_unwrap(ECDSA_WITH_SHA256_OID),
            parameters: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use signature::Signer as SignerV2;

    #[test]
    fn signs_and_verifies_with_p256_key() {
        let key = p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let signer = EcdsaP256Signer::new(key.clone());
        let sig = SignerV2::sign(&signer, b"bridge message");
        key.verifying_key()
            .verify(
                b"bridge message",
                &p256::ecdsa::DerSignature::from_bytes(sig.as_ref()).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn algorithm_identifier_is_ecdsa_with_sha256() {
        use spki::DynSignatureAlgorithmIdentifier;
        let signer =
            EcdsaP256Signer::new(p256::ecdsa::SigningKey::from_bytes((&[1u8; 32]).into()).unwrap());
        let alg = signer.signature_algorithm_identifier().unwrap();
        assert_eq!(alg.oid.to_string(), ECDSA_WITH_SHA256_OID);
        assert!(alg.parameters.is_none());
    }

    #[test]
    fn bitstring_wraps_der_bytes() {
        use signature::Signer;
        use spki::SignatureBitStringEncoding;
        let signer =
            EcdsaP256Signer::new(p256::ecdsa::SigningKey::from_bytes((&[2u8; 32]).into()).unwrap());
        let sig = signer.sign(b"test");
        let bits = sig.to_bitstring().unwrap();
        assert_eq!(bits.raw_bytes(), sig.as_ref());
        // A DER ECDSA-Sig-Value starts with a SEQUENCE tag.
        assert_eq!(sig.as_ref()[0], 0x30);
    }

    #[test]
    fn rejects_non_der_input() {
        assert!(EcdsaSignatureBytes::try_from(b"not der".as_slice()).is_err());
    }
}
