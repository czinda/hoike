//! Software key loading from PKCS#8 PEM/DER files.

use std::path::Path;

use crate::error::{Result, SignError};

/// Load an ECDSA P-256 signing key from a PKCS#8 PEM or DER file.
pub fn load_ecdsa_p256_key(path: &Path) -> Result<p256::ecdsa::SigningKey> {
    let data = std::fs::read(path).map_err(|e| {
        SignError::KeyLoad(format!("failed to read key file {}: {e}", path.display()))
    })?;

    if data.starts_with(b"-----BEGIN") {
        let pem_str = std::str::from_utf8(&data)
            .map_err(|e| SignError::KeyLoad(format!("key file is not valid UTF-8: {e}")))?;
        use p256::pkcs8::DecodePrivateKey;
        p256::ecdsa::SigningKey::from_pkcs8_pem(pem_str)
            .map_err(|e| SignError::KeyLoad(format!("PKCS#8 PEM decode: {e}")))
    } else {
        use p256::pkcs8::DecodePrivateKey;
        p256::ecdsa::SigningKey::from_pkcs8_der(&data)
            .map_err(|e| SignError::KeyLoad(format!("PKCS#8 DER decode: {e}")))
    }
}

/// Generate an ephemeral ECDSA P-256 signing key for demo/testing use only.
pub fn demo_ecdsa_p256_key() -> p256::ecdsa::SigningKey {
    let secret = [42u8; 32];
    p256::ecdsa::SigningKey::from_bytes((&secret).into()).expect("demo key generation failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::EncodePrivateKey;

    #[test]
    fn load_pkcs8_der_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test.der");

        let original = demo_ecdsa_p256_key();
        let der_bytes = original.to_pkcs8_der().expect("PKCS#8 DER encode failed");
        std::fs::write(&key_path, der_bytes.as_bytes()).unwrap();

        let loaded = load_ecdsa_p256_key(&key_path).unwrap();

        use signature::Signer;
        let msg = b"test message for signing";
        let sig_orig: p256::ecdsa::DerSignature = original.sign(msg);
        let sig_loaded: p256::ecdsa::DerSignature = loaded.sign(msg);
        assert_eq!(sig_orig.to_bytes(), sig_loaded.to_bytes());
    }

    #[test]
    fn load_pkcs8_pem_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test.pem");

        let original = demo_ecdsa_p256_key();
        let pem_str = original
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("PKCS#8 PEM encode failed");
        std::fs::write(&key_path, pem_str.as_bytes()).unwrap();

        let loaded = load_ecdsa_p256_key(&key_path).unwrap();

        use signature::Signer;
        let sig_orig: p256::ecdsa::DerSignature = original.sign(b"msg");
        let sig_loaded: p256::ecdsa::DerSignature = loaded.sign(b"msg");
        assert_eq!(sig_orig.to_bytes(), sig_loaded.to_bytes());
    }

    #[test]
    fn load_nonexistent_file_errors() {
        let result = load_ecdsa_p256_key(Path::new("/nonexistent/key.pem"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to read key file"));
    }

    #[test]
    fn load_invalid_data_errors() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("garbage.der");
        std::fs::write(&key_path, b"not a valid key").unwrap();

        let result = load_ecdsa_p256_key(&key_path);
        assert!(result.is_err());
    }
}
