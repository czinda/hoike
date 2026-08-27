//! Software key loading from PKCS#8 PEM/DER files.

use std::path::Path;

use crate::error::{Result, SignError};
use crate::ml_dsa_bridge::{MlDsaSignerVariant, load_ml_dsa_signer_from_pkcs8_der};

/// Decode a PEM block into DER bytes.
///
/// Validates the label contains `expected_label` (e.g. "PRIVATE KEY"),
/// handles whitespace trimming, and rejects truncated or missing PEM structure.
pub(crate) fn pem_to_der(pem_data: &[u8], expected_label: &str) -> Result<Vec<u8>> {
    let pem_str = std::str::from_utf8(pem_data)
        .map_err(|e| SignError::KeyLoad(format!("key file is not valid UTF-8: {e}")))?;

    use base64::Engine;
    let mut collecting = false;
    let mut found_end = false;
    let mut b64 = String::new();
    for line in pem_str.lines() {
        if line.starts_with("-----BEGIN") {
            if !line.contains(expected_label) {
                return Err(SignError::KeyLoad(format!(
                    "expected PEM {} but found: {}",
                    expected_label,
                    line.trim()
                )));
            }
            collecting = true;
            continue;
        }
        if line.starts_with("-----END") {
            if !line.contains(expected_label) {
                return Err(SignError::KeyLoad(format!(
                    "PEM label mismatch: BEGIN {} but END says: {}",
                    expected_label,
                    line.trim()
                )));
            }
            found_end = true;
            break;
        }
        if collecting {
            b64.push_str(line.trim());
        }
    }
    if !collecting {
        return Err(SignError::KeyLoad("no PEM header found in key file".into()));
    }
    if !found_end {
        return Err(SignError::KeyLoad(
            "PEM is truncated: found BEGIN but no END marker".into(),
        ));
    }
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| SignError::KeyLoad(format!("invalid base64 in PEM: {e}")))
}

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

/// Load an ML-DSA signer from a PKCS#8 PEM or DER file, auto-detecting the
/// parameter set (44/65/87) from the AlgorithmIdentifier OID.
pub fn load_ml_dsa_key(path: &Path) -> Result<MlDsaSignerVariant> {
    let data = std::fs::read(path).map_err(|e| {
        SignError::KeyLoad(format!("failed to read key file {}: {e}", path.display()))
    })?;

    let der_bytes = if data.starts_with(b"-----BEGIN") {
        pem_to_der(&data, "PRIVATE KEY")?
    } else {
        data
    };

    load_ml_dsa_signer_from_pkcs8_der(&der_bytes).map_err(SignError::KeyLoad)
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

    #[test]
    fn load_ml_dsa_pkcs8_der_file() {
        use ml_dsa::pkcs8::EncodePrivateKey;
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("ml-dsa-87.der");

        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed((&[42u8; 32]).into());
        let der_doc = sk.to_pkcs8_der().expect("encode PKCS#8");
        std::fs::write(&key_path, der_doc.as_bytes()).unwrap();

        let variant = load_ml_dsa_key(&key_path).unwrap();
        assert_eq!(variant.algorithm_name(), "ml-dsa-87");
    }

    #[test]
    fn load_ml_dsa_pkcs8_pem_file() {
        use ml_dsa::pkcs8::EncodePrivateKey;
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("ml-dsa-65.pem");

        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed((&[99u8; 32]).into());
        let der_doc = sk.to_pkcs8_der().expect("encode PKCS#8");

        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der_doc.as_bytes());
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        std::fs::write(&key_path, pem.as_bytes()).unwrap();

        let variant = load_ml_dsa_key(&key_path).unwrap();
        assert_eq!(variant.algorithm_name(), "ml-dsa-65");
    }

    #[test]
    fn load_ml_dsa_nonexistent_file_errors() {
        let result = load_ml_dsa_key(Path::new("/nonexistent/ml-dsa.pem"));
        assert!(result.is_err());
    }

    #[test]
    fn load_ml_dsa_ecdsa_key_errors() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("ecdsa.der");

        let ecdsa_key = demo_ecdsa_p256_key();
        let der_bytes = ecdsa_key.to_pkcs8_der().expect("PKCS#8 DER encode failed");
        std::fs::write(&key_path, der_bytes.as_bytes()).unwrap();

        let result = load_ml_dsa_key(&key_path);
        assert!(result.is_err());
    }
}
