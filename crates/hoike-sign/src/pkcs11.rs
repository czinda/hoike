//! PKCS#11 signing integration for hardware security modules.
//!
//! Supports any PKCS#11 v2.40+ compliant HSM:
//!
//! | Vendor          | Module Path                                  | Notes                               |
//! |-----------------|----------------------------------------------|-------------------------------------|
//! | Thales Luna     | `/usr/lib/libCryptoki2_64.so`                | Token label = partition name        |
//! | Entrust nShield | `/opt/nfast/toolkits/pkcs11/libcknfast.so`   | Security World model                |
//! | Utimaco         | `/usr/lib/libcs_pkcs11_R3.so`                | CryptoServer Se/Gen2                |
//! | FutureX         | `/opt/fxpkcs11/lib/libfxpkcs11.so`           | Vectera Plus                        |
//! | SoftHSM2        | `/usr/lib/softhsm/libsofthsm2.so`           | Testing without hardware            |
//!
//! This module is gated behind the `pkcs11` feature flag because it links
//! against the PKCS#11 C library at build time.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use tracing::info;

use crate::error::{Result, SignError};

/// Configuration for a PKCS#11 signing key.
#[derive(Debug, Clone)]
pub struct Pkcs11Config {
    /// Path to the vendor's PKCS#11 shared library.
    pub module_path: String,
    /// Explicit slot ID (mutually exclusive with token_label).
    pub slot_id: Option<u64>,
    /// Find slot by token label (e.g., Luna partition name).
    pub token_label: Option<String>,
    /// Login PIN. Read from pin_env environment variable if not set directly.
    pub pin: String,
    /// Find key by CKA_LABEL.
    pub key_label: Option<String>,
    /// Find key by CKA_ID (raw bytes).
    pub key_id: Option<Vec<u8>>,
}

/// ECDSA P-256 signer backed by a PKCS#11 HSM.
///
/// The session is held open for the lifetime of this signer, keeping the
/// HSM login active. Drop the signer to close the session.
pub struct Pkcs11Signer {
    _ctx: Pkcs11,
    session: cryptoki::session::Session,
    key_handle: ObjectHandle,
}

impl Pkcs11Signer {
    pub fn new(config: &Pkcs11Config) -> Result<Self> {
        let ctx = Pkcs11::new(&config.module_path)
            .map_err(|e| SignError::Pkcs11(format!("load module '{}': {e}", config.module_path)))?;

        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| SignError::Pkcs11(format!("initialize: {e}")))?;

        let slot = find_slot(&ctx, config)?;

        let session = ctx
            .open_rw_session(slot)
            .map_err(|e| SignError::Pkcs11(format!("open session: {e}")))?;

        session
            .login(UserType::User, Some(&AuthPin::new(config.pin.clone().into())))
            .map_err(|e| SignError::Pkcs11(format!("login: {e}")))?;

        let key_handle = find_key(&session, config)?;

        info!(
            module = %config.module_path,
            token_label = config.token_label.as_deref().unwrap_or(""),
            key_label = config.key_label.as_deref().unwrap_or(""),
            "PKCS#11 signer initialized"
        );

        Ok(Pkcs11Signer {
            _ctx: ctx,
            session,
            key_handle,
        })
    }

    /// Sign a pre-hashed digest via the HSM using CKM_ECDSA.
    ///
    /// CKM_ECDSA expects the caller to provide the hash (not raw data).
    /// The output is raw (r || s) concatenated scalars, which we convert
    /// to DER-encoded ECDSA signature for the OCSP response.
    pub fn sign_prehash(&self, hash: &[u8]) -> Result<Vec<u8>> {
        self.session
            .sign(&Mechanism::Ecdsa, self.key_handle, hash)
            .map_err(|e| SignError::Pkcs11(format!("sign: {e}")))
    }
}

fn find_slot(ctx: &Pkcs11, config: &Pkcs11Config) -> Result<cryptoki::slot::Slot> {
    if let Some(id) = config.slot_id {
        let slots = ctx
            .get_all_slots()
            .map_err(|e| SignError::Pkcs11(format!("get slots: {e}")))?;
        slots
            .into_iter()
            .find(|s| u64::from(s.id()) == id)
            .ok_or_else(|| SignError::Pkcs11(format!("slot {id} not found")))
    } else if let Some(label) = &config.token_label {
        let slots = ctx
            .get_slots_with_initialized_token()
            .map_err(|e| SignError::Pkcs11(format!("get slots: {e}")))?;
        for slot in &slots {
            if let Ok(info) = ctx.get_token_info(*slot) {
                let tl = info.label().trim();
                if tl == label.as_str() {
                    return Ok(*slot);
                }
            }
        }
        Err(SignError::Pkcs11(format!(
            "token '{}' not found (checked {} slots)",
            label,
            slots.len()
        )))
    } else {
        Err(SignError::Pkcs11(
            "neither slot_id nor token_label specified".into(),
        ))
    }
}

fn find_key(
    session: &cryptoki::session::Session,
    config: &Pkcs11Config,
) -> Result<ObjectHandle> {
    let mut template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Sign(true),
    ];
    if let Some(label) = &config.key_label {
        template.push(Attribute::Label(label.as_bytes().to_vec()));
    }
    if let Some(id) = &config.key_id {
        template.push(Attribute::Id(id.clone()));
    }

    let handles = session
        .find_objects(&template)
        .map_err(|e| SignError::Pkcs11(format!("find key: {e}")))?;

    handles.first().copied().ok_or_else(|| {
        let label_info = config
            .key_label
            .as_deref()
            .unwrap_or("(no label filter)");
        SignError::Pkcs11(format!(
            "signing key not found (label={label_info}, {} candidates)",
            handles.len()
        ))
    })
}

// ── signature v2 bridge ─────────────────────────────────────────────
//
// Same pattern as ml_dsa_bridge.rs: x509-ocsp's builder requires
// signature v2 traits, so we wrap the raw PKCS#11 signing output.

/// Wrapper implementing signature v2 traits for PKCS#11 ECDSA signing.
pub struct Pkcs11SignerBridge {
    inner: Pkcs11Signer,
}

impl Pkcs11SignerBridge {
    pub fn new(inner: Pkcs11Signer) -> Self {
        Pkcs11SignerBridge { inner }
    }
}

/// DER-encoded ECDSA signature from PKCS#11.
#[derive(Clone)]
pub struct Pkcs11EcdsaSignature {
    der_bytes: Vec<u8>,
}

impl From<Pkcs11EcdsaSignature> for Vec<u8> {
    fn from(sig: Pkcs11EcdsaSignature) -> Vec<u8> {
        sig.der_bytes
    }
}

impl signature::SignatureEncoding for Pkcs11EcdsaSignature {
    type Repr = Vec<u8>;
}

impl TryFrom<&[u8]> for Pkcs11EcdsaSignature {
    type Error = signature::Error;
    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        Ok(Pkcs11EcdsaSignature {
            der_bytes: bytes.to_vec(),
        })
    }
}

impl AsRef<[u8]> for Pkcs11EcdsaSignature {
    fn as_ref(&self) -> &[u8] {
        &self.der_bytes
    }
}

impl spki::SignatureBitStringEncoding for Pkcs11EcdsaSignature {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        der::asn1::BitString::from_bytes(&self.der_bytes)
    }
}

impl signature::Signer<Pkcs11EcdsaSignature> for Pkcs11SignerBridge {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Pkcs11EcdsaSignature, signature::Error> {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(msg);
        let raw_sig = self
            .inner
            .sign_prehash(&hash)
            .map_err(|_| signature::Error::new())?;

        // PKCS#11 CKM_ECDSA returns raw (r || s), each scalar is 32 bytes for P-256.
        // Convert to DER-encoded ECDSA-Sig-Value.
        let der_sig = raw_ecdsa_to_der(&raw_sig).map_err(|_| signature::Error::new())?;

        Ok(Pkcs11EcdsaSignature {
            der_bytes: der_sig,
        })
    }
}

impl spki::DynSignatureAlgorithmIdentifier for Pkcs11SignerBridge {
    fn signature_algorithm_identifier(
        &self,
    ) -> spki::Result<spki::AlgorithmIdentifierOwned> {
        Ok(spki::AlgorithmIdentifierOwned {
            oid: const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        })
    }
}

/// Convert raw PKCS#11 ECDSA output (r || s) to DER-encoded ECDSA-Sig-Value.
///
/// ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
fn raw_ecdsa_to_der(raw: &[u8]) -> std::result::Result<Vec<u8>, &'static str> {
    if raw.len() != 64 {
        return Err("expected 64-byte raw ECDSA signature for P-256");
    }

    let r = &raw[..32];
    let s = &raw[32..];

    fn encode_integer(val: &[u8]) -> Vec<u8> {
        // Strip leading zeros but keep at least one byte
        let stripped = val.iter().position(|&b| b != 0).unwrap_or(val.len() - 1);
        let val = &val[stripped..];

        // If high bit is set, prepend a zero byte
        let needs_pad = !val.is_empty() && (val[0] & 0x80) != 0;
        let len = val.len() + if needs_pad { 1 } else { 0 };

        let mut out = vec![0x02, len as u8]; // INTEGER tag + length
        if needs_pad {
            out.push(0x00);
        }
        out.extend_from_slice(val);
        out
    }

    let r_enc = encode_integer(r);
    let s_enc = encode_integer(s);
    let seq_len = r_enc.len() + s_enc.len();

    let mut der = vec![0x30]; // SEQUENCE tag
    if seq_len < 128 {
        der.push(seq_len as u8);
    } else {
        der.push(0x81);
        der.push(seq_len as u8);
    }
    der.extend_from_slice(&r_enc);
    der.extend_from_slice(&s_enc);

    Ok(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_ecdsa_to_der_valid() {
        // Both r and s are 32-byte scalars, no high-bit padding needed
        let mut raw = vec![0u8; 64];
        raw[0] = 0x01; // r = 1 (31 leading zeros + 0x01)
        raw[32] = 0x02; // s = 2 (31 leading zeros + 0x02)

        let der = raw_ecdsa_to_der(&raw).unwrap();
        // Should be SEQUENCE { INTEGER 1, INTEGER 2 }
        assert_eq!(&der[0..2], &[0x30, 0x06]); // SEQUENCE, length 6
        assert_eq!(&der[2..5], &[0x02, 0x01, 0x01]); // INTEGER 1
        assert_eq!(&der[5..8], &[0x02, 0x01, 0x02]); // INTEGER 2
    }

    #[test]
    fn raw_ecdsa_to_der_high_bit_padding() {
        // r has high bit set, needs 0x00 pad
        let mut raw = vec![0u8; 64];
        raw[0] = 0xFF;
        raw[1] = 0x01;
        raw[32] = 0x01;

        let der = raw_ecdsa_to_der(&raw).unwrap();
        // r should be 0x00 FF 01 (padded), s should be 01
        assert_eq!(der[2], 0x02); // INTEGER tag for r
        assert_eq!(der[3], 0x21); // length 33 (32 bytes + pad)
        assert_eq!(der[4], 0x00); // padding byte
        assert_eq!(der[5], 0xFF);
    }

    #[test]
    fn raw_ecdsa_to_der_wrong_length() {
        let result = raw_ecdsa_to_der(&[0u8; 48]);
        assert!(result.is_err());
    }
}
