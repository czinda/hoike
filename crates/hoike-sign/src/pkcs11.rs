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
use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use tracing::info;

use crate::error::{Result, SignError};

/// Configuration for a PKCS#11 signing key.
#[derive(Clone)]
pub struct Pkcs11Config {
    pub module_path: String,
    pub slot_id: Option<u64>,
    pub token_label: Option<String>,
    pub pin: String,
    pub key_label: Option<String>,
    pub key_id: Option<Vec<u8>>,
}

impl std::fmt::Debug for Pkcs11Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Config")
            .field("module_path", &self.module_path)
            .field("slot_id", &self.slot_id)
            .field("token_label", &self.token_label)
            .field("pin", &"[REDACTED]")
            .field("key_label", &self.key_label)
            .field("key_id", &self.key_id)
            .finish()
    }
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
            .open_ro_session(slot)
            .map_err(|e| SignError::Pkcs11(format!("open session: {e}")))?;

        session
            .login(
                UserType::User,
                Some(&AuthPin::new(config.pin.clone().into())),
            )
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

fn find_key(session: &cryptoki::session::Session, config: &Pkcs11Config) -> Result<ObjectHandle> {
    if config.key_label.is_none() && config.key_id.is_none() {
        return Err(SignError::Pkcs11(
            "PKCS#11 config must specify key_label or key_id to identify the signing key".into(),
        ));
    }

    let mut template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Sign(true),
    ];
    let mut filters = Vec::new();
    if let Some(label) = &config.key_label {
        template.push(Attribute::Label(label.as_bytes().to_vec()));
        filters.push(format!("CKA_LABEL={label}"));
    }
    if let Some(id) = &config.key_id {
        template.push(Attribute::Id(id.clone()));
        filters.push(format!("CKA_ID={}", hex::encode(id)));
    }

    let handles = session
        .find_objects(&template)
        .map_err(|e| SignError::Pkcs11(format!("find key: {e}")))?;

    if handles.is_empty() {
        return Err(SignError::Pkcs11(format!(
            "no signing key found matching [{}]",
            filters.join(", ")
        )));
    }

    if handles.len() > 1 {
        tracing::warn!(
            count = handles.len(),
            filters = filters.join(", "),
            "multiple HSM keys match — using first; narrow with key_label + key_id"
        );
    }

    Ok(handles[0])
}

// ── ML-DSA PKCS#11 signer ───────────────────────────────────────────

/// ML-DSA signer backed by a PKCS#11 HSM.
///
/// Uses CKM_ML_DSA (pure variant, per RFC 9881) — the full message is
/// passed to the token, not a prehash.
pub struct Pkcs11MlDsaSigner {
    _ctx: Pkcs11,
    session: cryptoki::session::Session,
    key_handle: ObjectHandle,
    sig_alg_oid: &'static str,
}

impl Pkcs11MlDsaSigner {
    pub fn new(
        config: &Pkcs11Config,
        parameter_set: cryptoki::object::MlDsaParameterSetType,
        sig_alg_oid: &'static str,
    ) -> Result<Self> {
        let ctx = Pkcs11::new(&config.module_path)
            .map_err(|e| SignError::Pkcs11(format!("load module '{}': {e}", config.module_path)))?;

        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| SignError::Pkcs11(format!("initialize: {e}")))?;

        let slot = find_slot(&ctx, config)?;

        let mechs = ctx
            .get_mechanism_list(slot)
            .map_err(|e| SignError::Pkcs11(format!("get mechanism list: {e}")))?;
        if !mechs.contains(&cryptoki::mechanism::MechanismType::ML_DSA) {
            return Err(SignError::Pkcs11(format!(
                "token on slot {} does not support CKM_ML_DSA — \
                 check firmware version or use a software key",
                u64::from(slot.id())
            )));
        }

        let session = ctx
            .open_ro_session(slot)
            .map_err(|e| SignError::Pkcs11(format!("open session: {e}")))?;

        session
            .login(
                UserType::User,
                Some(&AuthPin::new(config.pin.clone().into())),
            )
            .map_err(|e| SignError::Pkcs11(format!("login: {e}")))?;

        let key_handle = find_ml_dsa_key(&session, config, parameter_set)?;

        info!(
            module = %config.module_path,
            token_label = config.token_label.as_deref().unwrap_or(""),
            key_label = config.key_label.as_deref().unwrap_or(""),
            alg = sig_alg_oid,
            "PKCS#11 ML-DSA signer initialized"
        );

        Ok(Pkcs11MlDsaSigner {
            _ctx: ctx,
            session,
            key_handle,
            sig_alg_oid,
        })
    }

    pub fn sign_message(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let ctx = cryptoki::mechanism::dsa::SignAdditionalContext::new(
            cryptoki::mechanism::dsa::HedgeType::Preferred,
            None,
        );
        self.session
            .sign(
                &cryptoki::mechanism::Mechanism::MlDsa(ctx),
                self.key_handle,
                msg,
            )
            .map_err(|e| SignError::Pkcs11(format!("ML-DSA sign: {e}")))
    }
}

fn find_ml_dsa_key(
    session: &cryptoki::session::Session,
    config: &Pkcs11Config,
    parameter_set: cryptoki::object::MlDsaParameterSetType,
) -> Result<ObjectHandle> {
    if config.key_label.is_none() && config.key_id.is_none() {
        return Err(SignError::Pkcs11(
            "PKCS#11 config must specify key_label or key_id".into(),
        ));
    }

    let mut template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Sign(true),
        Attribute::KeyType(cryptoki::object::KeyType::ML_DSA),
        Attribute::ParameterSet(parameter_set.into()),
    ];
    let mut filters = Vec::new();
    if let Some(label) = &config.key_label {
        template.push(Attribute::Label(label.as_bytes().to_vec()));
        filters.push(format!("CKA_LABEL={label}"));
    }
    if let Some(id) = &config.key_id {
        template.push(Attribute::Id(id.clone()));
        filters.push(format!("CKA_ID={}", hex::encode(id)));
    }

    let handles = session
        .find_objects(&template)
        .map_err(|e| SignError::Pkcs11(format!("find ML-DSA key: {e}")))?;

    if handles.is_empty() {
        return Err(SignError::Pkcs11(format!(
            "no ML-DSA signing key found matching [{}]",
            filters.join(", ")
        )));
    }

    if handles.len() > 1 {
        tracing::warn!(
            count = handles.len(),
            filters = filters.join(", "),
            "multiple ML-DSA keys match — using first; narrow with key_label + key_id"
        );
    }

    Ok(handles[0])
}

// ── ML-DSA PKCS#11 signature v2 bridge ──────────────────────────────

/// Wrapper implementing signature v2 traits for PKCS#11 ML-DSA signing.
pub struct Pkcs11MlDsaSignerBridge {
    inner: Pkcs11MlDsaSigner,
}

impl Pkcs11MlDsaSignerBridge {
    pub fn new(inner: Pkcs11MlDsaSigner) -> Self {
        Pkcs11MlDsaSignerBridge { inner }
    }
}

/// Raw ML-DSA signature bytes from PKCS#11 (no DER conversion needed).
#[derive(Clone)]
pub struct Pkcs11MlDsaSignature {
    bytes: Vec<u8>,
}

impl From<Pkcs11MlDsaSignature> for Vec<u8> {
    fn from(sig: Pkcs11MlDsaSignature) -> Vec<u8> {
        sig.bytes
    }
}

impl signature::SignatureEncoding for Pkcs11MlDsaSignature {
    type Repr = Vec<u8>;
}

impl TryFrom<&[u8]> for Pkcs11MlDsaSignature {
    type Error = signature::Error;
    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        Ok(Pkcs11MlDsaSignature {
            bytes: bytes.to_vec(),
        })
    }
}

impl AsRef<[u8]> for Pkcs11MlDsaSignature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl spki::SignatureBitStringEncoding for Pkcs11MlDsaSignature {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        der::asn1::BitString::from_bytes(&self.bytes)
    }
}

impl signature::Signer<Pkcs11MlDsaSignature> for Pkcs11MlDsaSignerBridge {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Pkcs11MlDsaSignature, signature::Error> {
        let raw_sig = self
            .inner
            .sign_message(msg)
            .map_err(signature::Error::from_source)?;
        Ok(Pkcs11MlDsaSignature { bytes: raw_sig })
    }
}

impl spki::DynSignatureAlgorithmIdentifier for Pkcs11MlDsaSignerBridge {
    fn signature_algorithm_identifier(&self) -> spki::Result<spki::AlgorithmIdentifierOwned> {
        Ok(spki::AlgorithmIdentifierOwned {
            oid: const_oid::ObjectIdentifier::new_unwrap(self.inner.sig_alg_oid),
            parameters: None,
        })
    }
}

// ── ECDSA signature v2 bridge ───────────────────────────────────────
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
            .map_err(signature::Error::from_source)?;

        // PKCS#11 CKM_ECDSA returns raw (r || s), each scalar is 32 bytes for P-256.
        // Convert to DER-encoded ECDSA-Sig-Value.
        let der_sig = raw_ecdsa_to_der(&raw_sig).map_err(|e| {
            signature::Error::from_source(SignError::Signing(format!("raw ECDSA to DER: {e}")))
        })?;

        Ok(Pkcs11EcdsaSignature { der_bytes: der_sig })
    }
}

impl spki::DynSignatureAlgorithmIdentifier for Pkcs11SignerBridge {
    fn signature_algorithm_identifier(&self) -> spki::Result<spki::AlgorithmIdentifierOwned> {
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
