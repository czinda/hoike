//! CMS SignedData seal creation for ahu bundles.
//!
//! Creates a detached CMS SignedData (RFC 5652) over the manifest bytes.
//! The seal proves that a specific producer assembled the bundle; it does not
//! make the OCSP responses more trustworthy (their own signatures do that).
//!
//! Uses the der 0.8 ecosystem (via cms crate), separate from the OCSP-side
//! der 0.7 types. The p256 signing key bridges between them.

use cms::content_info::ContentInfo;
use cms::signed_data::{
    CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedData, SignerInfo,
    SignerInfos,
};
use der_v08::asn1::{ObjectIdentifier, OctetString, SetOfVec};
use der_v08::{Any, Decode, Encode};
use sha2::{Digest, Sha256};
use signature::Verifier as _;
use tracing::warn;
use x509_cert_v03::attr::{Attribute, AttributeValue, Attributes};
use x509_cert_v03::certificate::Certificate;

use crate::error::{Result, SignError};
use crate::ml_dsa_bridge::{ML_DSA_44_OID, ML_DSA_65_OID, ML_DSA_87_OID};

// OIDs
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_CT_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// Algorithm-agnostic seal signing key.
#[derive(Clone)]
pub enum SealKey {
    EcdsaP256(p256::ecdsa::SigningKey),
    MlDsa44(ml_dsa::SigningKey<ml_dsa::MlDsa44>),
    MlDsa65(ml_dsa::SigningKey<ml_dsa::MlDsa65>),
    MlDsa87(ml_dsa::SigningKey<ml_dsa::MlDsa87>),
}

impl SealKey {
    fn sign_attrs(&self, attrs_der: &[u8]) -> Result<Vec<u8>> {
        match self {
            SealKey::EcdsaP256(key) => {
                use p256::ecdsa::signature::hazmat::PrehashSigner;
                let hash = Sha256::digest(attrs_der);
                let sig: p256::ecdsa::Signature = key
                    .sign_prehash(&hash)
                    .map_err(|e| SignError::Seal(format!("ECDSA sign: {e}")))?;
                Ok(ecdsa_raw_to_der(&sig.to_bytes()))
            }
            SealKey::MlDsa44(key) => sign_ml_dsa(key, attrs_der),
            SealKey::MlDsa65(key) => sign_ml_dsa(key, attrs_der),
            SealKey::MlDsa87(key) => sign_ml_dsa(key, attrs_der),
        }
    }

    fn algorithm_oid(&self) -> ObjectIdentifier {
        match self {
            SealKey::EcdsaP256(_) => ID_ECDSA_SHA256,
            SealKey::MlDsa44(_) => ObjectIdentifier::new_unwrap(ML_DSA_44_OID),
            SealKey::MlDsa65(_) => ObjectIdentifier::new_unwrap(ML_DSA_65_OID),
            SealKey::MlDsa87(_) => ObjectIdentifier::new_unwrap(ML_DSA_87_OID),
        }
    }

    fn digest_algorithm_oid(&self) -> ObjectIdentifier {
        match self {
            SealKey::EcdsaP256(_) => ID_SHA256,
            // ML-DSA is a full-message scheme — no external digest
            SealKey::MlDsa44(_) | SealKey::MlDsa65(_) | SealKey::MlDsa87(_) => ID_SHA256,
        }
    }
}

fn sign_ml_dsa<P>(key: &ml_dsa::SigningKey<P>, data: &[u8]) -> Result<Vec<u8>>
where
    P: ml_dsa::MlDsaParams,
    ml_dsa::SigningKey<P>: ml_dsa::Signer<ml_dsa::Signature<P>>,
{
    use ml_dsa::Signer as Signer3;
    let sig: ml_dsa::Signature<P> = key
        .try_sign(data)
        .map_err(|e| SignError::Seal(format!("ML-DSA sign: {e}")))?;
    let encoded = sig.encode();
    let bytes: &[u8] = encoded.as_ref();
    Ok(bytes.to_vec())
}

/// Create a detached CMS SignedData seal over the manifest bytes.
///
/// Accepts any `SealKey` variant (ECDSA-P256 or ML-DSA). ECDSA uses
/// prehash signing; ML-DSA signs the raw signed attributes DER.
pub fn create_cms_seal(
    manifest_bytes: &[u8],
    seal_key: &SealKey,
    seal_cert_der: &[u8],
) -> Result<Vec<u8>> {
    let manifest_digest = Sha256::digest(manifest_bytes);

    let cert = Certificate::from_der(seal_cert_der)
        .map_err(|e| SignError::Seal(format!("parse seal cert: {e}")))?;

    let content_type_attr = build_content_type_attr()?;
    let message_digest_attr = build_message_digest_attr(&manifest_digest)?;

    let signed_attrs = Attributes::try_from(vec![content_type_attr, message_digest_attr])
        .map_err(|e| SignError::Seal(format!("build signed attrs: {e}")))?;

    let signed_attrs_der = signed_attrs
        .to_der()
        .map_err(|e| SignError::Seal(format!("encode signed attrs: {e}")))?;

    let sig_bytes = seal_key.sign_attrs(&signed_attrs_der)?;

    let signer_info = SignerInfo {
        version: cms::content_info::CmsVersion::V1,
        sid: cms::signed_data::SignerIdentifier::from(&cert),
        digest_alg: spki_v08::AlgorithmIdentifierOwned {
            oid: seal_key.digest_algorithm_oid(),
            parameters: None,
        },
        signed_attrs: Some(signed_attrs),
        signature_algorithm: spki_v08::AlgorithmIdentifierOwned {
            oid: seal_key.algorithm_oid(),
            parameters: None,
        },
        signature: OctetString::new(sig_bytes)
            .map_err(|e| SignError::Seal(format!("sig octet string: {e}")))?,
        unsigned_attrs: None,
    };

    let digest_alg = spki_v08::AlgorithmIdentifierOwned {
        oid: ID_SHA256,
        parameters: None,
    };
    let digest_algorithms = DigestAlgorithmIdentifiers::try_from(vec![digest_alg])
        .map_err(|e| SignError::Seal(format!("digest algs: {e}")))?;

    let cert_set = CertificateSet::try_from(vec![cms::cert::CertificateChoices::Certificate(cert)])
        .map_err(|e| SignError::Seal(format!("cert set: {e}")))?;

    let signer_infos = SignerInfos::try_from(vec![signer_info])
        .map_err(|e| SignError::Seal(format!("signer infos: {e}")))?;

    // Detached: no eContent
    let encap_content_info = EncapsulatedContentInfo {
        econtent_type: ID_CT_DATA,
        econtent: None,
    };

    let signed_data = SignedData {
        version: cms::content_info::CmsVersion::V1,
        digest_algorithms,
        encap_content_info,
        certificates: Some(cert_set),
        crls: None,
        signer_infos,
    };

    // Wrap in ContentInfo
    let signed_data_der = signed_data
        .to_der()
        .map_err(|e| SignError::Seal(format!("encode SignedData: {e}")))?;

    let content_info = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::from_der(&signed_data_der)
            .map_err(|e| SignError::Seal(format!("wrap ContentInfo: {e}")))?,
    };

    content_info
        .to_der()
        .map_err(|e| SignError::Seal(format!("encode ContentInfo: {e}")))
}

fn build_content_type_attr() -> Result<Attribute> {
    let oid_der = ID_CT_DATA
        .to_der()
        .map_err(|e| SignError::Seal(format!("encode content type OID: {e}")))?;
    let attr_val = AttributeValue::from_der(&oid_der)
        .map_err(|e| SignError::Seal(format!("attr value from OID: {e}")))?;
    let mut values = SetOfVec::new();
    values
        .insert(attr_val)
        .map_err(|e| SignError::Seal(format!("insert content type: {e}")))?;
    Ok(Attribute {
        oid: ID_CONTENT_TYPE,
        values,
    })
}

fn build_message_digest_attr(digest: &[u8]) -> Result<Attribute> {
    let octet_string = OctetString::new(digest.to_vec())
        .map_err(|e| SignError::Seal(format!("digest octet string: {e}")))?;
    let octet_der = octet_string
        .to_der()
        .map_err(|e| SignError::Seal(format!("encode digest: {e}")))?;
    let attr_val = AttributeValue::from_der(&octet_der)
        .map_err(|e| SignError::Seal(format!("attr value from digest: {e}")))?;
    let mut values = SetOfVec::new();
    values
        .insert(attr_val)
        .map_err(|e| SignError::Seal(format!("insert message digest: {e}")))?;
    Ok(Attribute {
        oid: ID_MESSAGE_DIGEST,
        values,
    })
}

/// Synthetic payload for the seal material preflight. Domain-separated so a
/// preflight seal can never be confused with a manifest seal.
const SEAL_PREFLIGHT_PAYLOAD: &[u8] = b"hoike:seal-preflight:v1";

/// Load a configured seal certificate, normalizing PEM or DER input to DER.
///
/// PEM input may carry ordinary line endings and whitespace; the label must
/// be a CERTIFICATE. The result must parse as an X.509 certificate (same
/// der 0.8 codec CMS seal creation uses) before it is returned, so malformed
/// input fails here instead of at bundle publication.
pub fn load_seal_certificate(path: &std::path::Path) -> Result<Vec<u8>> {
    let data = std::fs::read(path)
        .map_err(|e| SignError::Seal(format!("read seal certificate {}: {e}", path.display())))?;
    let der = if data.starts_with(b"-----BEGIN") {
        let pem = String::from_utf8(data).map_err(|e| {
            SignError::Seal(format!(
                "seal certificate {} PEM is not valid UTF-8: {e}",
                path.display()
            ))
        })?;
        // Validate the PEM label — reject non-certificate files.
        let first_line = pem.lines().next().unwrap_or("");
        if !first_line.contains("CERTIFICATE") {
            return Err(SignError::Seal(format!(
                "seal certificate {} has unexpected PEM label: {} — expected CERTIFICATE",
                path.display(),
                first_line.trim()
            )));
        }
        let mut b64 = String::new();
        for line in pem.lines() {
            if line.starts_with("-----") {
                continue;
            }
            b64.push_str(line.trim());
        }
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| {
                SignError::Seal(format!(
                    "seal certificate {} PEM base64 decode: {e}",
                    path.display()
                ))
            })?
    } else {
        data
    };
    Certificate::from_der(&der)
        .map_err(|e| SignError::Seal(format!("parse seal certificate {}: {e}", path.display())))?;
    Ok(der)
}

/// Prove the seal key/certificate pair before publication.
///
/// Creates a real CMS seal over the domain-separated preflight payload and
/// verifies it with `ahu::verify_seal_with_pins` using the configured
/// certificate as an exact pin at `now`. This exercises the actual signing
/// algorithm, the key/certificate binding, validity, and the supported
/// certificate profile.
pub fn validate_seal_materials(key: &SealKey, cert_der: &[u8], now: u64) -> Result<()> {
    let seal = create_cms_seal(SEAL_PREFLIGHT_PAYLOAD, key, cert_der)?;
    ahu::verify_seal_with_pins(SEAL_PREFLIGHT_PAYLOAD, &seal, &[cert_der.to_vec()], now)
        .map_err(|e| SignError::Seal(format!("seal material preflight: {e}")))?;
    Ok(())
}

/// Domain-separated message signed by the OCSP signer to prove its key is
/// not the seal key (F07). A signature over this message that verifies under
/// the seal public key proves prohibited key reuse.
const SEAL_OCSP_KEY_SEPARATION_MESSAGE: &[u8] = b"hoike:seal-ocsp-key-separation:v1";

/// Prove that the OCSP signer's key is distinct from the configured seal
/// key (F07).
///
/// Signs the domain-separated separation message with the OCSP signer through
/// the same fallible `Signer`/`SignatureBitStringEncoding` bridge bundle
/// production uses (software P-256 with `Sig = p256::ecdsa::DerSignature`, or
/// the PKCS#11 bridge with `Sig = hoike_sign::Pkcs11EcdsaSignature`), parses
/// the result as a valid DER P-256 signature, and rejects the configuration
/// if it verifies under the seal key's public key — proving the same key
/// material is configured for both roles even through different file names.
/// ML-DSA seal keys are algorithm-distinct from ECDSA OCSP signers and always
/// pass. Any signer or encoding error fails the preflight: this never
/// silently skips the check.
pub fn ensure_distinct_ecdsa_seal_key<S, Sig>(signer: &S, seal: &SealKey) -> Result<()>
where
    S: signature::Signer<Sig>,
    Sig: spki::SignatureBitStringEncoding,
{
    let seal_verifying = match seal {
        SealKey::EcdsaP256(key) => p256::ecdsa::VerifyingKey::from(key),
        // An ECDSA signature cannot verify under an ML-DSA seal key: the
        // algorithms are distinct by construction.
        SealKey::MlDsa44(_) | SealKey::MlDsa65(_) | SealKey::MlDsa87(_) => return Ok(()),
    };
    let sig = signer
        .try_sign(SEAL_OCSP_KEY_SEPARATION_MESSAGE)
        .map_err(|e| SignError::Seal(format!("seal/OCSP key separation proof signing: {e}")))?;
    let der_sig = p256::ecdsa::DerSignature::try_from(
        sig.to_bitstring()
            .map_err(|e| {
                SignError::Seal(format!("seal/OCSP key separation signature encoding: {e}"))
            })?
            .as_bytes()
            .ok_or_else(|| {
                SignError::Seal("seal/OCSP key separation signature has unused bits".into())
            })?,
    )
    .map_err(|e| {
        SignError::Seal(format!(
            "seal/OCSP key separation signature is not valid DER ECDSA: {e}"
        ))
    })?;
    if seal_verifying
        .verify(SEAL_OCSP_KEY_SEPARATION_MESSAGE, &der_sig)
        .is_ok()
    {
        return Err(SignError::Seal(
            "the OCSP signing key and the seal key are the same key — configure distinct \
             seal material (ahu spec §2.3)"
                .into(),
        ));
    }
    Ok(())
}

/// Convert raw ECDSA P-256 signature (r || s, 64 bytes) to DER encoding.
fn ecdsa_raw_to_der(raw: &[u8]) -> Vec<u8> {
    if raw.len() != 64 {
        return raw.to_vec();
    }
    let r = &raw[..32];
    let s = &raw[32..];

    fn encode_integer(val: &[u8]) -> Vec<u8> {
        let start = val.iter().position(|&b| b != 0).unwrap_or(val.len() - 1);
        let val = &val[start..];
        let needs_pad = val.first().is_some_and(|&b| b & 0x80 != 0);
        let len = val.len() + usize::from(needs_pad);
        let mut out = vec![0x02, len as u8];
        if needs_pad {
            out.push(0x00);
        }
        out.extend_from_slice(val);
        out
    }

    let r_enc = encode_integer(r);
    let s_enc = encode_integer(s);
    let total = r_enc.len() + s_enc.len();
    let mut out = vec![0x30, total as u8];
    out.extend_from_slice(&r_enc);
    out.extend_from_slice(&s_enc);
    out
}

/// Generate a self-signed seal certificate for testing/demo use.
pub fn generate_seal_cert(signing_key: &p256::ecdsa::SigningKey) -> Result<Vec<u8>> {
    generate_seal_cert_for_key(&SealKey::EcdsaP256(signing_key.clone()))
}

/// Generate a fresh, random ECDSA P-256 seal key for explicit demo mode
/// (F07).
///
/// Distinct from the fixed demo OCSP key and from any persistent seal key by
/// construction, so the demo signing path can never trip — or silently
/// satisfy — the OCSP/seal key-separation proof.
pub fn demo_ephemeral_seal_key() -> p256::ecdsa::SigningKey {
    use rand_core::OsRng;
    p256::ecdsa::SigningKey::random(&mut OsRng)
}

/// Resolve seal material under the shared F07 policy — the single source of
/// truth for the seal-material decision, consumed by the configured loader
/// (`orchestrate::load_seal_materials`) and the one-shot `hoike sign` path.
/// (`hoike-core`'s config validation mirrors the structural rules; it cannot
/// depend on `hoike-sign`.)
///
/// - both `seal_key` and `seal_cert` → load the persistent pair (the
///   certificate is PEM/DER-normalized) and prove it with the real CMS
///   preflight;
/// - exactly one → error: a half-configured seal pair is always an error;
/// - neither → error for production; explicit demo generates a distinct
///   ephemeral pair (warned, NOT FOR PRODUCTION) and proves it the same way.
///
/// Errors are policy messages without caller context; callers prefix their
/// own scope (CA label, flag-name guidance).
pub fn load_or_generate_seal_material(
    seal_key: Option<&std::path::Path>,
    seal_cert: Option<&std::path::Path>,
    demo: bool,
) -> std::result::Result<(SealKey, Vec<u8>), String> {
    let (seal_key, seal_cert_der) = match (seal_key, seal_cert) {
        (Some(key_path), Some(cert_path)) => {
            let ecdsa_key = crate::load_ecdsa_p256_key(key_path)
                .map_err(|e| format!("load seal key {}: {e}", key_path.display()))?;
            let cert =
                load_seal_certificate(cert_path).map_err(|e| format!("load seal cert: {e}"))?;
            (SealKey::EcdsaP256(ecdsa_key), cert)
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err("seal_key and seal_cert must be configured together — \
                 a half-configured seal pair is always an error"
                .into());
        }
        (None, None) => {
            if !demo {
                return Err("production signing requires a persistent seal_key and \
                     seal_cert pair — configure both, or use the demo signing \
                     key for testing"
                    .into());
            }
            warn!(
                "no seal material configured — generating a distinct ephemeral \
                 demo seal pair (NOT FOR PRODUCTION)"
            );
            let key = demo_ephemeral_seal_key();
            let cert = generate_seal_cert_for_key(&SealKey::EcdsaP256(key.clone()))
                .map_err(|e| format!("generate demo seal cert: {e}"))?;
            (SealKey::EcdsaP256(key), cert)
        }
    };
    // F08: prove the pair on every load — callers run this per signing pass
    // (background loop, on-demand signing, post-rotation reload), so the
    // verdict is never a startup-only cache. Failures propagate before any
    // bundle is produced or published.
    let now = crate::source::unix_now().map_err(|e| format!("clock: {e}"))?;
    validate_seal_materials(&seal_key, &seal_cert_der, now).map_err(|e| e.to_string())?;
    Ok((seal_key, seal_cert_der))
}

/// Generate a self-signed seal certificate for any `SealKey` type.
pub fn generate_seal_cert_for_key(seal_key: &SealKey) -> Result<Vec<u8>> {
    let (pub_key_bytes, alg_id_der) = match seal_key {
        SealKey::EcdsaP256(key) => {
            let vk = p256::ecdsa::VerifyingKey::from(key);
            let pub_key = p256::PublicKey::from(vk).to_sec1_bytes().to_vec();
            (pub_key, encode_ecdsa_alg_id())
        }
        SealKey::MlDsa44(key) => {
            use ml_dsa::Keypair;
            (
                key.verifying_key().encode().to_vec(),
                encode_ml_dsa_alg_id(ML_DSA_44_OID),
            )
        }
        SealKey::MlDsa65(key) => {
            use ml_dsa::Keypair;
            (
                key.verifying_key().encode().to_vec(),
                encode_ml_dsa_alg_id(ML_DSA_65_OID),
            )
        }
        SealKey::MlDsa87(key) => {
            use ml_dsa::Keypair;
            (
                key.verifying_key().encode().to_vec(),
                encode_ml_dsa_alg_id(ML_DSA_87_OID),
            )
        }
    };

    let spki_der = match seal_key {
        SealKey::EcdsaP256(_) => encode_ecdsa_spki(&pub_key_bytes),
        _ => encode_ml_dsa_spki(&pub_key_bytes, &alg_id_der),
    };

    let mut tbs = Vec::new();
    tbs.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);
    tbs.extend_from_slice(&[0x02, 0x01, 0x01]);
    tbs.extend_from_slice(&alg_id_der);
    let name = encode_cn("hoike-seal");
    tbs.extend_from_slice(&name);
    tbs.extend_from_slice(&encode_validity()?);
    tbs.extend_from_slice(&name);
    tbs.extend_from_slice(&spki_der);
    let tbs_seq = wrap_seq(&tbs);

    let sig_bytes = seal_key.sign_attrs(&tbs_seq)?;

    let mut cert = Vec::new();
    cert.extend_from_slice(&tbs_seq);
    cert.extend_from_slice(&alg_id_der);
    cert.extend_from_slice(&encode_bitstring(&sig_bytes));

    Ok(wrap_seq(&cert))
}

fn encode_bitstring(data: &[u8]) -> Vec<u8> {
    let bs_len = data.len() + 1; // +1 for unused-bits byte
    let mut bs = vec![0x03];
    encode_der_length(&mut bs, bs_len);
    bs.push(0x00); // unused bits
    bs.extend_from_slice(data);
    bs
}

/// Append a DER definite-length encoding to `out`.
fn encode_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 65536 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push(((len >> 8) & 0xFF) as u8);
        out.push((len & 0xFF) as u8);
    }
}

fn encode_ecdsa_alg_id() -> Vec<u8> {
    let oid = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
    wrap_seq(oid)
}

fn encode_ml_dsa_alg_id(oid_str: &str) -> Vec<u8> {
    let oid = ObjectIdentifier::new_unwrap(oid_str);
    let oid_der = oid.to_der().unwrap();
    wrap_seq(&oid_der)
}

fn encode_cn(cn: &str) -> Vec<u8> {
    let cn_oid = &[0x06, 0x03, 0x55, 0x04, 0x03];
    let cn_val = tlv(0x0C, cn.as_bytes());
    let mut attr = Vec::new();
    attr.extend_from_slice(cn_oid);
    attr.extend_from_slice(&cn_val);
    let attr_seq = wrap_seq(&attr);
    let rdn_set = tlv(0x31, &attr_seq);
    wrap_seq(&rdn_set)
}

/// Fresh validity window for generated (demo) certificates, anchored at the
/// generation time instead of a fixed historic range: backdated five minutes
/// for clock skew and expiring two years out, so generated material is always
/// freshly valid and never a fixed-window fixture.
fn encode_validity() -> Result<Vec<u8>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| SignError::Seal(format!("clock: {e}")))?;
    let not_before = now.as_secs().saturating_sub(300);
    let not_after = now.as_secs().saturating_add(2 * 365 * 86400);
    let mut v = Vec::new();
    // Tag 0x17 is UTCTime (YYMMDDHHMMSSZ), which der 0.7's `Time` CHOICE
    // accepts for years 1950–2049.
    v.extend_from_slice(&tlv(0x17, format_utc_time(not_before).as_bytes()));
    v.extend_from_slice(&tlv(0x17, format_utc_time(not_after).as_bytes()));
    Ok(wrap_seq(&v))
}

/// Format a unix timestamp as an RFC 5280 UTCTime `YYMMDDHHMMSSZ` literal
/// (valid for years 1950–2049, which covers generated demo material).
fn format_utc_time(unix_secs: u64) -> String {
    let days = unix_secs / 86400;
    let secs = unix_secs % 86400;
    // Howard Hinnant's civil-from-days conversion.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        year % 100,
        month,
        day,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn encode_ecdsa_spki(pub_key_uncompressed: &[u8]) -> Vec<u8> {
    let ec_oid = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    let p256_oid = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let mut alg = Vec::new();
    alg.extend_from_slice(ec_oid);
    alg.extend_from_slice(p256_oid);
    let alg_seq = wrap_seq(&alg);

    let mut spki = Vec::new();
    spki.extend_from_slice(&alg_seq);
    spki.extend_from_slice(&encode_bitstring(pub_key_uncompressed));
    wrap_seq(&spki)
}

fn encode_ml_dsa_spki(pub_key_bytes: &[u8], alg_id_der: &[u8]) -> Vec<u8> {
    let mut spki = Vec::new();
    spki.extend_from_slice(alg_id_der);
    spki.extend_from_slice(&encode_bitstring(pub_key_bytes));
    wrap_seq(&spki)
}

fn wrap_seq(content: &[u8]) -> Vec<u8> {
    tlv(0x30, content)
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    encode_der_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> p256::ecdsa::SigningKey {
        let secret = [7u8; 32];
        p256::ecdsa::SigningKey::from_bytes((&secret).into()).unwrap()
    }

    #[test]
    fn generate_seal_cert_parseable() {
        let key = test_key();
        let cert_der = generate_seal_cert(&key).unwrap();
        let cert = Certificate::from_der(&cert_der).unwrap();
        assert_eq!(cert.tbs_certificate().serial_number().as_bytes(), &[0x01]);
    }

    /// F07: the shared seal-material policy decision. One implementation,
    /// unit-tested here, consumed by the configured loader and the one-shot
    /// CLI sign path.
    #[test]
    fn load_or_generate_seal_material_policy() {
        use p256::pkcs8::EncodePrivateKey;

        let dir = tempfile::tempdir().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let key = test_key();
        let cert_der = generate_seal_cert(&key).unwrap();
        let key_path = dir.path().join("seal.p8");
        std::fs::write(&key_path, key.to_pkcs8_der().unwrap().as_bytes()).unwrap();
        let cert_path = dir.path().join("seal.der");
        std::fs::write(&cert_path, &cert_der).unwrap();
        let missing = dir.path().join("missing");

        // A complete pair loads and passes the CMS preflight.
        let (loaded, cert) =
            load_or_generate_seal_material(Some(&key_path), Some(&cert_path), false).unwrap();
        assert!(matches!(loaded, SealKey::EcdsaP256(_)));
        assert_eq!(cert, cert_der);

        // Exactly one input is always an error, in either direction, demo or
        // not.
        for demo in [false, true] {
            let err = load_or_generate_seal_material(Some(&key_path), None, demo)
                .err()
                .expect("half pair (key only) must error");
            assert!(err.contains("half-configured"), "demo={demo}: {err}");
            let err = load_or_generate_seal_material(None, Some(&cert_path), demo)
                .err()
                .expect("half pair (cert only) must error");
            assert!(err.contains("half-configured"), "demo={demo}: {err}");
        }

        // Neither input errors for production...
        let err = load_or_generate_seal_material(None, None, false)
            .err()
            .expect("production without seal material must error");
        assert!(err.contains("persistent"), "{err}");

        // ...and generates distinct ephemeral material for explicit demo.
        let (demo_seal, demo_cert) = load_or_generate_seal_material(None, None, true).unwrap();
        let SealKey::EcdsaP256(demo_key) = &demo_seal else {
            panic!("demo seal material must be ECDSA P-256");
        };
        assert_ne!(
            demo_key.verifying_key(),
            crate::demo_ecdsa_p256_key().verifying_key(),
            "demo seal key must be distinct from the demo OCSP key"
        );
        let (second, _) = load_or_generate_seal_material(None, None, true).unwrap();
        let SealKey::EcdsaP256(second_key) = &second else {
            panic!("demo seal material must be ECDSA P-256");
        };
        assert_ne!(
            second_key.verifying_key(),
            demo_key.verifying_key(),
            "ephemeral demo seal keys must be freshly generated"
        );
        assert!(validate_seal_materials(&demo_seal, &demo_cert, now).is_ok());

        // Load failures propagate: unreadable key or certificate files.
        assert!(
            load_or_generate_seal_material(Some(&missing), Some(&cert_path), false).is_err(),
            "unreadable seal key must fail the load"
        );
        assert!(
            load_or_generate_seal_material(Some(&key_path), Some(&missing), false).is_err(),
            "unreadable seal certificate must fail the load"
        );
    }

    #[test]
    fn seal_round_trip() {
        let key = test_key();
        let seal_key = SealKey::EcdsaP256(key.clone());
        let cert_der = generate_seal_cert(&key).unwrap();
        let manifest = b"test manifest data for seal verification";

        let seal = create_cms_seal(manifest, &seal_key, &cert_der).unwrap();
        assert!(!seal.is_empty());

        let ci = ContentInfo::from_der(&seal).unwrap();
        assert_eq!(ci.content_type, ID_SIGNED_DATA);

        let sd = ci.content.decode_as::<SignedData>().unwrap();
        assert!(sd.certificates.is_some());
        assert_eq!(sd.signer_infos.0.len(), 1);
        assert!(sd.encap_content_info.econtent.is_none());
    }

    #[test]
    fn seal_has_message_digest_attr() {
        let key = test_key();
        let seal_key = SealKey::EcdsaP256(key.clone());
        let cert_der = generate_seal_cert(&key).unwrap();
        let manifest = b"manifest";

        let seal = create_cms_seal(manifest, &seal_key, &cert_der).unwrap();
        let ci = ContentInfo::from_der(&seal).unwrap();
        let sd = ci.content.decode_as::<SignedData>().unwrap();
        let si = &sd.signer_infos.0.as_slice()[0];

        let attrs = si.signed_attrs.as_ref().expect("signed_attrs required");
        assert!(
            attrs.iter().any(|a| a.oid == ID_MESSAGE_DIGEST),
            "must contain message-digest attribute"
        );
        assert!(
            attrs.iter().any(|a| a.oid == ID_CONTENT_TYPE),
            "must contain content-type attribute"
        );
    }

    #[test]
    fn ml_dsa_87_seal_cert_parseable() {
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed((&[42u8; 32]).into());
        let seal_key = SealKey::MlDsa87(sk);
        let cert_der = generate_seal_cert_for_key(&seal_key).unwrap();
        let cert = Certificate::from_der(&cert_der).unwrap();
        assert_eq!(cert.tbs_certificate().serial_number().as_bytes(), &[0x01]);
    }

    #[test]
    fn ml_dsa_87_seal_round_trip() {
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed((&[99u8; 32]).into());
        let seal_key = SealKey::MlDsa87(sk);
        let cert_der = generate_seal_cert_for_key(&seal_key).unwrap();
        let manifest = b"ML-DSA sealed manifest";

        let seal = create_cms_seal(manifest, &seal_key, &cert_der).unwrap();
        assert!(!seal.is_empty());

        let ci = ContentInfo::from_der(&seal).unwrap();
        let sd = ci.content.decode_as::<SignedData>().unwrap();
        let si = &sd.signer_infos.0.as_slice()[0];

        let sig_alg = si.signature_algorithm.oid.to_string();
        assert_eq!(sig_alg, ML_DSA_87_OID);
        assert!(
            si.signature.as_bytes().len() > 4000,
            "ML-DSA-87 sig should be ~4627 bytes"
        );
    }
}
