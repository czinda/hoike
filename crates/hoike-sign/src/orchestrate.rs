//! Bundle-production orchestration shared by the CLI signer loop and the admin
//! signing API.
//!
//! This module turns a `(Config, CaConfig, RevocationSource)` into signed,
//! CMS-sealed bundle bytes — handling revocation snapshotting, anti-rollback
//! epoch derivation, signing-key source dispatch (ECDSA / ML-DSA × file / demo /
//! PKCS#11), seal materials, and responder-cert loading.
//!
//! It deliberately contains no interactive I/O: PKCS#11 PINs are resolved only
//! from config or the environment, never a terminal prompt. The CLI keeps its
//! own interactive PIN path for the one-shot `hoike sign` subcommand.

use std::collections::HashMap;
use std::path::PathBuf;

use hoike_core::config::{CaConfig, Config};
use sha2::Digest as _;
use tracing::{info, warn};

use crate::{CaIdentity, CrlSource, GenerationConfig, RevocationSource, SealKey};

/// Producer ID stamped into combined-mode bundles.
///
/// This string is part of the anti-rollback high-water-mark key, so the
/// background signer loop and the on-demand admin handler MUST use the same
/// value or they will derive divergent epochs for the same scope.
pub const COMBINED_PRODUCER_ID: &str = "hoike-combined";

/// Map of CA label → persistent revocation source. Stateful sources (DogtagSync)
/// retain their in-memory snapshot and sync cookie across signer passes and must
/// be shared, not rebuilt, between the background loop and on-demand signing.
pub type PersistentSources = HashMap<String, Box<dyn RevocationSource>>;

/// Outcome of signing one CA scope.
#[derive(Debug, Clone)]
pub struct SignedScope {
    pub label: String,
    /// Serialized, CMS-sealed bundle bytes.
    pub bytes: Vec<u8>,
    pub entry_count: usize,
    /// Epoch assigned to this generation (persisted high-water + 1).
    pub epoch: u64,
}

/// Build the persistent revocation sources for a config. Only stateful sources
/// (DogtagSync) are created here; stateless sources (CRL) are resolved fresh at
/// signing time.
#[allow(unused_mut)]
#[allow(unused_variables)]
// Without `dogtag-sync`, the match reduces to `_ => continue` (all arms diverge),
// making the trailing insert unreachable. It IS reached when the feature is on.
#[cfg_attr(not(feature = "dogtag-sync"), allow(unreachable_code))]
pub fn create_persistent_sources(
    config: &Config,
) -> std::result::Result<PersistentSources, String> {
    let mut sources = PersistentSources::new();
    for ca_config in &config.ca {
        let source_config = match &ca_config.source {
            Some(s) => s,
            None => continue,
        };
        let source: Box<dyn RevocationSource> = match source_config {
            #[cfg(feature = "dogtag-sync")]
            hoike_core::config::SourceConfig::DogtagSync {
                ldap_url,
                base_dn,
                bind_dn,
                bind_password,
                bind_password_env,
                cookie_path,
                filter,
                tls,
                ca_cert,
            } => {
                let password =
                    resolve_ldap_password(bind_password.as_deref(), bind_password_env.as_deref())?;
                let cookie = cookie_path.clone().unwrap_or_else(|| {
                    config
                        .storage
                        .state_db
                        .join(format!("sync-{}.json", ca_config.label))
                });
                let sync_config = crate::DogtagSyncConfig {
                    ldap_url: ldap_url.clone(),
                    base_dn: base_dn.clone(),
                    bind_dn: bind_dn.clone(),
                    bind_password: password,
                    cookie_path: cookie,
                    filter: filter
                        .clone()
                        .unwrap_or_else(|| "(objectClass=certificateRecord)".into()),
                    tls: tls.clone(),
                    ca_cert: ca_cert.clone(),
                };
                Box::new(crate::DogtagSyncSource::new(sync_config))
            }
            // CRL and other stateless sources are created fresh each pass.
            _ => continue,
        };
        sources.insert(ca_config.label.clone(), source);
    }
    Ok(sources)
}

/// Resolve the revocation source for a CA: prefer the shared persistent source,
/// otherwise build a fresh stateless one (CRL). Returns an owned box for the
/// fresh case so the caller can hold it alongside the borrowed persistent case.
fn resolve_source<'a>(
    ca_config: &CaConfig,
    persistent_sources: &'a PersistentSources,
    fresh_holder: &'a mut Option<Box<dyn RevocationSource>>,
) -> std::result::Result<&'a dyn RevocationSource, String> {
    if let Some(ps) = persistent_sources.get(&ca_config.label) {
        return Ok(ps.as_ref());
    }

    let source_config = ca_config
        .source
        .as_ref()
        .ok_or_else(|| format!("CA '{}': no revocation source configured", ca_config.label))?;

    let fresh: Box<dyn RevocationSource> = match source_config {
        hoike_core::config::SourceConfig::Crl { path, issuer_cert } => {
            let crl_data = std::fs::read(path)
                .map_err(|e| format!("failed to read CRL {}: {e}", path.display()))?;
            let source = if crl_data.starts_with(b"-----BEGIN") {
                let pem =
                    String::from_utf8(crl_data).map_err(|e| format!("CRL not valid UTF-8: {e}"))?;
                CrlSource::from_pem(&pem).map_err(|e| format!("CRL parse: {e}"))?
            } else {
                CrlSource::from_der(crl_data).map_err(|e| format!("CRL parse: {e}"))?
            };
            let issuer_path = issuer_cert.as_ref().ok_or_else(|| {
                format!(
                    "CA '{}': CRL source requires issuer_cert for authentication",
                    ca_config.label
                )
            })?;
            let issuer =
                std::fs::read(issuer_path).map_err(|e| format!("read issuer certificate: {e}"))?;
            Box::new(
                source
                    .with_issuer_certificate(&issuer)
                    .map_err(|e| format!("issuer certificate: {e}"))?,
            )
        }
        #[cfg(feature = "dogtag-sync")]
        hoike_core::config::SourceConfig::DogtagSync { .. } => {
            return Err(format!(
                "CA '{}': DogtagSync source must be persistent but was not found",
                ca_config.label
            ));
        }
        #[cfg(not(feature = "dogtag-sync"))]
        hoike_core::config::SourceConfig::DogtagSync { .. } => {
            return Err("dogtag-sync requires the 'dogtag-sync' feature flag".into());
        }
    };
    *fresh_holder = Some(fresh);
    Ok(fresh_holder.as_ref().unwrap().as_ref())
}

/// Produce a signed bundle for one CA scope from an already-resolved revocation
/// source. Pure with respect to the filesystem for the *bundle* (does not write
/// the `.ahu`); it does read the state store to derive the epoch.
pub fn sign_ca_scope(
    config: &Config,
    ca_config: &CaConfig,
    source: &dyn RevocationSource,
) -> std::result::Result<SignedScope, String> {
    let ca = CaIdentity {
        label: ca_config.label.clone(),
        issuer_name_der: decode_issuer_name(ca_config)?,
        issuer_key_bytes: decode_issuer_key(ca_config)?,
    };

    let snapshot = source
        .snapshot(&ca)
        .map_err(|e| format!("snapshot failed for {}: {e}", ca_config.label))?;

    // Derive epoch from the persisted high-water mark — never from wall-clock
    // time, which can step backward (NTP correction, VM restore) and permanently
    // lock out mirrors.
    let epoch = {
        let state_db_path = config.storage.state_db.join("state.json");
        let store = hoike_core::StateStore::open(&state_db_path)
            .map_err(|e| format!("state store: {e}"))?;
        let issuer_key_hash_hex = hex::encode(sha2::Sha256::digest(&ca.issuer_key_bytes));
        store
            .get_high_water(COMBINED_PRODUCER_ID, &issuer_key_hash_hex)
            .unwrap_or(0)
            .saturating_add(1)
    };

    let gen_config = GenerationConfig {
        producer_id: COMBINED_PRODUCER_ID.into(),
        epoch,
        validity_secs: ca_config.validity_secs,
        certid_compat: crate::CertIdCompat::Dual,
        completeness: match ca_config.completeness.as_str() {
            "authoritative-complete" if source.is_authoritative_complete() => {
                ahu::Completeness::AuthoritativeComplete
            }
            "authoritative-complete" => {
                return Err(format!(
                    "CA '{}': source cannot prove authoritative completeness; configure partial",
                    ca_config.label
                ));
            }
            "partial" => ahu::Completeness::Partial,
            other => return Err(format!("unknown completeness: {other}")),
        },
        ..Default::default()
    };

    // Also protect on-demand generation against invalid live key/cert replacements.
    if ca_config.nonce_policy == "live" {
        crate::live::load_live_material(ca_config)?;
    }
    let responder_cert_der = load_responder_cert(ca_config)?;
    let (seal_key, seal_cert_der) = load_seal_materials(ca_config)?;

    let bundle_bytes = produce_scope_bundle(
        ca_config,
        &ca,
        &snapshot,
        &gen_config,
        &seal_key,
        &seal_cert_der,
        responder_cert_der.as_deref(),
    )?;

    Ok(SignedScope {
        label: ca_config.label.clone(),
        entry_count: snapshot.entries.len(),
        epoch,
        bytes: bundle_bytes,
    })
}

/// Sign one CA scope by label, resolving its source, and write the resulting
/// `.ahu` to the configured bundle directory. Used by the on-demand admin API.
pub fn sign_and_write_scope(
    config: &Config,
    persistent_sources: &PersistentSources,
    ca_config: &CaConfig,
) -> std::result::Result<SignedScope, String> {
    let mut fresh_holder: Option<Box<dyn RevocationSource>> = None;
    let source = resolve_source(ca_config, persistent_sources, &mut fresh_holder)?;
    let signed = sign_ca_scope(config, ca_config, source)?;
    let path = write_bundle(config, &signed.label, &signed.bytes)?;
    info!(
        ca = signed.label,
        epoch = signed.epoch,
        entries = signed.entry_count,
        size = signed.bytes.len(),
        path = %path.display(),
        "bundle produced (CMS sealed)"
    );
    Ok(signed)
}

/// Sign every configured CA that has a revocation source, writing each `.ahu`.
/// CAs without a source are skipped. Returns the list of signed scopes.
pub fn sign_and_write_all(
    config: &Config,
    persistent_sources: &PersistentSources,
) -> std::result::Result<Vec<SignedScope>, String> {
    let mut out = Vec::new();
    for ca_config in &config.ca {
        if ca_config.source.is_none() {
            continue;
        }
        out.push(sign_and_write_scope(config, persistent_sources, ca_config)?);
    }
    Ok(out)
}

/// Write bundle bytes to `{bundle_dir}/{label}.ahu`, creating the directory if
/// needed. Returns the written path.
pub fn write_bundle(
    config: &Config,
    label: &str,
    bytes: &[u8],
) -> std::result::Result<PathBuf, String> {
    let path = config
        .ca
        .iter()
        .find(|ca| ca.label == label)
        .and_then(|ca| ca.bundle_file.clone())
        .unwrap_or_else(|| config.storage.bundle_dir.join(format!("{label}.ahu")));
    write_bundle_atomic(&path, bytes)?;
    Ok(path)
}

/// Durable replacement: readers see either complete old or complete new bytes.
pub fn write_bundle_atomic(
    path: &std::path::Path,
    bytes: &[u8],
) -> std::result::Result<(), String> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| format!("create bundle directory: {e}"))?;
    let tmp = parent.join(format!(".hoike-{}.tmp", uuid::Uuid::now_v7()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok::<_, std::io::Error>(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(|e| format!("publish {}: {e}", path.display()))
}

/// Dispatch bundle production over the CA's configured signing-key source and
/// algorithm. This is the single place the ECDSA/ML-DSA × file/demo/PKCS#11
/// matrix lives.
#[allow(clippy::too_many_arguments)]
fn produce_scope_bundle(
    ca_config: &CaConfig,
    ca: &CaIdentity,
    snapshot: &crate::StatusSnapshot,
    gen_config: &GenerationConfig,
    seal_key: &SealKey,
    seal_cert_der: &[u8],
    responder_cert_der: Option<&[u8]>,
) -> std::result::Result<Vec<u8>, String> {
    let bundle_bytes = if ca_config.is_ml_dsa() {
        match &ca_config.signing_key {
            Some(hoike_core::config::SigningKeyConfig::File { path }) => {
                let mut v =
                    crate::load_ml_dsa_key(path).map_err(|e| format!("signing key: {e}"))?;
                if v.algorithm_name() != ca_config.sig_alg {
                    return Err(format!(
                        "CA '{}': key is {} but sig_alg is {}",
                        ca_config.label,
                        v.algorithm_name(),
                        ca_config.sig_alg
                    ));
                }
                info!(ca = ca_config.label, key = %path.display(), alg = v.algorithm_name(), "using file-based ML-DSA signing key");
                let sk = seal_key.clone();
                let sc = seal_cert_der.to_vec();
                v.sign_bundle(
                    ca,
                    snapshot,
                    gen_config,
                    move |m| crate::create_cms_seal(m, &sk, &sc),
                    responder_cert_der,
                )
            }
            Some(hoike_core::config::SigningKeyConfig::Demo) => {
                warn!(ca = ca_config.label, "using demo ML-DSA key — NOT FOR PRODUCTION");
                let mut v = crate::MlDsaSignerVariant::demo(&ca_config.sig_alg)
                    .map_err(|e| format!("CA '{}': {e}", ca_config.label))?;
                let sk = seal_key.clone();
                let sc = seal_cert_der.to_vec();
                v.sign_bundle(
                    ca,
                    snapshot,
                    gen_config,
                    move |m| crate::create_cms_seal(m, &sk, &sc),
                    responder_cert_der,
                )
            }
            #[cfg(feature = "pkcs11")]
            Some(hoike_core::config::SigningKeyConfig::Pkcs11 { .. }) => {
                let pkcs11_config = resolve_pkcs11_config(ca_config)?;
                let (param_set, oid) = ml_dsa_pkcs11_params(&ca_config.sig_alg)?;
                let inner = crate::Pkcs11MlDsaSigner::new(&pkcs11_config, param_set, oid)
                    .map_err(|e| format!("PKCS#11 ML-DSA init: {e}"))?;
                let mut bridge = crate::Pkcs11MlDsaSignerBridge::new(inner);
                let sk = seal_key.clone();
                let sc = seal_cert_der.to_vec();
                crate::produce_bundle::<_, crate::Pkcs11MlDsaSignature>(
                    ca,
                    snapshot,
                    gen_config,
                    &mut bridge,
                    move |m| {
                        crate::create_cms_seal(m, &sk, &sc)
                            .map_err(|e| crate::SignError::Seal(e.to_string()))
                    },
                    responder_cert_der,
                )
            }
            #[cfg(not(feature = "pkcs11"))]
            Some(hoike_core::config::SigningKeyConfig::Pkcs11 { .. }) => {
                return Err(format!(
                    "CA '{}' requires PKCS#11 but hoike was built without 'pkcs11' feature",
                    ca_config.label
                ));
            }
            None => {
                return Err(format!("CA '{}': no signing_key configured", ca_config.label));
            }
        }
    } else {
        match &ca_config.signing_key {
            Some(hoike_core::config::SigningKeyConfig::File { path }) => {
                let mut signing_key =
                    crate::load_ecdsa_p256_key(path).map_err(|e| format!("signing key: {e}"))?;
                info!(ca = ca_config.label, key = %path.display(), "using file-based signing key");
                let sk = seal_key.clone();
                let sc = seal_cert_der.to_vec();
                crate::produce_bundle::<_, p256::ecdsa::DerSignature>(
                    ca,
                    snapshot,
                    gen_config,
                    &mut signing_key,
                    move |m| crate::create_cms_seal(m, &sk, &sc),
                    responder_cert_der,
                )
            }
            #[cfg(feature = "pkcs11")]
            Some(hoike_core::config::SigningKeyConfig::Pkcs11 { .. }) => {
                let pkcs11_config = resolve_pkcs11_config(ca_config)?;
                let inner = crate::Pkcs11Signer::new(&pkcs11_config)
                    .map_err(|e| format!("PKCS#11 init: {e}"))?;
                let mut bridge = crate::Pkcs11SignerBridge::new(inner);
                let sk = seal_key.clone();
                let sc = seal_cert_der.to_vec();
                crate::produce_bundle::<_, crate::Pkcs11EcdsaSignature>(
                    ca,
                    snapshot,
                    gen_config,
                    &mut bridge,
                    move |m| {
                        crate::create_cms_seal(m, &sk, &sc)
                            .map_err(|e| crate::SignError::Seal(e.to_string()))
                    },
                    responder_cert_der,
                )
            }
            #[cfg(not(feature = "pkcs11"))]
            Some(hoike_core::config::SigningKeyConfig::Pkcs11 { .. }) => {
                return Err(format!(
                    "CA '{}' requires PKCS#11 but hoike was built without 'pkcs11' feature",
                    ca_config.label
                ));
            }
            Some(hoike_core::config::SigningKeyConfig::Demo) => {
                warn!(ca = ca_config.label, "using demo signing key — NOT FOR PRODUCTION");
                let mut signing_key = crate::demo_ecdsa_p256_key();
                let sk = seal_key.clone();
                let sc = seal_cert_der.to_vec();
                crate::produce_bundle::<_, p256::ecdsa::DerSignature>(
                    ca,
                    snapshot,
                    gen_config,
                    &mut signing_key,
                    move |m| crate::create_cms_seal(m, &sk, &sc),
                    responder_cert_der,
                )
            }
            None => {
                return Err(format!("CA '{}': no signing_key configured", ca_config.label));
            }
        }
    }
    .map_err(|e| format!("bundle production failed for {}: {e}", ca_config.label))?;

    Ok(bundle_bytes)
}

// ---------------------------------------------------------------------------
// Config-derived material loading (moved from the CLI so both surfaces share it)
// ---------------------------------------------------------------------------

fn decode_b64_field(
    b64: &Option<String>,
    field_name: &str,
    ca_label: &str,
    fallback: &str,
) -> std::result::Result<Vec<u8>, String> {
    match b64 {
        Some(val) => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(val)
                .map_err(|e| format!("CA '{}': invalid base64 in {}: {e}", ca_label, field_name))
        }
        None => Ok(fallback.as_bytes().to_vec()),
    }
}

fn configured_issuer(ca: &CaConfig) -> std::result::Result<Option<x509_cert::Certificate>, String> {
    if let Some(hoike_core::config::SourceConfig::Crl {
        issuer_cert: Some(path),
        ..
    }) = &ca.source
    {
        let bytes = std::fs::read(path).map_err(|e| format!("read issuer certificate: {e}"))?;
        return crate::rotation::parse_certificate(&bytes)
            .map(Some)
            .map_err(|e| e.to_string());
    }
    Ok(None)
}

/// Decode the issuer DN (DER) for a CA, falling back to a synthetic `CN=<label>`.
pub fn decode_issuer_name(ca: &CaConfig) -> std::result::Result<Vec<u8>, String> {
    if ca.issuer_name_der_b64.is_none() {
        if let Some(cert) = configured_issuer(ca)? {
            use der::Encode;
            return cert
                .tbs_certificate
                .subject
                .to_der()
                .map_err(|e| e.to_string());
        }
    }
    decode_b64_field(
        &ca.issuer_name_der_b64,
        "issuer_name_der_b64",
        &ca.label,
        &format!("CN={}", ca.label),
    )
}

/// Decode the issuer public-key bytes for a CA, falling back to a synthetic key.
pub fn decode_issuer_key(ca: &CaConfig) -> std::result::Result<Vec<u8>, String> {
    if ca.issuer_key_bytes_b64.is_none() {
        if let Some(cert) = configured_issuer(ca)? {
            return cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .map(|b| b.to_vec())
                .ok_or_else(|| "issuer public key has unused bits".into());
        }
    }
    decode_b64_field(
        &ca.issuer_key_bytes_b64,
        "issuer_key_bytes_b64",
        &ca.label,
        &format!("{}-key", ca.label),
    )
}

/// Resolve the LDAP bind password from config or environment (no interactive I/O).
#[cfg(feature = "dogtag-sync")]
pub fn resolve_ldap_password(
    password: Option<&str>,
    env_var: Option<&str>,
) -> std::result::Result<String, String> {
    if let Some(pw) = password {
        return Ok(pw.to_string());
    }
    if let Some(var) = env_var {
        return std::env::var(var).map_err(|_| {
            format!(
                "LDAP bind password env var '{var}' not set. \
                 Set it or use bind_password in config."
            )
        });
    }
    Err("no LDAP bind password: set bind_password or bind_password_env in config".into())
}

/// Load and normalize a responder certificate to DER, if configured.
pub fn load_responder_cert(ca: &CaConfig) -> std::result::Result<Option<Vec<u8>>, String> {
    match &ca.responder_cert {
        Some(path) => {
            let data = std::fs::read(path)
                .map_err(|e| format!("failed to read responder cert '{}': {e}", path.display()))?;
            if data.starts_with(b"-----BEGIN") {
                let pem_str = String::from_utf8(data)
                    .map_err(|e| format!("responder cert PEM is not valid UTF-8: {e}"))?;
                // Validate the PEM label — reject non-certificate files.
                let first_line = pem_str.lines().next().unwrap_or("");
                if !first_line.contains("CERTIFICATE") {
                    return Err(format!(
                        "responder cert '{}' has unexpected PEM label: {} — expected CERTIFICATE",
                        path.display(),
                        first_line.trim()
                    ));
                }
                use base64::Engine;
                let mut b64 = String::new();
                for line in pem_str.lines() {
                    if line.starts_with("-----") {
                        continue;
                    }
                    b64.push_str(line.trim());
                }
                let der = base64::engine::general_purpose::STANDARD
                    .decode(&b64)
                    .map_err(|e| format!("responder cert PEM base64 decode: {e}"))?;
                Ok(Some(der))
            } else {
                Ok(Some(data))
            }
        }
        None => Ok(None),
    }
}

/// Load the seal key and certificate for CMS bundle sealing.
///
/// Falls back to the OCSP signing key if no `seal_key` is configured and the
/// signing key is ECDSA P-256. For ML-DSA signing keys (which are not P-256),
/// falls back to an ephemeral demo seal key with a warning.
pub fn load_seal_materials(
    ca_config: &CaConfig,
) -> std::result::Result<(SealKey, Vec<u8>), String> {
    let seal_key = if let Some(path) = &ca_config.seal_key {
        let ecdsa_key =
            crate::load_ecdsa_p256_key(path).map_err(|e| format!("load seal key: {e}"))?;
        SealKey::EcdsaP256(ecdsa_key)
    } else if !ca_config.is_ml_dsa() {
        if let Some(hoike_core::config::SigningKeyConfig::File { path }) = &ca_config.signing_key {
            warn!(
                ca = ca_config.label,
                "using OCSP signing key as seal key — configure seal_key for production"
            );
            let ecdsa_key = crate::load_ecdsa_p256_key(path)
                .map_err(|e| format!("load signing key for seal: {e}"))?;
            SealKey::EcdsaP256(ecdsa_key)
        } else {
            warn!(
                ca = ca_config.label,
                "no seal_key configured — generating ephemeral seal key"
            );
            SealKey::EcdsaP256(crate::demo_ecdsa_p256_key())
        }
    } else {
        warn!(
            ca = ca_config.label,
            "ML-DSA signing key cannot be used as P-256 seal key — \
             configure seal_key for production; using ephemeral seal key"
        );
        SealKey::EcdsaP256(crate::demo_ecdsa_p256_key())
    };

    let seal_cert_der = if let Some(path) = &ca_config.seal_cert {
        std::fs::read(path).map_err(|e| format!("read seal cert: {e}"))?
    } else {
        crate::generate_seal_cert_for_key(&seal_key)
            .map_err(|e| format!("generate seal cert: {e}"))?
    };

    Ok((seal_key, seal_cert_der))
}

/// Resolve a PKCS#11 config from a CA's signing-key config. PIN resolution is
/// non-interactive: `pin` → `pin_env` → error. (The CLI's one-shot `sign`
/// command has its own interactive-prompt variant.)
#[cfg(feature = "pkcs11")]
pub fn resolve_pkcs11_config(
    ca_config: &CaConfig,
) -> std::result::Result<crate::Pkcs11Config, String> {
    match &ca_config.signing_key {
        Some(hoike_core::config::SigningKeyConfig::Pkcs11 {
            module,
            token_label,
            slot_id,
            pin,
            pin_env,
            key_label,
            key_id,
        }) => {
            let resolved_pin = resolve_pkcs11_pin_noninteractive(&ca_config.label, pin, pin_env)?;
            Ok(crate::Pkcs11Config {
                module_path: module.clone(),
                slot_id: *slot_id,
                token_label: token_label.clone(),
                pin: resolved_pin,
                key_label: key_label.clone(),
                key_id: key_id
                    .as_ref()
                    .map(|h| {
                        hex::decode(h).map_err(|e| {
                            format!(
                                "CA '{}': invalid hex in key_id '{}': {e}",
                                ca_config.label, h
                            )
                        })
                    })
                    .transpose()?,
            })
        }
        _ => Err(format!(
            "CA '{}': not a PKCS#11 signing key config",
            ca_config.label
        )),
    }
}

/// Non-interactive PKCS#11 PIN resolution: config value, then environment.
#[cfg(feature = "pkcs11")]
fn resolve_pkcs11_pin_noninteractive(
    ca_label: &str,
    pin: &Option<String>,
    pin_env: &Option<String>,
) -> std::result::Result<String, String> {
    if let Some(p) = pin {
        warn!(
            ca = ca_label,
            "PKCS#11 PIN is in config file — use pin_env for production"
        );
        return Ok(p.clone());
    }
    if let Some(env_var) = pin_env {
        return std::env::var(env_var).map_err(|_| {
            format!(
                "CA '{}': PKCS#11 pin_env '{}' is not set in environment",
                ca_label, env_var
            )
        });
    }
    Err(format!(
        "CA '{}': PKCS#11 PIN required — set pin_env (on-demand signing cannot prompt interactively)",
        ca_label
    ))
}

/// Map an ML-DSA sig-alg string to its PKCS#11 parameter set and OID.
#[cfg(feature = "pkcs11")]
pub fn ml_dsa_pkcs11_params(
    sig_alg: &str,
) -> std::result::Result<(cryptoki::object::MlDsaParameterSetType, &'static str), String> {
    match sig_alg {
        "ml-dsa-44" => Ok((
            cryptoki::object::MlDsaParameterSetType::ML_DSA_44,
            crate::ML_DSA_44_OID,
        )),
        "ml-dsa-65" => Ok((
            cryptoki::object::MlDsaParameterSetType::ML_DSA_65,
            crate::ML_DSA_65_OID,
        )),
        "ml-dsa-87" => Ok((
            cryptoki::object::MlDsaParameterSetType::ML_DSA_87,
            crate::ML_DSA_87_OID,
        )),
        other => Err(format!("unknown ML-DSA variant for PKCS#11: {other}")),
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;

    #[test]
    fn configured_bundle_destination_is_respected_and_failure_preserves_old_file() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("custom/active.ahu");
        let config_path = dir.path().join("hoike.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[server]
[storage]
bundle_dir = "{}/default"
[[ca]]
label = "test"
bundle_file = "{}"
"#,
                dir.path().display(),
                destination.display()
            ),
        )
        .unwrap();
        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(write_bundle(&config, "test", b"old").unwrap(), destination);
        write_bundle(&config, "test", b"complete replacement").unwrap();
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"complete replacement"
        );
        assert!(!config.storage.bundle_dir.join("test.ahu").exists());
        // A rename onto a directory fails after the temporary file is written.
        let blocked = dir.path().join("blocked");
        std::fs::create_dir(&blocked).unwrap();
        std::fs::write(blocked.join("previous"), b"old").unwrap();
        assert!(write_bundle_atomic(&blocked, b"new").is_err());
        assert_eq!(std::fs::read(blocked.join("previous")).unwrap(), b"old");
        assert!(
            !std::fs::read_dir(dir.path()).unwrap().any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp"))
        );
    }
}
