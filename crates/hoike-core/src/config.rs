use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub ca: Vec<CaConfig>,
    pub gossip: Option<GossipConfigSection>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GossipConfigSection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_gossip_bind")]
    pub bind: String,
    #[serde(default)]
    pub seeds: Vec<String>,
    #[serde(default = "default_gossip_node_name")]
    pub node_name: String,
}

fn default_gossip_bind() -> String {
    "0.0.0.0:7946".into()
}
fn default_gossip_node_name() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "hoike-node".into())
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_max_request")]
    pub max_request: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    pub bundle_dir: PathBuf,
    #[serde(default = "default_state_db")]
    pub state_db: PathBuf,
    #[serde(default = "default_max_chain")]
    pub max_chain: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CaConfig {
    pub label: String,
    pub bundle_file: Option<PathBuf>,
    #[serde(default = "default_nonce_policy")]
    pub nonce_policy: String,
    #[serde(default = "default_completeness")]
    pub completeness: String,
    /// Hex-encoded issuerNameHash for explicit routing.
    /// If absent, extracted from the bundle manifest on load.
    pub issuer_name_hash: Option<String>,
    /// Hex-encoded issuerKeyHash for explicit routing.
    /// If absent, extracted from the bundle manifest on load.
    pub issuer_key_hash: Option<String>,
    /// URL to forward nonce-bearing requests to (for nonce_policy = "forward")
    pub forward_to: Option<String>,
    /// Revocation source (required for combined/signer mode)
    pub source: Option<SourceConfig>,
    /// Batch production interval in seconds (combined/signer mode)
    #[serde(default = "default_batch_interval")]
    pub batch_interval: u64,
    /// OCSP response validity in seconds
    #[serde(default = "default_validity_secs")]
    pub validity_secs: u64,
    /// DER bytes of the issuer DN (for CertID computation in signer mode).
    /// Base64-encoded in config, decoded on load.
    pub issuer_name_der_b64: Option<String>,
    /// Raw issuer public key bytes (for CertID computation in signer mode).
    /// Base64-encoded in config, decoded on load.
    pub issuer_key_bytes_b64: Option<String>,
    /// Signing key configuration (required for signer/combined mode).
    pub signing_key: Option<SigningKeyConfig>,
}

/// How to obtain the signing key for OCSP response production.
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum SigningKeyConfig {
    /// Load from a PKCS#8 PEM or DER file on disk.
    #[serde(rename = "file")]
    File { path: PathBuf },

    /// Sign via a PKCS#11 hardware security module.
    ///
    /// Supported HSMs: Thales Luna, Entrust nShield, Utimaco CryptoServer,
    /// FutureX Vectera Plus, SoftHSM2 (testing).
    #[serde(rename = "pkcs11")]
    Pkcs11 {
        /// Path to the vendor's PKCS#11 shared library.
        module: String,
        /// Find slot by token label (e.g., Luna partition name).
        token_label: Option<String>,
        /// Explicit slot ID (alternative to token_label).
        slot_id: Option<u64>,
        /// Login PIN (plaintext — prefer pin_env for production).
        pin: Option<String>,
        /// Environment variable containing the login PIN.
        pin_env: Option<String>,
        /// Find key by CKA_LABEL.
        key_label: Option<String>,
        /// Find key by CKA_ID (hex-encoded).
        key_id: Option<String>,
    },

    /// Ephemeral demo key for testing only. Produces a warning on every use.
    #[serde(rename = "demo")]
    Demo,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum SourceConfig {
    #[serde(rename = "crl")]
    Crl { path: PathBuf },
}

fn default_mode() -> String {
    "edge".into()
}
fn default_listen() -> String {
    "0.0.0.0:2560".into()
}
fn default_max_request() -> usize {
    8192
}
fn default_state_db() -> PathBuf {
    PathBuf::from("/var/lib/hoike/state")
}
fn default_max_chain() -> u32 {
    24
}
fn default_nonce_policy() -> String {
    "ignore".into()
}
fn default_completeness() -> String {
    "authoritative-complete".into()
}
fn default_batch_interval() -> u64 {
    3600
}
fn default_validity_secs() -> u64 {
    86400
}

impl Config {
    pub fn from_file(path: &std::path::Path) -> crate::error::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        toml::from_str(&contents).map_err(|e| crate::error::CoreError::Config(e.to_string()))
    }

    pub fn is_combined(&self) -> bool {
        self.server.mode == "combined"
    }

    pub fn is_signer(&self) -> bool {
        self.server.mode == "signer"
    }

    pub fn needs_signing(&self) -> bool {
        self.is_combined() || self.is_signer()
    }

    pub fn validate_for_mode(&self) -> crate::error::Result<()> {
        if self.needs_signing() {
            for ca in &self.ca {
                if ca.source.is_none() {
                    return Err(crate::error::CoreError::Config(format!(
                        "CA '{}' has no source configured, required for {} mode",
                        ca.label, self.server.mode
                    )));
                }
                if ca.signing_key.is_none() {
                    return Err(crate::error::CoreError::Config(format!(
                        "CA '{}' has no signing_key configured, required for {} mode. \
                         Use type='file' with a PKCS#8 key, type='pkcs11' for HSM, \
                         or type='demo' for testing only.",
                        ca.label, self.server.mode
                    )));
                }
                // PKCS#11 PIN resolution: pin (config) → pin_env (env var) → interactive prompt.
                // All three are valid — no validation error if both pin and pin_env are absent,
                // because the CLI will prompt interactively at startup.
            }
            if self.ca.is_empty() {
                return Err(crate::error::CoreError::Config(format!(
                    "{} mode requires at least one [[ca]] with a source",
                    self.server.mode
                )));
            }
        }
        Ok(())
    }
}
