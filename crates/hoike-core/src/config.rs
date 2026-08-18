use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub ca: Vec<CaConfig>,
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
