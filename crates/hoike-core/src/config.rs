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

impl Config {
    pub fn from_file(path: &std::path::Path) -> crate::error::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        toml::from_str(&contents).map_err(|e| crate::error::CoreError::Config(e.to_string()))
    }
}
