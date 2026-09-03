use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct GossipConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default)]
    pub seeds: Vec<String>,
    #[serde(default = "default_node_name")]
    pub node_name: String,
    /// Ed25519 PKCS#8 private key for signing outbound broadcasts (FPT_ITT.1).
    /// When set, every custom broadcast this node emits is signed.
    #[serde(default)]
    pub identity_key: Option<PathBuf>,
    /// Ed25519 SPKI public keys trusted to sign peer broadcasts. When non-empty,
    /// the node enforces authentication (drops unsigned/forged messages); when
    /// empty, it stays permissive for a mixed-fleet rollout. See
    /// [`crate::crypto`] for the full policy.
    #[serde(default)]
    pub peer_keys: Vec<PathBuf>,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_bind(),
            seeds: Vec::new(),
            node_name: default_node_name(),
            identity_key: None,
            peer_keys: Vec::new(),
        }
    }
}

fn default_bind() -> String {
    "0.0.0.0:7946".into()
}

fn default_node_name() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "hoike-node".into())
}
