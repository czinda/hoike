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
    /// Deprecated unbound key list. Nonempty values fail startup with migration
    /// instructions; use peer_identities to authorize each key's node identity.
    #[serde(default)]
    pub peer_keys: Vec<PathBuf>,
    /// Authorized node name to Ed25519 SPKI public key.
    #[serde(default)]
    pub peer_identities: std::collections::BTreeMap<String, PathBuf>,
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
            peer_identities: Default::default(),
        }
    }
}

fn default_bind() -> String {
    "0.0.0.0:7946".into()
}

fn default_node_name() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "hoike-node".into())
}
