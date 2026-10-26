use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::crypto::GossipCryptoError;

/// Explicit inbound authentication policy for gossip broadcasts (FPT_ITT.1).
///
/// The policy no longer follows implicitly from which key files happen to be
/// present:
///
/// - [`AuthMode::Required`] (the default) must have a local `identity_key`
///   and drops unsigned, unknown, and forged broadcasts.
/// - [`AuthMode::Permissive`] is the explicit rollout mode: unsigned legacy
///   broadcasts are still accepted, but every signed frame is verified
///   against the provisioned named identities — unknown or forged signed
///   frames reject in both modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    #[default]
    Required,
    Permissive,
}

impl std::str::FromStr for AuthMode {
    type Err = GossipCryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "required" => Ok(Self::Required),
            "permissive" => Ok(Self::Permissive),
            other => Err(GossipCryptoError::Config(format!(
                "invalid gossip auth_mode '{other}' — expected \"required\" or \"permissive\""
            ))),
        }
    }
}

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
    /// Explicit inbound authentication policy (FPT_ITT.1). Defaults to
    /// `required`; see [`AuthMode`] for what each mode enforces.
    #[serde(default)]
    pub auth_mode: AuthMode,
    /// Ed25519 PKCS#8 private key for signing outbound broadcasts (FPT_ITT.1).
    /// Required in `required` mode; optional while a fleet rolls out in
    /// `permissive` mode.
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
            auth_mode: AuthMode::default(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn auth_mode_defaults_to_required_and_parses_lowercase() {
        assert_eq!(AuthMode::default(), AuthMode::Required);
        assert_eq!(
            serde_json::from_str::<AuthMode>("\"permissive\"").unwrap(),
            AuthMode::Permissive
        );
        let config: GossipConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config.auth_mode, AuthMode::Required);
        assert_eq!(
            serde_json::to_string(&AuthMode::Permissive).unwrap(),
            "\"permissive\""
        );
    }

    #[test]
    fn auth_mode_from_str_rejects_unknown_values() {
        assert_eq!(AuthMode::from_str("required").unwrap(), AuthMode::Required);
        assert_eq!(
            AuthMode::from_str("permissive").unwrap(),
            AuthMode::Permissive
        );
        assert!(matches!(
            AuthMode::from_str("strict"),
            Err(GossipCryptoError::Config(_))
        ));
    }
}
