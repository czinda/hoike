use serde::Deserialize;

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
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_bind(),
            seeds: Vec::new(),
            node_name: default_node_name(),
        }
    }
}

fn default_bind() -> String {
    "0.0.0.0:7946".into()
}

fn default_node_name() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "hoike-node".into())
}
