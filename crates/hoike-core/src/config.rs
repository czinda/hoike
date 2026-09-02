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
    pub admin: Option<AdminConfig>,
    pub webui: Option<WebUiConfig>,
    /// Optional dedicated listener for the Prometheus `/metrics` endpoint, e.g.
    /// "127.0.0.1:9184". Kept off the public OCSP port. Requires a build with
    /// the `metrics` feature to expose data; otherwise `/metrics` returns 503.
    pub metrics_listen: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WebUiConfig {
    pub static_dir: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AdminConfig {
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
    #[serde(default)]
    pub operators: Vec<OperatorConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OperatorConfig {
    pub name: String,
    pub password_hash: String,
    #[serde(default = "default_operator_role")]
    pub role: String,
}

fn default_session_ttl() -> u64 {
    3600
}
fn default_operator_role() -> String {
    "viewer".into()
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    pub bundle_dir: PathBuf,
    #[serde(default = "default_state_db")]
    pub state_db: PathBuf,
    #[serde(default = "default_max_chain")]
    pub max_chain: u32,
    /// DER or PEM certificates trusted as seal signers.
    /// When set, bundles without a valid CMS seal are rejected on load.
    #[serde(default)]
    pub seal_trust_anchors: Option<Vec<PathBuf>>,
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
    /// Signing algorithm: ecdsa-p256 (default), ml-dsa-44, ml-dsa-65, ml-dsa-87
    #[serde(default = "default_sig_alg")]
    pub sig_alg: String,
    /// Signing key configuration (required for signer/combined mode).
    pub signing_key: Option<SigningKeyConfig>,
    /// Path to the delegated OCSP signing certificate (DER or PEM).
    /// Embedded in each OCSPResponse per RFC 9919 §3.2.2 so clients
    /// can validate the response without pre-caching the responder cert.
    pub responder_cert: Option<PathBuf>,
    /// Key rotation monitoring configuration.
    pub key_rotation: Option<KeyRotationConfigToml>,
    /// Path to PKCS#8 PEM/DER key for bundle seal signing.
    /// If absent, falls back to the OCSP signing key (with a warning).
    /// The seal key SHOULD be different from the OCSP signing key.
    pub seal_key: Option<PathBuf>,
    /// Path to the DER/PEM certificate for the seal signer.
    /// If absent, generates a self-signed cert (for testing only).
    pub seal_cert: Option<PathBuf>,
}

impl CaConfig {
    /// Returns true if the configured sig_alg is an ML-DSA variant.
    pub fn is_ml_dsa(&self) -> bool {
        matches!(
            self.sig_alg.as_str(),
            "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87"
        )
    }
}

/// TOML-level key rotation configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct KeyRotationConfigToml {
    /// Days before cert expiry to trigger rotation warning/action (default: 7).
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u64,
    /// Hours between rotation checks (default: 1).
    #[serde(default = "default_check_interval_hours")]
    pub check_interval_hours: u64,
    /// Shell command to execute when rotation is needed.
    /// The command receives CA label and cert path as arguments.
    pub rotation_command: Option<String>,
}

fn default_renew_before_days() -> u64 {
    7
}
fn default_check_interval_hours() -> u64 {
    1
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

    /// RFC 4533 syncrepl against a Dogtag 389 DS certificate repository.
    ///
    /// Initial refresh loads the full cert population; subsequent refreshes
    /// send the stored sync cookie so 389 DS returns only changes.
    /// Produces both `Good` and `Revoked` entries — enables
    /// `authoritative-complete` bundles.
    #[serde(rename = "dogtag-sync")]
    DogtagSync {
        /// LDAP URL, e.g. `ldap://ds-iot.cert-lab.local:3389`
        ldap_url: String,
        /// Search base DN, e.g. `ou=certificateRepository,ou=ca,o=pki-iot-ca-CA`
        base_dn: String,
        /// Bind DN (e.g. `cn=Directory Manager`)
        #[serde(default = "default_bind_dn")]
        bind_dn: String,
        /// Bind password (plaintext — prefer `bind_password_env`)
        bind_password: Option<String>,
        /// Environment variable holding the bind password
        bind_password_env: Option<String>,
        /// Path to checkpoint the sync cookie (default: state_db/sync-cookie.dat)
        cookie_path: Option<PathBuf>,
        /// LDAP filter (default: `(objectClass=certificateRecord)`)
        #[serde(default = "default_sync_filter")]
        filter: Option<String>,
    },
}

fn default_bind_dn() -> String {
    "cn=Directory Manager".into()
}

fn default_sync_filter() -> Option<String> {
    Some("(objectClass=certificateRecord)".into())
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
fn default_sig_alg() -> String {
    "ecdsa-p256".into()
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
        let valid_sig_algs = ["ecdsa-p256", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"];
        for ca in &self.ca {
            if !valid_sig_algs.contains(&ca.sig_alg.as_str()) {
                return Err(crate::error::CoreError::Config(format!(
                    "CA '{}' has invalid sig_alg '{}' — expected one of: {}",
                    ca.label,
                    ca.sig_alg,
                    valid_sig_algs.join(", ")
                )));
            }
            if ca.is_ml_dsa() && ca.nonce_policy == "live" {
                return Err(crate::error::CoreError::Config(format!(
                    "CA '{}': nonce_policy=live is not yet supported with {} signing",
                    ca.label, ca.sig_alg
                )));
            }
        }
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
