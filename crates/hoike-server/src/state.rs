use hoike_core::ResponderState;
use hoike_core::config::Config;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub responder: Arc<ResponderState>,
    pub live_signers: Arc<std::sync::RwLock<HashMap<String, Arc<LiveSignerState>>>>,
    pub signer: Option<Arc<SignerContext>>,
    /// Handle to the running gossip node, when this process participates in the
    /// SWIM mesh. `None` when gossip is disabled — admin fleet endpoints then
    /// report an empty/disabled roster instead of members and generations.
    pub gossip: Option<Arc<hoike_gossip::GossipNode>>,
    pub admin: Arc<AdminState>,
}

pub struct LiveSignerState {
    pub signer: Mutex<p256::ecdsa::SigningKey>,
    pub responder_key_bytes: Vec<u8>,
    pub validity_secs: u64,
    pub responder_cert_der: Option<Vec<u8>>,
}

/// Shared on-demand signing context. Holds the persistent revocation sources
/// (DogtagSync retains a sync cookie — must be shared, not rebuilt each pass)
/// behind a mutex that serializes on-demand signing (admin API) against the
/// background signer loop, so epoch derivation (from the state store) and
/// `{label}.ahu` writes never interleave.
pub struct SignerContext {
    pub sources: Mutex<hoike_sign::PersistentSources>,
}

pub struct AdminState {
    pub config: Config,
    pub started_at: Instant,
    pub sessions: Mutex<HashMap<String, Session>>,
}

#[derive(Clone)]
pub struct Session {
    pub operator_name: String,
    pub role: OperatorRole,
    pub expires_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperatorRole {
    Administrator,
    Operator,
    Viewer,
}

impl OperatorRole {
    pub fn rank(self) -> u8 {
        match self {
            Self::Viewer => 1,
            Self::Operator => 2,
            Self::Administrator => 3,
        }
    }

    pub fn has_at_least(self, min: Self) -> bool {
        self.rank() >= min.rank()
    }
}

impl std::str::FromStr for OperatorRole {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "administrator" => Ok(Self::Administrator),
            "operator" => Ok(Self::Operator),
            "viewer" => Ok(Self::Viewer),
            other => Err(format!("unknown role: {other}")),
        }
    }
}

impl std::fmt::Display for OperatorRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Administrator => write!(f, "administrator"),
            Self::Operator => write!(f, "operator"),
            Self::Viewer => write!(f, "viewer"),
        }
    }
}

impl AppState {
    pub fn new(responder: ResponderState, config: Config) -> Self {
        AppState {
            responder: Arc::new(responder),
            live_signers: Arc::new(std::sync::RwLock::new(HashMap::new())),
            signer: None,
            gossip: None,
            admin: Arc::new(AdminState {
                config,
                started_at: Instant::now(),
                sessions: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Single-CA compatibility builder; never provides a cross-CA fallback.
    pub fn with_live_signer(self, live: LiveSignerState) -> Self {
        let labels: Vec<_> = self
            .admin
            .config
            .ca
            .iter()
            .filter(|ca| ca.nonce_policy == "live")
            .map(|ca| ca.label.clone())
            .collect();
        assert_eq!(
            labels.len(),
            1,
            "with_live_signer requires exactly one live CA"
        );
        self.with_live_signer_for(&labels[0], live)
    }

    pub fn with_live_signer_for(self, label: &str, live: LiveSignerState) -> Self {
        self.live_signers
            .write()
            .expect("live signer lock poisoned")
            .insert(label.into(), Arc::new(live));
        self
    }

    pub fn live_signer_for(&self, label: &str) -> Option<Arc<LiveSignerState>> {
        self.live_signers.read().ok()?.get(label).cloned()
    }

    pub fn reload_live_signer(&self, ca: &hoike_core::config::CaConfig) -> Result<(), String> {
        if ca.nonce_policy != "live" {
            return Ok(());
        }
        let live = LiveSignerState::from_config(ca)?;
        self.live_signers
            .write()
            .map_err(|e| e.to_string())?
            .insert(ca.label.clone(), Arc::new(live));
        Ok(())
    }

    /// Attach the shared on-demand signing context. The returned `Arc` is also
    /// cloned into the background signer loop so both paths share one mutex.
    pub fn with_signer_context(mut self, ctx: SignerContext) -> Self {
        self.signer = Some(Arc::new(ctx));
        self
    }

    /// Attach a handle to the running gossip node so admin fleet endpoints can
    /// read membership and the generation table, and so the signer path can
    /// announce new generations.
    pub fn with_gossip(mut self, gossip: Arc<hoike_gossip::GossipNode>) -> Self {
        self.gossip = Some(gossip);
        self
    }
}

impl LiveSignerState {
    pub fn from_config(ca: &hoike_core::config::CaConfig) -> Result<Self, String> {
        let material = hoike_sign::live::load_live_material(ca)?;
        Ok(Self {
            signer: Mutex::new(material.key),
            responder_key_bytes: material.responder_key_bytes,
            validity_secs: ca.validity_secs,
            responder_cert_der: material.responder_cert_der,
        })
    }
}
