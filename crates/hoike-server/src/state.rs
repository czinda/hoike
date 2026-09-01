use hoike_core::ResponderState;
use hoike_core::config::Config;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub responder: Arc<ResponderState>,
    pub live_signer: Option<Arc<LiveSignerState>>,
    pub admin: Arc<AdminState>,
}

pub struct LiveSignerState {
    pub signer: Mutex<p256::ecdsa::SigningKey>,
    pub responder_key_bytes: Vec<u8>,
    pub validity_secs: u64,
    pub responder_cert_der: Option<Vec<u8>>,
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
            live_signer: None,
            admin: Arc::new(AdminState {
                config,
                started_at: Instant::now(),
                sessions: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn with_live_signer(mut self, live: LiveSignerState) -> Self {
        self.live_signer = Some(Arc::new(live));
        self
    }
}
