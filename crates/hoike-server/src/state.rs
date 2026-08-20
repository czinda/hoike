use hoike_core::ResponderState;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Shared application state, cheaply cloneable via Arc.
#[derive(Clone)]
pub struct AppState {
    pub responder: Arc<ResponderState>,
    pub live_signer: Option<Arc<LiveSignerState>>,
}

/// Holds the signing key and responder identity for live nonce signing.
pub struct LiveSignerState {
    pub signer: Mutex<p256::ecdsa::SigningKey>,
    pub responder_key_bytes: Vec<u8>,
    pub validity_secs: u64,
}

impl AppState {
    pub fn new(responder: ResponderState) -> Self {
        AppState {
            responder: Arc::new(responder),
            live_signer: None,
        }
    }

    pub fn with_live_signer(mut self, live: LiveSignerState) -> Self {
        self.live_signer = Some(Arc::new(live));
        self
    }
}
