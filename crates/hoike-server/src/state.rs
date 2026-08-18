use std::sync::Arc;
use hoike_core::ResponderState;

/// Shared application state, cheaply cloneable via Arc.
#[derive(Clone)]
pub struct AppState {
    pub responder: Arc<ResponderState>,
}

impl AppState {
    pub fn new(responder: ResponderState) -> Self {
        AppState {
            responder: Arc::new(responder),
        }
    }
}
