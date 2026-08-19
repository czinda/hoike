use hoike_core::ResponderState;
use std::sync::Arc;

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
