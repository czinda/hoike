mod handlers;
mod state;

pub use state::AppState;

use axum::Router;
use axum::routing::{get, post};

/// Build the axum router for the OCSP responder.
///
/// Routes:
///   GET  /*path  — RFC 9919 §6: base64(OCSPRequest) in the URL path
///   POST /       — body is DER-encoded OCSPRequest
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", post(handlers::handle_post))
        .route("/", get(handlers::handle_get_root))
        .route("/{*path}", get(handlers::handle_get))
        .route("/{*path}", post(handlers::handle_post))
        .with_state(state)
}
