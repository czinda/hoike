mod auth;
mod bundles;
mod query;
mod rbac;
mod signing;
mod status;

use crate::state::AppState;
use axum::Router;
use axum::routing::{delete, get, post};

pub fn build_admin_router(state: AppState) -> Router {
    Router::new()
        // Auth
        .route("/session", post(auth::login))
        .route("/session", delete(auth::logout))
        // Status (read-only, Viewer+)
        .route("/status", get(status::get_status))
        .route("/bundles", get(status::get_bundles))
        .route("/bundles/{label}", get(status::get_bundle_detail))
        .route("/certs", get(status::get_certs))
        .route("/rotation", get(status::get_rotation))
        .route("/gossip", get(status::get_gossip))
        .route("/config", get(status::get_config))
        .route("/state", get(status::get_state))
        // Bundle operations (Operator+)
        .route("/bundles/reload", post(bundles::reload_bundles))
        .route("/bundles/inspect", post(bundles::inspect_bundle))
        .route("/bundles/verify", post(bundles::verify_bundle))
        // Signing operations (Operator+)
        .route("/sign/all", post(signing::sign_all))
        .route("/sign/{label}", post(signing::sign_ca))
        .route("/rotate/{label}", post(signing::rotate_ca))
        // Query / debug (Viewer+)
        .route("/query", post(query::ocsp_query))
        .with_state(state)
}
