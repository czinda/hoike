mod auth;
mod bundles;
mod query;
mod rbac;
mod signing;
mod status;

use crate::state::AppState;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};

/// Body limit for admin bundle-upload routes (inspect/verify/diff/extract/apply).
/// These are authenticated Operator/Viewer endpoints handling whole bundles —
/// well above axum's 2 MiB default. diff/apply carry base64 (≈+33%), so this
/// caps the raw bundle at roughly 48 MiB.
const ADMIN_BODY_LIMIT: usize = 64 * 1024 * 1024;

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
        // Bundle operations (Operator+, except extract which is Viewer+)
        .route("/bundles/reload", post(bundles::reload_bundles))
        .route("/bundles/inspect", post(bundles::inspect_bundle))
        .route("/bundles/verify", post(bundles::verify_bundle))
        .route("/bundles/diff", post(bundles::diff_bundles))
        .route("/bundles/extract", post(bundles::extract_entry))
        .route("/bundles/apply", post(bundles::apply_deltas))
        // Signing operations (Operator+)
        .route("/sign/all", post(signing::sign_all))
        .route("/sign/{label}", post(signing::sign_ca))
        .route("/rotate/{label}", post(signing::rotate_ca))
        // Query / debug (Viewer+)
        .route("/query", post(query::ocsp_query))
        .layer(DefaultBodyLimit::max(ADMIN_BODY_LIMIT))
        .with_state(state)
}
