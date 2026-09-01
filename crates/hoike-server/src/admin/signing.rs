use axum::Json;
use axum::extract::{Path, State};
use axum::response::IntoResponse;

use super::rbac::Authenticated;
use crate::state::{AppState, OperatorRole};

pub async fn sign_ca(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(label): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Operator) {
        return e;
    }
    if !state.admin.config.needs_signing() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": "server mode does not support signing (requires combined or signer mode)"})),
        )
            .into_response();
    }
    let ca_exists = state.admin.config.ca.iter().any(|ca| ca.label == label);
    if !ca_exists {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({"detail": format!("CA '{label}' not found")})),
        )
            .into_response();
    }
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "status": "not_implemented",
            "ca_label": label,
            "message": "on-demand signing via admin API is not yet implemented — use the batch signer loop",
        })),
    )
        .into_response()
}

pub async fn sign_all(State(state): State<AppState>, auth: Authenticated) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Operator) {
        return e;
    }
    if !state.admin.config.needs_signing() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": "server mode does not support signing (requires combined or signer mode)"})),
        )
            .into_response();
    }
    let labels: Vec<&str> = state
        .admin
        .config
        .ca
        .iter()
        .map(|ca| ca.label.as_str())
        .collect();
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "status": "not_implemented",
            "cas": labels,
            "message": "on-demand signing via admin API is not yet implemented — use the batch signer loop",
        })),
    )
        .into_response()
}

pub async fn rotate_ca(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(label): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Administrator) {
        return e;
    }
    let ca = state.admin.config.ca.iter().find(|ca| ca.label == label);
    let ca = match ca {
        Some(ca) => ca,
        None => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                Json(serde_json::json!({"detail": format!("CA '{label}' not found")})),
            )
                .into_response();
        }
    };
    let command = ca
        .key_rotation
        .as_ref()
        .and_then(|kr| kr.rotation_command.as_deref());
    match command {
        Some(cmd) => match hoike_sign::rotation::run_rotation_command(&label, cmd) {
            Ok(()) => Json(serde_json::json!({
                "status": "ok",
                "ca_label": label,
                "command": cmd,
            }))
            .into_response(),
            Err(e) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"detail": format!("rotation command failed: {e}")})),
            )
                .into_response(),
        },
        None => (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": format!("no rotation_command configured for CA '{label}'")})),
        )
            .into_response(),
    }
}
