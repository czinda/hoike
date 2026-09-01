use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;

use super::rbac::Authenticated;
use crate::state::{AppState, OperatorRole};

pub async fn reload_bundles(
    State(state): State<AppState>,
    auth: Authenticated,
) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Operator) {
        return e;
    }
    match state.responder.reload() {
        Ok(()) => Json(serde_json::json!({
            "status": "ok",
            "bundle_count": state.responder.bundle_count(),
            "total_entries": state.responder.total_entries(),
        }))
        .into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"detail": format!("reload failed: {e}")})),
        )
            .into_response(),
    }
}

pub async fn inspect_bundle(auth: Authenticated, body: axum::body::Bytes) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Operator) {
        return e;
    }
    match ahu::Bundle::from_bytes(&body) {
        Ok(bundle) => {
            let manifest = &bundle.manifest;
            Json(serde_json::json!({
                "bundle_id": manifest.bundle_id.to_string(),
                "producer_id": manifest.producer_id,
                "created_at": manifest.created_at,
                "bundle_type": format!("{:?}", manifest.bundle_type),
                "entry_count": manifest.entry_count,
                "window": {
                    "produced_at": manifest.window.produced_at,
                    "this_update_min": manifest.window.this_update_min,
                    "next_update_min": manifest.window.next_update_min,
                    "next_update_max": manifest.window.next_update_max,
                },
                "scopes": manifest.ca_scopes.iter().map(|s| serde_json::json!({
                    "issuer_name_hash": hex::encode(&s.issuer_name_hash),
                    "issuer_key_hash": hex::encode(&s.issuer_key_hash),
                    "epoch": s.epoch,
                    "completeness": format!("{:?}", s.completeness),
                    "signature_algorithm": hex::encode(&s.signature_algorithm),
                })).collect::<Vec<_>>(),
                "integrity": {
                    "index_digest": hex::encode(manifest.integrity.index_digest),
                    "data_digest": hex::encode(manifest.integrity.data_digest),
                },
                "seal_present": !bundle.seal_bytes.is_empty(),
                "index_records": bundle.index.len(),
            }))
            .into_response()
        }
        Err(e) => (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": format!("failed to parse bundle: {e}")})),
        )
            .into_response(),
    }
}

pub async fn verify_bundle(auth: Authenticated, body: axum::body::Bytes) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Operator) {
        return e;
    }
    match ahu::Bundle::from_bytes(&body) {
        Ok(bundle) => match ahu::verify::verify_structure(&bundle) {
            Ok(result) => Json(serde_json::json!({
                "header_ok": result.header_ok,
                "manifest_ok": result.manifest_ok,
                "index_digest_ok": result.index_digest_ok,
                "data_digest_ok": result.data_digest_ok,
                "sort_order_ok": result.sort_order_ok,
                "entry_bounds_ok": result.entry_bounds_ok,
                "seal_present": result.seal_present,
                "entry_count_matches": result.entry_count_matches,
                "warnings": result.warnings,
                "overall_ok": result.header_ok && result.manifest_ok && result.index_digest_ok && result.data_digest_ok && result.sort_order_ok && result.entry_bounds_ok && result.entry_count_matches,
            }))
            .into_response(),
            Err(e) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"detail": format!("verification error: {e}")})),
            )
                .into_response(),
        },
        Err(e) => (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": format!("failed to parse bundle: {e}")})),
        )
            .into_response(),
    }
}
