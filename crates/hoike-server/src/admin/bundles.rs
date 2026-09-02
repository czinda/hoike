use axum::Json;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use base64::Engine;
use serde::Deserialize;

use super::rbac::Authenticated;
use crate::state::{AppState, OperatorRole};

/// Base64 (standard) decode helper returning a uniform 400 response on failure.
///
/// The `Err` variant is a full axum `Response` (>128 bytes), which trips
/// `clippy::result_large_err`. Boxing it would ripple through all four
/// `match`-based call sites for no runtime benefit — this is a request-time
/// decode helper, never a hot path — so the lint is allowed locally instead.
#[allow(clippy::result_large_err)]
fn b64_decode(field: &str, s: &str) -> Result<Vec<u8>, axum::response::Response> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": format!("invalid base64 in '{field}': {e}")})),
            )
                .into_response()
        })
}

fn entry_ref_json(r: &ahu::EntryRef) -> serde_json::Value {
    serde_json::json!({
        "entry_key": hex::encode(r.entry_key),
        "discriminator": r.discriminator,
    })
}

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
        Err(e) => {
            crate::obs::record_bundle_load_failure("all", crate::obs::load_failure_reason(&e));
            crate::obs::audit!(
                event = "bundle_load_failed",
                trigger = "admin_reload",
                reason = crate::obs::load_failure_reason(&e),
                error = %e,
                "operator-triggered bundle reload failed"
            );
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"detail": format!("reload failed: {e}")})),
            )
                .into_response()
        }
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

#[derive(Deserialize)]
pub struct DiffRequest {
    /// Base64-encoded "A" (older/left) bundle.
    a: String,
    /// Base64-encoded "B" (newer/right) bundle.
    b: String,
}

/// Structural diff of two uploaded bundles (A → B). Operator+.
pub async fn diff_bundles(auth: Authenticated, Json(req): Json<DiffRequest>) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Operator) {
        return e;
    }
    let a_bytes = match b64_decode("a", &req.a) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let b_bytes = match b64_decode("b", &req.b) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let a = match ahu::Bundle::from_bytes(&a_bytes) {
        Ok(b) => b,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": format!("failed to parse bundle A: {e}")})),
            )
                .into_response();
        }
    };
    let b = match ahu::Bundle::from_bytes(&b_bytes) {
        Ok(b) => b,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": format!("failed to parse bundle B: {e}")})),
            )
                .into_response();
        }
    };

    let d = ahu::diff(&a, &b);
    Json(serde_json::json!({
        "a_entry_count": d.a_entry_count,
        "b_entry_count": d.b_entry_count,
        "a_epochs": d.a_epochs,
        "b_epochs": d.b_epochs,
        "added": d.added.iter().map(entry_ref_json).collect::<Vec<_>>(),
        "removed": d.removed.iter().map(entry_ref_json).collect::<Vec<_>>(),
        "changed": d.changed.iter().map(entry_ref_json).collect::<Vec<_>>(),
        "unchanged": d.unchanged,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct ExtractParams {
    /// 64-hex-char entry key (SHA-256 of the DER CertID).
    certid: String,
}

/// Extract a single pre-signed OCSP response from an uploaded bundle by entry
/// key. Body is the raw bundle (octet-stream). Viewer+ (read-only lookup).
pub async fn extract_entry(
    auth: Authenticated,
    Query(params): Query<ExtractParams>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Viewer) {
        return e;
    }
    let key_bytes = match hex::decode(&params.certid) {
        Ok(v) => v,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": format!("invalid certid hex: {e}")})),
            )
                .into_response();
        }
    };
    if key_bytes.len() != 32 {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "detail": format!("entry key must be 32 bytes (64 hex chars), got {}", key_bytes.len())
            })),
        )
            .into_response();
    }
    let mut entry_key = [0u8; 32];
    entry_key.copy_from_slice(&key_bytes);

    let bundle = match ahu::Bundle::from_bytes(&body) {
        Ok(b) => b,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": format!("failed to parse bundle: {e}")})),
            )
                .into_response();
        }
    };

    match bundle.lookup(&entry_key) {
        Some(resp) => Json(serde_json::json!({
            "found": true,
            "length": resp.len(),
            "response_b64": base64::engine::general_purpose::STANDARD.encode(resp),
        }))
        .into_response(),
        None => Json(serde_json::json!({
            "found": false,
            "length": 0,
            "response_b64": null,
        }))
        .into_response(),
    }
}

#[derive(Deserialize)]
pub struct ApplyRequest {
    /// Base64-encoded full base bundle.
    base: String,
    /// Base64-encoded delta bundles, in application order.
    deltas: Vec<String>,
}

/// Apply an ordered chain of deltas onto a base bundle, returning the
/// materialized full bundle (base64). Operator+.
pub async fn apply_deltas(auth: Authenticated, Json(req): Json<ApplyRequest>) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Operator) {
        return e;
    }

    let base_bytes = match b64_decode("base", &req.base) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let base = match ahu::Bundle::from_bytes(&base_bytes) {
        Ok(b) => b,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": format!("failed to parse base bundle: {e}")})),
            )
                .into_response();
        }
    };
    if let Err(e) = ahu::verify_structure(&base) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": format!("base bundle failed verification: {e}")})),
        )
            .into_response();
    }

    let mut deltas = Vec::with_capacity(req.deltas.len());
    for (i, d_b64) in req.deltas.iter().enumerate() {
        let d_bytes = match b64_decode(&format!("deltas[{i}]"), d_b64) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let delta = match ahu::Bundle::from_bytes(&d_bytes) {
            Ok(b) => b,
            Err(e) => {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"detail": format!("failed to parse delta {}: {e}", i + 1)})),
                )
                    .into_response();
            }
        };
        if let Err(e) = ahu::verify_structure(&delta) {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": format!("delta {} failed verification: {e}", i + 1)})),
            )
                .into_response();
        }
        deltas.push(delta);
    }

    match ahu::apply(&base, &deltas) {
        Ok(result) => Json(serde_json::json!({
            "entry_count": result.entry_count,
            "final_epoch": result.final_epoch,
            "byte_length": result.bytes.len(),
            "deltas": result.deltas.iter().map(|s| serde_json::json!({
                "added": s.added,
                "replaced": s.replaced,
                "removed": s.removed,
                "chain_length_warning": s.chain_length_warning,
            })).collect::<Vec<_>>(),
            "bundle_b64": base64::engine::general_purpose::STANDARD.encode(&result.bytes),
        }))
        .into_response(),
        Err(e) => (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": format!("apply failed: {e}")})),
        )
            .into_response(),
    }
}
