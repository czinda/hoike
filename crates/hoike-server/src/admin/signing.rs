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
    let ca_config = match state.admin.config.ca.iter().find(|ca| ca.label == label) {
        Some(ca) => ca,
        None => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                Json(serde_json::json!({"detail": format!("CA '{label}' not found")})),
            )
                .into_response();
        }
    };
    let ctx = match &state.signer {
        Some(ctx) => ctx,
        None => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"detail": "signing context not initialized"})),
            )
                .into_response();
        }
    };

    // Lock the shared signing mutex so on-demand signing and the background loop
    // never interleave epoch derivation (from the state store) with `.ahu` writes.
    let sources = ctx.sources.lock().await;
    let gen_start = std::time::Instant::now();
    let signed = match hoike_sign::sign_and_write_scope(&state.admin.config, &sources, ca_config) {
        Ok(signed) => signed,
        Err(e) => {
            crate::obs::audit!(
                event = "signer_generation_failed",
                ca = %label,
                trigger = "on_demand",
                error = %e,
                "on-demand signing failed"
            );
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"detail": format!("signing failed: {e}")})),
            )
                .into_response();
        }
    };
    crate::obs::record_signer_generation(&signed.label, gen_start.elapsed().as_secs_f64());
    crate::obs::audit!(
        event = "signer_generation",
        ca = %signed.label,
        trigger = "on_demand",
        epoch = signed.epoch,
        entry_count = signed.entry_count,
        "produced bundle on demand"
    );

    // Hot-reload the freshly written bundle into the serving router.
    if let Err(e) = state.responder.reload() {
        crate::obs::record_bundle_load_failure(&label, crate::obs::load_failure_reason(&e));
        crate::obs::audit!(
            event = "bundle_load_failed",
            ca = %label,
            trigger = "on_demand_reload",
            reason = crate::obs::load_failure_reason(&e),
            error = %e,
            "reload failed after on-demand signing"
        );
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"detail": format!("signed but reload failed: {e}")})),
        )
            .into_response();
    }
    // Announce the new generation to the mesh (best-effort; never fails the API).
    if let Some(g) = state.gossip.as_ref() {
        crate::announce_bundle_scopes(g, &signed.bytes).await;
    }
    Json(serde_json::json!({
        "status": "ok",
        "ca_label": signed.label,
        "epoch": signed.epoch,
        "entry_count": signed.entry_count,
        "bundle_count": state.responder.bundle_count(),
        "total_entries": state.responder.total_entries(),
    }))
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
    let ctx = match &state.signer {
        Some(ctx) => ctx,
        None => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"detail": "signing context not initialized"})),
            )
                .into_response();
        }
    };

    let sources = ctx.sources.lock().await;
    let gen_start = std::time::Instant::now();
    let signed = match hoike_sign::sign_and_write_all(&state.admin.config, &sources) {
        Ok(signed) => signed,
        Err(e) => {
            crate::obs::audit!(
                event = "signer_generation_failed",
                trigger = "on_demand_all",
                error = %e,
                "on-demand signing (all scopes) failed"
            );
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"detail": format!("signing failed: {e}")})),
            )
                .into_response();
        }
    };
    // Attribute the elapsed time to each produced scope. `sign_and_write_all`
    // does not time scopes individually, so this records the whole-pass duration
    // per label — a conservative upper bound useful for alerting on slow passes.
    let gen_secs = gen_start.elapsed().as_secs_f64();
    for s in &signed {
        crate::obs::record_signer_generation(&s.label, gen_secs);
        crate::obs::audit!(
            event = "signer_generation",
            ca = %s.label,
            trigger = "on_demand_all",
            epoch = s.epoch,
            entry_count = s.entry_count,
            "produced bundle on demand (all scopes)"
        );
    }

    if let Err(e) = state.responder.reload() {
        crate::obs::record_bundle_load_failure("all", crate::obs::load_failure_reason(&e));
        crate::obs::audit!(
            event = "bundle_load_failed",
            trigger = "on_demand_all_reload",
            reason = crate::obs::load_failure_reason(&e),
            error = %e,
            "reload failed after on-demand signing (all scopes)"
        );
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"detail": format!("signed but reload failed: {e}")})),
        )
            .into_response();
    }
    if let Some(g) = state.gossip.as_ref() {
        for s in &signed {
            crate::announce_bundle_scopes(g, &s.bytes).await;
        }
    }
    let scopes: Vec<serde_json::Value> = signed
        .iter()
        .map(|s| {
            serde_json::json!({
                "ca_label": s.label,
                "epoch": s.epoch,
                "entry_count": s.entry_count,
            })
        })
        .collect();
    Json(serde_json::json!({
        "status": "ok",
        "signed_count": signed.len(),
        "scopes": scopes,
        "bundle_count": state.responder.bundle_count(),
        "total_entries": state.responder.total_entries(),
    }))
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
    let Some(ctx) = &state.signer else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail":"rotation requires a signer node"})),
        )
            .into_response();
    };
    let _guard = ctx.sources.lock().await;
    let command = ca
        .key_rotation
        .as_ref()
        .and_then(|kr| kr.rotation_command.as_deref());
    match command {
        Some(cmd) => {
            let name = label.clone(); let command = cmd.to_owned();
            let result = tokio::task::spawn_blocking(move || hoike_sign::rotation::run_rotation_command(&name, &command))
                .await.map_err(|e| e.to_string()).and_then(|r| r);
            match result {
            Ok(()) => match state.reload_live_signer(ca) {
                Ok(()) => Json(serde_json::json!({"status":"ok", "ca_label":label})).into_response(),
                Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"detail":format!("rotation completed but replacement material was rejected: {e}")}))).into_response(),
            },
            Err(e) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"detail": format!("rotation command failed: {e}")})),
            )
                .into_response(),
            }
        },
        None => (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": format!("no rotation_command configured for CA '{label}'")})),
        )
            .into_response(),
    }
}
