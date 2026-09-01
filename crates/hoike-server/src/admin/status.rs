use axum::Json;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use serde::Serialize;

use super::rbac::Authenticated;
use crate::state::{AppState, OperatorRole};

#[derive(Serialize)]
struct ServerStatus {
    version: &'static str,
    mode: String,
    listen: String,
    uptime_secs: u64,
    bundle_count: usize,
    total_entries: u64,
    scope_count: usize,
}

pub async fn get_status(State(state): State<AppState>, auth: Authenticated) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Viewer) {
        return e;
    }
    let uptime = state.admin.started_at.elapsed().as_secs();
    Json(ServerStatus {
        version: env!("CARGO_PKG_VERSION"),
        mode: state.admin.config.server.mode.clone(),
        listen: state.admin.config.server.listen.clone(),
        uptime_secs: uptime,
        bundle_count: state.responder.bundle_count(),
        total_entries: state.responder.total_entries(),
        scope_count: state.responder.scope_count(),
    })
    .into_response()
}

#[derive(Serialize)]
struct BundleInfo {
    ca_label: String,
    epoch: u64,
    completeness: String,
    window: Option<WindowInfo>,
}

#[derive(Serialize, Clone)]
struct WindowInfo {
    produced_at: u64,
    this_update_min: u64,
    next_update_min: u64,
    next_update_max: u64,
}

pub async fn get_bundles(State(state): State<AppState>, auth: Authenticated) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Viewer) {
        return e;
    }
    let scopes = state.responder.scope_info();
    let window = state.responder.default_window();
    let window_info = window.map(|w| WindowInfo {
        produced_at: w.produced_at,
        this_update_min: w.this_update_min,
        next_update_min: w.next_update_min,
        next_update_max: w.next_update_max,
    });

    let bundles: Vec<BundleInfo> = scopes
        .iter()
        .map(|(label, epoch, completeness)| BundleInfo {
            ca_label: label.clone(),
            epoch: *epoch,
            completeness: completeness.clone(),
            window: window_info.clone(),
        })
        .collect();

    Json(serde_json::json!({
        "bundles": bundles,
        "total_entries": state.responder.total_entries(),
    }))
    .into_response()
}

pub async fn get_bundle_detail(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(label): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Viewer) {
        return e;
    }
    let scopes = state.responder.scope_info();
    let scope = scopes.iter().find(|(l, _, _)| l == &label);
    match scope {
        Some((ca_label, epoch, completeness)) => Json(serde_json::json!({
            "ca_label": ca_label,
            "epoch": epoch,
            "completeness": completeness,
        }))
        .into_response(),
        None => (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({"detail": format!("CA '{label}' not found")})),
        )
            .into_response(),
    }
}

pub async fn get_certs(State(state): State<AppState>, auth: Authenticated) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Viewer) {
        return e;
    }
    let mut certs = Vec::new();
    for ca in &state.admin.config.ca {
        if let Some(cert_path) = &ca.responder_cert {
            if let Ok(cert_der) = std::fs::read(cert_path) {
                if let Ok(info) = hoike_sign::rotation::format_cert_info(&cert_der) {
                    certs.push(serde_json::json!({
                        "ca_label": ca.label,
                        "subject": info.subject,
                        "issuer": info.issuer,
                        "not_before": info.not_before,
                        "not_after": info.not_after,
                        "is_expired": info.is_expired,
                        "days_remaining": info.days_remaining,
                        "has_ocsp_signing_eku": info.has_ocsp_signing_eku,
                    }));
                }
            }
        }
    }
    Json(serde_json::json!({ "certs": certs })).into_response()
}

pub async fn get_rotation(State(state): State<AppState>, auth: Authenticated) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Viewer) {
        return e;
    }
    let mut statuses = Vec::new();
    for ca in &state.admin.config.ca {
        if let Some(cert_path) = &ca.responder_cert {
            if let Ok(cert_der) = std::fs::read(cert_path) {
                let renew_before = ca
                    .key_rotation
                    .as_ref()
                    .map(|kr| kr.renew_before_days * 86400)
                    .unwrap_or(7 * 86400);
                match hoike_sign::rotation::check_rotation_needed(&cert_der, renew_before) {
                    Ok(status) => {
                        let (status_str, expires_in) = match status {
                            hoike_sign::rotation::RotationStatus::Ok { expires_in_secs } => {
                                ("ok", Some(expires_in_secs))
                            }
                            hoike_sign::rotation::RotationStatus::RenewSoon { expires_in_secs } => {
                                ("renew_soon", Some(expires_in_secs))
                            }
                            hoike_sign::rotation::RotationStatus::Expired => ("expired", None),
                        };
                        statuses.push(serde_json::json!({
                            "ca_label": ca.label,
                            "status": status_str,
                            "expires_in_secs": expires_in,
                        }));
                    }
                    Err(e) => {
                        statuses.push(serde_json::json!({
                            "ca_label": ca.label,
                            "status": "error",
                            "error": e.to_string(),
                        }));
                    }
                }
            }
        }
    }
    Json(serde_json::json!({ "rotation": statuses })).into_response()
}

pub async fn get_gossip(State(state): State<AppState>, auth: Authenticated) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Viewer) {
        return e;
    }
    let gossip_enabled = state
        .admin
        .config
        .gossip
        .as_ref()
        .is_some_and(|g| g.enabled);
    Json(serde_json::json!({
        "enabled": gossip_enabled,
        "message": if gossip_enabled { "gossip cluster status not yet exposed via admin API" } else { "gossip is disabled" },
    }))
    .into_response()
}

pub async fn get_config(State(state): State<AppState>, auth: Authenticated) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Viewer) {
        return e;
    }
    let config = &state.admin.config;
    Json(serde_json::json!({
        "server": {
            "mode": config.server.mode,
            "listen": config.server.listen,
            "max_request": config.server.max_request,
        },
        "storage": {
            "bundle_dir": config.storage.bundle_dir.display().to_string(),
            "state_db": config.storage.state_db.display().to_string(),
            "max_chain": config.storage.max_chain,
            "seal_trust_anchors": config.storage.seal_trust_anchors.as_ref().map(|v| v.iter().map(|p| p.display().to_string()).collect::<Vec<_>>()),
        },
        "cas": config.ca.iter().map(|ca| serde_json::json!({
            "label": ca.label,
            "nonce_policy": ca.nonce_policy,
            "completeness": ca.completeness,
            "sig_alg": ca.sig_alg,
            "batch_interval": ca.batch_interval,
            "validity_secs": ca.validity_secs,
            "has_signing_key": ca.signing_key.is_some(),
            "has_responder_cert": ca.responder_cert.is_some(),
            "has_seal_key": ca.seal_key.is_some(),
            "source_type": ca.source.as_ref().map(|s| match s {
                hoike_core::config::SourceConfig::Crl { .. } => "crl",
                hoike_core::config::SourceConfig::DogtagSync { .. } => "dogtag-sync",
            }),
        })).collect::<Vec<_>>(),
        "gossip": config.gossip.as_ref().map(|g| serde_json::json!({
            "enabled": g.enabled,
            "bind": g.bind,
            "seeds": g.seeds,
            "node_name": g.node_name,
        })),
    }))
    .into_response()
}

pub async fn get_state(State(state): State<AppState>, auth: Authenticated) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Viewer) {
        return e;
    }
    let state_path = state.admin.config.storage.state_db.join("state.json");
    match std::fs::read_to_string(&state_path) {
        Ok(contents) => match serde_json::from_str::<serde_json::Value>(&contents) {
            Ok(val) => Json(val).into_response(),
            Err(_) => Json(serde_json::json!({"raw": contents})).into_response(),
        },
        Err(_) => Json(serde_json::json!({"detail": "no state file found"})).into_response(),
    }
}
