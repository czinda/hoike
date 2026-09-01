use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

use crate::state::{AppState, OperatorRole, Session};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub name: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub session_token: String,
    pub role: OperatorRole,
    pub operator: String,
    pub expires_in_secs: u64,
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    let admin_config = match &state.admin.config.server.admin {
        Some(c) => c,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"detail": "admin API not configured"})),
            )
                .into_response();
        }
    };

    let operator = admin_config.operators.iter().find(|op| op.name == req.name);

    let operator = match operator {
        Some(op) => op,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"detail": "invalid credentials"})),
            )
                .into_response();
        }
    };

    let password = req.password.clone();
    let hash = operator.password_hash.clone();
    let op_name = operator.name.clone();
    let password_ok = tokio::task::spawn_blocking(move || match bcrypt::verify(&password, &hash) {
        Ok(valid) => valid,
        Err(e) => {
            tracing::warn!(
                operator = %op_name,
                error = %e,
                "bcrypt verification error — check password_hash format in config"
            );
            false
        }
    })
    .await
    .unwrap_or(false);
    if !password_ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"detail": "invalid credentials"})),
        )
            .into_response();
    }

    let role: OperatorRole = operator.role.parse().unwrap_or(OperatorRole::Viewer);

    let ttl = admin_config.session_ttl_secs;
    let token = generate_token();
    let session = Session {
        operator_name: operator.name.clone(),
        role,
        expires_at: Instant::now() + Duration::from_secs(ttl),
    };

    state
        .admin
        .sessions
        .lock()
        .await
        .insert(token.clone(), session);

    Json(LoginResponse {
        session_token: token,
        role,
        operator: operator.name.clone(),
        expires_in_secs: ttl,
    })
    .into_response()
}

pub async fn logout(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    if let Some(token) = extract_bearer_token(&req) {
        state.admin.sessions.lock().await.remove(token);
    }
    StatusCode::NO_CONTENT
}

pub fn extract_bearer_token(req: &axum::http::Request<axum::body::Body>) -> Option<&str> {
    req.headers()
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn generate_token() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}
