use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

use crate::state::{AppState, OperatorRole, Session};

/// Syntactically valid cost-12 bcrypt hash used as a decoy when the requested
/// operator does not exist, so `bcrypt::verify` performs equivalent work whether
/// or not the account exists (username-enumeration timing defense). MUST remain
/// a parseable bcrypt hash — see `tests::dummy_hash_is_valid_bcrypt`.
const DUMMY_HASH: &str = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW";

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

    // Look up the operator, but always run bcrypt afterward — even when the
    // name is unknown — so login latency does not reveal whether an account
    // exists (defends against username enumeration via response timing).
    let operator = admin_config.operators.iter().find(|op| op.name == req.name);

    // When the operator is unknown, verify against DUMMY_HASH so bcrypt performs
    // equivalent work in both branches. The result is discarded: `operator` being
    // None forces a 401 below regardless of whether the decoy happened to match.
    let hash = operator
        .map(|op| op.password_hash.clone())
        .unwrap_or_else(|| DUMMY_HASH.to_string());
    let password = req.password.clone();
    let password_ok = tokio::task::spawn_blocking(move || match bcrypt::verify(&password, &hash) {
        Ok(valid) => valid,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "bcrypt verification error — check password_hash format in config"
            );
            false
        }
    })
    .await
    .unwrap_or(false);

    let operator = match operator {
        Some(op) if password_ok => op,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"detail": "invalid credentials"})),
            )
                .into_response();
        }
    };

    let role: OperatorRole = operator.role.parse().unwrap_or(OperatorRole::Viewer);

    let ttl = admin_config.session_ttl_secs;
    let token = generate_token();
    let session = Session {
        operator_name: operator.name.clone(),
        role,
        expires_at: Instant::now() + Duration::from_secs(ttl),
    };

    {
        // Prune expired sessions before inserting so the store cannot grow
        // without bound when clients never call logout (expired entries are
        // otherwise only removed when re-presented after their TTL).
        let mut sessions = state.admin.sessions.lock().await;
        let now = Instant::now();
        sessions.retain(|_, s| s.expires_at > now);
        sessions.insert(token.clone(), session);
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_hash_is_valid_bcrypt() {
        // The username-enumeration timing defense relies on DUMMY_HASH being a
        // parseable bcrypt hash: an invalid hash would make bcrypt::verify return
        // Err immediately, reopening the fast-path timing side channel.
        assert!(
            bcrypt::verify("not-the-password", DUMMY_HASH).is_ok(),
            "DUMMY_HASH must be a valid bcrypt hash"
        );
    }
}
