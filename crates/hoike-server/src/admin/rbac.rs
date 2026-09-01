use axum::Json;
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};

use crate::state::{AppState, OperatorRole};

#[allow(dead_code)]
pub struct Authenticated {
    pub operator_name: String,
    pub role: OperatorRole,
}

impl Authenticated {
    pub fn require_role(&self, min: OperatorRole) -> Result<(), Response> {
        if self.role.has_at_least(min) {
            Ok(())
        } else {
            Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"detail": "insufficient permissions"})),
            )
                .into_response())
        }
    }
}

impl FromRequestParts<AppState> for Authenticated {
    type Rejection = Response;

    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            let token = parts
                .headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .ok_or_else(|| {
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({"detail": "missing or invalid Authorization header"})),
                    )
                        .into_response()
                })?;

            let mut sessions = state.admin.sessions.lock().await;
            let session = sessions.get(token).cloned().ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"detail": "invalid or expired session"})),
                )
                    .into_response()
            })?;

            if session.expires_at < std::time::Instant::now() {
                sessions.remove(token);
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"detail": "session expired"})),
                )
                    .into_response());
            }

            Ok(Authenticated {
                operator_name: session.operator_name,
                role: session.role,
            })
        }
    }
}
