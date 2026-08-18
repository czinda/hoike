use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, EXPIRES};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use hoike_core::{
    CONTENT_TYPE_OCSP_REQUEST, CONTENT_TYPE_OCSP_RESPONSE, INTERNAL_ERROR, MALFORMED_REQUEST,
    TRY_LATER, UNAUTHORIZED, LookupResult, NonceAction, decode_get_path, parse_ocsp_request,
    validate_nonce,
};

use crate::state::AppState;

pub async fn handle_get_root() -> Response {
    ocsp_error_response(MALFORMED_REQUEST)
}

pub async fn handle_get(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Response {
    let der_bytes = match decode_get_path(&path) {
        Ok(b) => b,
        Err(e) => {
            debug!(error = %e, "GET path decode failed");
            return ocsp_error_response(MALFORMED_REQUEST);
        }
    };

    let max = state.responder.config.server.max_request;
    if der_bytes.len() > max {
        debug!(size = der_bytes.len(), max, "GET decoded request too large");
        return ocsp_error_response(MALFORMED_REQUEST);
    }

    process_request(&state, &der_bytes).await
}

pub async fn handle_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(ct) = headers.get(CONTENT_TYPE) {
        if let Ok(ct_str) = ct.to_str() {
            if !ct_str
                .split(';')
                .next()
                .is_some_and(|t| t.trim().eq_ignore_ascii_case(CONTENT_TYPE_OCSP_REQUEST))
            {
                debug!(content_type = ct_str, "unexpected Content-Type on POST");
            }
        }
    }

    let max = state.responder.config.server.max_request;
    if body.len() > max {
        debug!(size = body.len(), max, "POST body too large");
        return ocsp_error_response(MALFORMED_REQUEST);
    }

    process_request(&state, &body).await
}

async fn process_request(state: &AppState, der_bytes: &[u8]) -> Response {
    let parsed = match parse_ocsp_request(der_bytes) {
        Ok(p) => p,
        Err(e) => {
            debug!(error = %e, "OCSP request parse failed");
            return ocsp_error_response(MALFORMED_REQUEST);
        }
    };

    // RFC 9654 nonce validation — applies regardless of policy.
    let nonce_action = parsed.nonce.as_ref().map(|n| validate_nonce(n));
    if let Some(NonceAction::MalformedRequest) = nonce_action {
        debug!(
            nonce_len = parsed.nonce.as_ref().map(|n| n.len()),
            "nonce length rejected"
        );
        return ocsp_error_response(MALFORMED_REQUEST);
    }

    let cert_id = match parsed.cert_ids.first() {
        Some(cid) => cid,
        None => return ocsp_error_response(MALFORMED_REQUEST),
    };

    let has_nonce = parsed.nonce.is_some();

    match state.responder.lookup(cert_id) {
        Some(result) => {
            // Nonce policy only matters when the request carries a nonce.
            if has_nonce {
                match result.nonce_policy.as_str() {
                    "live" => {
                        // Live signing requires key access — placeholder for M3.
                        warn!(
                            ca = result.ca_label,
                            "live nonce signing not yet implemented — returning internalError"
                        );
                        return ocsp_error_response(INTERNAL_ERROR);
                    }
                    "forward" => {
                        if let Some(url) = &result.forward_to {
                            debug!(
                                ca = result.ca_label,
                                url = url,
                                "forwarding nonce-bearing request upstream"
                            );
                            return forward_request(url, der_bytes).await;
                        }
                        // forward_to missing should be caught at config validation,
                        // but handle gracefully at runtime.
                        warn!(ca = result.ca_label, "forward policy but no forward_to URL");
                        return ocsp_error_response(INTERNAL_ERROR);
                    }
                    _ => {
                        // "ignore" — serve pre-signed response without nonce.
                        // RFC 9919 §3.2.1 blesses this.
                    }
                }
            }

            debug!(
                entry_key = hex::encode(cert_id.entry_key),
                ca = result.ca_label,
                size = result.response_bytes.len(),
                "serving pre-signed response"
            );
            ocsp_success_response(&result)
        }
        None => {
            debug!(
                entry_key = hex::encode(cert_id.entry_key),
                serial = hex::encode(&cert_id.serial_number),
                "no entry — returning unauthorized"
            );
            ocsp_error_response(UNAUTHORIZED)
        }
    }
}

async fn forward_request(url: &str, der_bytes: &[u8]) -> Response {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    match client
        .post(url)
        .header("Content-Type", CONTENT_TYPE_OCSP_REQUEST)
        .body(der_bytes.to_vec())
        .send()
        .await
    {
        Ok(upstream_resp) => {
            match upstream_resp.bytes().await {
                Ok(body) => {
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        CONTENT_TYPE,
                        HeaderValue::from_static(CONTENT_TYPE_OCSP_RESPONSE),
                    );
                    headers.insert(
                        CACHE_CONTROL,
                        HeaderValue::from_static("no-cache, no-store"),
                    );
                    (StatusCode::OK, headers, body.to_vec()).into_response()
                }
                Err(e) => {
                    warn!(error = %e, "failed to read upstream response body");
                    ocsp_error_response(TRY_LATER)
                }
            }
        }
        Err(e) => {
            warn!(url = url, error = %e, "failed to forward request upstream");
            ocsp_error_response(TRY_LATER)
        }
    }
}

fn ocsp_success_response(result: &LookupResult) -> Response {
    let etag = format!(
        "\"{}\"",
        hex::encode(Sha256::digest(&result.response_bytes))
    );

    let window = &result.window;
    let validity_secs = window.next_update_min.saturating_sub(window.this_update_min);
    let max_age = (validity_secs / 2).max(60);

    let cache_control = format!("max-age={max_age}, public, no-transform, must-revalidate");

    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_OCSP_RESPONSE),
    );
    headers.insert(ETAG, HeaderValue::from_str(&etag).unwrap());
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_str(&cache_control).unwrap(),
    );

    if let Ok(expires_time) = std::time::SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(window.next_update_min))
        .ok_or(())
    {
        if let Ok(formatted) = httpdate_format(expires_time) {
            headers.insert(EXPIRES, HeaderValue::from_str(&formatted).unwrap());
        }
    }

    (StatusCode::OK, headers, result.response_bytes.clone()).into_response()
}

fn ocsp_error_response(status_der: &[u8]) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_OCSP_RESPONSE),
    );
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store"),
    );

    (StatusCode::OK, headers, status_der.to_vec()).into_response()
}

fn httpdate_format(time: std::time::SystemTime) -> std::result::Result<String, ()> {
    let duration = time.duration_since(std::time::UNIX_EPOCH).map_err(|_| ())?;
    let secs = duration.as_secs();

    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let weekday = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][(days % 7) as usize];

    let (year, month, day) = days_to_ymd(days);
    let month_name = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(month - 1) as usize];

    Ok(format!(
        "{weekday}, {day:02} {month_name} {year} {hours:02}:{minutes:02}:{seconds:02} GMT"
    ))
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
