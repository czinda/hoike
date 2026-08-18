use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, EXPIRES};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use tracing::debug;

use hoike_core::{
    CONTENT_TYPE_OCSP_REQUEST, CONTENT_TYPE_OCSP_RESPONSE, MALFORMED_REQUEST,
    UNAUTHORIZED, LookupResult, decode_get_path, parse_ocsp_request, validate_nonce, NonceAction,
};

use crate::state::AppState;

/// GET on root path — no request data, always malformedRequest.
pub async fn handle_get_root() -> Response {
    ocsp_error_response(MALFORMED_REQUEST)
}

/// Handle GET requests.
///
/// RFC 9919 §6: the path segment after the AIA URI is the
/// base64url-encoded, percent-encoded DER OCSPRequest.
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

    process_request(&state, &der_bytes)
}

/// Handle POST requests.
///
/// Content-Type must be application/ocsp-request.
/// Body is the raw DER-encoded OCSPRequest.
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

    process_request(&state, &body)
}

/// Core request processing: parse → route → lookup → respond.
fn process_request(state: &AppState, der_bytes: &[u8]) -> Response {
    let parsed = match parse_ocsp_request(der_bytes) {
        Ok(p) => p,
        Err(e) => {
            debug!(error = %e, "OCSP request parse failed");
            return ocsp_error_response(MALFORMED_REQUEST);
        }
    };

    // RFC 9654 nonce validation.
    if let Some(nonce) = &parsed.nonce {
        match validate_nonce(nonce) {
            NonceAction::MalformedRequest => {
                debug!(nonce_len = nonce.len(), "nonce length rejected");
                return ocsp_error_response(MALFORMED_REQUEST);
            }
            NonceAction::MayOmit | NonceAction::MustAccept => {
                // In "ignore" nonce policy (default for edge), we serve
                // the pre-signed response without a nonce. RFC 9919 §3.2.1
                // blesses this — conformant clients fall back to time-based freshness.
            }
        }
    }

    // RFC 9919 profiles requests to a single Request. We handle the
    // first CertID; if there are more, they would need to come from
    // the same signer (same BasicOCSPResponse), which pre-signed
    // bundles don't support across CAs.
    let cert_id = match parsed.cert_ids.first() {
        Some(cid) => cid,
        None => return ocsp_error_response(MALFORMED_REQUEST),
    };

    match state.responder.lookup(cert_id) {
        Some(result) => {
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
                issuer_key_hash = hex::encode(&cert_id.issuer_key_hash[..8.min(cert_id.issuer_key_hash.len())]),
                "no entry — returning unauthorized"
            );
            ocsp_error_response(UNAUTHORIZED)
        }
    }
}

/// Build an HTTP response for a successful OCSP lookup.
///
/// Headers per RFC 9919 §6 and §7.2:
///   Content-Type: application/ocsp-response
///   ETag: "<sha256 hex>"
///   Cache-Control: max-age=N, public, no-transform, must-revalidate
fn ocsp_success_response(result: &LookupResult) -> Response {
    let etag = format!("\"{}\"", hex::encode(Sha256::digest(&result.response_bytes)));

    let window = &result.window;

    // max-age: use half of (next_update_min - this_update_min) as a
    // reasonable default, clamped to at least 60 seconds.
    let validity_secs = window.next_update_min.saturating_sub(window.this_update_min);
    let max_age = (validity_secs / 2).max(60);

    let cache_control = format!(
        "max-age={max_age}, public, no-transform, must-revalidate"
    );

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

    // Expires: next_update_min as HTTP-date.
    if let Ok(expires_time) =
        std::time::SystemTime::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(window.next_update_min))
            .ok_or(())
    {
        if let Ok(formatted) = httpdate_format(expires_time) {
            headers.insert(EXPIRES, HeaderValue::from_str(&formatted).unwrap());
        }
    }

    (StatusCode::OK, headers, result.response_bytes.clone()).into_response()
}

/// Build an HTTP response for an OCSP error (unauthorized, malformed, etc.).
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
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
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
