use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, EXPIRES, LAST_MODIFIED};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use hoike_core::{
    CONTENT_TYPE_OCSP_REQUEST, CONTENT_TYPE_OCSP_RESPONSE, INTERNAL_ERROR, LookupResult,
    MALFORMED_REQUEST, NonceAction, TRY_LATER, UNAUTHORIZED, decode_get_path, parse_ocsp_request,
    validate_nonce,
};

use crate::state::AppState;

pub async fn handle_get_root() -> Response {
    ocsp_error_response(MALFORMED_REQUEST)
}

pub async fn handle_get(State(state): State<AppState>, Path(path): Path<String>) -> Response {
    let der_bytes = match decode_get_path(&path) {
        Ok(b) => b,
        Err(e) => {
            debug!(error = %e, "GET path decode failed");
            crate::obs::record_request("unknown", "get", "malformed");
            return ocsp_error_response(MALFORMED_REQUEST);
        }
    };

    let max = state.responder.config.server.max_request;
    if der_bytes.len() > max {
        debug!(size = der_bytes.len(), max, "GET decoded request too large");
        crate::obs::record_request("unknown", "get", "malformed");
        return ocsp_error_response(MALFORMED_REQUEST);
    }

    process_request(&state, &der_bytes, "get").await
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
        crate::obs::record_request("unknown", "post", "malformed");
        return ocsp_error_response(MALFORMED_REQUEST);
    }

    process_request(&state, &body, "post").await
}

/// Time and record every processed request. The inner function returns the
/// resolved CA label and a `&'static str` status so the counter/histogram get
/// accurate `{ca,method,status}` labels without threading metrics through every
/// early-return branch.
async fn process_request(state: &AppState, der_bytes: &[u8], method: &'static str) -> Response {
    let start = std::time::Instant::now();
    let (resp, ca, status) = process_request_inner(state, der_bytes).await;
    crate::obs::record_request(&ca, method, status);
    crate::obs::record_request_duration(&ca, start.elapsed().as_secs_f64());
    resp
}

async fn process_request_inner(
    state: &AppState,
    der_bytes: &[u8],
) -> (Response, String, &'static str) {
    let unknown = || "unknown".to_string();

    let parsed = match parse_ocsp_request(der_bytes) {
        Ok(p) => p,
        Err(e) => {
            debug!(error = %e, "OCSP request parse failed");
            return (
                ocsp_error_response(MALFORMED_REQUEST),
                unknown(),
                "malformed",
            );
        }
    };

    // RFC 9654 nonce validation — applies regardless of policy.
    let nonce_action = parsed.nonce.as_ref().map(|n| validate_nonce(n));
    if let Some(NonceAction::MalformedRequest) = nonce_action {
        debug!(
            nonce_len = parsed.nonce.as_ref().map(|n| n.len()),
            "nonce length rejected"
        );
        crate::obs::record_nonce("unknown", "unknown", "rejected");
        return (
            ocsp_error_response(MALFORMED_REQUEST),
            unknown(),
            "malformed",
        );
    }

    let cert_id = match parsed.cert_ids.first() {
        Some(cid) => cid,
        None => {
            return (
                ocsp_error_response(MALFORMED_REQUEST),
                unknown(),
                "malformed",
            );
        }
    };

    let has_nonce = parsed.nonce.is_some();

    match state.responder.lookup(cert_id, &parsed.preferred_sig_algs) {
        Some(result) => {
            let ca = result.ca_label.clone();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now < result.window.this_update_min || now >= result.window.next_update_min {
                return (ocsp_error_response(TRY_LATER), ca, "tryLater");
            }
            crate::obs::record_certid_alg(&ca, &cert_id.hash_alg_oid);

            // Nonce policy only matters when the request carries a nonce.
            if has_nonce {
                match result.nonce_policy.as_str() {
                    "live" => {
                        crate::obs::record_nonce(&ca, "live", "live");
                        if let Some(live) = state.live_signer_for(&ca) {
                            let nonce_bytes = parsed.nonce.as_ref().unwrap();
                            let source = match hoike_sign::live::extract_status_for_cert(
                                &result.response_bytes,
                                &cert_id.certid_der,
                            ) {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!(error = %e, "failed to extract status for live signing");
                                    return (
                                        ocsp_error_response(INTERNAL_ERROR),
                                        ca,
                                        "internalError",
                                    );
                                }
                            };
                            let mut signer = live.signer.lock().await;
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            match hoike_sign::live::sign_live_response_with_window::<
                                _,
                                p256::ecdsa::DerSignature,
                            >(
                                &cert_id.certid_der,
                                source.status,
                                nonce_bytes,
                                &live.responder_key_bytes,
                                &mut *signer,
                                now,
                                source.this_update,
                                source
                                    .next_update
                                    .min(result.window.next_update_min)
                                    .min(now.saturating_add(live.validity_secs)),
                                live.responder_cert_der.as_deref(),
                            ) {
                                Ok(response_der) => {
                                    debug!(
                                        ca = result.ca_label,
                                        nonce_len = nonce_bytes.len(),
                                        "signed live response with nonce"
                                    );
                                    return (live_response(&response_der), ca, "live");
                                }
                                Err(e) => {
                                    warn!(error = %e, "live signing failed");
                                    return (
                                        ocsp_error_response(INTERNAL_ERROR),
                                        ca,
                                        "internalError",
                                    );
                                }
                            }
                        }
                        debug!(
                            ca = result.ca_label,
                            "live nonce policy but no signer configured"
                        );
                        return (ocsp_error_response(INTERNAL_ERROR), ca, "internalError");
                    }
                    "forward" => {
                        crate::obs::record_nonce(&ca, "forward", "forwarded");
                        if let Some(url) = &result.forward_to {
                            debug!(
                                ca = result.ca_label,
                                url = url,
                                "forwarding nonce-bearing request upstream"
                            );
                            let insecure = state
                                .admin
                                .config
                                .ca
                                .iter()
                                .find(|c| c.label == ca)
                                .is_some_and(|c| c.forward_insecure);
                            return (
                                forward_request(url, der_bytes, insecure).await,
                                ca,
                                "forwarded",
                            );
                        }
                        // forward_to missing should be caught at config validation,
                        // but handle gracefully at runtime.
                        warn!(ca = result.ca_label, "forward policy but no forward_to URL");
                        return (ocsp_error_response(INTERNAL_ERROR), ca, "internalError");
                    }
                    _ => {
                        // "ignore" — serve pre-signed response without nonce.
                        // RFC 9919 §3.2.1 blesses this.
                        crate::obs::record_nonce(&ca, &result.nonce_policy, "ignored");
                    }
                }
            }

            debug!(
                entry_key = hex::encode(cert_id.entry_key),
                ca = result.ca_label,
                size = result.response_bytes.len(),
                "serving pre-signed response"
            );
            let status = presigned_status_label(&result.response_bytes);
            (ocsp_success_response(&result), ca, status)
        }
        None => {
            debug!(
                entry_key = hex::encode(cert_id.entry_key),
                serial = hex::encode(&cert_id.serial_number),
                "no entry — returning unauthorized"
            );
            crate::obs::record_certid_alg("unknown", &cert_id.hash_alg_oid);
            crate::obs::audit!(
                event = "request_rejected",
                reason = "unauthorized",
                serial = %hex::encode(&cert_id.serial_number),
                "no bundle entry for requested serial"
            );
            (ocsp_error_response(UNAUTHORIZED), unknown(), "unauthorized")
        }
    }
}

/// Classify a pre-signed OCSP response into a `{good,revoked}` status label for
/// the request counter. Decoding is skipped entirely (returns `"served"`) when
/// the `metrics` feature is off, keeping the serving hot path allocation-free.
#[cfg(feature = "metrics")]
fn presigned_status_label(response_bytes: &[u8]) -> &'static str {
    match hoike_sign::extract_status_from_response(response_bytes) {
        Ok(hoike_sign::LiveCertStatus::Good) => "good",
        Ok(hoike_sign::LiveCertStatus::Unknown) => "unknown",
        Ok(hoike_sign::LiveCertStatus::Revoked { .. }) => "revoked",
        Err(_) => "served",
    }
}

#[cfg(not(feature = "metrics"))]
#[inline]
fn presigned_status_label(_response_bytes: &[u8]) -> &'static str {
    "served"
}

/// Shared outbound client for nonce forwarding.
///
/// Built once (not per request): `reqwest`'s rustls-tls stack validates the
/// upstream certificate against the system trust store by default, giving the
/// forward channel a real trusted channel (FTP_ITC.1). Constructed lazily so a
/// responder that never forwards pays nothing.
static FORWARD_CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();

fn forward_client() -> &'static reqwest::Client {
    FORWARD_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client for forwarding")
    })
}

async fn forward_request(url: &str, der_bytes: &[u8], allow_insecure: bool) -> Response {
    let permitted = reqwest::Url::parse(url)
        .is_ok_and(|u| u.scheme() == "https" || (allow_insecure && u.scheme() == "http"));
    if !permitted {
        return ocsp_error_response(INTERNAL_ERROR);
    }
    // Defense in depth: `hoike check` refuses a cleartext `forward_to` unless
    // `forward_insecure` is set, but warn at runtime too so an operator who
    // bypassed validation still sees the trusted-channel violation.
    if !url.starts_with("https://") {
        warn!(
            url = url,
            "forwarding OCSP request over a non-TLS channel — bind password/nonce \
             traffic is not confidentiality-protected (FTP_ITC.1)"
        );
    }

    let client = forward_client();

    match client
        .post(url)
        .header("Content-Type", CONTENT_TYPE_OCSP_REQUEST)
        .body(der_bytes.to_vec())
        .send()
        .await
    {
        Ok(mut upstream_resp) => {
            let status = upstream_resp.status();
            if !status.is_success() {
                warn!(
                    url = url,
                    status = %status,
                    "upstream OCSP responder returned non-success status"
                );
                return ocsp_error_response(TRY_LATER);
            }

            // Validate Content-Type — upstream should return application/ocsp-response.
            let ct_ok = upstream_resp
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|ct| {
                    ct.split(';')
                        .next()
                        .is_some_and(|t| t.trim().eq_ignore_ascii_case(CONTENT_TYPE_OCSP_RESPONSE))
                })
                .unwrap_or(false);

            if !ct_ok {
                warn!(
                    url = url,
                    "upstream response has unexpected Content-Type, not application/ocsp-response"
                );
                return ocsp_error_response(TRY_LATER);
            }

            const MAX_FORWARD_RESPONSE: usize = 65536;
            if upstream_resp
                .content_length()
                .is_some_and(|n| n > MAX_FORWARD_RESPONSE as u64)
            {
                return ocsp_error_response(INTERNAL_ERROR);
            }
            let mut body = Vec::new();
            loop {
                match upstream_resp.chunk().await {
                    Ok(Some(chunk)) => {
                        if chunk.len() > MAX_FORWARD_RESPONSE.saturating_sub(body.len()) {
                            return ocsp_error_response(INTERNAL_ERROR);
                        }
                        body.extend_from_slice(&chunk);
                    }
                    Ok(None) => break,
                    Err(e) => {
                        warn!(error = %e, "upstream body read failed");
                        return ocsp_error_response(TRY_LATER);
                    }
                }
            }
            live_response(&body)
        }
        Err(e) => {
            warn!(url = url, error = %e, "failed to forward request upstream");
            ocsp_error_response(TRY_LATER)
        }
    }
}

fn ocsp_success_response(result: &LookupResult) -> Response {
    let window = &result.window;

    // Per-result expiry check (the bundle-level check in process_request
    // catches most cases, but a multi-CA deployment may have bundles with
    // different windows).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now < window.this_update_min || now >= window.next_update_min {
        return ocsp_error_response(TRY_LATER);
    }

    let etag = format!(
        "\"{}\"",
        hex::encode(Sha256::digest(&result.response_bytes))
    );

    let validity_secs = window
        .next_update_min
        .saturating_sub(window.this_update_min);
    let max_age = (validity_secs / 2).min(window.next_update_min.saturating_sub(now));

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

    // Last-Modified: thisUpdate (RFC 9919 §7.2)
    if let Ok(last_modified_time) = std::time::SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(window.this_update_min))
        .ok_or(())
    {
        if let Ok(formatted) = httpdate_format(last_modified_time) {
            headers.insert(LAST_MODIFIED, HeaderValue::from_str(&formatted).unwrap());
        }
    }

    // Expires: nextUpdate
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

/// HTTP response for a live-signed OCSP response (nonce-bearing).
/// Not cached — the nonce makes it unique.
fn live_response(response_bytes: &[u8]) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_OCSP_RESPONSE),
    );
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store"),
    );
    (StatusCode::OK, headers, response_bytes.to_vec()).into_response()
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

#[cfg(test)]
mod forwarding_regressions {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn body(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn cleartext_forwarding_requires_explicit_opt_in() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        assert_eq!(
            body(forward_request(&url, b"request", false).await).await,
            INTERNAL_ERROR
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let location = format!("http://{}/", target.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await.unwrap();
            socket.write_all(format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.unwrap();
        });
        assert_eq!(
            body(forward_request(&url, b"request", true).await).await,
            TRY_LATER
        );
        server.await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), target.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn chunked_response_is_rejected_before_unbounded_buffering() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await.unwrap();
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
            for _ in 0..17 {
                if socket.write_all(b"1000\r\n").await.is_err() {
                    return;
                }
                if socket.write_all(&[42; 4096]).await.is_err() {
                    return;
                }
                if socket.write_all(b"\r\n").await.is_err() {
                    return;
                }
            }
            // No terminating chunk: the bound must trigger without waiting for EOF.
            std::future::pending::<()>().await;
        });
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            forward_request(&url, b"request", true),
        )
        .await
        .unwrap();
        assert_eq!(body(response).await, INTERNAL_ERROR);
        server.abort();
    }
}
