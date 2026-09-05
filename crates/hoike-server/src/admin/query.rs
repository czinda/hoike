use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::Deserialize;

use super::rbac::Authenticated;
use crate::state::{AppState, OperatorRole};

#[derive(Deserialize)]
pub struct QueryRequest {
    pub serial: String,
    pub issuer_name_hash: String,
    pub issuer_key_hash: String,
    #[serde(default)]
    pub prefer: Vec<String>,
}

pub async fn ocsp_query(
    State(state): State<AppState>,
    auth: Authenticated,
    Json(req): Json<QueryRequest>,
) -> impl IntoResponse {
    if let Err(e) = auth.require_role(OperatorRole::Viewer) {
        return e;
    }

    let inh = match hex::decode(&req.issuer_name_hash) {
        Ok(v) => v,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": format!("invalid issuer_name_hash hex: {e}")})),
            )
                .into_response();
        }
    };
    let ikh = match hex::decode(&req.issuer_key_hash) {
        Ok(v) => v,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": format!("invalid issuer_key_hash hex: {e}")})),
            )
                .into_response();
        }
    };
    let serial = match hex::decode(&req.serial) {
        Ok(v) => v,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": format!("invalid serial hex: {e}")})),
            )
                .into_response();
        }
    };

    let certid_der = build_certid_der(&inh, &ikh, &serial);
    let entry_key = {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(&certid_der);
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        key
    };
    let preferred_algs = parse_preferred_algs(&req.prefer);

    let parsed = hoike_core::ParsedCertId {
        entry_key,
        certid_der,
        issuer_name_hash: inh,
        issuer_key_hash: ikh,
        serial_number: serial,
        // build_certid_der() hardcodes the SHA-256 AlgorithmIdentifier.
        hash_alg_oid: "2.16.840.1.101.3.4.2.1".to_string(),
    };

    match state.responder.lookup(&parsed, &preferred_algs) {
        Some(result) => Json(serde_json::json!({
            "found": true,
            "ca_label": result.ca_label,
            "response_bytes_len": result.response_bytes.len(),
            "nonce_policy": result.nonce_policy,
            "window": {
                "produced_at": result.window.produced_at,
                "this_update_min": result.window.this_update_min,
                "next_update_min": result.window.next_update_min,
                "next_update_max": result.window.next_update_max,
            },
        }))
        .into_response(),
        None => Json(serde_json::json!({
            "found": false,
            "message": "no matching entry in loaded bundles",
        }))
        .into_response(),
    }
}

/// Build the DER encoding of a CertID (RFC 6960) from its component fields.
/// The entry key is SHA-256 of this DER, matching hoike-core/src/request.rs.
fn build_certid_der(inh: &[u8], ikh: &[u8], serial: &[u8]) -> Vec<u8> {
    // SHA-256 AlgorithmIdentifier: SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }
    let hash_alg: &[u8] = &[
        0x30, 0x0d, // SEQUENCE, length 13
        0x06, 0x09, // OID, length 9
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // 2.16.840.1.101.3.4.2.1
        0x05, 0x00, // NULL
    ];
    // issuerNameHash: OCTET STRING
    let inh_tagged = der_octet_string(inh);
    // issuerKeyHash: OCTET STRING
    let ikh_tagged = der_octet_string(ikh);
    // serialNumber: INTEGER
    let serial_tagged = der_integer(serial);

    let inner_len = hash_alg.len() + inh_tagged.len() + ikh_tagged.len() + serial_tagged.len();
    let mut out = Vec::with_capacity(2 + inner_len + 2); // SEQUENCE tag + length + contents
    out.push(0x30); // SEQUENCE
    push_der_length(&mut out, inner_len);
    out.extend_from_slice(hash_alg);
    out.extend_from_slice(&inh_tagged);
    out.extend_from_slice(&ikh_tagged);
    out.extend_from_slice(&serial_tagged);
    out
}

fn der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + data.len());
    out.push(0x04); // OCTET STRING
    push_der_length(&mut out, data.len());
    out.extend_from_slice(data);
    out
}

fn der_integer(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + data.len() + 1);
    out.push(0x02); // INTEGER
    // If the high bit is set, prepend a zero byte to keep the integer positive
    if !data.is_empty() && data[0] & 0x80 != 0 {
        push_der_length(&mut out, data.len() + 1);
        out.push(0x00);
    } else {
        push_der_length(&mut out, data.len());
    }
    out.extend_from_slice(data);
    out
}

fn push_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

fn parse_preferred_algs(prefs: &[String]) -> Vec<u16> {
    prefs
        .iter()
        .filter_map(|s| match s.as_str() {
            "ecdsa-p256" => Some(ahu::ALG_DISC_DEFAULT),
            "ml-dsa-44" => Some(ahu::ALG_DISC_ML_DSA_44),
            "ml-dsa-65" => Some(ahu::ALG_DISC_ML_DSA_65),
            "ml-dsa-87" => Some(ahu::ALG_DISC_ML_DSA_87),
            _ => None,
        })
        .collect()
}
