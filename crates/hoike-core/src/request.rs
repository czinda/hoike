use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use x509_ocsp::OcspRequest;

use crate::error::{CoreError, Result};

/// Maximum allowed OCSP request size in bytes.
pub const MAX_REQUEST_SIZE: usize = 8192;

/// Parsed OCSP request reduced to what the edge needs for lookup.
#[derive(Debug)]
pub struct ParsedRequest {
    pub cert_ids: Vec<ParsedCertId>,
    pub nonce: Option<Vec<u8>>,
}

/// A CertID extracted from a request, with its precomputed entry key
/// and the issuer hash fields needed for multi-CA routing.
#[derive(Debug, Clone)]
pub struct ParsedCertId {
    pub entry_key: [u8; 32],
    pub certid_der: Vec<u8>,
    pub issuer_name_hash: Vec<u8>,
    pub issuer_key_hash: Vec<u8>,
    pub serial_number: Vec<u8>,
}

/// Parse a DER-encoded OCSPRequest into the fields we need for lookup.
pub fn parse_ocsp_request(der_bytes: &[u8]) -> Result<ParsedRequest> {
    if der_bytes.is_empty() {
        return Err(CoreError::EmptyRequest);
    }
    if der_bytes.len() > MAX_REQUEST_SIZE {
        return Err(CoreError::RequestTooLarge {
            size: der_bytes.len(),
            max: MAX_REQUEST_SIZE,
        });
    }

    let ocsp_req = OcspRequest::from_der(der_bytes).map_err(|e| CoreError::DerParse {
        context: "OCSPRequest",
        detail: e.to_string(),
    })?;

    let tbs = &ocsp_req.tbs_request;

    if tbs.request_list.is_empty() {
        return Err(CoreError::EmptyRequestList);
    }

    let mut cert_ids = Vec::with_capacity(tbs.request_list.len());

    for req in tbs.request_list.iter() {
        let cert_id = &req.req_cert;

        let certid_der = cert_id.to_der().map_err(|e| CoreError::DerParse {
            context: "CertID encode",
            detail: e.to_string(),
        })?;

        let entry_key: [u8; 32] = Sha256::digest(&certid_der).into();

        cert_ids.push(ParsedCertId {
            entry_key,
            certid_der,
            issuer_name_hash: cert_id.issuer_name_hash.as_bytes().to_vec(),
            issuer_key_hash: cert_id.issuer_key_hash.as_bytes().to_vec(),
            serial_number: cert_id.serial_number.as_bytes().to_vec(),
        });
    }

    // Extract nonce extension if present.
    // OID: 1.3.6.1.5.5.7.48.1.2 (id-pkix-ocsp-nonce)
    // extn_value contains the DER encoding of the extension value,
    // which for the nonce is an OCTET STRING wrapping the raw nonce.
    // We parse through that inner OCTET STRING to get the actual nonce bytes
    // so RFC 9654 length validation applies to the nonce itself, not
    // its DER wrapper.
    let nonce_ext = tbs
        .request_extensions
        .as_ref()
        .and_then(|exts| {
            exts.iter().find(|ext| {
                ext.extn_id == der::oid::db::rfc6960::ID_PKIX_OCSP_NONCE
            })
        });

    let nonce = match nonce_ext {
        Some(ext) => {
            let raw = ext.extn_value.as_bytes();
            let inner = der::asn1::OctetStringRef::from_der(raw).map_err(|e| {
                CoreError::DerParse {
                    context: "nonce extension value",
                    detail: e.to_string(),
                }
            })?;
            Some(inner.as_bytes().to_vec())
        }
        None => None,
    };

    Ok(ParsedRequest { cert_ids, nonce })
}

/// Decode a GET request path into DER bytes.
///
/// RFC 9919 §6: the path after the AIA URI is the base64 encoding of the
/// DER-encoded OCSPRequest, URL-encoded.
pub fn decode_get_path(path: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    use percent_encoding::percent_decode_str;

    let decoded_path = percent_decode_str(path)
        .decode_utf8()
        .map_err(|e| CoreError::GetDecode(format!("URL decode: {e}")))?;

    let trimmed = decoded_path.trim_start_matches('/');

    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|e| CoreError::GetDecode(format!("base64: {e}")))
}

/// Validate nonce length per RFC 9654.
pub fn validate_nonce(nonce_bytes: &[u8]) -> NonceAction {
    match nonce_bytes.len() {
        0 => NonceAction::MalformedRequest,
        1..=15 => NonceAction::MayOmit,
        16..=32 => NonceAction::MustAccept,
        33..=128 => NonceAction::MayOmit,
        _ => NonceAction::MalformedRequest,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceAction {
    MustAccept,
    MayOmit,
    MalformedRequest,
}
