/// Static DER-encoded OCSP error responses.
///
/// These are constant byte arrays because error responses contain only
/// a responseStatus ENUMERATED and no responseBytes — they never change
/// and never need signing.
///
/// ```asn1
/// OCSPResponse ::= SEQUENCE {
///     responseStatus  OCSPResponseStatus,   -- ENUMERATED
///     responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL
/// }
/// ```

/// responseStatus = unauthorized (6)
/// Used when the responder has no entry for the requested CertID.
/// RFC 9919 §3.2.3: a mirror that misses a lookup MUST answer unauthorized.
pub const UNAUTHORIZED: &[u8] = &[0x30, 0x03, 0x0A, 0x01, 0x06];

/// responseStatus = malformedRequest (1)
/// Used when the request cannot be parsed or violates profile rules.
pub const MALFORMED_REQUEST: &[u8] = &[0x30, 0x03, 0x0A, 0x01, 0x01];

/// responseStatus = internalError (2)
pub const INTERNAL_ERROR: &[u8] = &[0x30, 0x03, 0x0A, 0x01, 0x02];

/// responseStatus = tryLater (3)
pub const TRY_LATER: &[u8] = &[0x30, 0x03, 0x0A, 0x01, 0x03];

/// Content-Type for all OCSP responses (success and error alike).
pub const CONTENT_TYPE_OCSP_RESPONSE: &str = "application/ocsp-response";

/// Content-Type expected on POST requests.
pub const CONTENT_TYPE_OCSP_REQUEST: &str = "application/ocsp-request";
