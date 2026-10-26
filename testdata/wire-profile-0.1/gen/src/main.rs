//! Independent generator for the ahu 0.1 golden wire-profile vectors.
//!
//! Every byte of the container is hand-assembled directly from the layout in
//! `ahu-format-spec.md`: the 64-byte big-endian file header, the
//! deterministic CBOR manifest (RFC 8949 §4.2: definite lengths, canonical
//! map ordering, shortest-form integers), the 48-byte index records, and the
//! data payloads. The manifest is sealed with a hand-assembled detached CMS
//! `SignedData` (RFC 5652) carrying the required `content-type` and
//! `message-digest` signed attributes over `id-data`.
//!
//! This program shares no code with the `ahu` crate: the only dependencies
//! are SHA-256, P-256 signing (deterministic RFC 6979 nonces, so the output
//! is byte-for-byte reproducible), and hex for the printed report. The
//! committed fixtures under `testdata/wire-profile-0.1/` are the canonical
//! vectors; this generator exists so they can be re-derived and audited.
//!
//! Payloads are documented opaque placeholder octets: the container profile
//! treats entry payloads as verbatim bytes and never parses them. Entry keys
//! are SHA-256 over documented preimages standing in for SHA-256(DER of
//! CertID).

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

// ─── Fixed inputs (all values recorded in README.md) ─────────────────────

/// Synthetic P-256 seal key: secret scalar 0x77 repeated 32 times.
/// Deterministic RFC 6979 nonces make every signature reproducible.
const SEAL_KEY_SEED: [u8; 32] = [0x77; 32];

/// Fixed seal-certificate validity window (unix seconds). Deliberately
/// wide so the immutable vectors stay verifiable for the life of the 0.1
/// profile; the fixed test verification time must fall inside it.
const SEAL_CERT_NOT_BEFORE: u64 = 1_700_000_000;
const SEAL_CERT_NOT_AFTER: u64 = 2_200_000_000;
const SEAL_CERT_CN: &str = "hoike-wire-profile-0.1";
const SEAL_CERT_SERIAL: u128 = 1;

/// Fixed verification time used by the golden-vector tests (recorded in
/// README.md; production clocks stay real).
const FIXED_TEST_TIME: u64 = 1_800_000_000;

const PRODUCER_ID: &str = "wire-profile-0.1";
const CREATED_AT: u64 = 1_800_000_000;
const WINDOW_NEXT_UPDATE_MIN: u64 = 1_800_086_400;
const WINDOW_NEXT_UPDATE_MAX: u64 = 1_800_093_600;

/// SHA-256 OID content octets (2.16.840.1.101.3.4.2.1) — the CertID
/// hashAlgorithm this scope's entry keys were built with.
const SHA256_OID_CONTENT: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// ECDSA-with-SHA256 OID content octets (1.2.840.10045.4.3.2) — the
/// signature algorithm used on responses in this scope.
const ECDSA_SHA256_OID_CONTENT: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

// ─── DER helpers ──────────────────────────────────────────────────────────

fn der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else if len < 0x1_0000 {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    } else {
        out.extend_from_slice(&[0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]);
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

fn seq(content: &[u8]) -> Vec<u8> {
    tlv(0x30, content)
}

/// SEQUENCE over the concatenation of already-encoded parts.
fn seq_parts(parts: &[Vec<u8>]) -> Vec<u8> {
    let content = parts.concat();
    seq(&content)
}

/// SET OF over the concatenation of already-encoded parts.
fn set_of(parts: &[Vec<u8>]) -> Vec<u8> {
    let content = parts.concat();
    tlv(0x31, &content)
}

/// DER OBJECT IDENTIFIER from dotted string content octets.
fn oid(content: &[u8]) -> Vec<u8> {
    tlv(0x06, content)
}

fn integer_u128(v: u128) -> Vec<u8> {
    // Minimal two's-complement INTEGER encoding of a non-negative value.
    let bytes = v.to_be_bytes();
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let val = &bytes[start..];
    let pad = usize::from(val[0] & 0x80 != 0);
    let mut content = vec![0u8; pad];
    content.extend_from_slice(val);
    tlv(0x02, &content)
}

// OID content octets for the CMS profile.
const OID_DATA: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01]; // 1.2.840.113549.1.7.1
const OID_SIGNED_DATA: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]; // 1.2.840.113549.1.7.2
const OID_CONTENT_TYPE_ATTR: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03]; // 1.2.840.113549.1.9.3
const OID_MESSAGE_DIGEST_ATTR: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04]; // 1.2.840.113549.1.9.4
const OID_SHA256: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]; // 2.16.840.1.101.3.4.2.1
const OID_ECDSA_SHA256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]; // 1.2.840.10045.4.3.2
const OID_EC_PUB: [u8; 7] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]; // 1.2.840.10045.2.1
const OID_P256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]; // 1.2.840.10045.3.1.7
const OID_CN: [u8; 3] = [0x55, 0x04, 0x03]; // 2.5.4.3

// ─── X.509 seal certificate (fixed validity window) ──────────────────────

fn encode_cn(cn: &str) -> Vec<u8> {
    let attr = seq_parts(&[oid(&OID_CN), tlv(0x0C, cn.as_bytes())]);
    let rdn = tlv(0x31, &attr); // RelativeDistinguishedName SET
    seq_parts(&[rdn]) // Name
}

/// RFC 5280 UTCTime "YYMMDDHHMMSSZ" (valid for years 1950–2049).
fn utc_time(unix_secs: u64) -> String {
    let days = unix_secs / 86400;
    let secs = unix_secs % 86400;
    // Howard Hinnant's civil-from-days conversion.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        year % 100,
        month,
        day,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn ecdsa_spki(public_key_sec1: &[u8]) -> Vec<u8> {
    let alg = seq_parts(&[oid(&OID_EC_PUB), oid(&OID_P256)]);
    let mut bits = vec![0x00]; // unused-bits byte
    bits.extend_from_slice(public_key_sec1);
    seq_parts(&[alg, tlv(0x03, &bits)])
}

/// Convert a raw ECDSA P-256 signature (r || s, 64 bytes) to DER.
fn ecdsa_raw_to_der(raw: &[u8]) -> Vec<u8> {
    fn encode_int(val: &[u8; 32]) -> Vec<u8> {
        let start = val.iter().position(|&b| b != 0).unwrap_or(val.len() - 1);
        let v = &val[start..];
        let pad = usize::from(v[0] & 0x80 != 0);
        let mut content = vec![0u8; pad];
        content.extend_from_slice(v);
        tlv(0x02, &content)
    }
    let (r, s) = raw.split_at(32);
    let r_arr: [u8; 32] = r.try_into().unwrap();
    let s_arr: [u8; 32] = s.try_into().unwrap();
    seq_parts(&[encode_int(&r_arr), encode_int(&s_arr)])
}

fn sign_prehash_der(key: &SigningKey, payload: &[u8]) -> Vec<u8> {
    let hash = Sha256::digest(payload);
    let sig: Signature = key.sign_prehash(&hash).expect("P-256 prehash sign");
    ecdsa_raw_to_der(&sig.to_bytes())
}

/// Self-signed seal certificate with a fixed validity window, no extensions,
/// subject/issuer CN only — the bounded profile the reference reader accepts.
fn build_seal_cert(key: &SigningKey) -> Vec<u8> {
    let name = encode_cn(SEAL_CERT_CN);
    let mut tbs = Vec::new();
    tbs.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]); // [0] EXPLICIT version 2
    tbs.extend_from_slice(&integer_u128(SEAL_CERT_SERIAL));
    let sig_alg = seq(&oid(&OID_ECDSA_SHA256));
    tbs.extend_from_slice(&sig_alg);
    tbs.extend_from_slice(&name); // issuer
    let validity = seq_parts(&[
        tlv(0x17, utc_time(SEAL_CERT_NOT_BEFORE).as_bytes()),
        tlv(0x17, utc_time(SEAL_CERT_NOT_AFTER).as_bytes()),
    ]);
    tbs.extend_from_slice(&validity);
    tbs.extend_from_slice(&name); // subject
    let pub_sec1 = p256::ecdsa::VerifyingKey::from(key)
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    tbs.extend_from_slice(&ecdsa_spki(&pub_sec1));
    let tbs = seq(&tbs);

    let signature = sign_prehash_der(key, &tbs);
    let mut bits = vec![0x00];
    bits.extend_from_slice(&signature);
    seq_parts(&[tbs, sig_alg, tlv(0x03, &bits)])
}

// ─── Detached CMS SignedData seal ─────────────────────────────────────────

/// Build the detached CMS SignedData over the manifest octets:
/// eContentType = id-data, eContent absent, exactly one SignerInfo with
/// SHA-256 digest and the content-type + message-digest signed attributes.
fn build_seal(manifest_bytes: &[u8], key: &SigningKey, cert_der: &[u8]) -> Vec<u8> {
    let manifest_digest = Sha256::digest(manifest_bytes);
    let sig_alg = seq(&oid(&OID_ECDSA_SHA256));

    // Attribute ::= SEQUENCE { type OID, values SET OF AttributeValue }
    // content-type value is the id-data OID TLV; message-digest value is an
    // OCTET STRING. Attributes sort content-type < message-digest (the SET OF
    // requires DER order).
    let content_type_attr = seq_parts(&[oid(&OID_CONTENT_TYPE_ATTR), set_of(&[oid(&OID_DATA)])]);
    let message_digest_attr = seq_parts(&[
        oid(&OID_MESSAGE_DIGEST_ATTR),
        set_of(&[tlv(0x04, &manifest_digest[..])]),
    ]);
    let attrs_content = [content_type_attr, message_digest_attr].concat();

    // The signature is computed over the signed attributes encoded as a
    // SET OF (tag 0x31) — RFC 5652 §5.4 — even though they are carried in
    // the SignerInfo under an IMPLICIT [0] tag.
    let signed_attrs_set = tlv(0x31, &attrs_content);
    let signature = sign_prehash_der(key, &signed_attrs_set);

    // SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm,
    //   signedAttrs [0] IMPLICIT, signatureAlgorithm, signature }
    let name = encode_cn(SEAL_CERT_CN);
    let sid = seq_parts(&[name, integer_u128(SEAL_CERT_SERIAL)]); // IssuerAndSerialNumber
    let digest_alg = seq_parts(&[oid(&OID_SHA256)]);
    let mut signer_info_content = Vec::new();
    signer_info_content.extend_from_slice(&integer_u128(1)); // version v1
    signer_info_content.extend_from_slice(&sid);
    signer_info_content.extend_from_slice(&digest_alg);
    signer_info_content.extend_from_slice(&tlv(0xA0, &attrs_content)); // [0] IMPLICIT
    signer_info_content.extend_from_slice(&sig_alg);
    signer_info_content.extend_from_slice(&tlv(0x04, &signature));
    let signer_info = seq(&signer_info_content);

    // SignedData ::= SEQUENCE { version, digestAlgorithms SET OF,
    //   encapContentInfo, certificates [0] IMPLICIT OPTIONAL, crls,
    //   signerInfos SET OF }
    let mut sd_content = Vec::new();
    sd_content.extend_from_slice(&integer_u128(1)); // version v1
    sd_content.extend_from_slice(&tlv(0x31, &digest_alg)); // exactly SHA-256
    sd_content.extend_from_slice(&seq_parts(&[oid(&OID_DATA)])); // detached id-data
    sd_content.extend_from_slice(&tlv(0xA0, cert_der)); // [0] IMPLICIT CertificateSet
    sd_content.extend_from_slice(&tlv(0x31, &signer_info));
    let signed_data = seq(&sd_content);

    // ContentInfo ::= SEQUENCE { contentType, content [0] EXPLICIT }
    seq_parts(&[oid(&OID_SIGNED_DATA), tlv(0xA0, &signed_data)])
}

// ─── Deterministic CBOR (RFC 8949 §4.2) ───────────────────────────────────

fn cbor_head(major: u8, arg: u64) -> Vec<u8> {
    let m = major << 5;
    if arg < 24 {
        vec![m | arg as u8]
    } else if arg < 0x100 {
        vec![m | 24, arg as u8]
    } else if arg < 0x1_0000 {
        vec![m | 25, (arg >> 8) as u8, arg as u8]
    } else {
        vec![
            m | 26,
            (arg >> 24) as u8,
            (arg >> 16) as u8,
            (arg >> 8) as u8,
            arg as u8,
        ]
    }
}

fn cbor_uint(v: u64) -> Vec<u8> {
    cbor_head(0, v)
}

fn cbor_bstr(b: &[u8]) -> Vec<u8> {
    let mut out = cbor_head(2, b.len() as u64);
    out.extend_from_slice(b);
    out
}

fn cbor_text(s: &str) -> Vec<u8> {
    let mut out = cbor_head(3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
    out
}

fn cbor_map(n: usize) -> Vec<u8> {
    cbor_head(5, n as u64)
}

fn cbor_array(n: usize) -> Vec<u8> {
    cbor_head(4, n as u64)
}

// ─── Container assembly ───────────────────────────────────────────────────

#[derive(Clone)]
struct Entry {
    /// SHA-256 over the documented preimage standing in for DER of CertID.
    entry_key: [u8; 32],
    discriminator: u16,
    payload: Vec<u8>,
}

struct BundleSpec {
    bundle_id: [u8; 16],
    entries: Vec<Entry>,
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Hand-encode the manifest CBOR map. Keys 1..10 ascending, optional keys
/// 11/12/13 omitted. Field values mirror the documented vector contents.
fn encode_manifest(spec: &BundleSpec, index_digest: [u8; 32], data_digest: [u8; 32]) -> Vec<u8> {
    let issuer_name_hash = sha256(b"wire-profile-0.1/issuer-name");
    let issuer_key_hash = sha256(b"wire-profile-0.1/issuer-key");
    let responder_key = &sha256(b"wire-profile-0.1/responder-key")[..20];

    // ca_scope = { 1: hashAlg, 2: issuerNameHash, 3: issuerKeyHash, 4: epoch,
    //              5: responderId {1: type, 2: value}, 7: sigAlg, 8: completeness }
    let mut scope = Vec::new();
    scope.extend_from_slice(&cbor_uint(1));
    scope.extend_from_slice(&cbor_bstr(&SHA256_OID_CONTENT));
    scope.extend_from_slice(&cbor_uint(2));
    scope.extend_from_slice(&cbor_bstr(&issuer_name_hash));
    scope.extend_from_slice(&cbor_uint(3));
    scope.extend_from_slice(&cbor_bstr(&issuer_key_hash));
    scope.extend_from_slice(&cbor_uint(4));
    scope.extend_from_slice(&cbor_uint(1)); // epoch
    scope.extend_from_slice(&cbor_uint(5));
    let mut rid = cbor_map(2);
    rid.extend_from_slice(&cbor_uint(1));
    rid.extend_from_slice(&cbor_uint(1)); // byKey
    rid.extend_from_slice(&cbor_uint(2));
    rid.extend_from_slice(&cbor_bstr(responder_key));
    scope.extend_from_slice(&rid);
    scope.extend_from_slice(&cbor_uint(7));
    scope.extend_from_slice(&cbor_bstr(&ECDSA_SHA256_OID_CONTENT));
    scope.extend_from_slice(&cbor_uint(8));
    scope.extend_from_slice(&cbor_uint(1)); // authoritative-complete
    let ca_scope = {
        let mut m = cbor_map(7);
        m.extend_from_slice(&scope);
        m
    };

    // window = { 1: producedAt, 2: thisUpdateMin, 3: nextUpdateMin, 4: nextUpdateMax }
    let mut window = cbor_map(4);
    for (k, v) in [
        (1u64, CREATED_AT),
        (2, CREATED_AT),
        (3, WINDOW_NEXT_UPDATE_MIN),
        (4, WINDOW_NEXT_UPDATE_MAX),
    ] {
        window.extend_from_slice(&cbor_uint(k));
        window.extend_from_slice(&cbor_uint(v));
    }

    // integrity = { 1: indexDigest, 2: dataDigest }
    let mut integrity = cbor_map(2);
    integrity.extend_from_slice(&cbor_uint(1));
    integrity.extend_from_slice(&cbor_bstr(&index_digest));
    integrity.extend_from_slice(&cbor_uint(2));
    integrity.extend_from_slice(&cbor_bstr(&data_digest));

    // continuity = { 3: chain_length }  (no prev/base digests)
    let mut continuity = cbor_map(1);
    continuity.extend_from_slice(&cbor_uint(3));
    continuity.extend_from_slice(&cbor_uint(0));

    // Root map: keys 1..10.
    let mut m = cbor_map(10);
    m.extend_from_slice(&cbor_uint(1)); // 1: format_version
    m.extend_from_slice(&cbor_uint(1));
    m.extend_from_slice(&cbor_uint(2)); // 2: bundle_id
    m.extend_from_slice(&cbor_bstr(&spec.bundle_id));
    m.extend_from_slice(&cbor_uint(3)); // 3: producer_id
    m.extend_from_slice(&cbor_text(PRODUCER_ID));
    m.extend_from_slice(&cbor_uint(4)); // 4: created_at
    m.extend_from_slice(&cbor_uint(CREATED_AT));
    m.extend_from_slice(&cbor_uint(5)); // 5: bundle_type (0 = full)
    m.extend_from_slice(&cbor_uint(0));
    m.extend_from_slice(&cbor_uint(6)); // 6: ca_scopes
    m.extend_from_slice(&cbor_array(1));
    m.extend_from_slice(&ca_scope);
    m.extend_from_slice(&cbor_uint(7)); // 7: window
    m.extend_from_slice(&window);
    m.extend_from_slice(&cbor_uint(8)); // 8: integrity
    m.extend_from_slice(&integrity);
    m.extend_from_slice(&cbor_uint(9)); // 9: entry_count
    m.extend_from_slice(&cbor_uint(spec.entries.len() as u64));
    m.extend_from_slice(&cbor_uint(10)); // 10: continuity
    m.extend_from_slice(&continuity);
    m
}

/// Assemble the complete bundle file: header | manifest | seal | index | data.
fn build_bundle(spec: &BundleSpec, key: &SigningKey, cert_der: &[u8]) -> Vec<u8> {
    // Index records, sorted ascending by (entry_key, discriminator); data
    // payloads appended in sorted-record order.
    let mut entries = spec.entries.clone();
    entries.sort_by(|a, b| {
        a.entry_key
            .cmp(&b.entry_key)
            .then(a.discriminator.cmp(&b.discriminator))
    });

    let mut data_section = Vec::new();
    let mut index_records = Vec::new();
    for e in &entries {
        let offset = data_section.len() as u64;
        data_section.extend_from_slice(&e.payload);
        let mut rec = Vec::with_capacity(48);
        rec.extend_from_slice(&e.entry_key);
        put_u64(&mut rec, offset);
        put_u32(&mut rec, e.payload.len() as u32);
        put_u16(&mut rec, 0); // flags
        put_u16(&mut rec, e.discriminator);
        assert_eq!(rec.len(), 48);
        index_records.push(rec);
    }
    let index_section = index_records.concat();
    let index_digest = sha256(&index_section);
    let data_digest = sha256(&data_section);

    let manifest_bytes = encode_manifest(spec, index_digest, data_digest);
    let seal_bytes = build_seal(&manifest_bytes, key, cert_der);

    let manifest_offset = 64u64;
    let manifest_length = manifest_bytes.len() as u64;
    let seal_offset = manifest_offset + manifest_length;
    let seal_length = seal_bytes.len() as u64;
    let index_offset = seal_offset + seal_length;
    let index_length = index_section.len() as u64;
    let data_offset = index_offset + index_length;
    let data_length = data_section.len() as u64;

    let mut header = Vec::with_capacity(64);
    header.extend_from_slice(b"AHU1");
    put_u16(&mut header, 0); // format_major
    put_u16(&mut header, 1); // format_minor
    put_u64(&mut header, manifest_offset);
    put_u32(&mut header, manifest_length as u32);
    put_u64(&mut header, seal_offset);
    put_u32(&mut header, seal_length as u32);
    put_u64(&mut header, index_offset);
    put_u64(&mut header, index_length);
    put_u64(&mut header, data_offset);
    put_u64(&mut header, data_length);
    assert_eq!(header.len(), 64);

    let mut out = header;
    out.extend_from_slice(&manifest_bytes);
    out.extend_from_slice(&seal_bytes);
    out.extend_from_slice(&index_section);
    out.extend_from_slice(&data_section);
    out
}

fn uuid_string(b: &[u8; 16]) -> String {
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn main() {
    let key =
        SigningKey::from_bytes((&SEAL_KEY_SEED).into()).expect("fixed scalar is a valid P-256 key");
    let cert_der = build_seal_cert(&key);

    let minimal = BundleSpec {
        bundle_id: [
            0x01, 0x93, 0x9f, 0x6e, 0xb0, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ],
        entries: vec![Entry {
            entry_key: sha256(b"wire-profile-0.1/minimal/certid"),
            discriminator: 0,
            payload: b"wire-profile-0.1/minimal/response".to_vec(),
        }],
    };

    let dual = BundleSpec {
        bundle_id: [
            0x01, 0x93, 0x9f, 0x6e, 0xb0, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ],
        entries: vec![
            Entry {
                entry_key: sha256(b"wire-profile-0.1/dual/certid"),
                discriminator: 0,
                payload: b"wire-profile-0.1/dual/response/ecdsa".to_vec(),
            },
            Entry {
                entry_key: sha256(b"wire-profile-0.1/dual/certid"),
                discriminator: 4,
                payload: b"wire-profile-0.1/dual/response/mldsa87".to_vec(),
            },
        ],
    };

    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    for (name, spec) in [
        ("minimal-full.ahu", &minimal),
        ("dual-algorithm.ahu", &dual),
    ] {
        let bytes = build_bundle(spec, &key, &cert_der);
        std::fs::write(out_dir.join(name), &bytes).expect("write fixture");

        let header = &bytes[..64];
        let manifest_len = u32::from_be_bytes(header[16..20].try_into().unwrap()) as usize;
        let seal_off = u64::from_be_bytes(header[20..28].try_into().unwrap()) as usize;
        let seal_len = u32::from_be_bytes(header[28..32].try_into().unwrap()) as usize;
        let index_off = u64::from_be_bytes(header[32..40].try_into().unwrap()) as usize;
        let index_len = u64::from_be_bytes(header[40..48].try_into().unwrap()) as usize;
        let data_off = u64::from_be_bytes(header[48..56].try_into().unwrap()) as usize;

        println!("=== {name} ===");
        println!("file sha256      : {}", hex::encode(sha256(&bytes)));
        println!("size             : {}", bytes.len());
        println!("bundle_id        : {}", uuid_string(&spec.bundle_id));
        println!("producer_id      : {PRODUCER_ID}");
        println!("created_at       : {CREATED_AT}");
        println!("format_version   : 1  (header 0.1)");
        println!("manifest offset  : 64  length: {manifest_len}");
        println!(
            "manifest sha256  : {}",
            hex::encode(sha256(&bytes[64..64 + manifest_len]))
        );
        println!("seal offset      : {seal_off}  length: {seal_len}");
        println!(
            "seal sha256      : {}",
            hex::encode(sha256(&bytes[seal_off..seal_off + seal_len]))
        );
        println!(
            "index offset     : {index_off}  length: {index_len} ({} records)",
            index_len / 48
        );
        println!(
            "data offset      : {data_off}  length: {}",
            bytes.len() - data_off
        );
        for (i, e) in spec.entries.iter().enumerate() {
            println!(
                "record[{i}]        : key {} disc {} offset {} len {} flags 0x0000",
                hex::encode(e.entry_key),
                e.discriminator,
                if i == 0 {
                    0
                } else {
                    spec.entries[0].payload.len()
                },
                e.payload.len()
            );
            println!(
                "  payload         : {}",
                String::from_utf8_lossy(&e.payload)
            );
        }
        println!();
    }
    std::fs::write(out_dir.join("seal-cert.der"), &cert_der).expect("write seal cert");
    println!("=== seal-cert.der ===");
    println!("sha256           : {}", hex::encode(sha256(&cert_der)));
    println!("subject/issuer   : CN={SEAL_CERT_CN}");
    println!("serial           : {SEAL_CERT_SERIAL}");
    println!(
        "not_before       : {SEAL_CERT_NOT_BEFORE} ({})",
        utc_time(SEAL_CERT_NOT_BEFORE)
    );
    println!(
        "not_after        : {SEAL_CERT_NOT_AFTER} ({})",
        utc_time(SEAL_CERT_NOT_AFTER)
    );
    println!(
        "fixed test time  : {FIXED_TEST_TIME} ({})",
        utc_time(FIXED_TEST_TIME)
    );
    let pub_sec1 = p256::ecdsa::VerifyingKey::from(&key)
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    println!("seal public key (SEC1): {}", hex::encode(pub_sec1));
}
