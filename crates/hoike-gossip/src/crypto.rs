//! Ed25519 message authentication for gossip broadcasts (design §6.3, FPT_ITT.1).
//!
//! SWIM membership traffic (foca's postcard-coded pings/acks) is left alone; this
//! layer wraps only the `GossipMessage` *custom broadcasts* — the payloads that
//! announce new signed artifacts and drive bundle propagation. Those are the
//! messages that carry a trust decision ("epoch N exists for this scope"), so
//! those are the ones that must be attributable to a known fleet member.
//!
//! ## Wire framing
//!
//! A signed broadcast is `[TAG][64-byte Ed25519 signature over payload][payload]`
//! where `payload` is the exact JSON `GossipMessage` bytes an unsigned node would
//! emit. Legacy (unsigned) payloads are raw JSON and therefore always begin with
//! `{` (0x7B); the [`SIGNED_TAG`] byte (0x01) can never collide with that, so a
//! receiver can tell signed from unsigned without a version handshake. The
//! signature travels with the message, so a relaying node re-broadcasts the
//! *original signer's* signature — every hop verifies the origin, not the last
//! hop.
//!
//! ## Rollout policy
//!
//! Encoded entirely by the two config fields already present on the gossip
//! section, with no third flag:
//!
//! * `identity_key` set  → this node **signs** every outbound broadcast.
//! * `peer_keys` empty   → [`VerifyPolicy::Permissive`]: accept unsigned legacy
//!   messages (a signed-but-invalid message is still dropped). This is the first
//!   phase of a rolling upgrade — everyone starts signing while the fleet still
//!   contains nodes that don't.
//! * `peer_keys` populated → [`VerifyPolicy::Required`]: drop anything without a
//!   valid signature from a trusted key. This is the enforced end state.

use std::fs;
use std::path::Path;

use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Wire tag for a signed broadcast frame. Chosen so it can never collide with a
/// legacy raw-JSON payload, which always starts with `{` (0x7B).
pub const SIGNED_TAG: u8 = 0x01;
const SIG_LEN: usize = 64;

/// Error loading an Ed25519 gossip key.
#[derive(Debug)]
pub enum GossipCryptoError {
    Io(std::io::Error),
    Decode(String),
}

impl std::fmt::Display for GossipCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GossipCryptoError::Io(e) => write!(f, "gossip key I/O: {e}"),
            GossipCryptoError::Decode(m) => write!(f, "gossip key decode: {m}"),
        }
    }
}

impl std::error::Error for GossipCryptoError {}

impl From<std::io::Error> for GossipCryptoError {
    fn from(e: std::io::Error) -> Self {
        GossipCryptoError::Io(e)
    }
}

/// Load an Ed25519 PKCS#8 private key. Accepts PEM (`-----BEGIN PRIVATE KEY-----`)
/// or raw DER, chosen by sniffing for the PEM armor.
pub fn load_signing_key(path: &Path) -> Result<SigningKey, GossipCryptoError> {
    let bytes = fs::read(path)?;
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if text.contains("-----BEGIN") {
            return SigningKey::from_pkcs8_pem(text)
                .map_err(|e| GossipCryptoError::Decode(format!("PKCS#8 PEM: {e}")));
        }
    }
    SigningKey::from_pkcs8_der(&bytes)
        .map_err(|e| GossipCryptoError::Decode(format!("PKCS#8 DER: {e}")))
}

/// Load an Ed25519 SPKI public key. Accepts PEM (`-----BEGIN PUBLIC KEY-----`)
/// or raw DER.
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey, GossipCryptoError> {
    let bytes = fs::read(path)?;
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if text.contains("-----BEGIN") {
            return VerifyingKey::from_public_key_pem(text)
                .map_err(|e| GossipCryptoError::Decode(format!("SPKI PEM: {e}")));
        }
    }
    VerifyingKey::from_public_key_der(&bytes)
        .map_err(|e| GossipCryptoError::Decode(format!("SPKI DER: {e}")))
}

/// Signs outbound gossip broadcasts with this node's identity key.
pub struct GossipSigner {
    key: SigningKey,
}

impl GossipSigner {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }

    /// This signer's public half — folded into the local verifier's trusted set
    /// so a node accepts its own broadcasts echoed back through the mesh.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Wrap a raw JSON payload in a signed frame: `[TAG][sig][payload]`.
    pub fn frame(&self, payload: &[u8]) -> Vec<u8> {
        let sig = self.key.sign(payload);
        let mut out = Vec::with_capacity(1 + SIG_LEN + payload.len());
        out.push(SIGNED_TAG);
        out.extend_from_slice(&sig.to_bytes());
        out.extend_from_slice(payload);
        out
    }
}

/// Inbound verification stance — see the module-level rollout policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VerifyPolicy {
    /// Accept unsigned (legacy) messages; a signed-but-invalid message is still
    /// dropped. Used while the fleet still contains unsigned nodes.
    Permissive,
    /// Drop anything without a valid signature from a trusted key.
    Required,
}

/// Result of checking an inbound broadcast frame.
pub enum VerifyOutcome<'a> {
    /// The inner JSON payload to decode (signature verified, or unsigned under a
    /// permissive policy).
    Accept(&'a [u8]),
    /// Drop the message; the reason is a static string for logging.
    Reject(&'static str),
}

/// Verifies inbound gossip broadcasts against a set of trusted Ed25519 keys.
pub struct GossipVerifier {
    trusted: Vec<VerifyingKey>,
    policy: VerifyPolicy,
}

impl GossipVerifier {
    pub fn new(trusted: Vec<VerifyingKey>, policy: VerifyPolicy) -> Self {
        Self { trusted, policy }
    }

    pub fn policy(&self) -> VerifyPolicy {
        self.policy
    }

    /// Classify a raw broadcast frame, returning the payload to decode or a drop
    /// reason. A signed frame (leading [`SIGNED_TAG`]) must verify against a
    /// trusted key regardless of policy; an unsigned frame is admitted only when
    /// the policy is [`VerifyPolicy::Permissive`].
    pub fn check<'a>(&self, data: &'a [u8]) -> VerifyOutcome<'a> {
        match data.first() {
            Some(&SIGNED_TAG) => {
                if data.len() < 1 + SIG_LEN {
                    return VerifyOutcome::Reject("truncated signed frame");
                }
                let sig_arr: [u8; SIG_LEN] = match data[1..1 + SIG_LEN].try_into() {
                    Ok(a) => a,
                    Err(_) => return VerifyOutcome::Reject("bad signature length"),
                };
                let sig = Signature::from_bytes(&sig_arr);
                let payload = &data[1 + SIG_LEN..];
                let ok = self.trusted.iter().any(|k| k.verify(payload, &sig).is_ok());
                if ok {
                    VerifyOutcome::Accept(payload)
                } else {
                    VerifyOutcome::Reject("no trusted key verified signature")
                }
            }
            // Legacy / unsigned raw JSON (or empty).
            _ => match self.policy {
                VerifyPolicy::Permissive => VerifyOutcome::Accept(data),
                VerifyPolicy::Required => {
                    VerifyOutcome::Reject("unsigned message under required-auth policy")
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn signed_frame_round_trips_and_verifies() {
        let signer = GossipSigner::new(test_key(1));
        let verifier = GossipVerifier::new(vec![signer.verifying_key()], VerifyPolicy::Required);

        let payload = br#"{"GenerationAnnouncement":{"epoch":7}}"#;
        let framed = signer.frame(payload);
        assert_eq!(framed[0], SIGNED_TAG);

        match verifier.check(&framed) {
            VerifyOutcome::Accept(p) => assert_eq!(p, payload),
            VerifyOutcome::Reject(r) => panic!("expected accept, got reject: {r}"),
        }
    }

    #[test]
    fn required_policy_drops_forged_signature() {
        // Framed by an attacker key the verifier does not trust.
        let attacker = GossipSigner::new(test_key(9));
        let trusted =
            GossipVerifier::new(vec![test_key(1).verifying_key()], VerifyPolicy::Required);
        let framed = attacker.frame(br#"{"UrgentRevocation":{"epoch":1}}"#);
        assert!(matches!(
            trusted.check(&framed),
            VerifyOutcome::Reject("no trusted key verified signature")
        ));
    }

    #[test]
    fn required_policy_drops_tampered_payload() {
        let signer = GossipSigner::new(test_key(1));
        let verifier = GossipVerifier::new(vec![signer.verifying_key()], VerifyPolicy::Required);
        let mut framed = signer.frame(br#"{"epoch":1}"#);
        // Flip a byte in the payload region (after tag + signature).
        let last = framed.len() - 1;
        framed[last] ^= 0xFF;
        assert!(matches!(verifier.check(&framed), VerifyOutcome::Reject(_)));
    }

    #[test]
    fn required_policy_drops_unsigned_legacy() {
        let verifier =
            GossipVerifier::new(vec![test_key(1).verifying_key()], VerifyPolicy::Required);
        let legacy = br#"{"GenerationAnnouncement":{"epoch":7}}"#;
        assert!(matches!(
            verifier.check(legacy),
            VerifyOutcome::Reject("unsigned message under required-auth policy")
        ));
    }

    #[test]
    fn permissive_policy_accepts_unsigned_legacy() {
        // Empty trusted set + permissive == today's behavior during rollout.
        let verifier = GossipVerifier::new(vec![], VerifyPolicy::Permissive);
        let legacy = br#"{"GenerationAnnouncement":{"epoch":7}}"#;
        match verifier.check(legacy) {
            VerifyOutcome::Accept(p) => assert_eq!(p, legacy),
            VerifyOutcome::Reject(r) => panic!("permissive must accept legacy: {r}"),
        }
    }

    #[test]
    fn permissive_policy_still_drops_forged_signed() {
        // Even permissive nodes must not honor a signed message from an untrusted
        // key — otherwise signing would be worse than useless during rollout.
        let attacker = GossipSigner::new(test_key(9));
        let verifier =
            GossipVerifier::new(vec![test_key(1).verifying_key()], VerifyPolicy::Permissive);
        let framed = attacker.frame(br#"{"epoch":1}"#);
        assert!(matches!(verifier.check(&framed), VerifyOutcome::Reject(_)));
    }

    #[test]
    fn truncated_signed_frame_rejected() {
        let verifier = GossipVerifier::new(vec![], VerifyPolicy::Permissive);
        // Tag present but no room for a full signature.
        let truncated = [SIGNED_TAG, 0x00, 0x01, 0x02];
        assert!(matches!(
            verifier.check(&truncated),
            VerifyOutcome::Reject("truncated signed frame")
        ));
    }
}
