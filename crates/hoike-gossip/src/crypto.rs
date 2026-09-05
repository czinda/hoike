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
//! `identity_key` signs outbound messages. `peer_identities` binds each trusted
//! key to its node name; a nonempty mapping requires authenticated broadcasts.
//! An empty mapping retains unsigned rollout compatibility. Legacy `peer_keys`
//! is rejected at startup because a key list cannot authorize node identities.

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
    identities: Vec<(String, VerifyingKey)>,
}

impl GossipVerifier {
    #[cfg(test)]
    pub(crate) fn new(trusted: Vec<VerifyingKey>, policy: VerifyPolicy) -> Self {
        Self {
            trusted,
            policy,
            identities: Vec::new(),
        }
    }

    /// Bind a verified key to the origin claimed in the signed payload.
    pub fn for_identities(identities: Vec<(String, VerifyingKey)>, policy: VerifyPolicy) -> Self {
        Self {
            trusted: identities.iter().map(|(_, key)| *key).collect(),
            policy,
            identities,
        }
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
                    if !self.identities.is_empty() {
                        let Ok(msg) =
                            serde_json::from_slice::<crate::broadcast::GossipMessage>(payload)
                        else {
                            return VerifyOutcome::Reject("invalid signed message");
                        };
                        if !self.identities.iter().any(|(name, key)| {
                            name == msg.origin_node() && key.verify_strict(payload, &sig).is_ok()
                        }) {
                            return VerifyOutcome::Reject("signing key not authorized for origin");
                        }
                    }
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

/// Strip a signed frame's tag + signature *without verifying it*, returning the
/// inner JSON payload; pass any unsigned/raw payload through unchanged.
///
/// This is the decode path for a node that has opted out of verification
/// entirely (`verifier: None` — neither an `identity_key` nor `peer_keys`
/// configured). Such a node must still understand the signed wire format enough
/// to reach the inner payload, or it would fail to decode *every* framed
/// broadcast a signing peer emits during a rolling upgrade — exactly the
/// "mixed fleet stays interoperable" property the [`SIGNED_TAG`] framing is
/// meant to provide. Accepting the unverified payload is no weaker than the
/// unsigned messages this node already accepts (an attacker could send the same
/// bytes unsigned), so it opens no new attack surface. A node that wants
/// authentication configures `peer_keys` and gets a real [`GossipVerifier`]
/// instead of this pass-through.
pub fn unwrap_frame(data: &[u8]) -> &[u8] {
    if data.first() == Some(&SIGNED_TAG) && data.len() > SIG_LEN {
        &data[1 + SIG_LEN..]
    } else {
        data
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
    fn authenticated_peer_cannot_claim_another_origin() {
        let signer = GossipSigner::new(test_key(1));
        let verifier = GossipVerifier::for_identities(
            vec![("node-a".into(), signer.verifying_key())],
            VerifyPolicy::Required,
        );
        let message = |origin: &str| {
            serde_json::to_vec(&crate::broadcast::GossipMessage::UrgentRevocation {
                producer_id: "p".into(),
                issuer_key_hash: vec![1; 32],
                epoch: 1,
                origin_node: origin.into(),
            })
            .unwrap()
        };
        assert!(matches!(
            verifier.check(&signer.frame(&message("node-a"))),
            VerifyOutcome::Accept(_)
        ));
        for origin in ["node-b", ""] {
            assert!(matches!(
                verifier.check(&signer.frame(&message(origin))),
                VerifyOutcome::Reject(_)
            ));
        }
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
