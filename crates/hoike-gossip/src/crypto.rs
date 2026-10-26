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
//! `gossip.auth_mode` selects the inbound policy explicitly. `required`
//! (default) needs a local `identity_key`, trusts the named origins in
//! `peer_identities` (a single-node deployment may trust only its own key),
//! and drops unsigned, unknown, and forged broadcasts. `permissive` is the
//! documented rollout mode: it accepts unsigned legacy broadcasts while the
//! fleet still contains unsigned nodes, but verifies every signed frame
//! against the provisioned identities — an unknown or forged signature is
//! rejected in both modes, including when no identities are provisioned at
//! all. Legacy `peer_keys` is rejected at startup because a key list cannot
//! authorize node identities.

use std::fs;
use std::path::Path;

use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
#[cfg(test)]
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::config::{AuthMode, GossipConfig};

/// Wire tag for a signed broadcast frame. Chosen so it can never collide with a
/// legacy raw-JSON payload, which always starts with `{` (0x7B).
pub const SIGNED_TAG: u8 = 0x01;
const SIG_LEN: usize = 64;

/// Error loading or configuring gossip authentication.
#[derive(Debug)]
pub enum GossipCryptoError {
    Io(std::io::Error),
    Decode(String),
    /// Invalid authentication policy or identity configuration (F09): the
    /// string names what an operator must fix, and callers treat it as a
    /// fatal startup/check failure.
    Config(String),
}

impl std::fmt::Display for GossipCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GossipCryptoError::Io(e) => write!(f, "gossip key I/O: {e}"),
            GossipCryptoError::Decode(m) => write!(f, "gossip key decode: {m}"),
            GossipCryptoError::Config(m) => write!(f, "gossip authentication config: {m}"),
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

/// Result of checking an inbound broadcast frame.
pub enum VerifyOutcome<'a> {
    /// The inner JSON payload to decode (signature verified, or unsigned under a
    /// permissive policy).
    Accept(&'a [u8]),
    /// Drop the message; the reason is a static string for logging.
    Reject(&'static str),
}

/// Verifies inbound gossip broadcasts against a set of trusted Ed25519 keys
/// bound to node names, under the explicit [`AuthMode`] policy.
pub struct GossipVerifier {
    trusted: Vec<VerifyingKey>,
    mode: AuthMode,
    identities: Vec<(String, VerifyingKey)>,
}

impl GossipVerifier {
    #[cfg(test)]
    pub(crate) fn new(trusted: Vec<VerifyingKey>, mode: AuthMode) -> Self {
        Self {
            trusted,
            mode,
            identities: Vec::new(),
        }
    }

    /// Bind each verified key to the origin claimed in the signed payload.
    pub fn for_identities(identities: Vec<(String, VerifyingKey)>, mode: AuthMode) -> Self {
        Self {
            trusted: identities.iter().map(|(_, key)| *key).collect(),
            mode,
            identities,
        }
    }

    /// The explicit inbound policy this verifier enforces.
    pub fn auth_mode(&self) -> AuthMode {
        self.mode
    }

    /// Classify a raw broadcast frame, returning the payload to decode or a drop
    /// reason. A signed frame (leading [`SIGNED_TAG`]) must verify against a
    /// trusted key regardless of policy; an unsigned frame is admitted only when
    /// the policy is [`AuthMode::Permissive`].
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
            _ => match self.mode {
                AuthMode::Permissive => VerifyOutcome::Accept(data),
                AuthMode::Required => {
                    VerifyOutcome::Reject("unsigned message under required-auth policy")
                }
            },
        }
    }
}

/// Load the authentication material implied by `config`: the outbound signer
/// (when an `identity_key` is configured) and the always-present inbound
/// verifier for the configured [`AuthMode`] (F09).
///
/// This is the single policy-loading path shared by `GossipNode::start` and
/// `hoike check`, so both decide the effective policy identically. Failures
/// are fatal configuration errors, never a fallback to unauthenticated
/// operation:
///
/// - a nonempty legacy `peer_keys` list (cannot authorize node identities);
/// - `required` mode without a local `identity_key`;
/// - unreadable or invalid key material;
/// - a `peer_identities` mapping for the local node name that disagrees with
///   the local `identity_key` (ambiguous attribution).
///
/// Disabled gossip never calls this, so a disabled section needs no key
/// material. In permissive mode a node without an `identity_key` still gets a
/// verifier: unsigned input is accepted, but signed input is held to the
/// provisioned identities — an empty trusted set rejects every signature.
pub fn load_authentication(
    config: &GossipConfig,
) -> Result<(Option<GossipSigner>, GossipVerifier), GossipCryptoError> {
    if !config.peer_keys.is_empty() {
        return Err(GossipCryptoError::Config(
            "gossip.peer_keys is no longer safe: migrate to gossip.peer_identities \
             (node name -> public key path)"
                .into(),
        ));
    }

    let signer = match &config.identity_key {
        Some(path) => {
            let key = load_signing_key(path).map_err(|e| {
                GossipCryptoError::Config(format!("gossip.identity_key {}: {e}", path.display()))
            })?;
            Some(GossipSigner::new(key))
        }
        None => None,
    };

    if config.auth_mode == AuthMode::Required && signer.is_none() {
        return Err(GossipCryptoError::Config(format!(
            "gossip auth_mode \"required\" needs gossip.identity_key for node '{}'",
            config.node_name
        )));
    }

    let mut identities: Vec<(String, VerifyingKey)> = Vec::new();
    for (name, path) in &config.peer_identities {
        if name.is_empty() || name.len() > 256 {
            return Err(GossipCryptoError::Config(
                "gossip peer identity names must contain 1..=256 bytes".into(),
            ));
        }
        let key = load_verifying_key(path).map_err(|e| {
            GossipCryptoError::Config(format!(
                "gossip.peer_identities '{name}' ({}): {e}",
                path.display()
            ))
        })?;
        // A mapping for the local node name must agree with the local
        // identity key, or origin attribution for this node's own name is
        // ambiguous.
        if name == &config.node_name {
            match &signer {
                Some(s) if s.verifying_key() != key => {
                    return Err(GossipCryptoError::Config(format!(
                        "gossip.peer_identities maps local node '{}' to a different key than \
                         gossip.identity_key",
                        config.node_name
                    )));
                }
                _ => {}
            }
        }
        identities.push((name.clone(), key));
    }
    // Fold the local identity in (it is always authorized for its own name);
    // skip when an identical self-mapping is already present. Nested ifs, not
    // a let-chain: the workspace floor is Rust 1.85, which cannot parse
    // edition-2024 let-chains.
    if let Some(s) = &signer {
        if !identities
            .iter()
            .any(|(name, key)| name == &config.node_name && *key == s.verifying_key())
        {
            identities.push((config.node_name.clone(), s.verifying_key()));
        }
    }

    Ok((
        signer,
        GossipVerifier::for_identities(identities, config.auth_mode),
    ))
}

/// Write a synthetic Ed25519 identity (PKCS#8 private + SPKI public PEM)
/// into `dir`; returns the signing key and both file paths.
#[cfg(test)]
pub(crate) fn write_test_identity(
    dir: &std::path::Path,
    name: &str,
    seed: u8,
) -> (SigningKey, std::path::PathBuf, std::path::PathBuf) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let priv_path = dir.join(format!("{name}.ed25519.p8"));
    let priv_pem = key.to_pkcs8_pem(Default::default()).unwrap();
    fs::write(&priv_path, priv_pem.as_str()).unwrap();
    let pub_path = dir.join(format!("{name}.ed25519.pub.pem"));
    let pub_pem = key
        .verifying_key()
        .to_public_key_pem(Default::default())
        .unwrap();
    fs::write(&pub_path, pub_pem).unwrap();
    (key, priv_path, pub_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthMode, GossipConfig};
    use ed25519_dalek::SigningKey;

    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// A gossip config with explicit auth mode, optional local identity, and
    /// named peer mappings — the surface `load_authentication` consumes.
    fn auth_config(
        node_name: &str,
        mode: AuthMode,
        identity: Option<&std::path::Path>,
        peers: &[(&str, &std::path::Path)],
    ) -> GossipConfig {
        GossipConfig {
            enabled: true,
            bind: "127.0.0.1:0".into(),
            seeds: vec![],
            node_name: node_name.into(),
            auth_mode: mode,
            identity_key: identity.map(std::path::Path::to_path_buf),
            peer_keys: vec![],
            peer_identities: peers
                .iter()
                .map(|(name, path)| ((*name).to_string(), path.to_path_buf()))
                .collect(),
        }
    }

    /// A serializable broadcast payload claiming `origin`.
    fn broadcast(origin: &str) -> Vec<u8> {
        serde_json::to_vec(&crate::broadcast::GossipMessage::UrgentRevocation {
            producer_id: "producer".into(),
            issuer_key_hash: vec![1; 32],
            epoch: 1,
            origin_node: origin.into(),
        })
        .unwrap()
    }

    #[test]
    fn authenticated_peer_cannot_claim_another_origin() {
        let signer = GossipSigner::new(test_key(1));
        let verifier = GossipVerifier::for_identities(
            vec![("node-a".into(), signer.verifying_key())],
            AuthMode::Required,
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
        let verifier = GossipVerifier::new(vec![signer.verifying_key()], AuthMode::Required);

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
        let trusted = GossipVerifier::new(vec![test_key(1).verifying_key()], AuthMode::Required);
        let framed = attacker.frame(br#"{"UrgentRevocation":{"epoch":1}}"#);
        assert!(matches!(
            trusted.check(&framed),
            VerifyOutcome::Reject("no trusted key verified signature")
        ));
    }

    #[test]
    fn required_policy_drops_tampered_payload() {
        let signer = GossipSigner::new(test_key(1));
        let verifier = GossipVerifier::new(vec![signer.verifying_key()], AuthMode::Required);
        let mut framed = signer.frame(br#"{"epoch":1}"#);
        // Flip a byte in the payload region (after tag + signature).
        let last = framed.len() - 1;
        framed[last] ^= 0xFF;
        assert!(matches!(verifier.check(&framed), VerifyOutcome::Reject(_)));
    }

    #[test]
    fn required_policy_drops_unsigned_legacy() {
        let verifier = GossipVerifier::new(vec![test_key(1).verifying_key()], AuthMode::Required);
        let legacy = br#"{"GenerationAnnouncement":{"epoch":7}}"#;
        assert!(matches!(
            verifier.check(legacy),
            VerifyOutcome::Reject("unsigned message under required-auth policy")
        ));
    }

    #[test]
    fn permissive_policy_accepts_unsigned_legacy() {
        // Empty trusted set + permissive == today's behavior during rollout.
        let verifier = GossipVerifier::new(vec![], AuthMode::Permissive);
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
        let verifier = GossipVerifier::new(vec![test_key(1).verifying_key()], AuthMode::Permissive);
        let framed = attacker.frame(br#"{"epoch":1}"#);
        assert!(matches!(verifier.check(&framed), VerifyOutcome::Reject(_)));
    }

    #[test]
    fn truncated_signed_frame_rejected() {
        let verifier = GossipVerifier::new(vec![], AuthMode::Permissive);
        // Tag present but no room for a full signature.
        let truncated = [SIGNED_TAG, 0x00, 0x01, 0x02];
        assert!(matches!(
            verifier.check(&truncated),
            VerifyOutcome::Reject("truncated signed frame")
        ));
    }

    // ── F09: explicit auth_mode policy through load_authentication ──

    // Permissive rollout mode accepts unsigned legacy input and signed input
    // from provisioned identities, but never signed input from an
    // unprovisioned key.
    #[test]
    fn permissive_accepts_known_signed_and_unsigned_peers() {
        let dir = tempfile::tempdir().unwrap();
        let (_key_a, _, pub_a) = write_test_identity(dir.path(), "a", 1);
        let (_key_b, priv_b, pub_b) = write_test_identity(dir.path(), "b", 2);
        let (key_c, _, _) = write_test_identity(dir.path(), "c", 3);

        // node-b runs permissive with its own identity and both A/B mapped.
        let config = auth_config(
            "node-b",
            AuthMode::Permissive,
            Some(&priv_b),
            &[("node-a", &pub_a), ("node-b", &pub_b)],
        );
        let (signer, permissive) = load_authentication(&config).unwrap();
        let signer_b = signer.expect("permissive node keeps its outbound signer");

        let unsigned = broadcast("node-a");
        let b_signed = signer_b.frame(&broadcast("node-b"));
        let c_signed = GossipSigner::new(key_c).frame(&broadcast("node-c"));

        assert!(matches!(
            permissive.check(&b_signed),
            VerifyOutcome::Accept(_)
        ));
        assert!(matches!(
            permissive.check(&unsigned),
            VerifyOutcome::Accept(_)
        ));
        assert!(matches!(
            permissive.check(&c_signed),
            VerifyOutcome::Reject(_)
        ));
    }

    // Permissive does not degrade into accepting signed input: unknown
    // origins and forged attributions reject, including when the trusted set
    // is empty (no identities provisioned at all).
    #[test]
    fn permissive_rejects_unknown_and_forged_signed_frames() {
        let dir = tempfile::tempdir().unwrap();
        let (key_a, _, pub_a) = write_test_identity(dir.path(), "a", 1);
        let (_key_b, _, pub_b) = write_test_identity(dir.path(), "b", 2);
        let (key_c, _, _) = write_test_identity(dir.path(), "c", 3);

        let config = auth_config(
            "node-b",
            AuthMode::Permissive,
            None,
            &[("node-a", &pub_a), ("node-b", &pub_b)],
        );
        let (signer, permissive) = load_authentication(&config).unwrap();
        assert!(signer.is_none(), "no identity_key configured");

        let c_signer = GossipSigner::new(key_c);
        // Unknown origin: C signs claiming to be node-c, which no mapping
        // authorizes.
        let unknown = c_signer.frame(&broadcast("node-c"));
        // Forged attribution: C signs claiming to be node-b.
        let forged = c_signer.frame(&broadcast("node-b"));
        assert!(matches!(
            permissive.check(&unknown),
            VerifyOutcome::Reject(_)
        ));
        assert!(matches!(
            permissive.check(&forged),
            VerifyOutcome::Reject(_)
        ));

        // Control: a provisioned key with its mapped origin is accepted.
        let a_signer = GossipSigner::new(key_a);
        let known = a_signer.frame(&broadcast("node-a"));
        assert!(matches!(permissive.check(&known), VerifyOutcome::Accept(_)));

        // Repeat the unknown-signed rejection with an empty trusted set: a
        // node that provisioned nothing must not honor any signature.
        let empty = auth_config("node-b", AuthMode::Permissive, None, &[]);
        let (_, empty_verifier) = load_authentication(&empty).unwrap();
        assert!(matches!(
            empty_verifier.check(&unknown),
            VerifyOutcome::Reject(_)
        ));
        assert!(matches!(
            empty_verifier.check(&forged),
            VerifyOutcome::Reject(_)
        ));
    }

    // Required mode drops unsigned input, and a required configuration
    // without a local identity is a fatal configuration error rather than a
    // silently unauthenticated node.
    #[test]
    fn required_rejects_unsigned_and_missing_identity() {
        let dir = tempfile::tempdir().unwrap();
        let (_key_a, priv_a, pub_a) = write_test_identity(dir.path(), "a", 1);

        let config = auth_config(
            "node-a",
            AuthMode::Required,
            Some(&priv_a),
            &[("node-a", &pub_a)],
        );
        let (signer, required) = load_authentication(&config).unwrap();
        assert!(signer.is_some(), "single-node required trusts its own key");

        let unsigned = broadcast("node-a");
        assert!(matches!(
            required.check(&unsigned),
            VerifyOutcome::Reject(_)
        ));

        let missing = auth_config("node-a", AuthMode::Required, None, &[]);
        assert!(matches!(
            load_authentication(&missing),
            Err(GossipCryptoError::Config(_))
        ));
    }

    // A peer_identities mapping for the local node name that disagrees with
    // the local identity_key is ambiguous attribution — fatal, not merged.
    #[test]
    fn local_identity_conflict_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let (_key_a, _, pub_a) = write_test_identity(dir.path(), "a", 1);
        let (_key_b, priv_b, pub_b) = write_test_identity(dir.path(), "b", 2);

        let conflicting = auth_config(
            "node-b",
            AuthMode::Permissive,
            Some(&priv_b),
            &[("node-b", &pub_a)],
        );
        assert!(matches!(
            load_authentication(&conflicting),
            Err(GossipCryptoError::Config(_))
        ));

        // Mapping the local name to the local key is consistent.
        let consistent = auth_config(
            "node-b",
            AuthMode::Required,
            Some(&priv_b),
            &[("node-b", &pub_b), ("node-a", &pub_a)],
        );
        assert!(load_authentication(&consistent).is_ok());
    }
}
