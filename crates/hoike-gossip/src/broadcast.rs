use serde::{Deserialize, Serialize};
use std::fmt;

/// Gossip message payload carried as a foca custom broadcast.
///
/// These messages announce the *existence* of signed artifacts — they never
/// carry certificate status themselves. A node acts on a gossip message only
/// by fetching and validating a sealed bundle.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum GossipMessage {
    GenerationAnnouncement {
        producer_id: String,
        issuer_key_hash: Vec<u8>,
        epoch: u64,
        manifest_digest: [u8; 32],
        bundle_url: Option<String>,
        /// Name of the node that produced this announcement, so receivers can
        /// attribute the epoch to a specific fleet member and compute
        /// per-node staleness. Added after the initial wire format; `#[serde(default)]`
        /// keeps it backward-compatible — messages from older nodes decode with an
        /// empty origin (the JSON payload simply omits the field).
        #[serde(default)]
        origin_node: String,
    },
    UrgentRevocation {
        producer_id: String,
        issuer_key_hash: Vec<u8>,
        epoch: u64,
        /// See `GenerationAnnouncement::origin_node`.
        #[serde(default)]
        origin_node: String,
    },
}

impl GossipMessage {
    pub(crate) fn valid_bounds(&self) -> bool {
        let (producer, hash) = self.scope_key();
        !producer.is_empty()
            && producer.len() <= 256
            && self.origin_node().len() <= 256
            && matches!(hash.len(), 20 | 32)
            && match self {
                Self::GenerationAnnouncement {
                    bundle_url: Some(url),
                    ..
                } => url.len() <= 1024,
                _ => true,
            }
    }

    pub fn scope_key(&self) -> (&str, &[u8]) {
        match self {
            GossipMessage::GenerationAnnouncement {
                producer_id,
                issuer_key_hash,
                ..
            } => (producer_id, issuer_key_hash),
            GossipMessage::UrgentRevocation {
                producer_id,
                issuer_key_hash,
                ..
            } => (producer_id, issuer_key_hash),
        }
    }

    pub fn epoch(&self) -> u64 {
        match self {
            GossipMessage::GenerationAnnouncement { epoch, .. } => *epoch,
            GossipMessage::UrgentRevocation { epoch, .. } => *epoch,
        }
    }

    /// The announcing node's name, or `""` if the message came from an older
    /// node that predates the `origin_node` field.
    pub fn origin_node(&self) -> &str {
        match self {
            GossipMessage::GenerationAnnouncement { origin_node, .. } => origin_node,
            GossipMessage::UrgentRevocation { origin_node, .. } => origin_node,
        }
    }
}

impl fmt::Display for GossipMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GossipMessage::GenerationAnnouncement {
                producer_id,
                issuer_key_hash,
                epoch,
                ..
            } => write!(
                f,
                "GenerationAnnouncement(producer={}, ikh={}, epoch={})",
                producer_id,
                hex::encode(&issuer_key_hash[..8.min(issuer_key_hash.len())]),
                epoch
            ),
            GossipMessage::UrgentRevocation {
                producer_id,
                issuer_key_hash,
                epoch,
                ..
            } => write!(
                f,
                "UrgentRevocation(producer={}, ikh={}, epoch={})",
                producer_id,
                hex::encode(&issuer_key_hash[..8.min(issuer_key_hash.len())]),
                epoch
            ),
        }
    }
}

/// Broadcast key for foca's deduplication. Two broadcasts with the same
/// (producer_id, issuer_key_hash) scope where the newer one has a higher
/// epoch invalidate the older one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BroadcastKey {
    pub producer_id: String,
    pub issuer_key_hash: Vec<u8>,
    pub epoch: u64,
}

impl foca::Invalidates for BroadcastKey {
    fn invalidates(&self, other: &Self) -> bool {
        self.producer_id == other.producer_id
            && self.issuer_key_hash == other.issuer_key_hash
            && self.epoch > other.epoch
    }
}

/// BroadcastHandler that processes GossipMessage broadcasts.
pub struct HoikeBroadcastHandler {
    tx: tokio::sync::mpsc::Sender<GossipMessage>,
    /// Inbound message authentication (FPT_ITT.1). Always present: the
    /// authentication policy is explicit (`gossip.auth_mode`), so there is no
    /// verifier-less bypass. A permissive verifier is the documented rollout
    /// stance — it still rejects signed frames from unprovisioned keys.
    verifier: crate::crypto::GossipVerifier,
    admitted: std::collections::HashMap<(String, Vec<u8>), std::time::Instant>,
}

impl HoikeBroadcastHandler {
    pub fn new(
        tx: tokio::sync::mpsc::Sender<GossipMessage>,
        verifier: crate::crypto::GossipVerifier,
    ) -> Self {
        Self {
            tx,
            verifier,
            admitted: Default::default(),
        }
    }
}

#[derive(Debug)]
pub struct BroadcastError(String);

impl fmt::Display for BroadcastError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "broadcast error: {}", self.0)
    }
}

impl std::error::Error for BroadcastError {}

impl<T> foca::BroadcastHandler<T> for HoikeBroadcastHandler {
    type Key = BroadcastKey;
    type Error = BroadcastError;

    fn receive_item(
        &mut self,
        data: &[u8],
        _sender: Option<&T>,
    ) -> Result<Option<Self::Key>, Self::Error> {
        if data.len() > 2048 {
            return Ok(None);
        }
        // Authenticate before decoding. A dropped message returns `Ok(None)` so
        // foca neither stores nor re-broadcasts it — the forgery dies at this
        // hop. The verifier is always present; even permissive mode verifies
        // signed frames against the provisioned named identities.
        let payload: &[u8] = match self.verifier.check(data) {
            crate::crypto::VerifyOutcome::Accept(p) => p,
            crate::crypto::VerifyOutcome::Reject(reason) => {
                tracing::warn!(reason, "gossip message rejected (authentication)");
                return Ok(None);
            }
        };

        let msg: GossipMessage =
            serde_json::from_slice(payload).map_err(|e| BroadcastError(format!("decode: {e}")))?;

        if !msg.valid_bounds() {
            return Ok(None);
        }
        self.admitted
            .retain(|_, seen| seen.elapsed() < std::time::Duration::from_secs(3600));
        let scope = (msg.scope_key().0.to_string(), msg.scope_key().1.to_vec());
        if !self.admitted.contains_key(&scope) && self.admitted.len() >= 4096 {
            return Ok(None);
        }
        self.admitted.insert(scope, std::time::Instant::now());
        let key = BroadcastKey {
            producer_id: msg.scope_key().0.to_string(),
            issuer_key_hash: msg.scope_key().1.to_vec(),
            epoch: msg.epoch(),
        };

        if let Err(e) = self.tx.try_send(msg) {
            tracing::warn!(error = %e, "gossip message channel full — announcement may be lost");
        }

        Ok(Some(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_bounds_new_scopes_and_payloads() {
        use crate::config::AuthMode;
        use crate::crypto::GossipVerifier;
        use foca::BroadcastHandler;
        let (tx, _rx) = tokio::sync::mpsc::channel(8192);
        // Explicit permissive verifier: unsigned payloads admitted, so the
        // bounds/deduplication logic below is what is under test.
        let mut handler = HoikeBroadcastHandler::new(
            tx,
            GossipVerifier::for_identities(vec![], AuthMode::Permissive),
        );
        for n in 0..4100 {
            let msg = GossipMessage::UrgentRevocation {
                producer_id: format!("p{n}"),
                issuer_key_hash: vec![1; 32],
                epoch: 1,
                origin_node: "peer".into(),
            };
            let accepted = handler
                .receive_item(&serde_json::to_vec(&msg).unwrap(), None::<&()>)
                .unwrap()
                .is_some();
            assert_eq!(accepted, n < 4096);
        }
        assert!(
            handler
                .receive_item(&vec![0; 2049], None::<&()>)
                .unwrap()
                .is_none()
        );
        assert_eq!(handler.admitted.len(), 4096);
    }

    #[test]
    fn gossip_message_serialization_round_trip() {
        let msg = GossipMessage::GenerationAnnouncement {
            producer_id: "signer-a".into(),
            issuer_key_hash: vec![0xAA; 32],
            epoch: 42,
            manifest_digest: [0xBB; 32],
            bundle_url: Some("https://signer-a.example/ahu/latest.ahu".into()),
            origin_node: "edge-1".into(),
        };

        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: GossipMessage = serde_json::from_slice(&json).unwrap();
        assert_eq!(msg, decoded);
        assert_eq!(decoded.origin_node(), "edge-1");

        let msg2 = GossipMessage::UrgentRevocation {
            producer_id: "signer-b".into(),
            issuer_key_hash: vec![0xCC; 32],
            epoch: 100,
            origin_node: "signer-b".into(),
        };
        let json2 = serde_json::to_vec(&msg2).unwrap();
        let decoded2: GossipMessage = serde_json::from_slice(&json2).unwrap();
        assert_eq!(msg2, decoded2);
    }

    // A node running the pre-`origin_node` wire format emits JSON without that
    // field. `#[serde(default)]` must let a new node decode it (empty origin)
    // rather than rejecting the message — otherwise a mixed fleet partitions
    // during a rolling upgrade.
    #[test]
    fn legacy_announcement_without_origin_node_decodes() {
        let legacy = serde_json::json!({
            "GenerationAnnouncement": {
                "producer_id": "signer-a",
                "issuer_key_hash": [1, 2, 3],
                "epoch": 7,
                "manifest_digest": vec![0u8; 32],
                "bundle_url": null
            }
        });
        let decoded: GossipMessage = serde_json::from_value(legacy).unwrap();
        assert_eq!(decoded.epoch(), 7);
        assert_eq!(decoded.origin_node(), "", "missing origin decodes to empty");
    }

    // The authentication integration point: a verifier-equipped handler must
    // admit a validly signed broadcast (onto the channel + re-broadcast) and
    // silently drop a forged one — foca sees `Ok(None)` so nothing propagates.
    #[test]
    fn handler_drops_forged_and_admits_signed() {
        use crate::config::AuthMode;
        use crate::crypto::{GossipSigner, GossipVerifier};
        use ed25519_dalek::SigningKey;
        use foca::BroadcastHandler;

        let trusted_key = SigningKey::from_bytes(&[1u8; 32]);
        let signer = GossipSigner::new(trusted_key.clone());
        let verifier = GossipVerifier::new(vec![trusted_key.verifying_key()], AuthMode::Required);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<GossipMessage>(4);
        let mut handler = HoikeBroadcastHandler::new(tx, verifier);

        let msg = GossipMessage::GenerationAnnouncement {
            producer_id: "signer-a".into(),
            issuer_key_hash: vec![0xAA; 32],
            epoch: 9,
            manifest_digest: [0u8; 32],
            bundle_url: None,
            origin_node: "node-a".into(),
        };
        let payload = serde_json::to_vec(&msg).unwrap();

        // Valid signature → accepted (returns a broadcast key, lands on channel).
        let good = signer.frame(&payload);
        let key = handler
            .receive_item(&good, None::<&()>)
            .expect("no decode error");
        assert!(key.is_some(), "valid signed message must be accepted");
        assert_eq!(rx.try_recv().unwrap().epoch(), 9);

        // Forged by an untrusted key → dropped (Ok(None), nothing on channel).
        let attacker = GossipSigner::new(SigningKey::from_bytes(&[9u8; 32]));
        let forged = attacker.frame(&payload);
        let key = handler
            .receive_item(&forged, None::<&()>)
            .expect("drop is not a decode error");
        assert!(key.is_none(), "forged message must be dropped");
        assert!(
            rx.try_recv().is_err(),
            "nothing forwarded for forged message"
        );

        // Unsigned legacy under Required policy → dropped too.
        let key = handler
            .receive_item(&payload, None::<&()>)
            .expect("drop is not a decode error");
        assert!(
            key.is_none(),
            "unsigned message dropped under Required policy"
        );
        assert!(rx.try_recv().is_err());
    }

    // The mixed-fleet property that survives F09: a permissive node that has
    // provisioned a signing peer's key decodes that peer's signed frames and
    // the same peer's legacy unsigned frames — that is the provision →
    // permissive → sign rollout window. There is no keyless bypass anymore:
    // permissive nodes that did NOT provision the signer reject its frames.
    #[test]
    fn permissive_handler_decodes_signed_and_unsigned_from_provisioned_peer() {
        use crate::config::AuthMode;
        use crate::crypto::{GossipSigner, GossipVerifier};
        use ed25519_dalek::SigningKey;
        use foca::BroadcastHandler;

        let peer_key = SigningKey::from_bytes(&[7u8; 32]);
        let signer = GossipSigner::new(peer_key.clone());
        let verifier = GossipVerifier::for_identities(
            vec![("node-a".into(), peer_key.verifying_key())],
            AuthMode::Permissive,
        );

        let (tx, mut rx) = tokio::sync::mpsc::channel::<GossipMessage>(4);
        let mut handler = HoikeBroadcastHandler::new(tx, verifier);

        let msg = GossipMessage::GenerationAnnouncement {
            producer_id: "signer-a".into(),
            issuer_key_hash: vec![0xAA; 32],
            epoch: 11,
            manifest_digest: [0u8; 32],
            bundle_url: None,
            origin_node: "node-a".into(),
        };
        let payload = serde_json::to_vec(&msg).unwrap();

        // Signed frame from the provisioned peer → verified and admitted.
        let framed = signer.frame(&payload);
        let key = handler
            .receive_item(&framed, None::<&()>)
            .expect("permissive node must decode a provisioned peer's frame");
        assert!(key.is_some());
        assert_eq!(rx.try_recv().unwrap().epoch(), 11);

        // Plain unsigned payload from the same peer → still admitted.
        let key = handler
            .receive_item(&payload, None::<&()>)
            .expect("permissive node decodes unsigned too");
        assert!(key.is_some());
        assert_eq!(rx.try_recv().unwrap().epoch(), 11);

        // A signed frame from a key this node never provisioned is dropped:
        // permissive is not a no-auth bypass for signed input.
        let unprovisioned = GossipSigner::new(SigningKey::from_bytes(&[9u8; 32]));
        let forged = unprovisioned.frame(&payload);
        let key = handler
            .receive_item(&forged, None::<&()>)
            .expect("drop is not a decode error");
        assert!(key.is_none());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn broadcast_key_invalidation() {
        let old = BroadcastKey {
            producer_id: "prod-1".into(),
            issuer_key_hash: vec![0x01; 32],
            epoch: 5,
        };
        let new = BroadcastKey {
            producer_id: "prod-1".into(),
            issuer_key_hash: vec![0x01; 32],
            epoch: 10,
        };
        let other_producer = BroadcastKey {
            producer_id: "prod-2".into(),
            issuer_key_hash: vec![0x01; 32],
            epoch: 10,
        };

        use foca::Invalidates;
        assert!(new.invalidates(&old));
        assert!(!old.invalidates(&new));
        assert!(!new.invalidates(&other_producer));
        assert!(!old.invalidates(&old)); // same epoch doesn't invalidate
    }
}
