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
    },
    UrgentRevocation {
        producer_id: String,
        issuer_key_hash: Vec<u8>,
        epoch: u64,
    },
}

impl GossipMessage {
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
}

impl HoikeBroadcastHandler {
    pub fn new(tx: tokio::sync::mpsc::Sender<GossipMessage>) -> Self {
        Self { tx }
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
        let msg: GossipMessage = serde_json::from_slice(data)
            .map_err(|e| BroadcastError(format!("decode: {e}")))?;

        let key = BroadcastKey {
            producer_id: msg.scope_key().0.to_string(),
            issuer_key_hash: msg.scope_key().1.to_vec(),
            epoch: msg.epoch(),
        };

        // Non-blocking send to the gossip message processor
        let _ = self.tx.try_send(msg);

        Ok(Some(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gossip_message_serialization_round_trip() {
        let msg = GossipMessage::GenerationAnnouncement {
            producer_id: "signer-a".into(),
            issuer_key_hash: vec![0xAA; 32],
            epoch: 42,
            manifest_digest: [0xBB; 32],
            bundle_url: Some("https://signer-a.example/ahu/latest.ahu".into()),
        };

        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: GossipMessage = serde_json::from_slice(&json).unwrap();
        assert_eq!(msg, decoded);

        let msg2 = GossipMessage::UrgentRevocation {
            producer_id: "signer-b".into(),
            issuer_key_hash: vec![0xCC; 32],
            epoch: 100,
        };
        let json2 = serde_json::to_vec(&msg2).unwrap();
        let decoded2: GossipMessage = serde_json::from_slice(&json2).unwrap();
        assert_eq!(msg2, decoded2);
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
