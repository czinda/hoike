//! F11 regression: generation announcements must advertise the digest of the
//! serialized manifest, not the index digest.
//!
//! This is a delivery-level test: it starts a real (ephemeral, isolated)
//! gossip node and invokes the production announcer
//! [`hoike_server::announce_bundle_scopes`]. foca's `add_broadcast` feeds every
//! locally-added broadcast through the node's own `HoikeBroadcastHandler`, so
//! the messages observed on the node's channel are exactly the messages the
//! announcer delivered — the same capture point the audit's P08 probe used.

use ahu::{
    Bundle, BundleBuilder, BundleType, CaScope, Completeness, Continuity, Integrity, Manifest,
    ResponderId, ResponderIdType, Window,
};
use hoike_gossip::{GossipConfig, GossipMessage, GossipNode};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::sync::mpsc;
use uuid::Uuid;

fn scope(issuer_key_hash: Vec<u8>, epoch: u64) -> CaScope {
    CaScope {
        hash_algorithm: vec![0x01],
        issuer_name_hash: vec![0xAA; 32],
        issuer_key_hash,
        epoch,
        responder_id: ResponderId {
            id_type: ResponderIdType::ByKey,
            value: vec![0xCC; 20],
        },
        responder_chain: None,
        signature_algorithm: vec![0x02],
        completeness: Completeness::AuthoritativeComplete,
    }
}

/// Manifest with two CA scopes so the "one announcement per manifest scope"
/// claim is exercised on a multi-scope bundle.
fn manifest(epoch: u64, produced_at: u64) -> Manifest {
    Manifest {
        format_version: 1,
        bundle_id: Uuid::nil(),
        producer_id: "signer-test".into(),
        created_at: produced_at,
        bundle_type: BundleType::Full,
        ca_scopes: vec![scope(vec![0xBB; 32], epoch), scope(vec![0xBC; 32], epoch)],
        window: Window {
            produced_at,
            this_update_min: produced_at,
            next_update_min: produced_at + 86_400,
            next_update_max: produced_at + 172_800,
        },
        integrity: Integrity {
            index_digest: [0; 32],
            data_digest: [0; 32],
        },
        entry_count: 0,
        continuity: Continuity {
            prev_manifest_digest: None,
            base_manifest_digest: None,
            chain_length: 0,
        },
        shard: None,
        compression: None,
        extensions: None,
    }
}

/// Build a valid full bundle carrying the same entries for every parameter
/// set — so any two bundles share identical index bytes and index digest —
/// differing only in epoch/window metadata.
fn full_bundle(epoch: u64, produced_at: u64) -> (Vec<u8>, Bundle) {
    let mut builder = BundleBuilder::new(manifest(epoch, produced_at));
    builder.add_entry([0xAA; 32], b"ocsp-response-a".to_vec());
    builder.add_entry([0xAB; 32], b"ocsp-response-b".to_vec());
    let bytes = builder.build(|m| Ok(Sha256::digest(m).to_vec())).unwrap();
    let bundle = Bundle::from_bytes(&bytes).unwrap();
    (bytes, bundle)
}

/// Bind a real but isolated gossip node (ephemeral port, no seeds) in the
/// explicit permissive auth mode — this delivery-level test captures
/// announcements, it does not exercise authentication policy (F09 covers
/// that in hoike-gossip and hoike-cli). Returns the node and the channel
/// every locally delivered broadcast lands on.
async fn ephemeral_node(name: &str) -> (GossipNode, mpsc::Receiver<GossipMessage>) {
    let (tx, rx) = mpsc::channel(16);
    let config = GossipConfig {
        enabled: true,
        bind: "127.0.0.1:0".into(),
        seeds: vec![],
        node_name: name.into(),
        auth_mode: hoike_gossip::AuthMode::Permissive,
        identity_key: None,
        peer_keys: vec![],
        peer_identities: Default::default(),
    };
    let node = GossipNode::start(config, tx)
        .await
        .expect("ephemeral gossip node starts");
    (node, rx)
}

/// Receive one delivered announcement, failing the test if nothing arrives
/// within the deadline (a lost announcement must not pass silently).
async fn next_announcement(
    rx: &mut mpsc::Receiver<GossipMessage>,
) -> (Vec<u8>, u64, [u8; 32], Option<String>) {
    let msg = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("announcement delivered within deadline")
        .expect("gossip channel stays open");
    match msg {
        GossipMessage::GenerationAnnouncement {
            issuer_key_hash,
            epoch,
            manifest_digest,
            bundle_url,
            ..
        } => (issuer_key_hash, epoch, manifest_digest, bundle_url),
        other => panic!("expected GenerationAnnouncement, got {other:?}"),
    }
}

/// Collect the announcements one announce pass delivered for a bundle and
/// assert they identify the bundle's manifest: one announcement per CA scope,
/// each carrying the digest of the serialized manifest, the scope's epoch,
/// and no fabricated bundle URL.
async fn assert_announces_manifest(
    rx: &mut mpsc::Receiver<GossipMessage>,
    bundle: &Bundle,
    expected_digest: [u8; 32],
) {
    let mut seen_scopes = Vec::new();
    for _ in 0..bundle.manifest.ca_scopes.len() {
        let (issuer_key_hash, epoch, digest, bundle_url) = next_announcement(rx).await;
        assert_eq!(
            digest, expected_digest,
            "announced digest must be the serialized manifest digest"
        );
        assert!(
            bundle_url.is_none(),
            "no bundle URL may be fabricated for a nonexistent retrieval route"
        );
        let scope = bundle
            .manifest
            .ca_scopes
            .iter()
            .find(|s| s.issuer_key_hash == issuer_key_hash)
            .expect("announcement names a scope from the bundle");
        assert_eq!(epoch, scope.epoch, "announcement carries its scope's epoch");
        seen_scopes.push(issuer_key_hash);
    }
    let mut expected_scopes: Vec<Vec<u8>> = bundle
        .manifest
        .ca_scopes
        .iter()
        .map(|s| s.issuer_key_hash.clone())
        .collect();
    expected_scopes.sort();
    seen_scopes.sort();
    assert_eq!(
        seen_scopes, expected_scopes,
        "exactly one announcement per manifest scope"
    );
}

#[tokio::test]
async fn announcement_identifies_manifest_not_index() {
    let (bytes_a, bundle_a) = full_bundle(5, 1_700_000_000);
    let (bytes_b, bundle_b) = full_bundle(6, 1_700_100_000);

    // Both are structurally valid full bundles.
    ahu::verify_structure(&bundle_a).unwrap();
    ahu::verify_structure(&bundle_b).unwrap();

    // Precondition for the regression: identical index bytes (hence identical
    // index digest) but different epoch/window metadata, so the serialized
    // manifests — and their digests — differ.
    assert_eq!(bundle_a.index, bundle_b.index, "index records identical");
    assert_eq!(
        bundle_a.manifest.integrity.index_digest, bundle_b.manifest.integrity.index_digest,
        "index digest derived only from index bytes"
    );
    assert_ne!(bundle_a.manifest_bytes, bundle_b.manifest_bytes);
    let digest_a = ahu::manifest_digest(&bundle_a.manifest_bytes);
    let digest_b = ahu::manifest_digest(&bundle_b.manifest_bytes);
    assert_ne!(digest_a, digest_b);

    let (node, mut rx) = ephemeral_node("announce-capture").await;

    // Exercise the real announcer, as the signing pass does.
    hoike_server::announce_bundle_scopes(&node, &bytes_a).await;
    hoike_server::announce_bundle_scopes(&node, &bytes_b).await;

    assert_announces_manifest(&mut rx, &bundle_a, digest_a).await;
    assert_announces_manifest(&mut rx, &bundle_b, digest_b).await;

    // Nothing beyond one announcement per scope was delivered.
    assert!(
        rx.try_recv().is_err(),
        "no extra announcements beyond one per manifest scope"
    );
}
