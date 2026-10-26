use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use foca::{AccumulatingRuntime, Config as FocaConfig, Foca, PostcardCodec, Timer};
use rand::SeedableRng;
use rand::rngs::SmallRng;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

use crate::broadcast::{GossipMessage, HoikeBroadcastHandler};
use crate::config::GossipConfig;
use crate::crypto::{self, GossipSigner};

/// Seconds since the Unix epoch, or 0 if the clock is set before 1970.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// SWIM liveness state of a fleet member, mirrored from foca's [`foca::State`]
/// into a type the admin API and UI can consume without a foca dependency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberState {
    Alive,
    Suspect,
    Down,
}

impl From<foca::State> for MemberState {
    fn from(s: foca::State) -> Self {
        match s {
            foca::State::Alive => MemberState::Alive,
            foca::State::Suspect => MemberState::Suspect,
            foca::State::Down => MemberState::Down,
        }
    }
}

/// A point-in-time snapshot of one fleet member's identity and liveness.
#[derive(Clone, Debug, Serialize)]
pub struct MemberInfo {
    pub name: String,
    pub addr: SocketAddr,
    /// The identity's own incarnation counter (bumped on rejoin), not foca's
    /// per-member suspicion incarnation.
    pub incarnation: u64,
    pub state: MemberState,
    /// True for the local node, which foca does not list among its peers.
    pub is_self: bool,
}

/// The latest generation this node has heard a given peer announce for a given
/// scope. Keyed in the table by (origin node, producer, issuer-key-hash).
#[derive(Clone, Debug, Serialize)]
pub struct GenRecord {
    /// Name of the announcing node (empty for pre-`origin_node` senders).
    pub origin_node: String,
    pub producer_id: String,
    /// Hex-encoded issuer key hash — identifies the CA scope.
    pub issuer_key_hash: String,
    pub epoch: u64,
    pub manifest_digest: String,
    /// Wall-clock (Unix seconds) when this announcement was last observed.
    pub last_seen_unix: u64,
}

/// Table key: one row per (announcing node, CA scope).
type GenKey = (String, String, String);
type GenerationTable = Arc<RwLock<HashMap<GenKey, GenRecord>>>;

/// Node identity in the gossip mesh. Includes the address (for routing)
/// and a monotonic incarnation counter (for conflict resolution on rejoin).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId {
    pub addr: SocketAddr,
    pub name: String,
    pub incarnation: u64,
}

impl foca::Identity for NodeId {
    type Addr = SocketAddr;

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn renew(&self) -> Option<Self> {
        Some(NodeId {
            addr: self.addr,
            name: self.name.clone(),
            incarnation: self.incarnation + 1,
        })
    }

    fn win_addr_conflict(&self, adversary: &Self) -> bool {
        self.incarnation > adversary.incarnation
    }
}

type HoikeFoca = Foca<NodeId, PostcardCodec, SmallRng, HoikeBroadcastHandler>;
type TimerQueue = Arc<Mutex<Vec<(Duration, Timer<NodeId>)>>>;

pub struct GossipNode {
    foca: Arc<Mutex<HoikeFoca>>,
    #[allow(dead_code)]
    socket: Arc<UdpSocket>,
    config: GossipConfig,
    /// This node's own gossip identity — used to stamp outgoing announcements
    /// and to include the local node in the fleet view.
    identity: NodeId,
    /// Per-(node, scope) generation records built from received announcements.
    generations: GenerationTable,
    /// Ed25519 signer for outbound broadcasts (FPT_ITT.1). `None` when no
    /// `identity_key` is configured — broadcasts go out unsigned, as before.
    signer: Option<GossipSigner>,
}

impl GossipNode {
    /// Start the gossip node: validate the authentication policy, bind UDP,
    /// initialize foca, join seeds.
    pub async fn start(
        config: GossipConfig,
        msg_tx: tokio::sync::mpsc::Sender<GossipMessage>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Message authentication (FPT_ITT.1, F09). One shared helper loads the
        // outbound signer and the always-present inbound verifier for the
        // configured auth_mode. It runs before any socket is bound: an
        // invalid enabled configuration is a fatal startup error, never a
        // warning-and-continue that would silently run unauthenticated gossip
        // (or bind a socket the process is about to abandon).
        let (signer, verifier) = crypto::load_authentication(&config)?;
        info!(
            auth_mode = ?config.auth_mode,
            peers = config.peer_identities.len(),
            signing = signer.is_some(),
            "gossip message authentication loaded"
        );

        let bind_addr: SocketAddr = config
            .bind
            .parse()
            .map_err(|e| format!("invalid gossip bind address '{}': {}", config.bind, e))?;

        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| format!("failed to bind gossip socket on {}: {}", bind_addr, e))?;

        let local_addr = socket.local_addr()?;
        info!(addr = %local_addr, name = %config.node_name, "gossip node starting");

        let identity = NodeId {
            addr: local_addr,
            name: config.node_name.clone(),
            incarnation: 0,
        };

        let foca_config = FocaConfig::simple();
        let rng = SmallRng::seed_from_u64(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        );

        let broadcast_handler = HoikeBroadcastHandler::new(msg_tx, verifier);

        // Keep a copy of our identity: `with_custom_broadcast` consumes it, but
        // we need it to stamp outgoing announcements and to show the local node
        // in the fleet view (foca lists only *peers*, never self).
        let self_identity = identity.clone();

        let foca = Foca::with_custom_broadcast(
            identity,
            foca_config,
            rng,
            PostcardCodec,
            broadcast_handler,
        );

        let socket = Arc::new(socket);
        let foca = Arc::new(Mutex::new(foca));
        let timer_queue: TimerQueue = Arc::new(Mutex::new(Vec::new()));

        let node = GossipNode {
            foca: Arc::clone(&foca),
            socket: Arc::clone(&socket),
            config: config.clone(),
            identity: self_identity,
            generations: Arc::new(RwLock::new(HashMap::new())),
            signer,
        };

        // Spawn the receive loop
        {
            let foca = Arc::clone(&foca);
            let socket = Arc::clone(&socket);
            let tq = Arc::clone(&timer_queue);
            tokio::spawn(async move {
                receive_loop(foca, socket, tq).await;
            });
        }

        // Spawn the timer loop
        {
            let foca = Arc::clone(&foca);
            let socket_clone = Arc::clone(&socket);
            let tq = Arc::clone(&timer_queue);
            tokio::spawn(async move {
                timer_loop(foca, socket_clone, tq).await;
            });
        }

        // Join seed nodes
        for seed in &config.seeds {
            match seed.parse::<SocketAddr>() {
                Ok(addr) => {
                    let seed_id = NodeId {
                        addr,
                        name: String::new(),
                        incarnation: 0,
                    };
                    let mut foca_guard = foca.lock().await;
                    let mut runtime = AccumulatingRuntime::new();
                    if let Err(e) = foca_guard.announce(seed_id, &mut runtime) {
                        warn!(seed = %addr, error = %e, "failed to announce to seed");
                    }
                    drain_runtime(&mut runtime, &socket, &timer_queue).await;
                    info!(seed = %addr, "announced to seed");
                }
                Err(e) => {
                    warn!(seed = %seed, error = %e, "invalid seed address, skipping");
                }
            }
        }

        Ok(node)
    }

    /// Wrap a JSON broadcast payload in a signed frame when signing is enabled,
    /// or pass it through unchanged otherwise. Isolated so both announce paths
    /// share one code path for the wire format.
    fn frame_broadcast(&self, payload: Vec<u8>) -> Vec<u8> {
        match &self.signer {
            Some(signer) => signer.frame(&payload),
            None => payload,
        }
    }

    /// Broadcast a generation announcement to the gossip mesh.
    pub async fn announce_generation(
        &self,
        producer_id: String,
        issuer_key_hash: Vec<u8>,
        epoch: u64,
        manifest_digest: [u8; 32],
        bundle_url: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let msg = GossipMessage::GenerationAnnouncement {
            producer_id,
            issuer_key_hash,
            epoch,
            manifest_digest,
            bundle_url,
            origin_node: self.identity.name.clone(),
        };

        let data = self.frame_broadcast(serde_json::to_vec(&msg)?);
        let mut foca = self.foca.lock().await;
        foca.add_broadcast(&data)?;

        info!(msg = %msg, "broadcasting generation announcement");
        Ok(())
    }

    /// Broadcast an urgent revocation notice.
    pub async fn announce_urgent_revocation(
        &self,
        producer_id: String,
        issuer_key_hash: Vec<u8>,
        epoch: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let msg = GossipMessage::UrgentRevocation {
            producer_id,
            issuer_key_hash,
            epoch,
            origin_node: self.identity.name.clone(),
        };

        let data = self.frame_broadcast(serde_json::to_vec(&msg)?);
        let mut foca = self.foca.lock().await;
        foca.add_broadcast(&data)?;

        info!(msg = %msg, "broadcasting urgent revocation");
        Ok(())
    }

    pub fn config(&self) -> &GossipConfig {
        &self.config
    }

    /// This node's own gossip identity.
    pub fn identity(&self) -> &NodeId {
        &self.identity
    }

    /// Snapshot the current cluster membership, including the local node.
    ///
    /// foca tracks only *peers* — the local node never appears in its own
    /// member list — so we append `self` (always `Alive` from its own vantage)
    /// to give the fleet view a complete roster.
    pub async fn members(&self) -> Vec<MemberInfo> {
        let foca = self.foca.lock().await;
        let mut out: Vec<MemberInfo> = foca
            .iter_membership_state()
            .map(|m| {
                let id = m.id();
                MemberInfo {
                    name: id.name.clone(),
                    addr: id.addr,
                    incarnation: id.incarnation,
                    state: m.state().into(),
                    is_self: false,
                }
            })
            .collect();
        drop(foca);

        out.push(MemberInfo {
            name: self.identity.name.clone(),
            addr: self.identity.addr,
            incarnation: self.identity.incarnation,
            state: MemberState::Alive,
            is_self: true,
        });
        out
    }

    /// Fold a received generation announcement into the generation table.
    ///
    /// Only advances a (node, scope) row when the incoming epoch is newer,
    /// mirroring the anti-rollback stance of the serving path — a delayed or
    /// replayed lower-epoch announcement must not appear to regress a peer.
    /// `last_seen` is refreshed on every observation regardless, so liveness
    /// tracking stays accurate even when the epoch is unchanged.
    pub async fn record_generation(&self, msg: &GossipMessage) {
        let GossipMessage::GenerationAnnouncement {
            producer_id,
            issuer_key_hash,
            epoch,
            manifest_digest,
            origin_node,
            ..
        } = msg
        else {
            return;
        };

        if !msg.valid_bounds() {
            return;
        }
        let ikh_hex = hex::encode(issuer_key_hash);
        let key: GenKey = (origin_node.clone(), producer_id.clone(), ikh_hex.clone());
        let now = now_unix();

        let mut table = self.generations.write().await;
        table.retain(|_, row| now.saturating_sub(row.last_seen_unix) < 3600);
        if !table.contains_key(&key) && table.len() >= 4096 {
            return;
        }
        let entry = table.entry(key).or_insert_with(|| GenRecord {
            origin_node: origin_node.clone(),
            producer_id: producer_id.clone(),
            issuer_key_hash: ikh_hex,
            epoch: *epoch,
            manifest_digest: hex::encode(manifest_digest),
            last_seen_unix: now,
        });
        if *epoch >= entry.epoch {
            entry.epoch = *epoch;
            entry.manifest_digest = hex::encode(manifest_digest);
        }
        entry.last_seen_unix = now;
    }

    /// Snapshot all known per-(node, scope) generation records.
    pub async fn generations(&self) -> Vec<GenRecord> {
        let mut table = self.generations.write().await;
        let now = now_unix();
        table.retain(|_, row| now.saturating_sub(row.last_seen_unix) < 3600);
        table.values().cloned().collect()
    }
}

/// Receive incoming UDP packets and feed them to foca.
async fn receive_loop(
    foca: Arc<Mutex<HoikeFoca>>,
    socket: Arc<UdpSocket>,
    timer_queue: TimerQueue,
) {
    let mut buf = vec![0u8; 2048];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, from)) => {
                debug!(from = %from, len, "gossip packet received");
                let mut foca_guard = foca.lock().await;
                let mut runtime = AccumulatingRuntime::new();
                if let Err(e) = foca_guard.handle_data(&buf[..len], &mut runtime) {
                    debug!(from = %from, error = %e, "foca handle_data error (expected for arbitrary UDP)");
                }
                drop(foca_guard);
                drain_runtime(&mut runtime, &socket, &timer_queue).await;
            }
            Err(e) => {
                warn!(error = %e, "UDP recv error");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Process foca timer events at fixed intervals.
async fn timer_loop(
    foca: Arc<Mutex<HoikeFoca>>,
    socket: Arc<UdpSocket>,
    new_timers_rx: TimerQueue,
) {
    let mut pending_timers: Vec<(tokio::time::Instant, Timer<NodeId>)> = Vec::new();

    let tick = Duration::from_millis(200);
    let mut interval = tokio::time::interval(tick);

    loop {
        interval.tick().await;

        // Collect timers scheduled by receive_loop and seed announce
        {
            let mut incoming = new_timers_rx.lock().await;
            for (duration, timer) in incoming.drain(..) {
                pending_timers.push((tokio::time::Instant::now() + duration, timer));
            }
        }

        let now = tokio::time::Instant::now();

        let mut due = Vec::new();
        pending_timers.retain(|(deadline, timer)| {
            if *deadline <= now {
                due.push(timer.clone());
                false
            } else {
                true
            }
        });

        if due.is_empty() {
            continue;
        }

        let mut foca_guard = foca.lock().await;
        let mut runtime = AccumulatingRuntime::new();

        for timer in due {
            if let Err(e) = foca_guard.handle_timer(timer, &mut runtime) {
                debug!(error = %e, "foca timer error");
            }
        }

        while let Some(notification) = runtime.to_notify() {
            handle_notification(&notification);
        }

        while let Some((duration, timer)) = runtime.to_schedule() {
            pending_timers.push((tokio::time::Instant::now() + duration, timer));
        }

        drop(foca_guard);

        // Send any outgoing packets
        while let Some((to, data)) = runtime.to_send() {
            if let Err(e) = socket.send_to(&data, to.addr).await {
                debug!(to = %to.addr, error = %e, "failed to send gossip packet");
            }
        }
    }
}

fn handle_notification(notification: &foca::OwnedNotification<NodeId>) {
    match notification {
        foca::OwnedNotification::MemberUp(id) => {
            info!(name = %id.name, addr = %id.addr, "member joined");
        }
        foca::OwnedNotification::MemberDown(id) => {
            info!(name = %id.name, addr = %id.addr, "member left");
        }
        foca::OwnedNotification::Rename(before, after) => {
            info!(
                before_name = %before.name, before_addr = %before.addr,
                after_name = %after.name, after_addr = %after.addr,
                "member renamed (rejoin)"
            );
        }
        foca::OwnedNotification::Active => {
            info!("gossip node is active (known by cluster)");
        }
        foca::OwnedNotification::Idle => {
            info!("gossip node is idle (no known peers)");
        }
        foca::OwnedNotification::Defunct => {
            warn!("gossip node declared defunct — needs manual intervention");
        }
        foca::OwnedNotification::Rejoin(id) => {
            info!(name = %id.name, incarnation = id.incarnation, "auto-rejoined cluster");
        }
    }
}

/// Drain accumulated runtime events: send packets, forward timers, process notifications.
async fn drain_runtime(
    runtime: &mut AccumulatingRuntime<NodeId>,
    socket: &UdpSocket,
    timer_queue: &TimerQueue,
) {
    while let Some(notification) = runtime.to_notify() {
        handle_notification(&notification);
    }

    while let Some((to, data)) = runtime.to_send() {
        let addr = to.addr;
        if let Err(e) = socket.send_to(&data, addr).await {
            debug!(to = %addr, error = %e, "failed to send gossip packet");
        }
    }

    // Forward timer events to the timer_loop's shared queue
    let mut timers = timer_queue.lock().await;
    while let Some((duration, timer)) = runtime.to_schedule() {
        timers.push((duration, timer));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generation_storage_is_bounded_and_expires() {
        let node = test_node("edge").await;
        for n in 0..4100 {
            node.record_generation(&GossipMessage::GenerationAnnouncement {
                producer_id: format!("producer-{n}"),
                issuer_key_hash: vec![1; 32],
                epoch: 1,
                manifest_digest: [0; 32],
                bundle_url: None,
                origin_node: "peer".into(),
            })
            .await;
        }
        assert_eq!(node.generations().await.len(), 4096);
        for row in node.generations.write().await.values_mut() {
            row.last_seen_unix = 0;
        }
        assert!(node.generations().await.is_empty());
    }

    #[test]
    fn node_id_identity_trait() {
        let id = NodeId {
            addr: "127.0.0.1:7946".parse().unwrap(),
            name: "test-node".into(),
            incarnation: 0,
        };

        // Test addr()
        use foca::Identity;
        assert_eq!(id.addr(), "127.0.0.1:7946".parse::<SocketAddr>().unwrap());

        // Test renew()
        let renewed = id.renew().unwrap();
        assert_eq!(renewed.incarnation, 1);
        assert_eq!(renewed.addr, id.addr);
        assert_eq!(renewed.name, id.name);

        // Test win_addr_conflict()
        assert!(renewed.win_addr_conflict(&id));
        assert!(!id.win_addr_conflict(&renewed));
    }

    #[test]
    fn node_id_serde_round_trip() {
        let id = NodeId {
            addr: "192.168.1.1:7946".parse().unwrap(),
            name: "edge-node-01".into(),
            incarnation: 5,
        };

        let json = serde_json::to_string(&id).unwrap();
        let decoded: NodeId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, decoded);
    }

    /// Bind a real (but isolated: no seeds) gossip node on an ephemeral port.
    /// These tests exercise membership/table mechanics, not authentication, so
    /// they use the explicit permissive mode and no key material.
    async fn test_node(name: &str) -> GossipNode {
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let config = GossipConfig {
            enabled: true,
            bind: "127.0.0.1:0".into(),
            seeds: vec![],
            node_name: name.into(),
            auth_mode: crate::config::AuthMode::Permissive,
            identity_key: None,
            peer_keys: vec![],
            peer_identities: Default::default(),
        };
        GossipNode::start(config, tx).await.expect("node starts")
    }

    // A freshly started node has no peers, but the fleet view must still list
    // the local node — otherwise a single-node deployment shows an empty roster.
    #[tokio::test]
    async fn members_always_includes_self() {
        let node = test_node("solo").await;
        let members = node.members().await;
        assert_eq!(members.len(), 1, "no peers, only self");
        assert!(members[0].is_self);
        assert_eq!(members[0].name, "solo");
        assert_eq!(members[0].state, MemberState::Alive);
    }

    #[tokio::test]
    async fn record_generation_tracks_latest_epoch_per_scope() {
        let node = test_node("signer").await;
        let ikh = vec![0xAB; 32];

        let announce = |epoch: u64| GossipMessage::GenerationAnnouncement {
            producer_id: "prod-1".into(),
            issuer_key_hash: ikh.clone(),
            epoch,
            manifest_digest: [epoch as u8; 32],
            bundle_url: None,
            origin_node: "peer-a".into(),
        };

        node.record_generation(&announce(5)).await;
        node.record_generation(&announce(7)).await;
        // A stale/replayed lower epoch must not regress the recorded row.
        node.record_generation(&announce(6)).await;

        let gens = node.generations().await;
        assert_eq!(gens.len(), 1, "one (node, scope) row");
        assert_eq!(gens[0].epoch, 7);
        assert_eq!(gens[0].origin_node, "peer-a");
        assert_eq!(gens[0].producer_id, "prod-1");
        assert_eq!(gens[0].issuer_key_hash, hex::encode(&ikh));
    }

    // Two different announcing nodes for the same scope are distinct rows —
    // that separation is what lets the fleet view compute per-node staleness.
    #[tokio::test]
    async fn record_generation_separates_scopes_and_nodes() {
        let node = test_node("edge").await;
        node.record_generation(&GossipMessage::GenerationAnnouncement {
            producer_id: "prod-1".into(),
            issuer_key_hash: vec![0x01; 32],
            epoch: 3,
            manifest_digest: [0; 32],
            bundle_url: None,
            origin_node: "node-a".into(),
        })
        .await;
        node.record_generation(&GossipMessage::GenerationAnnouncement {
            producer_id: "prod-1".into(),
            issuer_key_hash: vec![0x01; 32],
            epoch: 3,
            manifest_digest: [0; 32],
            bundle_url: None,
            origin_node: "node-b".into(),
        })
        .await;
        assert_eq!(node.generations().await.len(), 2, "two distinct nodes");
    }

    // ── F09: the provision → permissive → sign → required rollout, on real
    // loopback sockets, with channel-based deadlines. ──

    /// Wait until `node`'s fleet view lists a member named `name`.
    async fn wait_for_member(node: &GossipNode, name: &str, limit: Duration) {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            if node.members().await.iter().any(|m| m.name == name) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "peer '{name}' never became visible in the fleet view"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Receive the next announcement for a specific CA scope, skipping
    /// duplicate deliveries of earlier scopes, failing on the deadline.
    async fn recv_scope(
        rx: &mut tokio::sync::mpsc::Receiver<GossipMessage>,
        issuer_key_hash: &[u8],
        limit: Duration,
    ) -> GossipMessage {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            let msg = tokio::time::timeout_at(deadline, rx.recv())
                .await
                .expect("announcement delivered within deadline")
                .expect("gossip channel stays open");
            if msg.scope_key().1 == issuer_key_hash {
                return msg;
            }
        }
    }

    fn identity_files(
        dir: &std::path::Path,
        name: &str,
        seed: u8,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let (_, priv_path, pub_path) = crate::crypto::write_test_identity(dir, name, seed);
        (priv_path, pub_path)
    }

    /// The full F09 rollout transition over loopback UDP: while the receiver
    /// runs in permissive mode during the signing rollout, mapped peers stay
    /// visible, signed announcements flow, and unsigned traffic is still
    /// accepted; once the receiver runs in required mode, unsigned traffic is
    /// rejected while the mapped signer's announcements keep flowing.
    #[tokio::test]
    async fn loopback_transition_permissive_signing_to_required() {
        let dir = tempfile::tempdir().unwrap();
        let (alpha_priv, alpha_pub) = identity_files(dir.path(), "alpha", 21);
        let (bravo_priv, bravo_pub) = identity_files(dir.path(), "bravo", 22);

        let node_config = |name: &str,
                           mode: crate::config::AuthMode,
                           identity: Option<std::path::PathBuf>,
                           peers: Vec<(&str, std::path::PathBuf)>,
                           seeds: Vec<String>| {
            let mut peer_identities = std::collections::BTreeMap::new();
            for (peer, path) in peers {
                peer_identities.insert(peer.to_string(), path);
            }
            GossipConfig {
                enabled: true,
                bind: "127.0.0.1:0".into(),
                seeds,
                node_name: name.into(),
                auth_mode: mode,
                identity_key: identity,
                peer_keys: vec![],
                peer_identities,
            }
        };
        let start = |config: GossipConfig| async move {
            let (tx, rx) = tokio::sync::mpsc::channel(16);
            let node = GossipNode::start(config, tx)
                .await
                .expect("gossip node starts");
            (node, rx)
        };

        // Phase 1 — permissive rollout. alpha signs with a provisioned key;
        // bravo maps alpha's key but has no local identity yet.
        let (bravo, mut bravo_rx) = start(node_config(
            "bravo",
            crate::config::AuthMode::Permissive,
            None,
            vec![("alpha", alpha_pub.clone())],
            vec![],
        ))
        .await;
        let (alpha, mut alpha_rx) = start(node_config(
            "alpha",
            crate::config::AuthMode::Permissive,
            Some(alpha_priv.clone()),
            vec![("alpha", alpha_pub.clone())],
            vec![bravo.identity().addr.to_string()],
        ))
        .await;

        // Mapped peers remain visible during the permissive signing rollout.
        wait_for_member(&bravo, "alpha", Duration::from_secs(15)).await;

        // alpha's signed announcement reaches the mapped permissive peer.
        alpha
            .announce_generation("producer".into(), vec![0x01; 32], 7, [7; 32], None)
            .await
            .unwrap();
        let signed = recv_scope(&mut bravo_rx, &[0x01; 32], Duration::from_secs(10)).await;
        assert_eq!(signed.epoch(), 7);

        // bravo's unsigned announcement still reaches permissive alpha.
        bravo
            .announce_generation("producer".into(), vec![0x02; 32], 3, [3; 32], None)
            .await
            .unwrap();
        let unsigned = recv_scope(&mut alpha_rx, &[0x02; 32], Duration::from_secs(10)).await;
        assert_eq!(unsigned.epoch(), 3);

        // Phase 2 — required mode. A receiver restarted with a local identity
        // and both mappings (the post-rollout configuration) still sees the
        // mapped signer, accepts its signed announcements, and drops bravo's
        // unsigned traffic.
        let (bravo_required, mut bravo_required_rx) = start(node_config(
            "bravo",
            crate::config::AuthMode::Required,
            Some(bravo_priv.clone()),
            vec![("alpha", alpha_pub.clone()), ("bravo", bravo_pub.clone())],
            vec![
                alpha.identity().addr.to_string(),
                bravo.identity().addr.to_string(),
            ],
        ))
        .await;
        wait_for_member(&bravo_required, "alpha", Duration::from_secs(15)).await;
        wait_for_member(&bravo_required, "bravo", Duration::from_secs(15)).await;

        // alpha's signed announcement still flows under required mode.
        alpha
            .announce_generation("producer".into(), vec![0x03; 32], 9, [9; 32], None)
            .await
            .unwrap();
        let signed = recv_scope(&mut bravo_required_rx, &[0x03; 32], Duration::from_secs(10)).await;
        assert_eq!(signed.epoch(), 9);

        // bravo's unsigned traffic is rejected after required mode: within
        // the deadline nothing carrying its scope may arrive, even though the
        // same emission path delivered to the permissive alpha in phase 1.
        bravo
            .announce_generation("producer".into(), vec![0x04; 32], 4, [4; 32], None)
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        let mut leaked = None;
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout_at(deadline, bravo_required_rx.recv()).await {
                Ok(Some(msg)) if msg.scope_key().1 == [0x04; 32] => {
                    leaked = Some(msg);
                    break;
                }
                // Stale re-transmissions of earlier signed scopes are fine.
                Ok(Some(_)) => continue,
                Ok(None) => panic!("required receiver's channel closed"),
                Err(_) => break, // deadline elapsed: nothing leaked
            }
        }
        assert!(
            leaked.is_none(),
            "unsigned broadcast must be rejected in required mode: {leaked:?}"
        );
    }
}
