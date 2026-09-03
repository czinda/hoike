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
use crate::crypto::{self, GossipSigner, GossipVerifier, VerifyPolicy};

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
    /// Start the gossip node: bind UDP, initialize foca, join seeds.
    pub async fn start(
        config: GossipConfig,
        msg_tx: tokio::sync::mpsc::Sender<GossipMessage>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
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
        // Message authentication (FPT_ITT.1). Load this node's signing key (if
        // any) and the trusted peer keys, then derive the rollout policy: an
        // empty `peer_keys` list stays permissive (accept unsigned during a
        // rolling upgrade), a populated one enforces (drop unsigned/forged).
        let signer = match &config.identity_key {
            Some(path) => {
                let key = crypto::load_signing_key(path)
                    .map_err(|e| format!("gossip identity_key {}: {e}", path.display()))?;
                info!(key = %path.display(), "gossip message signing enabled");
                Some(GossipSigner::new(key))
            }
            None => None,
        };

        let mut trusted = Vec::new();
        for path in &config.peer_keys {
            let vk = crypto::load_verifying_key(path)
                .map_err(|e| format!("gossip peer_key {}: {e}", path.display()))?;
            trusted.push(vk);
        }
        // Trust our own key so broadcasts echoed back through the mesh verify.
        if let Some(s) = &signer {
            trusted.push(s.verifying_key());
        }

        // A verifier exists whenever this node participates in the signed scheme
        // at all (has its own key or names trusted peers). `peer_keys` populated
        // ⇒ enforce; otherwise permissive.
        let verifier = if signer.is_some() || !config.peer_keys.is_empty() {
            let policy = if config.peer_keys.is_empty() {
                VerifyPolicy::Permissive
            } else {
                VerifyPolicy::Required
            };
            info!(
                ?policy,
                trusted_keys = trusted.len(),
                "gossip verification enabled"
            );
            Some(GossipVerifier::new(trusted, policy))
        } else {
            None
        };

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

        let ikh_hex = hex::encode(issuer_key_hash);
        let key: GenKey = (origin_node.clone(), producer_id.clone(), ikh_hex.clone());
        let now = now_unix();

        let mut table = self.generations.write().await;
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
        self.generations.read().await.values().cloned().collect()
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
    async fn test_node(name: &str) -> GossipNode {
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let config = GossipConfig {
            enabled: true,
            bind: "127.0.0.1:0".into(),
            seeds: vec![],
            node_name: name.into(),
            identity_key: None,
            peer_keys: vec![],
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
}
