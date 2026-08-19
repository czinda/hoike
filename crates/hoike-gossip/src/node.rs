use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use foca::{AccumulatingRuntime, Config as FocaConfig, Foca, PostcardCodec, Timer};
use rand::SeedableRng;
use rand::rngs::SmallRng;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::broadcast::{GossipMessage, HoikeBroadcastHandler};
use crate::config::GossipConfig;

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
        let broadcast_handler = HoikeBroadcastHandler::new(msg_tx);

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
        };

        let data = serde_json::to_vec(&msg)?;
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
        };

        let data = serde_json::to_vec(&msg)?;
        let mut foca = self.foca.lock().await;
        foca.add_broadcast(&data)?;

        info!(msg = %msg, "broadcasting urgent revocation");
        Ok(())
    }

    pub fn config(&self) -> &GossipConfig {
        &self.config
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
}
