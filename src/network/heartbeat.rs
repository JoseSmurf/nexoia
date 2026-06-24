// heartbeat.rs — Heartbeat sender and monitor
// Lock order: see GLOBAL LOCK ORDER in src/main.rs

use crate::network::identity::NodeIdentity;
use crate::network::reputation::ReputationStore;
use crate::network::session::SessionManager;
use crate::network::transport::{NetworkMessage, PeerList, PeerState, TrustedPeerList};
use crate::nex::action_executor::ActionExecutor;
use crate::nex::reactive::{NetworkEvent, ReactiveEngine};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// Envia heartbeat periodicamente e compartilha peers conhecidos.
pub async fn run_heartbeat_sender(
    node: NodeIdentity,
    trusted_peers: Arc<RwLock<TrustedPeerList>>,
    peer_states: Arc<RwLock<HashMap<SocketAddr, PeerState>>>,
    udp_addr: SocketAddr,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    let mut peer_exchange_counter = 0u32;

    loop {
        interval.tick().await;

        let peers = trusted_peers.read().await;
        let addrs: Vec<SocketAddr> = peers.addrs();
        drop(peers);

        if addrs.is_empty() {
            continue;
        }

        // Cria socket temporário para enviar heartbeats
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to create heartbeat socket: {}", e);
                continue;
            }
        };

        // Envia heartbeat para todos os peers
        let heartbeat = NetworkMessage::Heartbeat {
            node_id: node.node_id.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        if let Ok(data) = serde_json::to_vec(&heartbeat) {
            for addr in &addrs {
                let _ = socket.send_to(&data, addr).await;
            }
        }

        // Peer exchange a cada 5 heartbeats (2.5 min)
        peer_exchange_counter += 1;
        if peer_exchange_counter >= 5 {
            peer_exchange_counter = 0;
            let peers_list = trusted_peers.read().await;
            let peer_addrs: Vec<String> =
                peers_list.addrs().iter().map(|a| a.to_string()).collect();
            drop(peers_list);

            if !peer_addrs.is_empty() {
                let exchange = NetworkMessage::PeerExchange {
                    node_id: node.node_id.clone(),
                    peers: peer_addrs,
                };
                if let Ok(data) = serde_json::to_vec(&exchange) {
                    for addr in &addrs {
                        let _ = socket.send_to(&data, addr).await;
                    }
                }
            }
        }

        // Registra miss para peers que não responderam
        // Lock order: peer_states (see GLOBAL LOCK ORDER)
        let mut states = peer_states.write().await;
        for addr in &addrs {
            if let Some(state) = states.get_mut(addr) {
                if state.is_inactive(30) {
                    state.record_miss();
                }
            } else {
                states.insert(*addr, PeerState::new());
            }
        }
    }
}

/// Monitora peers inativos e gerencia reconexão.
/// Integra o ReactiveEngine com eventos reais da rede.
pub async fn run_heartbeat_monitor(
    peer_states: Arc<RwLock<HashMap<SocketAddr, PeerState>>>,
    trusted_peers: Arc<RwLock<TrustedPeerList>>,
    reputation: Arc<RwLock<ReputationStore>>,
    mut reactive_engine: ReactiveEngine,
    session_manager: Arc<SessionManager>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        interval.tick().await;

        // Cleanup sessões expiradas (5 minutos sem atividade)
        session_manager.cleanup(300).await;

        // Lock order: peer_states (see GLOBAL LOCK ORDER)
        let states = peer_states.read().await;
        let mut to_remove = Vec::new();
        let mut to_reconnect = Vec::new();
        let mut events = Vec::new();

        for (addr, state) in states.iter() {
            // Remove peer se inativo por mais de 5 minutos
            if state.is_inactive(300) {
                eprintln!(
                    "⚠ Peer {} inactive for >5 min (misses: {})",
                    addr, state.consecutive_misses
                );
                to_remove.push(*addr);
                events.push(NetworkEvent::PeerDisconnected {
                    node_id: format!("peer_{}", addr),
                });
            }
            // Tenta reconectar se peer tem misses mas ainda não expirou
            else if state.consecutive_misses >= 3 && state.should_reconnect() {
                to_reconnect.push(*addr);
                events.push(NetworkEvent::HeartbeatMiss {
                    count: state.consecutive_misses,
                });
            }
            // Avisa se peer está suspeito (2+ misses)
            else if state.consecutive_misses >= 2 {
                eprintln!(
                    "⚠ Peer {} has {} consecutive misses",
                    addr, state.consecutive_misses
                );
                events.push(NetworkEvent::HeartbeatMiss {
                    count: state.consecutive_misses,
                });
            }
        }
        drop(states);

        // Processa eventos através do ReactiveEngine
        let mut peer_addrs_map = HashMap::new();
        {
            let peer_list = trusted_peers.read().await;
            for peer in peer_list.peers() {
                peer_addrs_map.insert(peer.node_id.clone(), peer.addr);
            }
        }

        for event in &events {
            let result = reactive_engine.evaluate(event);
            if result.matched {
                // Lock order: peer_states → reputation (see GLOBAL LOCK ORDER)
                // Collect actions first, then apply
                let actions = {
                    let mut peer_states_mut = peer_states.write().await;
                    let mut rep = reputation.write().await;
                    let report = ActionExecutor::execute(
                        &result.actions,
                        &mut peer_states_mut,
                        &mut rep,
                        &peer_addrs_map,
                    );
                    drop(rep);
                    drop(peer_states_mut);
                    report
                };
                let _ = actions;
            }
        }

        // Remove peers inativos
        // Lock order: peer_states → trusted_peers (see GLOBAL LOCK ORDER)
        if !to_remove.is_empty() {
            let mut states = peer_states.write().await;
            let mut peers = trusted_peers.write().await;
            for addr in &to_remove {
                peers.remove(addr);
                states.remove(addr);
                eprintln!("✗ Peer {} removed from trusted list (inactive)", addr);
            }
        }

        // Agenda reconexão para peers com misses
        // Lock order: peer_states (see GLOBAL LOCK ORDER)
        if !to_reconnect.is_empty() {
            let mut states = peer_states.write().await;
            for addr in &to_reconnect {
                if let Some(state) = states.get_mut(addr) {
                    state.schedule_reconnect();
                    eprintln!(
                        "↻ Scheduling reconnect for {} (attempt {})",
                        addr, state.reconnect_attempts
                    );
                }
            }
        }
    }
}
