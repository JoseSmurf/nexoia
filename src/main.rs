// NexoIA — Main entry point
// Lock order: see GLOBAL LOCK ORDER comment below
#![allow(dead_code, unused_imports)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::too_many_arguments)]

mod ai;
mod decision;
mod defense;
mod evidence;
mod explain;
mod hash;
mod lgpd;
mod lgpd_rights;
mod limits;
mod network;
mod nex;
mod pipeline;
mod provenance;
mod quality;
mod state;
mod types;

use crate::limits::{MAX_PEERS, MAX_PENDING_HANDSHAKES};
use crate::network::api::{self, ApiState};
use crate::network::epa::SharedEPA;
use crate::network::handshake::PendingHandshake;
use crate::network::handshake_runner::run_udp_listener;
use crate::network::heartbeat::{run_heartbeat_monitor, run_heartbeat_sender};
use crate::network::identity::NodeIdentity;
use crate::network::listener::run_discovery;
use crate::network::persistence;
use crate::network::reputation::ReputationStore;
use crate::network::secure_transport::generate_handshake_nonce;
use crate::network::session::SessionManager;
use crate::network::transport::{
    NetworkMessage, PeerList, PeerState, TrustedPeerList, UdpTransport,
};
use crate::nex::layers::NexLayer;
use crate::pipeline::run_pipeline;
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use x25519_dalek::EphemeralSecret;

// ╔══════════════════════════════════════════════════════╗
// ║               GLOBAL LOCK ORDER                     ║
// ║  1. peer_states  (heartbeat tracking)               ║
// ║  2. sessions     (SessionManager)                   ║
// ║  3. peers        (PeerList / TrustedPeerList)       ║
// ║  4. reputation   (ReputationStore)                  ║
// ║  5. epas         (Vec<SharedEPA>)                   ║
// ║  6. lgpd_index   (LgpdIndex)                        ║
// ╚══════════════════════════════════════════════════════╝

struct Config {
    data_dir: std::path::PathBuf,
    api_port: u16,
    udp_port: u16,
    broadcast_port: u16,
    max_peers: usize,
    node_name: String,
    disable_encryption: bool,
    bootstrap_peers: Vec<SocketAddr>,
    tls_cert: Option<std::path::PathBuf>,
    tls_key: Option<std::path::PathBuf>,
}

impl Config {
    fn from_env() -> Self {
        let e = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        Config {
            data_dir: e("NEXOIA_DATA_DIR", "data").into(),
            api_port: e("NEXOIA_API_PORT", "8080").parse().unwrap_or(8080),
            udp_port: e("NEXOIA_UDP_PORT", "9000").parse().unwrap_or(9000),
            broadcast_port: e("NEXOIA_BROADCAST_PORT", "9001").parse().unwrap_or(9001),
            max_peers: e("NEXOIA_MAX_PEERS", "10").parse().unwrap_or(10),
            node_name: e("NEXOIA_NODE_NAME", "nexoia-node"),
            disable_encryption: e("NEXOIA_DISABLE_ENCRYPTION", "") == "1",
            bootstrap_peers: e("NEXOIA_BOOTSTRAP_PEERS", "")
                .split(',')
                .filter_map(|s: &str| s.trim().parse::<SocketAddr>().ok())
                .collect(),
            tls_cert: std::env::var("NEXOIA_TLS_CERT")
                .ok()
                .map(std::path::PathBuf::from),
            tls_key: std::env::var("NEXOIA_TLS_KEY")
                .ok()
                .map(std::path::PathBuf::from),
        }
    }
}

async fn bootstrap_peers(
    node: &NodeIdentity,
    cfg: &Config,
    pending: &Arc<RwLock<HashMap<SocketAddr, PendingHandshake>>>,
) {
    if cfg.bootstrap_peers.is_empty() {
        return;
    }
    println!(
        "Connecting to {} bootstrap peers...",
        cfg.bootstrap_peers.len()
    );
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Bootstrap socket error: {}", e);
            return;
        }
    };
    for addr in &cfg.bootstrap_peers {
        let nonce = generate_handshake_nonce();
        let es = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let ep = x25519_dalek::PublicKey::from(&es);
        let ln = generate_handshake_nonce();
        let mut hs = PendingHandshake::new_initiator(*addr, ln, es);
        hs.remote_nonce = Some(nonce);
        {
            let mut p = pending.write().await;
            if p.len() >= MAX_PENDING_HANDSHAKES {
                eprintln!(
                    "MAX_PENDING_HANDSHAKES ({}) reached — rejecting {}",
                    MAX_PENDING_HANDSHAKES, addr
                );
                continue;
            }
            p.insert(*addr, hs);
        }
        let hello = NetworkMessage::Hello {
            node_id: node.node_id.clone(),
            ed25519_pubkey: node.public_key.clone(),
            x25519_pubkey: ep.to_bytes().to_vec(),
            ml_kem_ek: node.ml_kem_keypair.encapsulation_key.clone(),
            nonce,
        };
        if let Ok(data) = serde_json::to_vec(&hello) {
            let len = data.len() as u32;
            let mut framed = Vec::with_capacity(4 + data.len());
            framed.extend_from_slice(&len.to_be_bytes());
            framed.extend_from_slice(&data);
            let _ = socket.send_to(&framed, addr).await;
            println!("  → Sent Hello to {}", addr);
        }
    }
}

fn add_default_rules(re: &mut crate::nex::reactive::ReactiveEngine) {
    let _ = re.add_rule(crate::nex::reactive::ReactiveRule {
        trigger: crate::nex::ast::Trigger::HeartbeatMiss { threshold: 3 },
        actions: vec![crate::nex::ast::ReactiveAction::Log(
            "Peer possivelmente inativo".into(),
        )],
    });
    let _ = re.add_rule(crate::nex::reactive::ReactiveRule {
        trigger: crate::nex::ast::Trigger::HeartbeatMiss { threshold: 5 },
        actions: vec![crate::nex::ast::ReactiveAction::MarkInactive {
            peer: "default".into(),
        }],
    });
}

fn spawn_tasks(
    node: &NodeIdentity,
    cfg: &Config,
    udp_addr: SocketAddr,
    epas: &Arc<RwLock<Vec<SharedEPA>>>,
    peers: &Arc<RwLock<PeerList>>,
    trusted: &Arc<RwLock<TrustedPeerList>>,
    reputation: &Arc<RwLock<ReputationStore>>,
    peer_states: &Arc<RwLock<HashMap<SocketAddr, PeerState>>>,
    sm: &Arc<SessionManager>,
    pending: &Arc<RwLock<HashMap<SocketAddr, PendingHandshake>>>,
    udp_socket: Arc<UdpTransport>,
    provenance_nodes: Arc<RwLock<Vec<crate::provenance::ProvenanceNode>>>,
    data_path: &std::path::Path,
    api_state: ApiState,
    api_addr: SocketAddr,
) {
    tokio::spawn(run_heartbeat_sender(
        node.clone(),
        Arc::clone(trusted),
        Arc::clone(peer_states),
        udp_addr,
    ));
    let mut re = crate::nex::reactive::ReactiveEngine::with_layer(NexLayer::Advanced);

    // Tenta carregar regras de arquivo .nex (env NEXOIA_NEX_RULES)
    if let Ok(nex_path) = std::env::var("NEXOIA_NEX_RULES") {
        match re.load_from_file(&nex_path) {
            Ok(count) => {
                println!("NEX Rules:     Loaded {} rules from {}", count, nex_path);
            }
            Err(e) => {
                eprintln!("⚠ NEX Rules load failed: {} (using defaults)", e);
                add_default_rules(&mut re);
            }
        }
    } else {
        add_default_rules(&mut re);
    }
    tokio::spawn(run_heartbeat_monitor(
        Arc::clone(peer_states),
        Arc::clone(trusted),
        Arc::clone(reputation),
        re,
        Arc::clone(sm),
    ));
    let pc = Arc::clone(pending);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let mut p = pc.write().await;
            let before = p.len();
            p.retain(|a, h| {
                if h.is_expired(Duration::from_secs(300)) {
                    eprintln!("  ⏰ Pending handshake expired for {}", a);
                    false
                } else {
                    true
                }
            });
            let r = before.saturating_sub(p.len());
            if r > 0 {
                eprintln!("Handshake cleanup: removed {} expired", r);
            }
        }
    });
    let dp = data_path.to_path_buf();
    tokio::spawn(run_udp_listener(
        udp_socket,
        node.clone(),
        Arc::clone(epas),
        Arc::clone(peers),
        Arc::clone(trusted),
        Arc::clone(reputation),
        Arc::clone(peer_states),
        dp,
        cfg.disable_encryption,
        Arc::clone(sm),
        Arc::clone(pending),
        Arc::clone(&provenance_nodes),
    ));
    let ac = api_addr;
    let tls_cert = cfg.tls_cert.clone();
    let tls_key = cfg.tls_key.clone();
    tokio::spawn(async move {
        let result = match (tls_cert, tls_key) {
            (Some(cert), Some(key)) => {
                println!(
                    "TLS: ENABLED (cert: {}, key: {})",
                    cert.display(),
                    key.display()
                );
                api::create_api_tls(api_state, ac, &cert, &key).await
            }
            _ => api::create_api(api_state, ac).await,
        };
        if let Err(e) = result {
            eprintln!("API error: {}", e);
        }
    });
    if cfg.tls_cert.is_some() && cfg.tls_key.is_some() {
        println!("API listening on https://{}", api_addr);
    } else {
        println!("API listening on http://{}", api_addr);
    }
    let ba: SocketAddr = ([255, 255, 255, 255], cfg.broadcast_port).into();
    tokio::spawn(run_discovery(
        node.clone(),
        udp_addr.port(),
        ba,
        Arc::clone(peers),
    ));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cfg = Config::from_env();
    let id_path = cfg.data_dir.join("identity.json");
    let data_path = cfg.data_dir.join("network.json");
    let passphrase = std::env::var("NEXOIA_PASSPHRASE")
        .ok()
        .map(|p| p.into_bytes());
    let node = NodeIdentity::load_or_create(&id_path, &cfg.node_name, passphrase.as_deref())?;
    println!("╔══════════════════════════════════════════╗\n║           NEXOIA Node Starting           ║\n╚══════════════════════════════════════════╝\n");
    println!("Node ID:      {}", node.node_id);
    println!("Public Key:   {}...", &node.public_key[..16]);
    if passphrase.is_some() {
        println!("Security:     🔐 Passphrase enabled");
    } else {
        println!("Security:     ○  No passphrase\n              Tip: set NEXOIA_PASSPHRASE to encrypt keys at rest.");
    }
    println!();
    let persisted = match persistence::load_data(&data_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("⚠ Load failed: {} (starting fresh)", e);
            persistence::PersistedData::default()
        }
    };
    let eff_max = cfg.max_peers.min(MAX_PEERS);
    let epas: Arc<RwLock<Vec<SharedEPA>>> = Arc::new(RwLock::new(persisted.epas));
    let peers: Arc<RwLock<PeerList>> = Arc::new(RwLock::new(PeerList::from_addrs(
        persistence::parse_peers(&persisted.peers),
        eff_max,
    )));

    // Reconstrói índice LGPD a partir dos EPAs carregados do disco
    let lgpd_index = Arc::new(RwLock::new(crate::lgpd_rights::LgpdIndex::new()));
    {
        let epas_guard = epas.read().await;
        let mut idx = lgpd_index.write().await;
        idx.build_from_epas(&epas_guard);
        println!(
            "LGPD Index:   Rebuilt from {} EPAs ({} subjects indexed)",
            epas_guard.len(),
            idx.subjects().len()
        );
    }

    // Reconstrói ProvenanceChain a partir dos nós persistidos
    let provenance_nodes: Arc<RwLock<Vec<crate::provenance::ProvenanceNode>>> =
        Arc::new(RwLock::new(persisted.provenance_nodes));
    let derivation_index: Arc<RwLock<crate::provenance::DerivationIndex>> = {
        let nodes = provenance_nodes.read().await;
        Arc::new(RwLock::new(
            crate::provenance::DerivationIndex::build_from_chain_refs(&nodes),
        ))
    };
    {
        let nodes = provenance_nodes.read().await;
        let idx = derivation_index.read().await;
        println!(
            "Provenance:   Loaded {} nodes ({} derivation links)",
            nodes.len(),
            idx.len()
        );
    }
    let mut rep_store = ReputationStore::with_path(cfg.data_dir.join("reputation.json"));
    match rep_store.load() {
        Ok(()) => {
            let b = rep_store.banned_count();
            if b > 0 {
                println!("Reputation:   Loaded ({} banned nodes)", b);
            } else {
                println!("Reputation:   Loaded (no banned nodes)");
            }
        }
        Err(e) => eprintln!("⚠ Reputation load failed: {} (starting fresh)", e),
    }
    let reputation: Arc<RwLock<ReputationStore>> = Arc::new(RwLock::new(rep_store));
    let trusted_data = persistence::persisted_to_trusted(&persisted.trusted_peers, eff_max);
    let tc = trusted_data.len();
    let trusted_peers: Arc<RwLock<TrustedPeerList>> = Arc::new(RwLock::new(trusted_data));
    if tc > 0 {
        println!("Trusted:      {} peers loaded from disk", tc);
    } else {
        println!("Trusted:      No trusted peers (will discover via handshake)");
    }
    let peer_states: Arc<RwLock<HashMap<SocketAddr, PeerState>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let udp_addr: SocketAddr = ([127, 0, 0, 1], cfg.udp_port).into();
    let udp_socket = Arc::new(UdpTransport::bind(udp_addr).await?);
    let api_addr: SocketAddr = ([127, 0, 0, 1], cfg.api_port).into();
    println!("Network:      UDP listening on {}", udp_addr);
    if cfg.disable_encryption {
        println!("Encryption:   ⚠️  DISABLED");
    } else {
        println!("Encryption:   🔒 ENABLED (X25519 + ChaCha20-Poly1305)");
    }
    println!(
        "API:          http://{}\nHeartbeat:    Every 30s, timeout 5min\n",
        api_addr
    );
    let pending = Arc::new(RwLock::new(HashMap::<SocketAddr, PendingHandshake>::new()));
    bootstrap_peers(&node, &cfg, &pending).await;
    let sm = Arc::new(SessionManager::new());
    let api_state = ApiState {
        node_id: node.node_id.clone(),
        public_key: node.public_key.clone(),
        node_identity: node.clone(),
        epas: Arc::clone(&epas),
        peers: Arc::clone(&peers),
        transport: Arc::clone(&udp_socket),
        lgpd_index: Arc::clone(&lgpd_index),
        rate_limiter: Arc::new(crate::defense::RateLimiter::new(
            100,
            Duration::from_secs(60),
        )),
        provenance_nodes: Arc::clone(&provenance_nodes),
        derivation_index: Arc::clone(&derivation_index),
    };
    spawn_tasks(
        &node,
        &cfg,
        udp_addr,
        &epas,
        &peers,
        &trusted_peers,
        &reputation,
        &peer_states,
        &sm,
        &pending,
        udp_socket,
        Arc::clone(&provenance_nodes),
        &data_path,
        api_state,
        api_addr,
    );
    run_pipeline(
        &node,
        &peers,
        &epas,
        &trusted_peers,
        &data_path,
        Some(lgpd_index),
        &provenance_nodes,
    )
    .await?;
    println!("\nNode running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;

    // Graceful shutdown: save state before exiting
    println!("Shutting down... saving state");
    if let Err(e) = reputation.read().await.save() {
        eprintln!("Failed to save reputation: {}", e);
    }
    persistence::save_network_state(&data_path, &peers, &epas, &trusted_peers, &provenance_nodes)
        .await;
    println!("State saved. Goodbye!");

    Ok(())
}
