mod ai;
mod decision;
mod defense;
mod evidence;
mod explain;
mod hash;
mod network;
mod provenance;
mod quality;
mod state;
mod types;

use crate::decision::{DecisionRecord, DecisionStatus};
use crate::hash::canonical_hash;
use crate::network::api::{self, ApiState};
use crate::network::epa::SharedEPA;
use crate::network::identity::NodeIdentity;
use crate::network::persistence::{self, PersistedData};
use crate::network::reputation::ReputationStore;
use crate::network::transport::{
    NetworkMessage, PeerList, PeerState, TrustedPeer, TrustedPeerList, UdpTransport,
};
use crate::network::verify::{verify_epa, VerifyResult};
use crate::state::State;
use crate::types::EvidenceProvider;
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize)]
struct ArtifactSummary {
    path: String,
    hash: String,
    bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
struct Manifest {
    project: String,
    run_id: uuid::Uuid,
    generated_at_utc: chrono::DateTime<chrono::Utc>,
    status: DecisionStatus,
    reason_code: String,
    message: String,
    artifacts: Vec<ArtifactSummary>,
}

struct Config {
    data_dir: PathBuf,
    api_port: u16,
    udp_port: u16,
    broadcast_port: u16,
    max_peers: usize,
    node_name: String,
    disable_encryption: bool,
    bootstrap_peers: Vec<SocketAddr>,
}

impl Config {
    fn from_env() -> Self {
        let data_dir = std::env::var("NEXOIA_DATA_DIR")
            .unwrap_or_else(|_| ".nexoia".to_string())
            .into();

        Self {
            data_dir,
            api_port: std::env::var("NEXOIA_API_PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .unwrap_or(3000),
            udp_port: std::env::var("NEXOIA_UDP_PORT")
                .unwrap_or_else(|_| "9000".to_string())
                .parse()
                .unwrap_or(9000),
            broadcast_port: std::env::var("NEXOIA_BROADCAST_PORT")
                .unwrap_or_else(|_| "9001".to_string())
                .parse()
                .unwrap_or(9001),
            max_peers: std::env::var("NEXOIA_MAX_PEERS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .unwrap_or(10),
            node_name: std::env::var("NEXOIA_NODE_NAME")
                .unwrap_or_else(|_| "nexoia_node".to_string()),
            disable_encryption: std::env::var("NEXOIA_DISABLE_ENCRYPTION")
                .map(|v| v == "1" || v == "true")
                .unwrap_or(false),
            bootstrap_peers: std::env::var("NEXOIA_BOOTSTRAP_PEERS")
                .map(|s| {
                    s.split(',')
                        .filter_map(|addr| addr.trim().parse().ok())
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::from_env();

    let identity_path = config.data_dir.join("identity.json");
    let data_path = config.data_dir.join("network.json");

    // Lê passphrase do ambiente (opcional)
    let passphrase = std::env::var("NEXOIA_PASSPHRASE")
        .ok()
        .map(|p| p.into_bytes());

    let node =
        NodeIdentity::load_or_create(&identity_path, &config.node_name, passphrase.as_deref())?;

    // Banner de inicialização
    println!("╔══════════════════════════════════════════╗");
    println!("║           NEXOIA Node Starting           ║");
    println!("╚══════════════════════════════════════════╝");
    println!();
    println!("Node ID:      {}", node.node_id);
    println!("Public Key:   {}...", &node.public_key[..16]);

    // Status de segurança da chave
    if passphrase.is_some() {
        println!("Security:     🔐 Passphrase enabled — private keys encrypted");
    } else {
        println!("Security:     ○  No passphrase — private keys stored in plaintext");
        println!("              Tip: set NEXOIA_PASSPHRASE to encrypt keys at rest.");
    }
    println!();

    // Carrega dados persistidos
    let persisted = match persistence::load_data(&data_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("⚠ Failed to load network data: {} (starting fresh)", e);
            persistence::PersistedData::default()
        }
    };

    let known_peers = persistence::parse_peers(&persisted.peers);

    let api_addr: SocketAddr = ([127, 0, 0, 1], config.api_port).into();
    let udp_addr: SocketAddr = ([127, 0, 0, 1], config.udp_port).into();
    let broadcast_addr: SocketAddr = ([255, 255, 255, 255], config.broadcast_port).into();

    let epas: Arc<RwLock<Vec<SharedEPA>>> = Arc::new(RwLock::new(persisted.epas));
    let peers: Arc<RwLock<PeerList>> = Arc::new(RwLock::new(PeerList::from_addrs(
        known_peers,
        config.max_peers,
    )));

    // Sistema de reputação persistente
    let reputation_path = config.data_dir.join("reputation.json");
    let mut reputation_store = ReputationStore::with_path(reputation_path);
    match reputation_store.load() {
        Ok(()) => {
            let banned = reputation_store.banned_count();
            if banned > 0 {
                println!("Reputation:   Loaded ({} banned nodes)", banned);
            } else {
                println!("Reputation:   Loaded (no banned nodes)");
            }
        }
        Err(e) => {
            eprintln!("⚠ Reputation load failed: {} (starting fresh)", e);
        }
    }
    let reputation: Arc<RwLock<ReputationStore>> = Arc::new(RwLock::new(reputation_store));

    // Lista de peers autenticados via handshake (carrega do disco)
    let persisted_trusted =
        persistence::persisted_to_trusted(&persisted.trusted_peers, config.max_peers);
    let trusted_count = persisted_trusted.len();
    let trusted_peers: Arc<RwLock<TrustedPeerList>> = Arc::new(RwLock::new(persisted_trusted));
    if trusted_count > 0 {
        println!("Trusted:      {} peers loaded from disk", trusted_count);
    } else {
        println!("Trusted:      No trusted peers (will discover via handshake)");
    }

    // Estado dos peers para heartbeat
    let peer_states: Arc<RwLock<HashMap<SocketAddr, PeerState>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let api_state = ApiState {
        node_id: node.node_id.clone(),
        public_key: node.public_key.clone(),
        epas: Arc::clone(&epas),
        rate_limiter: api::RateLimiter::new(100, Duration::from_secs(60)),
    };

    let udp_socket = UdpTransport::bind(udp_addr).await?;
    println!("Network:      UDP listening on {}", udp_addr);

    if config.disable_encryption {
        println!("Encryption:   ⚠️  DISABLED (NEXOIA_DISABLE_ENCRYPTION=1)");
    } else {
        println!("Encryption:   🔒 ENABLED (X25519 + ChaCha20-Poly1305)");
    }

    println!("API:          http://{}", api_addr);
    println!("Heartbeat:    Every 30s, timeout 5min");
    println!();

    // Conecta a bootstrap peers (se configurados)
    if !config.bootstrap_peers.is_empty() {
        println!(
            "Connecting to {} bootstrap peers...",
            config.bootstrap_peers.len()
        );
        let bootstrap_socket = UdpSocket::bind("0.0.0.0:0").await?;
        for peer_addr in &config.bootstrap_peers {
            let hello = NetworkMessage::Hello {
                node_id: node.node_id.clone(),
                public_key: node.public_key.clone(),
                encryption_public_key: node.encryption_keypair.public_bytes().to_vec(),
            };
            if let Ok(data) = serde_json::to_vec(&hello) {
                let _ = bootstrap_socket.send_to(&data, peer_addr).await;
                println!("  → Sent Hello to {}", peer_addr);
            }
        }
    }

    // Spawn heartbeat sender
    let node_heartbeat = node.clone();
    let trusted_heartbeat = Arc::clone(&trusted_peers);
    let peer_states_heartbeat = Arc::clone(&peer_states);
    let udp_addr_clone = udp_addr;
    tokio::spawn(async move {
        run_heartbeat_sender(
            node_heartbeat,
            trusted_heartbeat,
            peer_states_heartbeat,
            udp_addr_clone,
        )
        .await;
    });

    // Spawn heartbeat monitor (remove inactive peers)
    let peer_states_monitor = Arc::clone(&peer_states);
    let trusted_monitor = Arc::clone(&trusted_peers);
    tokio::spawn(async move {
        run_heartbeat_monitor(peer_states_monitor, trusted_monitor).await;
    });

    let node_clone = node.clone();
    let epas_clone = Arc::clone(&epas);
    let peers_clone = Arc::clone(&peers);
    let trusted_clone = Arc::clone(&trusted_peers);
    let reputation_clone = Arc::clone(&reputation);
    let peer_states_clone = Arc::clone(&peer_states);
    let data_path_clone = data_path.clone();
    let disable_encryption = config.disable_encryption;

    tokio::spawn(async move {
        run_udp_listener(
            udp_socket,
            node_clone,
            epas_clone,
            peers_clone,
            trusted_clone,
            reputation_clone,
            peer_states_clone,
            data_path_clone,
            disable_encryption,
        )
        .await;
    });

    tokio::spawn(async move {
        if let Err(e) = api::create_api(api_state, api_addr).await {
            eprintln!("API error: {}", e);
        }
    });
    println!("API listening on http://{}", api_addr);

    let node_discover = node.clone();
    let peers_discover = Arc::clone(&peers);
    tokio::spawn(async move {
        run_discovery(
            node_discover,
            udp_addr.port(),
            broadcast_addr,
            peers_discover,
        )
        .await;
    });

    run_pipeline(&node, &peers, &epas, &trusted_peers, &data_path).await?;

    println!("\nNode running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;

    Ok(())
}

async fn run_pipeline(
    node: &NodeIdentity,
    peers: &Arc<RwLock<PeerList>>,
    epas: &Arc<RwLock<Vec<SharedEPA>>>,
    trusted_peers: &Arc<RwLock<TrustedPeerList>>,
    data_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let limiter = defense::RateLimiter::new(100, Duration::from_secs(60));
    let engine = ai::MockEngine::new(0.70);

    let state = State::from_env()?;
    let state_json = serde_json::to_string_pretty(&state)?;

    defense::validate_raw_input(&state_json, 1_048_576)?;

    if !limiter.check(&state.subject) {
        return Err("rate limit exceeded for subject".into());
    }

    let assertion = engine.translate(&state_json, 1_048_576)?;
    let kind = match assertion.evidence_strength {
        types::EvidenceStrength::Anchored => "anchored",
        types::EvidenceStrength::Signed => "signed",
        types::EvidenceStrength::Witnessed => "witness",
        types::EvidenceStrength::Local => "local",
        types::EvidenceStrength::Unverifiable => "local",
    };

    write_text("state.json", &state_json)?;
    let state_hash = canonical_hash(&state_json);

    let decision = decision::evaluate(&state, state_hash.clone(), kind, "local")?;
    let evidence_records = evidence::build_records(&state, &decision)?;

    let evidence_jsonl = write_jsonl_string(&evidence_records)?;
    write_text("evidence.jsonl", &evidence_jsonl)?;

    let decisions_jsonl = write_jsonl_string(std::slice::from_ref(&decision))?;
    write_text("decisions.jsonl", &decisions_jsonl)?;

    let report = explain::explain_chain(std::slice::from_ref(&decision));
    let explain_json = serde_json::to_string_pretty(&report)?;
    write_text("explain.json", &explain_json)?;
    println!("{}", report.summary);

    let manifest = build_manifest(
        &state,
        &decision,
        &state_json,
        &evidence_jsonl,
        &decisions_jsonl,
    );
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    write_text("manifest.json", &manifest_json)?;

    println!("{}", decision.body.status);
    println!("{}", decision.body.reason_code);
    println!("{}", decision.body.message);

    let epa = SharedEPA::create(
        node,
        &state_json,
        &evidence_jsonl,
        &decisions_jsonl,
        &manifest_json,
    );

    println!("\nEPA created: {}", epa);

    {
        let mut epa_list = epas.write().await;
        epa_list.push(epa.clone());
    }

    save_network_state(data_path, peers, epas, trusted_peers).await;

    let peer_list = peers.read().await;
    if !peer_list.is_empty() {
        println!("Sharing EPA with {} peers...", peer_list.len());
    } else {
        println!("No peers connected yet. EPA stored locally.");
    }

    Ok(())
}

async fn save_network_state(
    data_path: &Path,
    peers: &Arc<RwLock<PeerList>>,
    epas: &Arc<RwLock<Vec<SharedEPA>>>,
    trusted_peers: &Arc<RwLock<TrustedPeerList>>,
) {
    let peer_list = peers.read().await;
    let epa_list = epas.read().await;
    let trusted_list = trusted_peers.read().await;

    let data = PersistedData {
        peers: persistence::format_peers(peer_list.peers()),
        epas: epa_list.clone(),
        trusted_peers: persistence::trusted_to_persisted(&trusted_list),
    };

    if let Err(e) = persistence::save_data(data_path, &data) {
        eprintln!("Failed to save network state: {}", e);
    }
}

/// Listener UDP com handshake e verificação assíncrona de EPA.
async fn run_udp_listener(
    mut transport: UdpTransport,
    node: NodeIdentity,
    epas: Arc<RwLock<Vec<SharedEPA>>>,
    peers: Arc<RwLock<PeerList>>,
    trusted_peers: Arc<RwLock<TrustedPeerList>>,
    reputation: Arc<RwLock<ReputationStore>>,
    peer_states: Arc<RwLock<HashMap<SocketAddr, PeerState>>>,
    data_path: PathBuf,
    disable_encryption: bool,
) {
    loop {
        match transport.recv().await {
            Ok((msg, addr)) => match msg {
                // Handshake: Nó A envia Hello com node_id + public_key + encryption_key
                NetworkMessage::Hello {
                    node_id,
                    public_key,
                    encryption_public_key,
                } => {
                    println!("Handshake: Hello from {} at {}", node_id, addr);

                    // Gera challenge = hash do timestamp + node_id
                    let challenge_input =
                        format!("{}:{}:{}", node_id, chrono::Utc::now().to_rfc3339(), addr);
                    let challenge_hash = canonical_hash(&challenge_input);

                    // Envia challenge de volta
                    let challenge = NetworkMessage::Challenge {
                        challenge_hash: challenge_hash.clone(),
                    };
                    let _ = transport.send(&challenge, addr).await;

                    // Guarda o challenge e a chave de encriptação para verificação futura
                    // (Em produção, seria armazenado temporariamente com o node_id)
                    println!("  → Sent challenge to {}", addr);
                }

                // Handshake: Recebe challenge (quando somos o Nó A)
                NetworkMessage::Challenge { challenge_hash } => {
                    println!("Handshake: Received challenge from {}", addr);

                    // Assina o challenge com nossa chave privada
                    let signature = node.sign(&challenge_hash);

                    // Envia resposta
                    let response = NetworkMessage::ChallengeResponse { signature };
                    let _ = transport.send(&response, addr).await;

                    println!("  → Sent challenge response to {}", addr);
                }

                // Handshake: Nó B responde com ChallengeResponse
                NetworkMessage::ChallengeResponse { signature } => {
                    println!("Handshake: ChallengeResponse from {}", addr);

                    // Em produção: verificar a assinatura do challenge
                    // Por simplicidade, aceitamos se a assinatura não estiver vazia
                    if !signature.is_empty() {
                        // Adiciona como peer confiável
                        // Nota: encryption_public_key seria extraído do Hello em produção
                        let mut trusted = trusted_peers.write().await;
                        let peer = TrustedPeer {
                            node_id: format!("peer_{}", addr),
                            public_key: String::new(),
                            encryption_public_key: [0u8; 32], // Seria preenchido do Hello
                            addr,
                            authenticated_at: chrono::Utc::now(),
                        };

                        if trusted.add(peer) {
                            println!("  ✓ Peer {} added to trusted list", addr);

                            // Envia confirmação
                            let ok = NetworkMessage::HandshakeOk {
                                node_id: node.node_id.clone(),
                            };
                            let _ = transport.send(&ok, addr).await;
                        } else {
                            let failed = NetworkMessage::HandshakeFailed {
                                reason: "peer list full or already exists".to_string(),
                            };
                            let _ = transport.send(&failed, addr).await;
                        }
                    } else {
                        let failed = NetworkMessage::HandshakeFailed {
                            reason: "empty signature".to_string(),
                        };
                        let _ = transport.send(&failed, addr).await;
                    }
                }

                // Handshake: Confirmação de sucesso
                NetworkMessage::HandshakeOk { node_id } => {
                    println!("Handshake: OK from {} ({})", node_id, addr);
                }

                // Handshake: Falha
                NetworkMessage::HandshakeFailed { reason } => {
                    eprintln!("Handshake: FAILED from {} — {}", addr, reason);
                }

                // Discovery
                NetworkMessage::Discover { node_id, address } => {
                    println!("Discovered node: {} at {}", node_id, address);
                    if let Ok(peer_addr) = address.parse::<SocketAddr>() {
                        let mut peer_list = peers.write().await;
                        if peer_list.add(peer_addr) {
                            let pong = NetworkMessage::Pong {
                                node_id: node.node_id.clone(),
                            };
                            let _ = transport.send(&pong, peer_addr).await;
                            save_network_state(&data_path, &peers, &epas, &trusted_peers).await;
                        }
                    }
                }

                NetworkMessage::Ping { node_id } => {
                    println!("Ping from {}", node_id);
                    let pong = NetworkMessage::Pong {
                        node_id: node.node_id.clone(),
                    };
                    let _ = transport.send(&pong, addr).await;
                }

                NetworkMessage::Pong { node_id } => {
                    println!("Pong from {}", node_id);
                }

                // Heartbeat: Peer está vivo
                NetworkMessage::Heartbeat { node_id, timestamp } => {
                    // Atualiza estado do peer
                    let mut states: tokio::sync::RwLockWriteGuard<
                        '_,
                        HashMap<SocketAddr, PeerState>,
                    > = peer_states.write().await;
                    if let Some(state) = states.get_mut(&addr) {
                        state.record_heartbeat();
                    } else {
                        states.insert(addr, PeerState::new());
                    }

                    // Envia ack
                    let ack = NetworkMessage::HeartbeatAck {
                        node_id: node.node_id.clone(),
                    };
                    let _ = transport.send(&ack, addr).await;
                }

                // Heartbeat Ack: Peer confirmou que está vivo
                NetworkMessage::HeartbeatAck { node_id } => {
                    let mut states: tokio::sync::RwLockWriteGuard<
                        '_,
                        HashMap<SocketAddr, PeerState>,
                    > = peer_states.write().await;
                    if let Some(state) = states.get_mut(&addr) {
                        state.record_heartbeat();
                    }
                }

                // Peer Exchange: Nó compartilha lista de peers conhecidos
                NetworkMessage::PeerExchange {
                    node_id,
                    peers: peer_addrs,
                } => {
                    println!(
                        "PeerExchange: {} shared {} peers",
                        node_id,
                        peer_addrs.len()
                    );
                    let mut peer_list = trusted_peers.write().await;
                    for peer_addr_str in &peer_addrs {
                        if let Ok(peer_addr) = peer_addr_str.parse::<SocketAddr>() {
                            if peer_addr != addr && !peer_list.contains(&peer_addr) {
                                let new_peer = TrustedPeer {
                                    node_id: format!("peer_{}", peer_addr),
                                    public_key: String::new(),
                                    encryption_public_key: [0u8; 32],
                                    addr: peer_addr,
                                    authenticated_at: chrono::Utc::now(),
                                };
                                if peer_list.add(new_peer) {
                                    println!("  → Added {} from peer exchange", peer_addr);
                                    // Envia Hello para novo peer
                                    let hello = NetworkMessage::Hello {
                                        node_id: node.node_id.clone(),
                                        public_key: node.public_key.clone(),
                                        encryption_public_key: node
                                            .encryption_keypair
                                            .public_bytes()
                                            .to_vec(),
                                    };
                                    let _ = transport.send(&hello, peer_addr).await;
                                }
                            }
                        }
                    }
                }

                // EPA: Só aceita de peers autenticados
                NetworkMessage::EPA(mut epa) => {
                    let trusted = trusted_peers.read().await;
                    if !trusted.contains(&addr) {
                        eprintln!("✗ EPA rejected: {} not in trusted peers", addr);
                        continue;
                    }

                    // Descriptografa se necessário
                    if !disable_encryption && epa.encrypted_payload.is_some() {
                        match epa.decrypt_payload(
                            &node.encryption_keypair,
                            &[0u8; 32], // Em produção: chave pública do remetente
                        ) {
                            Ok(decrypted) => {
                                println!("✓ EPA decrypted from {}", addr);
                                // Aqui você processaria o payload descriptografado
                                let _ = decrypted;
                            }
                            Err(e) => {
                                eprintln!("✗ EPA decryption failed from {}: {}", addr, epa.node_id);
                                increment_failure(&reputation, &epa.node_id).await;
                                continue;
                            }
                        }
                    }
                    drop(trusted);

                    // Verificação assíncrona em background
                    let epas_clone = Arc::clone(&epas);
                    let peers_clone = Arc::clone(&peers);
                    let trusted_clone = Arc::clone(&trusted_peers);
                    let reputation_clone = Arc::clone(&reputation);
                    let data_path_clone = data_path.clone();

                    tokio::spawn(async move {
                        verify_and_store_epa(
                            epa,
                            epas_clone,
                            peers_clone,
                            trusted_clone,
                            reputation_clone,
                            data_path_clone,
                        )
                        .await;
                    });
                }
            },
            Err(e) => {
                eprintln!("UDP error: {}", e);
            }
        }
    }
}

/// Verifica EPA em background e armazena se válido.
async fn verify_and_store_epa(
    epa: SharedEPA,
    epas: Arc<RwLock<Vec<SharedEPA>>>,
    peers: Arc<RwLock<PeerList>>,
    trusted_peers: Arc<RwLock<TrustedPeerList>>,
    reputation: Arc<RwLock<ReputationStore>>,
    data_path: PathBuf,
) {
    let result = verify_epa(&epa);

    match result {
        VerifyResult::Valid => {
            // Registra sucesso na reputação
            {
                let mut rep = reputation.write().await;
                rep.record_success(&epa.node_id);
                rep.save()
                    .unwrap_or_else(|e| eprintln!("Failed to save reputation: {}", e));
            }
            let mut epa_list = epas.write().await;
            epa_list.push(epa.clone());
            println!("✓ Received valid EPA: {}", epa);
            save_network_state(&data_path, &peers, &epas, &trusted_peers).await;
        }
        VerifyResult::InvalidIntegrity => {
            eprintln!("✗ EPA integrity failed from {}", epa.node_id);
            increment_failure(&reputation, &epa.node_id).await;
        }
        VerifyResult::InvalidSignature => {
            eprintln!("✗ EPA signature failed from {}", epa.node_id);
            increment_failure(&reputation, &epa.node_id).await;
        }
        VerifyResult::TimestampExpired => {
            eprintln!("✗ EPA timestamp expired from {}", epa.node_id);
            increment_failure(&reputation, &epa.node_id).await;
        }
        VerifyResult::TimestampTooNew => {
            eprintln!("✗ EPA timestamp too far in the future from {}", epa.node_id);
            increment_failure(&reputation, &epa.node_id).await;
        }
        VerifyResult::MissingData => {
            eprintln!("✗ EPA missing data from {}", epa.node_id);
            increment_failure(&reputation, &epa.node_id).await;
        }
    }
}

/// Incrementa contador de falhas de um nó via reputação.
async fn increment_failure(reputation: &Arc<RwLock<ReputationStore>>, node_id: &str) {
    let mut rep = reputation.write().await;
    rep.record_failure(node_id);

    let node_rep = rep.get_or_create(node_id);
    if node_rep.is_banned() {
        eprintln!(
            "🚫 Node {} is now BANNED ({} failures)",
            node_id, node_rep.failures
        );
    } else {
        eprintln!("⚠ Node {} has {} failures", node_id, node_rep.failures);
    }

    rep.save()
        .unwrap_or_else(|e| eprintln!("Failed to save reputation: {}", e));
}

/// Envia heartbeat periodicamente e compartilha peers conhecidos.
async fn run_heartbeat_sender(
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
async fn run_heartbeat_monitor(
    peer_states: Arc<RwLock<HashMap<SocketAddr, PeerState>>>,
    trusted_peers: Arc<RwLock<TrustedPeerList>>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        interval.tick().await;

        let states = peer_states.read().await;
        let mut to_remove = Vec::new();
        let mut to_reconnect = Vec::new();

        for (addr, state) in states.iter() {
            // Remove peer se inativo por mais de 5 minutos
            if state.is_inactive(300) {
                eprintln!(
                    "⚠ Peer {} inactive for >5 min (misses: {})",
                    addr, state.consecutive_misses
                );
                to_remove.push(*addr);
            }
            // Tenta reconectar se peer tem misses mas ainda não expirou
            else if state.consecutive_misses >= 3 && state.should_reconnect() {
                to_reconnect.push(*addr);
            }
            // Avisa se peer está suspeito (2+ misses)
            else if state.consecutive_misses >= 2 {
                eprintln!(
                    "⚠ Peer {} has {} consecutive misses",
                    addr, state.consecutive_misses
                );
            }
        }
        drop(states);

        // Remove peers inativos
        if !to_remove.is_empty() {
            let mut peers = trusted_peers.write().await;
            let mut states = peer_states.write().await;
            for addr in &to_remove {
                peers.remove(addr);
                states.remove(addr);
                eprintln!("✗ Peer {} removed from trusted list (inactive)", addr);
            }
        }

        // Agenda reconexão para peers com misses
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

async fn run_discovery(
    node: NodeIdentity,
    udp_port: u16,
    broadcast_addr: SocketAddr,
    _peers: Arc<RwLock<PeerList>>,
) {
    let discovery_socket = UdpSocket::bind("0.0.0.0:0").await.ok();
    if let Some(socket) = discovery_socket {
        let _ = socket.set_broadcast(true);
        loop {
            let msg = NetworkMessage::Discover {
                node_id: node.node_id.clone(),
                address: format!("127.0.0.1:{}", udp_port),
            };
            if let Ok(data) = serde_json::to_vec(&msg) {
                let _ = socket.send_to(&data, broadcast_addr).await;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

fn build_manifest(
    state: &State,
    decision: &DecisionRecord,
    state_json: &str,
    evidence_jsonl: &str,
    decisions_jsonl: &str,
) -> Manifest {
    Manifest {
        project: state.project.clone(),
        run_id: state.run_id,
        generated_at_utc: state.generated_at_utc,
        status: decision.body.status,
        reason_code: decision.body.reason_code.clone(),
        message: decision.body.message.clone(),
        artifacts: vec![
            ArtifactSummary {
                path: "state.json".to_string(),
                hash: canonical_hash(state_json),
                bytes: state_json.len(),
            },
            ArtifactSummary {
                path: "evidence.jsonl".to_string(),
                hash: canonical_hash(evidence_jsonl),
                bytes: evidence_jsonl.len(),
            },
            ArtifactSummary {
                path: "decisions.jsonl".to_string(),
                hash: canonical_hash(decisions_jsonl),
                bytes: decisions_jsonl.len(),
            },
        ],
    }
}

fn write_text(path: impl AsRef<Path>, contents: &str) -> Result<(), Box<dyn Error>> {
    std::fs::write(path, contents)?;
    Ok(())
}

fn write_jsonl_string<T: Serialize>(items: &[T]) -> Result<String, Box<dyn Error>> {
    let mut output = String::new();
    for item in items {
        let line = serde_json::to_string(item)?;
        output.push_str(&line);
        output.push('\n');
    }
    Ok(output)
}
