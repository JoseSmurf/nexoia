mod ai;
mod decision;
mod defense;
mod evidence;
mod explain;
mod hash;
mod network;
mod nex;
mod provenance;
mod quality;
mod state;
mod types;

use crate::decision::{DecisionRecord, DecisionStatus};
use crate::hash::canonical_hash;
use crate::network::api::{self, ApiState};
use crate::network::epa::SharedEPA;
use crate::network::handshake::{HandshakePhase, PendingHandshake};
use crate::network::identity::NodeIdentity;
use crate::network::persistence::{self, PersistedData};
use crate::network::reputation::ReputationStore;
use crate::network::secure_transport::{generate_handshake_nonce, generate_nonce, SecureMessage};
use crate::network::session::{SessionManager, SessionState};
use crate::network::transport::{
    NetworkMessage, PeerList, PeerState, TrustedPeer, TrustedPeerList, UdpTransport,
};
use crate::network::verify::{verify_epa, VerifyResult};
use crate::nex::action_executor::ActionExecutor;
use crate::nex::reactive::{NetworkEvent, ReactiveEngine};
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
use x25519_dalek::EphemeralSecret;

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
            let nonce = generate_handshake_nonce();
            // Gera chave efêmera X25519 para forward secrecy
            let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
            let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);
            let hello = NetworkMessage::Hello {
                node_id: node.node_id.clone(),
                ed25519_pubkey: node.public_key.clone(),
                x25519_pubkey: ephemeral_public.to_bytes().to_vec(),
                ml_kem_ek: node.ml_kem_keypair.encapsulation_key.clone(),
                nonce,
            };
            if let Ok(data) = serde_json::to_vec(&hello) {
                // Length-prefix framing
                let len = data.len() as u32;
                let mut framed = Vec::with_capacity(4 + data.len());
                framed.extend_from_slice(&len.to_be_bytes());
                framed.extend_from_slice(&data);
                let _ = bootstrap_socket.send_to(&framed, peer_addr).await;
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
    // Spawn heartbeat monitor com ReactiveEngine
    let peer_states_monitor = Arc::clone(&peer_states);
    let trusted_monitor = Arc::clone(&trusted_peers);
    let reputation_monitor = Arc::clone(&reputation);
    let mut reactive_engine = ReactiveEngine::new();

    // Adiciona regras reativas padrão
    reactive_engine.add_rule(crate::nex::reactive::ReactiveRule {
        trigger: crate::nex::ast::Trigger::HeartbeatMiss { threshold: 3 },
        actions: vec![crate::nex::ast::ReactiveAction::Log(
            "Peer possivelmente inativo".to_string(),
        )],
    });
    reactive_engine.add_rule(crate::nex::reactive::ReactiveRule {
        trigger: crate::nex::ast::Trigger::HeartbeatMiss { threshold: 5 },
        actions: vec![crate::nex::ast::ReactiveAction::MarkInactive {
            peer: "default".to_string(),
        }],
    });

    tokio::spawn(async move {
        run_heartbeat_monitor(
            peer_states_monitor,
            trusted_monitor,
            reputation_monitor,
            reactive_engine,
        )
        .await;
    });

    let node_clone = node.clone();
    let epas_clone = Arc::clone(&epas);
    let peers_clone = Arc::clone(&peers);
    let trusted_clone = Arc::clone(&trusted_peers);
    let reputation_clone = Arc::clone(&reputation);
    let peer_states_clone = Arc::clone(&peer_states);
    let data_path_clone = data_path.clone();
    let disable_encryption = config.disable_encryption;
    let session_manager = Arc::new(SessionManager::new());
    let pending_handshakes = Arc::new(RwLock::new(HashMap::new()));

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
            session_manager,
            pending_handshakes,
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
    session_manager: Arc<SessionManager>,
    pending_handshakes: Arc<RwLock<HashMap<SocketAddr, PendingHandshake>>>,
) {
    loop {
        match transport.recv().await {
            Ok((msg, addr)) => match msg {
                // ============================================
                // HANDSHAKE (4 fases)
                // ============================================

                // Fase 1: Hello — Initiação com chaves públicas
                NetworkMessage::Hello {
                    node_id,
                    ed25519_pubkey,
                    x25519_pubkey,
                    ml_kem_ek,
                    nonce,
                } => {
                    println!("Handshake: Hello from {} at {}", node_id, addr);

                    // Cria handshake state do respondedor
                    let local_nonce = generate_handshake_nonce();
                    let mut hs = PendingHandshake::new_responder(addr, local_nonce);
                    hs.remote_node_id = Some(node_id.clone());
                    hs.remote_ed25519_pubkey = Some(ed25519_pubkey.clone());
                    let mut key_arr = [0u8; 32];
                    key_arr.copy_from_slice(&x25519_pubkey);
                    hs.remote_x25519_pubkey = Some(key_arr);
                    hs.remote_nonce = Some(nonce);
                    hs.remote_ml_kem_ek = Some(ml_kem_ek);

                    // Gera challenge
                    let timestamp = chrono::Utc::now().to_rfc3339();
                    let challenge_input = format!("{}:{}:{}", node_id, timestamp, addr);
                    let challenge_hash = canonical_hash(&challenge_input);
                    hs.challenge_hash = Some(challenge_hash.clone());
                    hs.challenge_timestamp = Some(timestamp.clone());
                    hs.phase = HandshakePhase::ChallengeSent;

                    // Salva handshake pendente
                    {
                        let mut pending = pending_handshakes.write().await;
                        pending.insert(addr, hs);
                    }

                    // Envia challenge
                    let challenge = NetworkMessage::Challenge {
                        challenge_hash,
                        timestamp,
                    };
                    let _ = transport.send(&challenge, addr).await;
                    println!("  → Sent challenge to {}", addr);
                }

                // Fase 2: Challenge — Recebido pelo initiator
                NetworkMessage::Challenge {
                    challenge_hash,
                    timestamp,
                } => {
                    println!("Handshake: Received challenge from {}", addr);

                    // Busca handshake pendente
                    let mut pending = pending_handshakes.write().await;
                    let hs = pending.get_mut(&addr);
                    if hs.is_none() {
                        eprintln!("  ✗ No pending handshake for {}", addr);
                        continue;
                    }
                    let hs = hs.unwrap();

                    // Assina o challenge
                    let challenge_input = format!("{}:{}", challenge_hash, timestamp);
                    let signature = node.sign(&challenge_input);

                    // Envia resposta com chave efêmera
                    let ephemeral_pub = match hs.ephemeral_public {
                        Some(ep) => ep,
                        None => node.encryption_keypair.public_bytes(),
                    };
                    let response = NetworkMessage::ChallengeResponse {
                        ed25519_signature: signature,
                        nonce: hs.local_nonce,
                        x25519_pubkey: ephemeral_pub.to_vec(),
                    };
                    let _ = transport.send(&response, addr).await;

                    hs.phase = HandshakePhase::ChallengeSent;
                    println!("  → Sent challenge response to {}", addr);
                }

                // Fase 3: ChallengeResponse — Recebido pelo responder
                NetworkMessage::ChallengeResponse {
                    ed25519_signature,
                    nonce,
                    x25519_pubkey,
                } => {
                    println!("Handshake: ChallengeResponse from {}", addr);

                    // Busca handshake pendente
                    let mut pending = pending_handshakes.write().await;
                    let hs = pending.get_mut(&addr);
                    if hs.is_none() {
                        eprintln!("  ✗ No pending handshake for {}", addr);
                        continue;
                    }
                    let hs = hs.unwrap();

                    // Verifica assinatura Ed25519
                    let pubkey_hex = hs.remote_ed25519_pubkey.as_ref().unwrap();
                    let challenge = hs.challenge_hash.as_ref().unwrap();
                    let timestamp = hs.challenge_timestamp.as_ref().unwrap();
                    let challenge_input = format!("{}:{}", challenge, timestamp);

                    let valid = crate::network::identity::verify_signature(
                        pubkey_hex,
                        challenge_input.as_bytes(),
                        &ed25519_signature,
                    )
                    .unwrap_or(false);

                    if !valid {
                        eprintln!("  ✗ Invalid Ed25519 signature from {}", addr);
                        hs.phase = HandshakePhase::Failed("Invalid signature".to_string());
                        continue;
                    }

                    // Valida x25519 pubkey (chave efêmera do initiator)
                    if x25519_pubkey.len() != 32 {
                        eprintln!("  ✗ Invalid x25519 pubkey length from {}", addr);
                        continue;
                    }

                    let mut key_arr = [0u8; 32];
                    key_arr.copy_from_slice(&x25519_pubkey);
                    hs.remote_x25519_pubkey = Some(key_arr);
                    hs.remote_nonce = Some(nonce);

                    // Encapsula ML-KEM com a chave pública do initiator
                    let ml_kem_shared = match &hs.remote_ml_kem_ek {
                        Some(ek) => {
                            match crate::network::crypto::MlKemKeyPair::from_bytes(ek, &[]) {
                                Ok(keypair) => match keypair.encapsulate() {
                                    Ok((ct, shared)) => {
                                        hs.ml_kem_ciphertext = Some(ct.clone());
                                        Some(shared)
                                    }
                                    Err(e) => {
                                        eprintln!("  ✗ ML-KEM encapsulation failed: {}", e);
                                        continue;
                                    }
                                },
                                Err(e) => {
                                    eprintln!("  ✗ ML-KEM key reconstruction failed: {}", e);
                                    continue;
                                }
                            }
                        }
                        None => {
                            eprintln!("  ✗ No ML-KEM ek from {}", addr);
                            continue;
                        }
                    };

                    // DH com chave efêmera do initiator
                    let ephemeral_secret = hs.ephemeral_secret.take();
                    let ephemeral_secret = match ephemeral_secret {
                        Some(s) => s,
                        None => {
                            eprintln!("  ✗ Missing local ephemeral secret");
                            continue;
                        }
                    };
                    let initiator_ephemeral = x25519_dalek::PublicKey::from(key_arr);
                    let x25519_shared = ephemeral_secret.diffie_hellman(&initiator_ephemeral);

                    // Deriva chave de sessão híbrida
                    let ml_kem_shared = ml_kem_shared.unwrap_or([0u8; 32]);
                    let session_key = crate::network::crypto::derive_hybrid_session_key(
                        x25519_shared.as_bytes(),
                        &ml_kem_shared,
                        &hs.local_nonce,
                        &nonce,
                    );

                    // Salva chave de sessão para verificação no SessionKeyConfirm
                    let session_key_bytes: [u8; 32] = session_key.into();
                    hs.session_key = Some(session_key_bytes);

                    // Assina parâmetros da sessão
                    let mut sign_input = Vec::new();
                    if let Some(ref ct) = hs.ml_kem_ciphertext {
                        sign_input.extend_from_slice(ct);
                    }
                    sign_input.extend_from_slice(&hs.ephemeral_public.unwrap_or([0u8; 32]));
                    sign_input.extend_from_slice(&hs.local_nonce);
                    sign_input.extend_from_slice(&nonce);
                    let signature = node.sign(&String::from_utf8_lossy(&sign_input));

                    // Envia SessionKeyExchange com ciphertext + chave efêmera + assinatura
                    let exchange = NetworkMessage::SessionKeyExchange {
                        ml_kem_ciphertext: hs.ml_kem_ciphertext.clone().unwrap_or_default(),
                        x25519_pubkey: hs.ephemeral_public.unwrap_or([0u8; 32]).to_vec(),
                        signature,
                    };
                    let _ = transport.send(&exchange, addr).await;
                    println!("  → Sent SessionKeyExchange to {}", addr);

                    // Armazena chave de sessão para verificar SessionKeyConfirm depois
                    // (não adiciona peer ainda — espera confirmacao do initiator)
                    let remote_nonce = nonce;
                    let _ = session_key; // Usado na verificacao do SessionKeyConfirm

                    // Salva sessão temporariamente (será confirmada no SessionKeyConfirm)
                    // Nota: a sessão só é confirmada quando o initiator enviar SessionKeyConfirm
                    hs.phase = HandshakePhase::ResponseReceived;
                    println!("  ✓ Waiting for SessionKeyConfirm from {}", addr);
                }

                // Fase 4: SessionKeyExchange — Recebido pelo initiator
                NetworkMessage::SessionKeyExchange {
                    ml_kem_ciphertext,
                    x25519_pubkey: responder_ephemeral_pub,
                    signature: _,
                } => {
                    println!("Handshake: SessionKeyExchange from {}", addr);

                    // Busca handshake pendente
                    let mut pending = pending_handshakes.write().await;
                    let hs = pending.get_mut(&addr);
                    if hs.is_none() {
                        eprintln!("  ✗ No pending handshake for {}", addr);
                        continue;
                    }
                    let hs = hs.unwrap();

                    // 1. Desencapsula ML-KEM
                    let ml_kem_shared = match node.ml_kem_keypair.decapsulate(&ml_kem_ciphertext) {
                        Ok(shared) => shared,
                        Err(e) => {
                            eprintln!("  ✗ ML-KEM decapsulation failed: {}", e);
                            continue;
                        }
                    };
                    hs.ml_kem_shared = Some(ml_kem_shared);

                    // 2. DH com chave efêmera do respondedor
                    if responder_ephemeral_pub.len() != 32 {
                        eprintln!("  ✗ Invalid responder ephemeral x25519 pubkey");
                        continue;
                    }
                    let mut responder_pub_arr = [0u8; 32];
                    responder_pub_arr.copy_from_slice(&responder_ephemeral_pub);

                    let ephemeral_secret = match hs.ephemeral_secret.take() {
                        Some(s) => s,
                        None => {
                            eprintln!("  ✗ Missing local ephemeral secret");
                            continue;
                        }
                    };
                    let x25519_shared = ephemeral_secret
                        .diffie_hellman(&x25519_dalek::PublicKey::from(responder_pub_arr));

                    // 3. Deriva chave de sessão híbrida
                    let session_key = crate::network::crypto::derive_hybrid_session_key(
                        x25519_shared.as_bytes(),
                        &ml_kem_shared,
                        &hs.local_nonce,
                        &hs.remote_nonce.unwrap_or([0u8; 32]),
                    );

                    // 4. Encripta "OK" para confirmar
                    use chacha20poly1305::{
                        aead::{Aead, KeyInit},
                        ChaCha20Poly1305, Nonce,
                    };
                    let cipher = ChaCha20Poly1305::new(&session_key.into());
                    let confirm_nonce = Nonce::from_slice(&[0u8; 12]);
                    let encrypted_ok = cipher
                        .encrypt(confirm_nonce, b"OK" as &[u8])
                        .unwrap_or_default();

                    // Envia SessionKeyConfirm
                    let confirm = NetworkMessage::SessionKeyConfirm { encrypted_ok };
                    let _ = transport.send(&confirm, addr).await;

                    // Adiciona como peer confiável
                    let remote_nonce = hs.remote_nonce.unwrap_or([0u8; 32]);
                    let peer_x25519 = hs.remote_x25519_pubkey.unwrap_or([0u8; 32]);
                    let mut trusted = trusted_peers.write().await;
                    let peer = TrustedPeer {
                        node_id: hs.remote_node_id.clone().unwrap_or_default(),
                        public_key: hs.remote_ed25519_pubkey.clone().unwrap_or_default(),
                        encryption_public_key: peer_x25519,
                        addr,
                        authenticated_at: chrono::Utc::now(),
                    };

                    if trusted.add(peer) {
                        println!("  ✓ Peer {} authenticated and added to trusted list", addr);
                        let session = SessionState::new(session_key, hs.local_nonce, remote_nonce);
                        session_manager.insert(addr, session).await;
                    } else {
                        eprintln!("  ✗ Failed to add peer {} (list full?)", addr);
                    }

                    hs.phase = HandshakePhase::Complete;
                    pending.remove(&addr);
                }

                // Fase 5: SessionKeyConfirm — Recebido pelo responder
                NetworkMessage::SessionKeyConfirm { encrypted_ok } => {
                    println!("Handshake: SessionKeyConfirm from {}", addr);

                    // Busca handshake pendente
                    let mut pending = pending_handshakes.write().await;
                    let hs = pending.get_mut(&addr);
                    if hs.is_none() {
                        eprintln!("  ✗ No pending handshake for {}", addr);
                        continue;
                    }
                    let hs = hs.unwrap();

                    // Recupera chave de sessão derivada na fase anterior
                    let session_key = match hs.session_key {
                        Some(s) => s,
                        None => {
                            eprintln!(
                                "  ✗ Missing session key (SessionKeyExchange not processed?)"
                            );
                            continue;
                        }
                    };

                    let peer_x25519 = hs.remote_x25519_pubkey.unwrap_or([0u8; 32]);
                    let remote_nonce = hs.remote_nonce.unwrap_or([0u8; 32]);

                    // Verifica que "OK" foi descriptografado corretamente
                    use chacha20poly1305::{
                        aead::{Aead, KeyInit},
                        ChaCha20Poly1305, Nonce,
                    };
                    let cipher = ChaCha20Poly1305::new(&session_key.into());
                    let confirm_nonce = Nonce::from_slice(&[0u8; 12]);
                    let decrypted = cipher.decrypt(confirm_nonce, encrypted_ok.as_ref());

                    match decrypted {
                        Ok(msg) if msg == b"OK" => {
                            println!("  ✓ Session key verified with {}", addr);

                            // Adiciona como peer confiável
                            let mut trusted = trusted_peers.write().await;
                            let peer = TrustedPeer {
                                node_id: hs.remote_node_id.clone().unwrap_or_default(),
                                public_key: hs.remote_ed25519_pubkey.clone().unwrap_or_default(),
                                encryption_public_key: peer_x25519,
                                addr,
                                authenticated_at: chrono::Utc::now(),
                            };

                            if trusted.add(peer) {
                                println!("  ✓ Peer {} added to trusted list", addr);

                                // Salva sessão
                                let session =
                                    SessionState::new(session_key, hs.local_nonce, remote_nonce);
                                session_manager.insert(addr, session).await;
                            }

                            hs.phase = HandshakePhase::Complete;
                        }
                        _ => {
                            eprintln!("  ✗ Session key verification failed from {}", addr);
                            hs.phase =
                                HandshakePhase::Failed("Key verification failed".to_string());
                        }
                    }

                    // Remove handshake pendente
                    pending.remove(&addr);
                }

                // ============================================
                // MENSAGENS ENRIPTADAS (após handshake)
                // ============================================
                NetworkMessage::SecureMessage(secure_msg) => {
                    // Busca sessão
                    let session = session_manager.get(&addr).await;
                    if session.is_none() {
                        eprintln!("  ✗ No session for {}", addr);
                        continue;
                    }
                    let session = session.unwrap();

                    // Decripta mensagem
                    match secure_msg.decrypt(&session.session_key) {
                        Ok((counter, payload)) => {
                            // Verifica anti-replay
                            let mut session_mut = session.clone();
                            if !session_mut.check_counter(counter) {
                                eprintln!(
                                    "  ✗ Replay detected from {} (counter={})",
                                    addr, counter
                                );
                                continue;
                            }

                            // Desserializa payload como NetworkMessage
                            let inner_msg: Result<NetworkMessage, _> =
                                serde_json::from_slice(&payload);

                            match inner_msg {
                                Ok(inner) => {
                                    // Processa mensagem interna
                                    // (aqui você processaria EPA, Heartbeat, etc.)
                                    println!(
                                        "  ✓ Received secure message from {} (counter={})",
                                        addr, counter
                                    );
                                }
                                Err(e) => {
                                    eprintln!("  ✗ Failed to deserialize inner message: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("  ✗ Decryption failed from {}: {}", addr, e);
                        }
                    }
                }

                // ============================================
                // MENSAGENS LEGADAS (compatibilidade)
                // ============================================
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
                    // Verifica se tem sessão
                    if !session_manager.contains(&addr).await {
                        eprintln!("  ✗ Heartbeat from unauthenticated peer {}", addr);
                        continue;
                    }

                    // Atualiza estado do peer
                    let mut states = peer_states.write().await;
                    if let Some(state) = states.get_mut(&addr) {
                        state.record_heartbeat();
                    } else {
                        states.insert(addr, PeerState::new());
                    }

                    // Envia ack (encriptado se tiver sessão)
                    if let Some(session) = session_manager.get(&addr).await {
                        let ack_payload = serde_json::to_vec(&NetworkMessage::HeartbeatAck {
                            node_id: node.node_id.clone(),
                        })
                        .unwrap_or_default();

                        let nonce = generate_nonce();
                        let counter = session.next_send_counter();
                        match SecureMessage::encrypt(
                            &ack_payload,
                            &session.session_key,
                            counter,
                            &nonce,
                        ) {
                            Ok(secure_ack) => {
                                let msg = NetworkMessage::SecureMessage(secure_ack);
                                let _ = transport.send(&msg, addr).await;
                            }
                            Err(e) => {
                                eprintln!("  ✗ Failed to encrypt heartbeat ack: {}", e);
                            }
                        }
                    }
                }

                // Heartbeat Ack: Peer confirmou que está vivo
                NetworkMessage::HeartbeatAck { node_id } => {
                    let mut states = peer_states.write().await;
                    if let Some(state) = states.get_mut(&addr) {
                        state.record_heartbeat();
                    }
                }

                // Peer Exchange: Só aceita de peers autenticados
                NetworkMessage::PeerExchange {
                    node_id,
                    peers: peer_addrs,
                } => {
                    // Verifica autenticação
                    if !session_manager.contains(&addr).await {
                        eprintln!("  ✗ PeerExchange from unauthenticated peer {}", addr);
                        continue;
                    }

                    println!(
                        "PeerExchange: {} shared {} peers",
                        node_id,
                        peer_addrs.len()
                    );
                    let mut peer_list = trusted_peers.write().await;
                    for peer_addr_str in &peer_addrs {
                        if let Ok(peer_addr) = peer_addr_str.parse::<SocketAddr>() {
                            if peer_addr != addr && !peer_list.contains(&peer_addr) {
                                // Envia Hello para novo peer (inicia handshake)
                                let nonce = generate_handshake_nonce();
                                // Gera chave efêmera X25519 para forward secrecy
                                let ephemeral_secret =
                                    EphemeralSecret::random_from_rng(rand::rngs::OsRng);
                                let ephemeral_public =
                                    x25519_dalek::PublicKey::from(&ephemeral_secret);
                                let hello = NetworkMessage::Hello {
                                    node_id: node.node_id.clone(),
                                    ed25519_pubkey: node.public_key.clone(),
                                    x25519_pubkey: ephemeral_public.to_bytes().to_vec(),
                                    ml_kem_ek: node.ml_kem_keypair.encapsulation_key.clone(),
                                    nonce,
                                };
                                let _ = transport.send(&hello, peer_addr).await;
                                println!("  → Initiating handshake with {}", peer_addr);
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
                        // Busca chave pública do remetente
                        let sender_pubkey = trusted.get(&addr).map(|p| p.encryption_public_key);
                        if let Some(sender_key) = sender_pubkey {
                            match epa.decrypt_payload(&node.encryption_keypair, &sender_key) {
                                Ok(decrypted) => {
                                    println!("✓ EPA decrypted from {}", addr);
                                    let _ = decrypted;
                                }
                                Err(e) => {
                                    eprintln!(
                                        "✗ EPA decryption failed from {}: {}",
                                        addr, epa.node_id
                                    );
                                    increment_failure(&reputation, &epa.node_id).await;
                                    continue;
                                }
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

                // Mensagens legadas (compatibilidade)
                _ => {
                    println!("  ⚠ Received legacy message from {}", addr);
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
/// Integra o ReactiveEngine com eventos reais da rede.
async fn run_heartbeat_monitor(
    peer_states: Arc<RwLock<HashMap<SocketAddr, PeerState>>>,
    trusted_peers: Arc<RwLock<TrustedPeerList>>,
    reputation: Arc<RwLock<ReputationStore>>,
    mut reactive_engine: ReactiveEngine,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        interval.tick().await;

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
                let mut peer_states_mut = peer_states.write().await;
                let mut rep = reputation.write().await;
                let _report = ActionExecutor::execute(
                    &result.actions,
                    &mut peer_states_mut,
                    &mut rep,
                    &peer_addrs_map,
                );
            }
        }

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
