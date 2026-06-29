// handshake_runner.rs — UDP message loop with handshake and EPA verification
// Lock order: see GLOBAL LOCK ORDER in src/main.rs

use crate::hash::canonical_hash;
use crate::limits::{MAX_EPA_ENTRIES, MAX_PEER_STATES, MAX_PENDING_HANDSHAKES};
use crate::network::epa::SharedEPA;
use crate::network::handshake::{HandshakePhase, PendingHandshake};
use crate::network::identity::NodeIdentity;
use crate::network::persistence::save_network_state;
use crate::network::reputation::ReputationStore;
use crate::network::secure_transport::{generate_handshake_nonce, generate_nonce, SecureMessage};
use crate::network::session::{SessionManager, SessionState};
use crate::network::transport::{
    NetworkMessage, PeerList, PeerState, TrustedPeer, TrustedPeerList, UdpTransport,
};
use crate::network::verify::{verify_epa, VerifyResult};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Result of pending handshake exchange (extracted under lock, used after lock release).
type PendingExchangeResult = ([u8; 32], String, String, [u8; 32], [u8; 32], [u8; 32]);

/// Listener UDP com handshake e verificação assíncrona de EPA.
pub async fn run_udp_listener(
    transport: Arc<UdpTransport>,
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
                        if pending.len() >= MAX_PENDING_HANDSHAKES {
                            eprintln!(
                                "MAX_PENDING_HANDSHAKES ({}) reached — rejecting handshake from {}",
                                MAX_PENDING_HANDSHAKES, addr
                            );
                            continue;
                        }
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

                    // MEM-2 FIX: Usa bloco labelado para garantir cleanup em falhas
                    let result: Result<(), String> = 'hs: {
                        let mut pending = pending_handshakes.write().await;
                        let hs = match pending.get_mut(&addr) {
                            Some(hs) => hs,
                            None => {
                                eprintln!("  ✗ No pending handshake for {}", addr);
                                break 'hs Ok(());
                            }
                        };

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
                            break 'hs Err("Invalid Ed25519 signature".to_string());
                        }

                        // Valida x25519 pubkey (chave efêmera do initiator)
                        if x25519_pubkey.len() != 32 {
                            break 'hs Err("Invalid x25519 pubkey length".to_string());
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
                                            break 'hs Err(format!(
                                                "ML-KEM encapsulation failed: {}",
                                                e
                                            ));
                                        }
                                    },
                                    Err(e) => {
                                        break 'hs Err(format!(
                                            "ML-KEM key reconstruction failed: {}",
                                            e
                                        ));
                                    }
                                }
                            }
                            None => {
                                break 'hs Err("No ML-KEM ek".to_string());
                            }
                        };

                        // DH com chave efêmera do initiator
                        let ephemeral_secret = match hs.ephemeral_secret.take() {
                            Some(s) => s,
                            None => {
                                break 'hs Err("Missing local ephemeral secret".to_string());
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
                        let session_key_bytes = session_key;
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

                        hs.phase = HandshakePhase::ResponseReceived;
                        println!("  ✓ Waiting for SessionKeyConfirm from {}", addr);
                        Ok(())
                    };

                    // MEM-2 FIX: Remove pending handshake em caso de falha
                    if let Err(e) = result {
                        eprintln!("  ✗ ChallengeResponse failed from {}: {}", addr, e);
                        let mut pending = pending_handshakes.write().await;
                        pending.remove(&addr);
                    }
                }

                // Fase 4: SessionKeyExchange — Recebido pelo initiator
                NetworkMessage::SessionKeyExchange {
                    ml_kem_ciphertext,
                    x25519_pubkey: responder_ephemeral_pub,
                    signature: _,
                } => {
                    println!("Handshake: SessionKeyExchange from {}", addr);

                    // Step 1: Compute session key while holding pending, then release
                    let pending_result: Option<PendingExchangeResult> = {
                        let mut pending = pending_handshakes.write().await;
                        let hs = match pending.get_mut(&addr) {
                            Some(hs) => hs,
                            None => {
                                eprintln!("  ✗ No pending handshake for {}", addr);
                                drop(pending);
                                return;
                            }
                        };

                        // 1. Desencapsula ML-KEM
                        let ml_kem_shared =
                            node.ml_kem_keypair.decapsulate(&ml_kem_ciphertext).ok();

                        // 2. DH com chave efêmera do respondedor
                        if responder_ephemeral_pub.len() != 32 {
                            eprintln!("  ✗ Invalid responder ephemeral x25519 pubkey length");
                            drop(pending);
                            return;
                        }
                        let mut responder_pub_arr = [0u8; 32];
                        responder_pub_arr.copy_from_slice(&responder_ephemeral_pub);

                        let ephemeral_secret = match hs.ephemeral_secret.take() {
                            Some(s) => s,
                            None => {
                                eprintln!("  ✗ Missing local ephemeral secret");
                                drop(pending);
                                return;
                            }
                        };
                        let x25519_shared = ephemeral_secret
                            .diffie_hellman(&x25519_dalek::PublicKey::from(responder_pub_arr));

                        // 3. Deriva chave de sessão híbrida
                        let ml_kem_bytes = ml_kem_shared.unwrap_or([0u8; 32]);
                        let session_key = crate::network::crypto::derive_hybrid_session_key(
                            x25519_shared.as_bytes(),
                            &ml_kem_bytes,
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

                        // Extract data for post-lock phase
                        let remote_nonce = hs.remote_nonce.unwrap_or([0u8; 32]);
                        let peer_x25519 = hs.remote_x25519_pubkey.unwrap_or([0u8; 32]);
                        let node_id = hs.remote_node_id.clone().unwrap_or_default();
                        let pub_key = hs.remote_ed25519_pubkey.clone().unwrap_or_default();
                        let local_nonce = hs.local_nonce;
                        hs.phase = HandshakePhase::Complete;

                        // Send confirm BEFORE releasing lock (transport borrows self)
                        let confirm = NetworkMessage::SessionKeyConfirm { encrypted_ok };
                        let _ = transport.send(&confirm, addr).await;
                        println!("  → Sent SessionKeyConfirm to {}", addr);

                        Some((
                            session_key,
                            node_id,
                            pub_key,
                            peer_x25519,
                            local_nonce,
                            remote_nonce,
                        ))
                    };

                    // Step 2: Acquire trusted_peers and session_manager AFTER pending is released
                    if let Some((
                        session_key,
                        node_id,
                        pub_key,
                        peer_x25519,
                        local_nonce,
                        remote_nonce,
                    )) = pending_result
                    {
                        let mut trusted = trusted_peers.write().await;
                        let peer = TrustedPeer {
                            node_id,
                            public_key: pub_key,
                            encryption_public_key: peer_x25519,
                            addr,
                            authenticated_at: chrono::Utc::now(),
                        };

                        if trusted.add(peer) {
                            println!("  ✓ Peer {} authenticated and added to trusted list", addr);
                            let session = SessionState::new(session_key, local_nonce, remote_nonce);
                            session_manager.insert(addr, session).await;
                        } else {
                            eprintln!("  ✗ Failed to add peer {} (list full?)", addr);
                        }
                    }
                }

                // Fase 5: SessionKeyConfirm — Recebido pelo responder
                NetworkMessage::SessionKeyConfirm { encrypted_ok } => {
                    println!("Handshake: SessionKeyConfirm from {}", addr);

                    // Step 1: Extract data from pending, verify OK, release lock
                    let confirm_result: Option<PendingExchangeResult> = {
                        let mut pending = pending_handshakes.write().await;
                        let hs = match pending.get_mut(&addr) {
                            Some(hs) => hs,
                            None => {
                                eprintln!("  ✗ No pending handshake for {}", addr);
                                drop(pending);
                                return;
                            }
                        };

                        let session_key = match hs.session_key {
                            Some(s) => s,
                            None => {
                                eprintln!(
                                    "  ✗ Missing session key (SessionKeyExchange not processed?)"
                                );
                                drop(pending);
                                return;
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

                                let node_id = hs.remote_node_id.clone().unwrap_or_default();
                                let pub_key = hs.remote_ed25519_pubkey.clone().unwrap_or_default();
                                let local_nonce = hs.local_nonce;
                                hs.phase = HandshakePhase::Complete;
                                pending.remove(&addr);

                                Some((
                                    session_key,
                                    node_id,
                                    pub_key,
                                    peer_x25519,
                                    local_nonce,
                                    remote_nonce,
                                ))
                            }
                            _ => {
                                eprintln!("  ✗ Session key verification failed from {}", addr);
                                hs.phase =
                                    HandshakePhase::Failed("Key verification failed".to_string());
                                pending.remove(&addr);
                                None
                            }
                        }
                    };

                    // Step 2: Acquire trusted_peers and session_manager AFTER pending is released
                    if let Some((
                        session_key,
                        node_id,
                        pub_key,
                        peer_x25519,
                        local_nonce,
                        remote_nonce,
                    )) = confirm_result
                    {
                        let mut trusted = trusted_peers.write().await;
                        let peer = TrustedPeer {
                            node_id,
                            public_key: pub_key,
                            encryption_public_key: peer_x25519,
                            addr,
                            authenticated_at: chrono::Utc::now(),
                        };

                        if trusted.add(peer) {
                            println!("  ✓ Peer {} added to trusted list", addr);
                            let session = SessionState::new(session_key, local_nonce, remote_nonce);
                            session_manager.insert(addr, session).await;
                        }
                    }
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
                            // Verifica anti-replay diretamente na sessão armazenada (sem clone-discard)
                            if !session_manager.check_counter(&addr, counter).await {
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
                                Ok(_inner) => {
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
                NetworkMessage::Heartbeat {
                    node_id: _node_id,
                    timestamp: _timestamp,
                } => {
                    // Verifica se tem sessão (lock order: sessions first)
                    if !session_manager.contains(&addr).await {
                        eprintln!("  ✗ Heartbeat from unauthenticated peer {}", addr);
                        continue;
                    }

                    // Atualiza estado do peer
                    {
                        let mut states = peer_states.write().await;
                        if let Some(state) = states.get_mut(&addr) {
                            state.record_heartbeat();
                        } else {
                            if states.len() >= MAX_PEER_STATES {
                                if let Some((evict_addr, _)) =
                                    states.iter().min_by_key(|(_, s)| s.last_seen)
                                {
                                    let evict_addr = *evict_addr;
                                    eprintln!(
                                        "peer_states: evicting peer {} (last_seen={}) to make room",
                                        evict_addr, states[&evict_addr].last_seen
                                    );
                                    states.remove(&evict_addr);
                                }
                            }
                            states.insert(addr, PeerState::new());
                        }
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
                NetworkMessage::HeartbeatAck { node_id: _node_id } => {
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

                    // Step 1: Check which peers are unknown (read-only, no lock held)
                    let unknown_peers: Vec<SocketAddr> = {
                        let peer_list = trusted_peers.read().await;
                        peer_addrs
                            .iter()
                            .filter_map(|s| s.parse::<SocketAddr>().ok())
                            .filter(|&peer_addr| {
                                peer_addr != addr && !peer_list.contains(&peer_addr)
                            })
                            .collect()
                    };

                    // Step 2: Initiate handshakes (no trusted_peers lock held)
                    for peer_addr in &unknown_peers {
                        let nonce = generate_handshake_nonce();
                        let ephemeral_secret =
                            x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
                        let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);

                        let local_nonce = generate_handshake_nonce();
                        let mut hs = PendingHandshake::new_initiator(
                            *peer_addr,
                            local_nonce,
                            ephemeral_secret,
                        );
                        hs.remote_nonce = Some(nonce);
                        {
                            let mut pending = pending_handshakes.write().await;
                            if pending.len() >= MAX_PENDING_HANDSHAKES {
                                eprintln!(
                                    "MAX_PENDING_HANDSHAKES ({}) reached — rejecting handshake from {}",
                                    MAX_PENDING_HANDSHAKES, peer_addr
                                );
                                continue;
                            }
                            pending.insert(*peer_addr, hs);
                        }

                        let hello = NetworkMessage::Hello {
                            node_id: node.node_id.clone(),
                            ed25519_pubkey: node.public_key.clone(),
                            x25519_pubkey: ephemeral_public.to_bytes().to_vec(),
                            ml_kem_ek: node.ml_kem_keypair.encapsulation_key.clone(),
                            nonce,
                        };
                        let _ = transport.send(&hello, *peer_addr).await;
                        println!("  → Initiating handshake with {}", peer_addr);
                    }
                }

                // EPA: Só aceita de peers autenticados
                NetworkMessage::EPA(epa) => {
                    let trusted = trusted_peers.read().await;
                    if !trusted.contains(&addr) {
                        eprintln!("✗ EPA rejected: {} not in trusted peers", addr);
                        continue;
                    }

                    // Descriptografa se necessário
                    if !disable_encryption && epa.encrypted_payload.is_some() {
                        match epa.decrypt_payload(&node.encryption_keypair) {
                            Ok(_decrypted) => {
                                println!("✓ EPA decrypted from {}", addr);
                            }
                            Err(_e) => {
                                eprintln!(
                                    "✗ EPA decryption failed from {} ({})",
                                    addr, epa.node_id
                                );
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
            {
                let mut epa_list = epas.write().await;
                if epa_list.len() >= MAX_EPA_ENTRIES {
                    epa_list.remove(0);
                }
                epa_list.push(epa.clone());
            }
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
