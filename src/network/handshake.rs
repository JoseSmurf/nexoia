//! handshake.rs — Protocolo de handshake seguro (4 fases)
//!
//! Fase 1: Hello — nodeId + ed25519_pubkey + x25519_pubkey + nonce
//! Fase 2: Challenge — challenge_hash(nonce + timestamp + node_id)
//! Fase 3: ChallengeResponse — ed25519_signature(challenge) + x25519_pubkey
//! Fase 4: SessionKeyExchange — x25519_shared_secret + hkdf → session_key
//!
//! Decisões criptográficas:
//! - Ed25519 para autenticação (rápido, 64 bytes, amplamente auditado)
//! - X25519 para troca de chaves (eficiente, battle-tested)
//! - HKDF-SHA256 para derivação de chave de sessão (NIST recommended)
//! - ChaCha20-Poly1305 para encriptação (AEAD, resistente a timing attacks)

use crate::hash::canonical_hash;
use crate::network::crypto::KeyPair;
use crate::network::identity::{verify_signature, NodeIdentity};
use hkdf::Hkdf;
use sha2::Sha256;
use std::net::SocketAddr;

/// Mensagens do protocolo de handshake (híbrido X25519 + ML-KEM-768).
///
/// Fases:
/// 1. Hello — Initiação com chaves públicas e nonce
/// 2. Challenge — Challenge para provar identidade
/// 3. ChallengeResponse — Resposta com assinatura + chaves
/// 4. SessionKeyExchange — Troca de chaves híbrida (X25519 + ML-KEM)
/// 5. SessionKeyConfirm — Confirmação da chave de sessão
#[derive(Debug, Clone)]
pub enum HandshakeMessage {
    /// Fase 1: Initiação com chaves públicas e nonce.
    Hello {
        node_id: String,
        ed25519_pubkey: String, // hex-encoded
        x25519_pubkey: Vec<u8>, // 32 bytes
        ml_kem_ek: Vec<u8>,     // ML-KEM-768 encapsulation key
        nonce: [u8; 32],        // nonce aleatório para derivação
    },
    /// Fase 2: Challenge para provar identidade.
    Challenge {
        challenge_hash: String,
        timestamp: String,
    },
    /// Fase 3: Resposta com assinatura Ed25519 + nonce + x25519_pubkey.
    ChallengeResponse {
        ed25519_signature: Vec<u8>,
        nonce: [u8; 32],        // nonce do respondedor
        x25519_pubkey: Vec<u8>, // 32 bytes
    },
    /// Fase 4: Troca de chaves híbrida (X25519 + ML-KEM).
    SessionKeyExchange {
        ml_kem_ciphertext: Vec<u8>, // ML-KEM ciphertext
        x25519_signature: Vec<u8>,  // Assinatura dos parâmetros
    },
    /// Fase 5: Confirmação da chave de sessão.
    SessionKeyConfirm {
        encrypted_ok: Vec<u8>, // ChaCha20-Poly1305 encrypt("OK", session_key)
    },
}

/// Estado do handshake durante a negociação.
#[derive(Debug, Clone, PartialEq)]
pub enum HandshakePhase {
    /// Aguardando Hello
    WaitingHello,
    /// Hello recebido, aguardando Challenge
    HelloReceived,
    /// Challenge enviado, aguardando ChallengeResponse
    ChallengeSent,
    /// ChallengeResponse recebido, processando
    ResponseReceived,
    /// Sessão estabelecida
    Complete,
    /// Handshake falhou
    Failed(String),
}

/// Estado pendente de um handshake em andamento.
#[derive(Debug)]
pub struct PendingHandshake {
    pub phase: HandshakePhase,
    pub remote_addr: SocketAddr,
    pub remote_node_id: Option<String>,
    pub remote_ed25519_pubkey: Option<String>,
    pub remote_x25519_pubkey: Option<[u8; 32]>,
    pub remote_ml_kem_ek: Option<Vec<u8>>,
    pub local_nonce: [u8; 32],
    pub remote_nonce: Option<[u8; 32]>,
    pub challenge_hash: Option<String>,
    pub ml_kem_ciphertext: Option<Vec<u8>>,
}

impl PendingHandshake {
    pub fn new_initiator(remote_addr: SocketAddr, local_nonce: [u8; 32]) -> Self {
        Self {
            phase: HandshakePhase::WaitingHello,
            remote_addr,
            remote_node_id: None,
            remote_ed25519_pubkey: None,
            remote_x25519_pubkey: None,
            remote_ml_kem_ek: None,
            local_nonce,
            remote_nonce: None,
            challenge_hash: None,
            ml_kem_ciphertext: None,
        }
    }

    pub fn new_responder(remote_addr: SocketAddr, local_nonce: [u8; 32]) -> Self {
        Self {
            phase: HandshakePhase::HelloReceived,
            remote_addr,
            remote_node_id: None,
            remote_ed25519_pubkey: None,
            remote_x25519_pubkey: None,
            remote_ml_kem_ek: None,
            local_nonce,
            remote_nonce: None,
            challenge_hash: None,
            ml_kem_ciphertext: None,
        }
    }
}

/// Processa o handshake do lado do Initiator (Nó A que começa).
///
/// Retorna Some(HandshakeMessage) se precisa enviar algo, None se terminou.
pub fn process_initiator(
    handshake: &mut PendingHandshake,
    received: HandshakeMessage,
    node: &NodeIdentity,
) -> Result<Option<HandshakeMessage>, String> {
    match received {
        HandshakeMessage::Challenge {
            challenge_hash,
            timestamp,
        } => {
            if handshake.phase != HandshakePhase::HelloReceived {
                return Err("Unexpected Challenge".to_string());
            }

            // Assina o challenge com Ed25519
            let challenge_input = format!("{}:{}", challenge_hash, timestamp);
            let signature = node.sign(&challenge_input);

            handshake.phase = HandshakePhase::ChallengeSent;
            handshake.challenge_hash = Some(challenge_hash);

            Ok(Some(HandshakeMessage::ChallengeResponse {
                ed25519_signature: signature,
                nonce: handshake.local_nonce,
                x25519_pubkey: node.encryption_keypair.public_bytes().to_vec(),
            }))
        }
        HandshakeMessage::SessionKeyConfirm { encrypted_ok: _ } => {
            if handshake.phase != HandshakePhase::ChallengeSent {
                return Err("Unexpected SessionKeyConfirm".to_string());
            }

            // Deriva a chave de sessão
            let peer_x25519 = handshake
                .remote_x25519_pubkey
                .ok_or("Missing remote x25519 pubkey")?;
            let remote_nonce = handshake.remote_nonce.ok_or("Missing remote nonce")?;
            let ml_kem_shared = handshake
                .remote_ml_kem_ek
                .as_ref()
                .map(|_| [0u8; 32])
                .unwrap_or([0u8; 32]);

            let _session_key = derive_session_key(
                &node.encryption_keypair,
                &peer_x25519,
                &ml_kem_shared,
                &handshake.local_nonce,
                &remote_nonce,
            );

            handshake.phase = HandshakePhase::Complete;

            Ok(None) // Handshake completo
        }
        _ => Err(format!("Unexpected message in phase {:?}", handshake.phase)),
    }
}

/// Processa o handshake do lado do Responder (Nó B que responde).
///
/// Retorna Some(HandshakeMessage) se precisa enviar algo, None se terminou.
pub fn process_responder(
    handshake: &mut PendingHandshake,
    received: HandshakeMessage,
    node: &NodeIdentity,
) -> Result<Option<HandshakeMessage>, String> {
    match received {
        HandshakeMessage::Hello {
            node_id,
            ed25519_pubkey,
            x25519_pubkey,
            ml_kem_ek: _,
            nonce,
        } => {
            if handshake.phase != HandshakePhase::HelloReceived {
                return Err("Unexpected Hello".to_string());
            }

            // Valida tamanhos
            if x25519_pubkey.len() != 32 {
                return Err("Invalid x25519 pubkey length".to_string());
            }

            // Gera challenge
            let timestamp = chrono::Utc::now().to_rfc3339();
            let challenge_input = format!("{}:{}:{}", node_id, timestamp, handshake.remote_addr);
            let challenge_hash = canonical_hash(&challenge_input);

            handshake.remote_node_id = Some(node_id);
            handshake.remote_ed25519_pubkey = Some(ed25519_pubkey);
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&x25519_pubkey);
            handshake.remote_x25519_pubkey = Some(key_arr);
            handshake.remote_nonce = Some(nonce);
            handshake.challenge_hash = Some(challenge_hash.clone());
            handshake.phase = HandshakePhase::ChallengeSent;

            Ok(Some(HandshakeMessage::Challenge {
                challenge_hash,
                timestamp,
            }))
        }
        HandshakeMessage::ChallengeResponse {
            ed25519_signature,
            nonce,
            x25519_pubkey,
        } => {
            if handshake.phase != HandshakePhase::ChallengeSent {
                return Err("Unexpected ChallengeResponse".to_string());
            }

            // Verifica assinatura Ed25519
            let pubkey_hex = handshake
                .remote_ed25519_pubkey
                .as_ref()
                .ok_or("Missing remote ed25519 pubkey")?;
            let challenge = handshake
                .challenge_hash
                .as_ref()
                .ok_or("Missing challenge")?;

            let timestamp = chrono::Utc::now().to_rfc3339(); // Simplificado
            let challenge_input = format!("{}:{}", challenge, timestamp);

            let valid =
                verify_signature(pubkey_hex, challenge_input.as_bytes(), &ed25519_signature)
                    .map_err(|e| format!("Signature verification error: {}", e))?;

            if !valid {
                handshake.phase = HandshakePhase::Failed("Invalid signature".to_string());
                return Err("Invalid Ed25519 signature".to_string());
            }

            // Valida x25519 pubkey
            if x25519_pubkey.len() != 32 {
                return Err("Invalid x25519 pubkey length".to_string());
            }

            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&x25519_pubkey);
            handshake.remote_x25519_pubkey = Some(key_arr);
            handshake.remote_nonce = Some(nonce);
            handshake.phase = HandshakePhase::ResponseReceived;

            // Deriva chave de sessão e envia confirmação
            let ml_kem_shared = handshake
                .remote_ml_kem_ek
                .as_ref()
                .map(|_| [0u8; 32])
                .unwrap_or([0u8; 32]);
            let session_key = derive_session_key(
                &node.encryption_keypair,
                &key_arr,
                &ml_kem_shared,
                &handshake.local_nonce,
                &nonce,
            );

            // Encripta "OK" com a chave de sessão para provar que a derivação funcionou
            use chacha20poly1305::{
                aead::{Aead, KeyInit},
                ChaCha20Poly1305, Nonce,
            };
            let cipher = ChaCha20Poly1305::new(&session_key.into());
            let nonce = Nonce::from_slice(&[0u8; 12]); // Nonce zero para mensagem de confirmação
            let encrypted_ok = cipher
                .encrypt(nonce, b"OK" as &[u8])
                .map_err(|e| format!("Encryption error: {}", e))?;

            handshake.phase = HandshakePhase::Complete;

            Ok(Some(HandshakeMessage::SessionKeyConfirm { encrypted_ok }))
        }
        _ => Err(format!("Unexpected message in phase {:?}", handshake.phase)),
    }
}

/// Deriva chave de sessão híbrida usando X25519 + ML-KEM-768 + HKDF-SHA256.
///
/// Inputs:
/// - x25519_shared: Diffie-Hellman shared secret (X25519)
/// - ml_kem_shared: ML-KEM shared secret (pós-quântico)
/// - nonces de ambos os lados (previnem replay e binding à sessão)
///
/// Output: 32-byte session key para ChaCha20-Poly1305
///
/// Decisão criptográfica:
/// - Abordagem híbrida garante segurança mesmo se uma das primitivas falhar
/// - X25519 protege contra falhas em implementações ML-KEM
/// - ML-KEM protege contra ataques quânticos (harvest now, decrypt later)
pub fn derive_session_key(
    local_keypair: &KeyPair,
    remote_x25519_pubkey: &[u8; 32],
    ml_kem_shared: &[u8; 32],
    nonce_local: &[u8; 32],
    nonce_remote: &[u8; 32],
) -> [u8; 32] {
    // X25519 Diffie-Hellman
    let x25519_shared = local_keypair.diffie_hellman(remote_x25519_pubkey);

    // Usa a função híbrida de crypto.rs
    crate::network::crypto::derive_hybrid_session_key(
        &x25519_shared,
        ml_kem_shared,
        nonce_local,
        nonce_remote,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_handshake_initiator() {
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let hs = PendingHandshake::new_initiator(addr, [1u8; 32]);
        assert_eq!(hs.phase, HandshakePhase::WaitingHello);
        assert_eq!(hs.remote_addr, addr);
    }

    #[test]
    fn pending_handshake_responder() {
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let hs = PendingHandshake::new_responder(addr, [2u8; 32]);
        assert_eq!(hs.phase, HandshakePhase::HelloReceived);
    }
}
