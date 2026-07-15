//! handshake.rs — Protocolo de handshake seguro (5 fases)
//!
//! Fase 1: Hello — nodeId + ed25519_pubkey + x25519_ephemeral_pubkey + ml_kem_ek + nonce
//! Fase 2: Challenge — challenge_hash(nonce + timestamp + node_id)
//! Fase 3: ChallengeResponse — ed25519_signature(challenge) + x25519_ephemeral_pubkey
//! Fase 4: SessionKeyExchange — ml_kem_ciphertext + x25519_ephemeral_pubkey + signature
//! Fase 5: SessionKeyConfirm — encrypted_ok(session_key)
//!
//! Decisões criptográficas:
//! - Ed25519 para autenticação (rápido, 64 bytes, amplamente auditado)
//! - X25519 efêmero para forward secrecy (chaves descartadas após sessão)
//! - ML-KEM-768 para proteção pós-quântica (FIPS 203, category 3)
//! - HKDF-SHA256 para derivação de chave de sessão (NIST recommended)
//! - ChaCha20-Poly1305 para encriptação (AEAD, resistente a timing attacks)

use std::net::SocketAddr;
use std::time::Instant;
use x25519_dalek::EphemeralSecret;

/// Estado do handshake durante a negociação.
#[derive(Debug, Clone, PartialEq)]
pub enum HandshakePhase {
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
    pub challenge_timestamp: Option<String>,
    pub ml_kem_ciphertext: Option<Vec<u8>>,
    /// Chave efêmera X25519 local (para forward secrecy)
    pub ephemeral_secret: Option<EphemeralSecret>,
    /// Chave pública efêmera X25519 local (enviada ao peer)
    pub ephemeral_public: Option<[u8; 32]>,
    /// Shared secret ML-KEM após encapsulação/desencapsulação
    pub ml_kem_shared: Option<[u8; 32]>,
    /// Chave de sessão derivada (para verificação no SessionKeyConfirm)
    pub session_key: Option<[u8; 32]>,
    /// Timestamp de criação (para timeout de INV-2)
    pub created_at: Instant,
}

impl std::fmt::Debug for PendingHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingHandshake")
            .field("phase", &self.phase)
            .field("remote_addr", &self.remote_addr)
            .field("remote_node_id", &self.remote_node_id)
            .field("remote_ed25519_pubkey", &self.remote_ed25519_pubkey)
            .field("remote_x25519_pubkey", &self.remote_x25519_pubkey)
            .field(
                "remote_ml_kem_ek",
                &self.remote_ml_kem_ek.as_ref().map(|v| v.len()),
            )
            .field("local_nonce", &self.local_nonce)
            .field("remote_nonce", &self.remote_nonce)
            .field("challenge_hash", &self.challenge_hash)
            .field("challenge_timestamp", &self.challenge_timestamp)
            .field(
                "ml_kem_ciphertext",
                &self.ml_kem_ciphertext.as_ref().map(|v| v.len()),
            )
            .field("ephemeral_secret", &"[redacted]")
            .field("ephemeral_public", &self.ephemeral_public)
            .field("ml_kem_shared", &self.ml_kem_shared)
            .field("created_at", &self.created_at.elapsed())
            .finish()
    }
}

impl PendingHandshake {
    /// Retorna true se o handshake expirou (mais de `timeout` sem completar).
    pub fn is_expired(&self, timeout: std::time::Duration) -> bool {
        self.created_at.elapsed() > timeout
    }
    pub fn new_responder(remote_addr: SocketAddr, local_nonce: [u8; 32]) -> Self {
        // Gera chave efêmera X25519 para forward secrecy
        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);
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
            challenge_timestamp: None,
            ml_kem_ciphertext: None,
            ephemeral_secret: Some(ephemeral_secret),
            ephemeral_public: Some(ephemeral_public.to_bytes()),
            ml_kem_shared: None,
            session_key: None,
            created_at: Instant::now(),
        }
    }

    /// Cria handshake pendente para o initiator (quando enviamos Hello).
    /// O caller deve fornecer a chave efêmera já gerada (para usar no Hello).
    pub fn new_initiator(
        remote_addr: SocketAddr,
        local_nonce: [u8; 32],
        ephemeral_secret: EphemeralSecret,
    ) -> Self {
        let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);
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
            challenge_timestamp: None,
            ml_kem_ciphertext: None,
            ephemeral_secret: Some(ephemeral_secret),
            ephemeral_public: Some(ephemeral_public.to_bytes()),
            ml_kem_shared: None,
            session_key: None,
            created_at: Instant::now(),
        }
    }
}

impl Drop for PendingHandshake {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(ref mut secret) = self.ephemeral_secret {
            secret.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_handshake_responder() {
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let hs = PendingHandshake::new_responder(addr, [2u8; 32]);
        assert_eq!(hs.phase, HandshakePhase::HelloReceived);
        assert_eq!(hs.remote_addr, addr);
        assert_eq!(hs.local_nonce, [2u8; 32]);
        assert!(hs.remote_node_id.is_none());
        assert!(hs.ephemeral_secret.is_some());
        assert!(hs.ephemeral_public.is_some());
    }

    #[test]
    fn pending_handshake_initiator() {
        let addr: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let hs = PendingHandshake::new_initiator(addr, [3u8; 32], secret);
        assert_eq!(hs.phase, HandshakePhase::HelloReceived);
        assert_eq!(hs.remote_addr, addr);
        assert_eq!(hs.local_nonce, [3u8; 32]);
        assert!(hs.ephemeral_secret.is_some());
        assert!(hs.ephemeral_public.is_some());
    }

    #[test]
    fn handshake_not_expired_initially() {
        let addr: SocketAddr = "127.0.0.1:9003".parse().unwrap();
        let hs = PendingHandshake::new_responder(addr, [1u8; 32]);
        assert!(!hs.is_expired(std::time::Duration::from_secs(300)));
    }

    #[test]
    fn handshake_expires_after_timeout() {
        let addr: SocketAddr = "127.0.0.1:9004".parse().unwrap();
        let mut hs = PendingHandshake::new_responder(addr, [1u8; 32]);
        // Simula expiração forçando created_at para o passado
        hs.created_at = std::time::Instant::now() - std::time::Duration::from_secs(400);
        assert!(hs.is_expired(std::time::Duration::from_secs(300)));
    }

    #[test]
    fn handshake_phase_transitions() {
        let addr: SocketAddr = "127.0.0.1:9005".parse().unwrap();
        let mut hs = PendingHandshake::new_responder(addr, [1u8; 32]);

        assert_eq!(hs.phase, HandshakePhase::HelloReceived);

        hs.phase = HandshakePhase::ChallengeSent;
        assert_eq!(hs.phase, HandshakePhase::ChallengeSent);

        hs.phase = HandshakePhase::ResponseReceived;
        assert_eq!(hs.phase, HandshakePhase::ResponseReceived);

        hs.phase = HandshakePhase::Complete;
        assert_eq!(hs.phase, HandshakePhase::Complete);
    }

    #[test]
    fn handshake_failed_phase_carries_reason() {
        let phase = HandshakePhase::Failed("invalid signature".to_string());
        assert_eq!(
            phase,
            HandshakePhase::Failed("invalid signature".to_string())
        );
    }

    #[test]
    fn handshake_debug_redacts_ephemeral_secret() {
        let addr: SocketAddr = "127.0.0.1:9006".parse().unwrap();
        let hs = PendingHandshake::new_responder(addr, [1u8; 32]);
        let debug_str = format!("{:?}", hs);
        assert!(
            debug_str.contains("[redacted]"),
            "Debug should redact ephemeral_secret"
        );
        assert!(
            !debug_str.contains("ephemeral_secret: EphemeralSecret"),
            "Debug should not expose raw secret"
        );
    }

    #[test]
    fn handshake_remote_fields_initially_none() {
        let addr: SocketAddr = "127.0.0.1:9007".parse().unwrap();
        let hs = PendingHandshake::new_responder(addr, [1u8; 32]);
        assert!(hs.remote_node_id.is_none());
        assert!(hs.remote_ed25519_pubkey.is_none());
        assert!(hs.remote_x25519_pubkey.is_none());
        assert!(hs.remote_ml_kem_ek.is_none());
        assert!(hs.remote_nonce.is_none());
        assert!(hs.challenge_hash.is_none());
        assert!(hs.challenge_timestamp.is_none());
        assert!(hs.ml_kem_ciphertext.is_none());
        assert!(hs.ml_kem_shared.is_none());
        assert!(hs.session_key.is_none());
    }
}
