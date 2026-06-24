//! session.rs — Gerenciamento de sessão e chaves de sessão
//!
//! Gerencia o estado de conexão entre nós e chaves de sessão derivadas.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

/// Estado de uma sessão com um peer.
#[derive(Debug)]
pub struct SessionState {
    /// Chave de sessão derivada (X25519 + HKDF)
    pub session_key: [u8; 32],
    /// Contador de mensagens enviado (anti-replay)
    pub send_counter: AtomicU64,
    /// Último contador recebido (anti-replay)
    pub recv_counter: u64,
    /// Nonce本次交易
    pub nonce_local: [u8; 32],
    pub nonce_remote: [u8; 32],
}

impl Clone for SessionState {
    fn clone(&self) -> Self {
        Self {
            session_key: self.session_key,
            send_counter: AtomicU64::new(self.send_counter.load(Ordering::SeqCst)),
            recv_counter: self.recv_counter,
            nonce_local: self.nonce_local,
            nonce_remote: self.nonce_remote,
        }
    }
}

impl SessionState {
    pub fn new(session_key: [u8; 32], nonce_local: [u8; 32], nonce_remote: [u8; 32]) -> Self {
        Self {
            session_key,
            send_counter: AtomicU64::new(0),
            recv_counter: 0,
            nonce_local,
            nonce_remote,
        }
    }

    /// Incrementa e retorna o próximo contador de envio.
    pub fn next_send_counter(&self) -> u64 {
        self.send_counter.fetch_add(1, Ordering::SeqCst)
    }

    /// Verifica se o contador recebido é válido (anti-replay).
    /// Retorna true se o contador é maior que o último recebido.
    pub fn check_counter(&mut self, counter: u64) -> bool {
        if counter > self.recv_counter {
            self.recv_counter = counter;
            true
        } else {
            false // Replay detectado
        }
    }
}

/// Gerenciador de sessões ativas.
pub struct SessionManager {
    sessions: RwLock<HashMap<SocketAddr, SessionState>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Registra uma nova sessão após handshake completo.
    pub async fn insert(&self, addr: SocketAddr, session: SessionState) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(addr, session);
    }

    /// Obtém a sessão de um peer.
    pub async fn get(&self, addr: &SocketAddr) -> Option<SessionState> {
        let sessions = self.sessions.read().await;
        sessions.get(addr).cloned()
    }

    /// Remove a sessão de um peer.
    pub async fn remove(&self, addr: &SocketAddr) -> bool {
        let mut sessions = self.sessions.write().await;
        sessions.remove(addr).is_some()
    }

    /// Verifica se existe sessão ativa com um peer.
    pub async fn contains(&self, addr: &SocketAddr) -> bool {
        let sessions = self.sessions.read().await;
        sessions.contains_key(addr)
    }

    /// Retorna todas as sessões ativas.
    pub async fn all_addrs(&self) -> Vec<SocketAddr> {
        let sessions = self.sessions.read().await;
        sessions.keys().copied().collect()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_counter_increment() {
        let session = SessionState::new([0u8; 32], [1u8; 32], [2u8; 32]);
        assert_eq!(session.next_send_counter(), 0);
        assert_eq!(session.next_send_counter(), 1);
        assert_eq!(session.next_send_counter(), 2);
    }

    #[test]
    fn session_counter_replay_detection() {
        let mut session = SessionState::new([0u8; 32], [1u8; 32], [2u8; 32]);
        assert!(session.check_counter(1));
        assert!(session.check_counter(2));
        assert!(!session.check_counter(1)); // Replay
        assert!(!session.check_counter(2)); // Replay
        assert!(session.check_counter(3)); // Novo
    }

    #[tokio::test]
    async fn session_manager_insert_and_get() {
        let manager = SessionManager::new();
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let session = SessionState::new([0u8; 32], [1u8; 32], [2u8; 32]);

        manager.insert(addr, session).await;
        assert!(manager.contains(&addr).await);
        assert!(manager.get(&addr).await.is_some());
    }
}
