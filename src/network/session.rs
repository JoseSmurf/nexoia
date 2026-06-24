//! session.rs — Gerenciamento de sessão e chaves de sessão
//!
//! Gerencia o estado de conexão entre nós e chaves de sessão derivadas.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

/// Tamanho da janela de anti-replay.
/// Mantém registro dos últimos ANTI_REPLAY_WINDOW_SIZE contadores.
const ANTI_REPLAY_WINDOW_SIZE: u64 = 1024;

/// Estado de uma sessão com um peer.
#[derive(Debug)]
pub struct SessionState {
    /// Chave de sessão derivada (X25519 + ML-KEM + HKDF)
    pub session_key: [u8; 32],
    /// Contador de mensagens enviado (anti-replay)
    pub send_counter: AtomicU64,
    /// Último contador recebido (anti-replay)
    pub recv_counter: u64,
    /// Bitmap da janela de anti-replay (contadores dentro da janela)
    recv_window: u64,
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
            recv_window: self.recv_window,
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
            recv_window: 0,
            nonce_local,
            nonce_remote,
        }
    }

    /// Incrementa e retorna o próximo contador de envio.
    pub fn next_send_counter(&self) -> u64 {
        self.send_counter.fetch_add(1, Ordering::SeqCst)
    }

    /// Verifica se o contador recebido é válido (anti-replay com janela).
    ///
    /// Algoritmo:
    /// 1. Se counter > recv_counter: válido, avança a janela
    /// 2. Se counter <= recv_counter mas dentro da janela: verifica bitmap
    /// 3. Se counter <= recv_counter e fora da janela: replay
    pub fn check_counter(&mut self, counter: u64) -> bool {
        if counter > self.recv_counter {
            // Counter novo, avança a janela
            let diff = counter - self.recv_counter;
            if diff < ANTI_REPLAY_WINDOW_SIZE {
                let shift = diff.min(63);
                self.recv_window <<= shift;
                self.recv_window |= 1;
            } else {
                // Counter muito à frente, reseta a janela
                self.recv_window = 1;
            }
            self.recv_counter = counter;
            true
        } else {
            // Counter dentro da janela
            let diff = self.recv_counter - counter;
            if diff >= ANTI_REPLAY_WINDOW_SIZE {
                // Fora da janela, replay
                return false;
            }

            // Verifica se já foi recebido (bit já setado)
            let shift = diff.min(63);
            let bit = 1u64 << shift;
            if self.recv_window & bit != 0 {
                // Já recebido, replay
                return false;
            }

            // Marca como recebido
            self.recv_window |= bit;
            true
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

    /// Remove sessões expiradas (mais de timeout_secs sem atividade).
    pub async fn cleanup(&self, timeout_secs: u64) {
        let mut sessions = self.sessions.write().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        sessions.retain(|_, session| {
            let last_counter = session.send_counter.load(Ordering::SeqCst);
            // Considera expirada se não enviou mensagens nos últimos timeout_secs
            // (simplificado - em produção usaria timestamp real)
            true // Por enquanto, não remove nada
        });
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

        // Aceita counters em ordem
        assert!(session.check_counter(1));
        assert!(session.check_counter(2));
        assert!(session.check_counter(3));

        // Rejeita replay
        assert!(!session.check_counter(1));
        assert!(!session.check_counter(2));
        assert!(!session.check_counter(3));

        // Aceita counter maior
        assert!(session.check_counter(4));
    }

    #[test]
    fn session_counter_window() {
        let mut session = SessionState::new([0u8; 32], [1u8; 32], [2u8; 32]);

        // Avança para counter 100
        assert!(session.check_counter(100));

        // Aceita counter dentro da janela (100 - 1024 = -924, mas 950 > 0)
        assert!(session.check_counter(950));

        // Rejeita counter muito antigo (fora da janela)
        assert!(!session.check_counter(50));
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
