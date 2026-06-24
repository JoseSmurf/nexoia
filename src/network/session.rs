//! session.rs — Gerenciamento de sessão e chaves de sessão
//!
//! Gerencia o estado de conexão entre nós e chaves de sessão derivadas.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use tokio::sync::RwLock;

/// Tamanho da janela de anti-replay em bits.
const ANTI_REPLAY_WINDOW_SIZE: u64 = 1024;

/// Número de u64 words no bitmap (1024 / 64 = 16).
const WINDOW_WORDS: usize = 16;

/// Estado de uma sessão com um peer.
#[derive(Debug)]
pub struct SessionState {
    /// Chave de sessão derivada (X25519 + ML-KEM + HKDF)
    pub session_key: [u8; 32],
    /// Contador de mensagens enviado (anti-replay)
    pub send_counter: AtomicU64,
    /// Último contador recebido (anti-replay)
    pub recv_counter: u64,
    /// Bitmap da janela de anti-replay (1024 bits = 16 × u64)
    recv_window: [u64; WINDOW_WORDS],
    /// Nonce本次交易
    pub nonce_local: [u8; 32],
    pub nonce_remote: [u8; 32],
    /// Timestamp da última atividade (envio ou recebimento)
    last_activity: Mutex<Instant>,
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
            last_activity: Mutex::new(
                *self
                    .last_activity
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()),
            ),
        }
    }
}

impl SessionState {
    pub fn new(session_key: [u8; 32], nonce_local: [u8; 32], nonce_remote: [u8; 32]) -> Self {
        Self {
            session_key,
            send_counter: AtomicU64::new(0),
            recv_counter: 0,
            recv_window: [0u64; WINDOW_WORDS],
            nonce_local,
            nonce_remote,
            last_activity: Mutex::new(Instant::now()),
        }
    }

    /// Incrementa e retorna o próximo contador de envio.
    pub fn next_send_counter(&self) -> u64 {
        self.touch_activity();
        self.send_counter.fetch_add(1, Ordering::SeqCst)
    }

    /// Verifica se o contador recebido é válido (anti-replay com janela de 1024).
    ///
    /// Algoritmo:
    /// 1. Se counter > recv_counter: válido, avança a janela
    /// 2. Se counter <= recv_counter mas dentro da janela: verifica bitmap
    /// 3. Se counter <= recv_counter e fora da janela: replay
    pub fn check_counter(&mut self, counter: u64) -> bool {
        if counter > self.recv_counter {
            let diff = counter - self.recv_counter;
            if diff < ANTI_REPLAY_WINDOW_SIZE {
                shift_window_left(&mut self.recv_window, diff);
            } else {
                self.recv_window = [0u64; WINDOW_WORDS];
            }
            set_bit(&mut self.recv_window, 0);
            self.recv_counter = counter;
            self.touch_activity();
            true
        } else {
            let diff = self.recv_counter - counter;
            if diff >= ANTI_REPLAY_WINDOW_SIZE {
                return false;
            }

            if get_bit(&self.recv_window, diff) {
                return false;
            }

            set_bit(&mut self.recv_window, diff);
            self.touch_activity();
            true
        }
    }

    /// Retorna true se a sessão expirou (sem atividade por mais de `timeout`).
    pub fn is_expired(&self, timeout: std::time::Duration) -> bool {
        self.last_activity
            .lock()
            .map(|ts| ts.elapsed() > timeout)
            .unwrap_or(false)
    }

    /// Atualiza o timestamp de última atividade.
    fn touch_activity(&self) {
        if let Ok(mut ts) = self.last_activity.lock() {
            *ts = Instant::now();
        }
    }
}

/// Desloca o bitmap para a esquerda em `bits` posições (move bits para posições mais altas).
fn shift_window_left(window: &mut [u64; WINDOW_WORDS], bits: u64) {
    if bits >= ANTI_REPLAY_WINDOW_SIZE {
        *window = [0u64; WINDOW_WORDS];
        return;
    }
    let word_shift = (bits / 64) as usize;
    let bit_shift = (bits % 64) as u32;

    if bit_shift == 0 {
        for i in (word_shift..WINDOW_WORDS).rev() {
            window[i] = window[i - word_shift];
        }
    } else {
        for i in (word_shift..WINDOW_WORDS).rev() {
            let mut val = window[i - word_shift] << bit_shift;
            if i > word_shift {
                val |= window[i - word_shift - 1] >> (64 - bit_shift);
            }
            window[i] = val;
        }
    }
    for i in 0..word_shift.min(WINDOW_WORDS) {
        window[i] = 0;
    }
}

/// Retorna true se o bit na posição `pos` está setado.
fn get_bit(window: &[u64; WINDOW_WORDS], pos: u64) -> bool {
    let word = (pos / 64) as usize;
    let bit = (pos % 64) as u32;
    if word >= WINDOW_WORDS {
        return false;
    }
    window[word] & (1u64 << bit) != 0
}

/// Seta o bit na posição `pos`.
fn set_bit(window: &mut [u64; WINDOW_WORDS], pos: u64) {
    let word = (pos / 64) as usize;
    let bit = (pos % 64) as u32;
    if word < WINDOW_WORDS {
        window[word] |= 1u64 << bit;
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

    /// Retorna o número de sessões ativas.
    pub async fn len(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }

    /// Remove sessões expiradas (mais de timeout_secs sem atividade).
    pub async fn cleanup(&self, timeout_secs: u64) {
        let mut sessions = self.sessions.write().await;
        let timeout = std::time::Duration::from_secs(timeout_secs);

        let before = sessions.len();
        sessions.retain(|addr, session| {
            let alive = !session.is_expired(timeout);
            if !alive {
                eprintln!("Session expired for {} (no activity for {}s)", addr, timeout_secs);
            }
            alive
        });
        let removed = before.saturating_sub(sessions.len());
        if removed > 0 {
            eprintln!("Session cleanup: removed {} expired sessions", removed);
        }
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
        assert!(session.check_counter(3));

        assert!(!session.check_counter(1));
        assert!(!session.check_counter(2));
        assert!(!session.check_counter(3));

        assert!(session.check_counter(4));
    }

    #[test]
    fn session_counter_window() {
        let mut session = SessionState::new([0u8; 32], [1u8; 32], [2u8; 32]);

        assert!(session.check_counter(100));
        assert!(session.check_counter(950));
        assert!(!session.check_counter(50));
    }

    #[test]
    fn anti_replay_accepts_1024_sequential() {
        let mut session = SessionState::new([0u8; 32], [1u8; 32], [2u8; 32]);

        for i in 1..=1024u64 {
            assert!(session.check_counter(i), "counter {} should be accepted", i);
        }
    }

    #[test]
    fn anti_replay_rejects_outside_window() {
        let mut session = SessionState::new([0u8; 32], [1u8; 32], [2u8; 32]);

        // Avança para counter 2048
        assert!(session.check_counter(2048));

        // Counter 1023: diff = 2048 - 1023 = 1025 >= 1024 → replay
        assert!(!session.check_counter(1023));

        // Counter 1024: diff = 2048 - 1024 = 1024 >= 1024 → replay
        assert!(!session.check_counter(1024));
    }

    #[test]
    fn anti_replay_rejects_duplicate_within_window() {
        let mut session = SessionState::new([0u8; 32], [1u8; 32], [2u8; 32]);

        assert!(session.check_counter(100));
        assert!(!session.check_counter(100));
    }

    #[test]
    fn session_expiry() {
        let session = SessionState::new([0u8; 32], [1u8; 32], [2u8; 32]);
        assert!(!session.is_expired(std::time::Duration::from_secs(300)));
    }

    #[tokio::test]
    async fn cleanup_removes_expired_sessions() {
        let manager = SessionManager::new();
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let session = SessionState::new([0u8; 32], [1u8; 32], [2u8; 32]);

        manager.insert(addr, session).await;
        assert_eq!(manager.len().await, 1);

        // Cleanup com timeout de 0 segundos remove tudo
        manager.cleanup(0).await;
        assert_eq!(manager.len().await, 0);
    }

    #[tokio::test]
    async fn cleanup_keeps_fresh_sessions() {
        let manager = SessionManager::new();
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let session = SessionState::new([0u8; 32], [1u8; 32], [2u8; 32]);

        manager.insert(addr, session).await;

        // Cleanup com timeout longo mantém a sessão
        manager.cleanup(300).await;
        assert_eq!(manager.len().await, 1);
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
