use crate::network::epa::SharedEPA;
use ahash::AHashMap;
use bytes::BytesMut;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Mensagens de rede entre nós.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    EPA(SharedEPA),
    Ping {
        node_id: String,
    },
    Pong {
        node_id: String,
    },
    Discover {
        node_id: String,
        address: String,
    },
    // Heartbeat
    Heartbeat {
        node_id: String,
        timestamp: String,
    },
    HeartbeatAck {
        node_id: String,
    },
    // Peer Exchange (após autenticação)
    PeerExchange {
        node_id: String,
        peers: Vec<String>,
    },
    // Handshake (5 fases - híbrido X25519 + ML-KEM-768)
    Hello {
        node_id: String,
        ed25519_pubkey: String,
        x25519_pubkey: Vec<u8>,
        ml_kem_ek: Vec<u8>, // ML-KEM-768 encapsulation key
        nonce: [u8; 32],
    },
    Challenge {
        challenge_hash: String,
        timestamp: String,
    },
    ChallengeResponse {
        ed25519_signature: Vec<u8>,
        nonce: [u8; 32],
        x25519_pubkey: Vec<u8>,
    },
    SessionKeyExchange {
        ml_kem_ciphertext: Vec<u8>,
        x25519_pubkey: Vec<u8>, // responder's ephemeral x25519
        signature: Vec<u8>,     // Ed25519 signature over session params
    },
    SessionKeyConfirm {
        encrypted_ok: Vec<u8>,
    },
    // Mensagem encriptada (após handshake)
    SecureMessage(crate::network::secure_transport::SecureMessage),
}

/// Estado de um peer para controle de heartbeat e reconexão.
/// Usa sliding window para ser tolerante a latência e packet loss.
#[derive(Debug, Clone)]
pub struct PeerState {
    pub last_heartbeat: DateTime<Utc>,
    pub consecutive_misses: u32,
    pub last_seen: DateTime<Utc>,
    pub reconnect_attempts: u32,
    pub next_reconnect: DateTime<Utc>,
    /// Janela de heartbeat: armazena os últimos N heartbeats recebidos
    pub heartbeat_window: SmallVec<[DateTime<Utc>; HEARTBEAT_WINDOW_SIZE]>,
}

/// Tamanho da janela de heartbeat para sliding window.
const HEARTBEAT_WINDOW_SIZE: usize = 5;

/// Número mínimo de misses na janela para considerar inativo.
const MIN_MISSES_FOR_INACTIVE: u32 = 3;

impl Default for PeerState {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerState {
    pub fn new() -> Self {
        Self {
            last_heartbeat: Utc::now(),
            consecutive_misses: 0,
            last_seen: Utc::now(),
            reconnect_attempts: 0,
            next_reconnect: Utc::now(),
            heartbeat_window: SmallVec::new(),
        }
    }

    /// Registra heartbeat recebido (sliding window).
    pub fn record_heartbeat(&mut self) {
        let now = Utc::now();
        self.last_heartbeat = now;
        self.last_seen = now;
        self.consecutive_misses = 0;
        self.reconnect_attempts = 0;

        // Adiciona à janela e mantém apenas os últimos N
        if self.heartbeat_window.len() == HEARTBEAT_WINDOW_SIZE {
            self.heartbeat_window.remove(0);
        }
        self.heartbeat_window.push(now);
    }

    /// Registra miss (heartbeat não recebido).
    pub fn record_miss(&mut self) {
        self.consecutive_misses += 1;
    }

    /// Verifica se o peer está inativo usando sliding window.
    /// Retorna true se mais de MIN_MISSES_FOR_INACTIVE misses na janela.
    pub fn is_inactive(&self, timeout_secs: i64) -> bool {
        // Usa o último heartbeat registrado, não o tempo atual
        // para ser mais tolerante a latência
        if self.heartbeat_window.is_empty() {
            return true;
        }

        let last = self.heartbeat_window.last().unwrap();
        let age = Utc::now() - *last;

        // Inativo se: idade > timeout E misses suficientes
        age > chrono::Duration::seconds(timeout_secs)
            && self.consecutive_misses >= MIN_MISSES_FOR_INACTIVE
    }

    /// Calcula próximo tempo de reconexão com backoff exponencial.
    pub fn schedule_reconnect(&mut self) {
        self.reconnect_attempts += 1;
        // Backoff: 10s, 20s, 40s, 80s, 160s (máx 5 tentativas)
        let backoff_secs = (2u32.pow(self.reconnect_attempts.min(5)) * 5) as i64;
        self.next_reconnect = Utc::now() + chrono::Duration::seconds(backoff_secs);
    }

    /// Verifica se é hora de tentar reconexão.
    pub fn should_reconnect(&self) -> bool {
        Utc::now() >= self.next_reconnect && self.reconnect_attempts <= 5
    }
}

/// Peer autenticado via handshake.
#[derive(Debug, Clone)]
pub struct TrustedPeer {
    pub node_id: String,
    pub public_key: String,
    pub encryption_public_key: [u8; 32],
    pub addr: SocketAddr,
    pub authenticated_at: chrono::DateTime<chrono::Utc>,
}

/// Lista de peers autenticados.
/// Usa AHashMap para performance (DoS-resistant, hardware-accelerated).
pub struct TrustedPeerList {
    peers: AHashMap<SocketAddr, TrustedPeer>,
    max_peers: usize,
}

impl TrustedPeerList {
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: AHashMap::with_capacity(max_peers),
            max_peers,
        }
    }

    pub fn add(&mut self, peer: TrustedPeer) -> bool {
        if self.peers.contains_key(&peer.addr) {
            return false;
        }
        if self.peers.len() >= self.max_peers {
            // Evict oldest peer (by authenticated_at timestamp)
            if let Some((evict_addr, _)) = self.peers.iter().min_by_key(|(_, p)| p.authenticated_at)
            {
                let evict_addr = *evict_addr;
                eprintln!(
                    "TrustedPeerList: evicting oldest peer {} to make room",
                    evict_addr
                );
                self.peers.remove(&evict_addr);
            } else {
                return false;
            }
        }
        self.peers.insert(peer.addr, peer);
        true
    }

    pub fn get(&self, addr: &SocketAddr) -> Option<&TrustedPeer> {
        self.peers.get(addr)
    }

    pub fn contains(&self, addr: &SocketAddr) -> bool {
        self.peers.contains_key(addr)
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn peers(&self) -> Vec<&TrustedPeer> {
        self.peers.values().collect()
    }

    pub fn addrs(&self) -> Vec<SocketAddr> {
        self.peers.keys().copied().collect()
    }

    pub fn remove(&mut self, addr: &SocketAddr) -> bool {
        self.peers.remove(addr).is_some()
    }
}

/// UDP Transport para comunicação entre nós.
/// Usa length-prefix framing para prevenir truncamento de mensagens.
/// Compartilhado via `Arc<UdpTransport>`. O socket UDP permite `send_to` concorrente com `recv_from`.
pub struct UdpTransport {
    socket: UdpSocket,
    /// Pool de buffers para zero-copy receive
    recv_pool: Mutex<Vec<BytesMut>>,
}

impl UdpTransport {
    pub async fn bind(addr: SocketAddr) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self {
            socket,
            recv_pool: Mutex::new(Vec::with_capacity(32)),
        })
    }

    /// Envia mensagem com length-prefix framing (4 bytes big-endian).
    pub async fn send(
        &self,
        msg: &NetworkMessage,
        target: SocketAddr,
    ) -> Result<(), std::io::Error> {
        let data = serde_json::to_vec(msg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Length-prefix framing: 4 bytes + payload
        let len = data.len() as u32;
        let mut framed = Vec::with_capacity(4 + data.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&data);

        self.socket.send_to(&framed, target).await?;
        Ok(())
    }

    pub async fn broadcast(
        &self,
        msg: &NetworkMessage,
        broadcast_addr: SocketAddr,
    ) -> Result<(), std::io::Error> {
        let data = serde_json::to_vec(msg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Length-prefix framing
        let len = data.len() as u32;
        let mut framed = Vec::with_capacity(4 + data.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&data);

        self.socket.set_broadcast(true)?;
        self.socket.send_to(&framed, broadcast_addr).await?;
        self.socket.set_broadcast(false)?;
        Ok(())
    }

    /// Recebe mensagem com length-prefix framing usando buffer pool (zero-copy).
    pub async fn recv(&self) -> Result<(NetworkMessage, SocketAddr), std::io::Error> {
        // Pega buffer do pool ou aloca novo
        let mut buf = {
            let mut pool = self.recv_pool.lock();
            let mut b = pool.pop().unwrap_or_else(|| BytesMut::with_capacity(65536));
            // Resize to capacity so recv_from has space to write
            b.resize(b.capacity(), 0);
            b
        };

        let (len, addr) = self.socket.recv_from(&mut buf).await?;

        if len < 4 {
            // Devolve buffer ao pool
            buf.clear();
            self.recv_pool.lock().push(buf);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Message too short for frame header",
            ));
        }

        // Lê length prefix
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&buf[..4]);
        let expected_len = u32::from_be_bytes(len_bytes) as usize;

        if len < 4 + expected_len {
            buf.clear();
            self.recv_pool.lock().push(buf);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Message truncated",
            ));
        }

        // Parse JSON do payload (precisa copiar para owned para deserialize)
        let payload = &buf[4..4 + expected_len];
        let msg: NetworkMessage = serde_json::from_slice(payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Devolve buffer ao pool
        buf.clear();
        self.recv_pool.lock().push(buf);

        Ok((msg, addr))
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.socket.local_addr()
    }
}

/// Lista de peers (legado, mantida para compatibilidade).
pub struct PeerList {
    peers: Vec<SocketAddr>,
    max_peers: usize,
}

impl PeerList {
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: Vec::new(),
            max_peers,
        }
    }

    pub fn from_addrs(addrs: Vec<SocketAddr>, max_peers: usize) -> Self {
        let mut list = Self::new(max_peers);
        for addr in addrs {
            list.add(addr);
        }
        list
    }

    pub fn add(&mut self, addr: SocketAddr) -> bool {
        if self.peers.contains(&addr) {
            return false;
        }
        if self.peers.len() >= self.max_peers {
            // Evict oldest peer (first in list = oldest)
            if !self.peers.is_empty() {
                let evicted = self.peers.remove(0);
                eprintln!("PeerList: evicting oldest peer {} to make room", evicted);
            } else {
                return false;
            }
        }
        self.peers.push(addr);
        true
    }

    pub fn remove(&mut self, addr: &SocketAddr) -> bool {
        let len_before = self.peers.len();
        self.peers.retain(|&a| a != *addr);
        self.peers.len() < len_before
    }

    pub fn contains(&self, addr: &SocketAddr) -> bool {
        self.peers.contains(addr)
    }

    pub fn peers(&self) -> &[SocketAddr] {
        &self.peers
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_list_add_and_remove() {
        let mut list = PeerList::new(3);
        let addr1: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:9002".parse().unwrap();

        assert!(list.add(addr1));
        assert!(list.add(addr2));
        assert!(!list.add(addr1));
        assert_eq!(list.len(), 2);

        assert!(list.remove(&addr1));
        assert_eq!(list.len(), 1);
        assert!(!list.contains(&addr1));
        assert!(list.contains(&addr2));
    }

    #[test]
    fn peer_list_max_capacity() {
        let mut list = PeerList::new(2);
        let addr1: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        let addr3: SocketAddr = "127.0.0.1:9003".parse().unwrap();

        assert!(list.add(addr1));
        assert!(list.add(addr2));
        // Evicts oldest (addr1), then adds addr3
        assert!(list.add(addr3));
        assert_eq!(list.len(), 2);
        assert!(!list.contains(&addr1));
        assert!(list.contains(&addr3));
    }

    #[test]
    fn trusted_peer_list_basic() {
        let mut list = TrustedPeerList::new(2);
        let addr1: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:9002".parse().unwrap();

        let peer1 = TrustedPeer {
            node_id: "node_a".to_string(),
            public_key: "key_a".to_string(),
            encryption_public_key: [1u8; 32],
            addr: addr1,
            authenticated_at: chrono::Utc::now(),
        };

        let peer2 = TrustedPeer {
            node_id: "node_b".to_string(),
            public_key: "key_b".to_string(),
            encryption_public_key: [2u8; 32],
            addr: addr2,
            authenticated_at: chrono::Utc::now(),
        };

        assert!(list.add(peer1.clone()));
        assert!(list.add(peer2));
        assert!(!list.add(peer1));
        assert_eq!(list.len(), 2);
        assert!(list.contains(&addr1));
        assert!(list.contains(&addr2));
    }

    #[test]
    fn trusted_peer_list_evicts_oldest() {
        let mut list = TrustedPeerList::new(2);
        let addr1: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        let addr3: SocketAddr = "127.0.0.1:9003".parse().unwrap();

        let peer1 = TrustedPeer {
            node_id: "node_a".to_string(),
            public_key: "key_a".to_string(),
            encryption_public_key: [1u8; 32],
            addr: addr1,
            authenticated_at: chrono::Utc::now() - chrono::Duration::hours(1),
        };
        let peer2 = TrustedPeer {
            node_id: "node_b".to_string(),
            public_key: "key_b".to_string(),
            encryption_public_key: [2u8; 32],
            addr: addr2,
            authenticated_at: chrono::Utc::now(),
        };
        let peer3 = TrustedPeer {
            node_id: "node_c".to_string(),
            public_key: "key_c".to_string(),
            encryption_public_key: [3u8; 32],
            addr: addr3,
            authenticated_at: chrono::Utc::now(),
        };

        assert!(list.add(peer1));
        assert!(list.add(peer2));
        assert!(list.add(peer3)); // evicts peer1 (oldest)
        assert_eq!(list.len(), 2);
        assert!(!list.contains(&addr1));
        assert!(list.contains(&addr2));
        assert!(list.contains(&addr3));
    }

    #[test]
    fn trusted_peer_list_remove() {
        let mut list = TrustedPeerList::new(5);
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let peer = TrustedPeer {
            node_id: "node_a".to_string(),
            public_key: "key_a".to_string(),
            encryption_public_key: [1u8; 32],
            addr,
            authenticated_at: chrono::Utc::now(),
        };
        assert!(list.add(peer));
        assert!(list.remove(&addr));
        assert!(!list.contains(&addr));
        assert!(!list.remove(&addr)); // removing again returns false
    }

    #[test]
    fn trusted_peer_list_peers_and_addrs() {
        let mut list = TrustedPeerList::new(5);
        let addr1: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:9002".parse().unwrap();

        list.add(TrustedPeer {
            node_id: "a".to_string(),
            public_key: "k".to_string(),
            encryption_public_key: [1u8; 32],
            addr: addr1,
            authenticated_at: chrono::Utc::now(),
        });
        list.add(TrustedPeer {
            node_id: "b".to_string(),
            public_key: "k".to_string(),
            encryption_public_key: [2u8; 32],
            addr: addr2,
            authenticated_at: chrono::Utc::now(),
        });

        assert_eq!(list.peers().len(), 2);
        assert_eq!(list.addrs().len(), 2);
    }

    // ── PeerState tests (heartbeat) ─────────────────────────

    #[test]
    fn peer_state_new_has_no_misses() {
        let state = PeerState::new();
        assert_eq!(state.consecutive_misses, 0);
        assert!(state.heartbeat_window.is_empty());
    }

    #[test]
    fn peer_state_record_heartbeat_resets_misses() {
        let mut state = PeerState::new();
        state.consecutive_misses = 5;
        state.record_heartbeat();
        assert_eq!(state.consecutive_misses, 0);
    }

    #[test]
    fn peer_state_record_miss_increments() {
        let mut state = PeerState::new();
        state.record_miss();
        assert_eq!(state.consecutive_misses, 1);
        state.record_miss();
        assert_eq!(state.consecutive_misses, 2);
    }

    #[test]
    fn peer_state_sliding_window_limits_size() {
        let mut state = PeerState::new();
        for _ in 0..10 {
            state.record_heartbeat();
        }
        assert!(
            state.heartbeat_window.len() <= HEARTBEAT_WINDOW_SIZE,
            "Window should be capped at {}, got {}",
            HEARTBEAT_WINDOW_SIZE,
            state.heartbeat_window.len()
        );
    }

    #[test]
    fn peer_state_inactive_when_empty_window() {
        let state = PeerState::new();
        assert!(state.is_inactive(300));
    }

    #[test]
    fn peer_state_not_inactive_after_heartbeat() {
        let mut state = PeerState::new();
        state.record_heartbeat();
        assert!(!state.is_inactive(300));
    }

    #[test]
    fn peer_state_reconnect_backoff_increases() {
        let mut state = PeerState::new();
        state.schedule_reconnect();
        let first_backoff = state.next_reconnect;
        state.schedule_reconnect();
        let second_backoff = state.next_reconnect;
        assert!(
            second_backoff > first_backoff,
            "Backoff should increase with each attempt"
        );
    }

    #[test]
    fn peer_state_reconnect_stops_after_max_attempts() {
        let mut state = PeerState::new();
        for _ in 0..6 {
            state.schedule_reconnect();
        }
        assert!(!state.should_reconnect());
    }

    #[test]
    fn peer_state_reconnect_allowed_initially() {
        let state = PeerState::new();
        assert!(state.should_reconnect());
    }
}
