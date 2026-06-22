use crate::network::epa::SharedEPA;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// Mensagens de rede entre nós.
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
    // Peer Exchange
    PeerExchange {
        node_id: String,
        peers: Vec<String>,
    },
    // Handshake
    Hello {
        node_id: String,
        public_key: String,
        encryption_public_key: Vec<u8>,
    },
    Challenge {
        challenge_hash: String,
    },
    ChallengeResponse {
        signature: Vec<u8>,
    },
    HandshakeOk {
        node_id: String,
    },
    HandshakeFailed {
        reason: String,
    },
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
    pub heartbeat_window: Vec<DateTime<Utc>>,
}

/// Tamanho da janela de heartbeat para sliding window.
const HEARTBEAT_WINDOW_SIZE: usize = 5;

/// Número mínimo de misses na janela para considerar inativo.
const MIN_MISSES_FOR_INACTIVE: u32 = 3;

impl PeerState {
    pub fn new() -> Self {
        Self {
            last_heartbeat: Utc::now(),
            consecutive_misses: 0,
            last_seen: Utc::now(),
            reconnect_attempts: 0,
            next_reconnect: Utc::now(),
            heartbeat_window: Vec::with_capacity(HEARTBEAT_WINDOW_SIZE),
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
        self.heartbeat_window.push(now);
        if self.heartbeat_window.len() > HEARTBEAT_WINDOW_SIZE {
            self.heartbeat_window.remove(0);
        }
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
pub struct TrustedPeerList {
    peers: HashMap<SocketAddr, TrustedPeer>,
    max_peers: usize,
}

impl TrustedPeerList {
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            max_peers,
        }
    }

    pub fn add(&mut self, peer: TrustedPeer) -> bool {
        if self.peers.contains_key(&peer.addr) {
            return false;
        }
        if self.peers.len() >= self.max_peers {
            return false;
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
pub struct UdpTransport {
    socket: UdpSocket,
    recv_buffer: [u8; 65536],
}

impl UdpTransport {
    pub async fn bind(addr: SocketAddr) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self {
            socket,
            recv_buffer: [0; 65536],
        })
    }

    pub async fn send(
        &self,
        msg: &NetworkMessage,
        target: SocketAddr,
    ) -> Result<(), std::io::Error> {
        let data = serde_json::to_vec(msg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.socket.send_to(&data, target).await?;
        Ok(())
    }

    pub async fn broadcast(
        &self,
        msg: &NetworkMessage,
        broadcast_addr: SocketAddr,
    ) -> Result<(), std::io::Error> {
        let data = serde_json::to_vec(msg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.socket.set_broadcast(true)?;
        self.socket.send_to(&data, broadcast_addr).await?;
        self.socket.set_broadcast(false)?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<(NetworkMessage, SocketAddr), std::io::Error> {
        let (len, addr) = self.socket.recv_from(&mut self.recv_buffer).await?;
        let msg: NetworkMessage = serde_json::from_slice(&self.recv_buffer[..len])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
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
            return false;
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
        assert!(!list.add(addr3));
        assert_eq!(list.len(), 2);
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
}
