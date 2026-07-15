// listener.rs — UDP broadcast discovery
// Lock order: see GLOBAL LOCK ORDER in src/main.rs

use crate::network::identity::NodeIdentity;
use crate::network::transport::{NetworkMessage, PeerList};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

pub async fn run_discovery(
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
                // Length-prefix framing (4 bytes big-endian)
                let len = data.len() as u32;
                let mut framed = Vec::with_capacity(4 + data.len());
                framed.extend_from_slice(&len.to_be_bytes());
                framed.extend_from_slice(&data);
                let _ = socket.send_to(&framed, broadcast_addr).await;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}
