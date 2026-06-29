use crate::network::epa::SharedEPA;
use crate::network::transport::{PeerList, TrustedPeer, TrustedPeerList};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PersistedData {
    pub peers: Vec<String>,
    pub epas: Vec<SharedEPA>,
    pub trusted_peers: Vec<PersistedTrustedPeer>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedTrustedPeer {
    pub node_id: String,
    pub public_key: String,
    pub encryption_public_key: Vec<u8>,
    pub addr: String,
}

pub fn load_data(path: &Path) -> Result<PersistedData, std::io::Error> {
    if !path.exists() {
        return Ok(PersistedData::default());
    }
    let data = std::fs::read_to_string(path)?;
    let persisted: PersistedData = serde_json::from_str(&data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Validação e limpeza de dados corrompidos
    let mut valid_peers = Vec::new();
    let mut invalid_count = 0;
    for peer_addr in &persisted.peers {
        if peer_addr.parse::<SocketAddr>().is_ok() {
            valid_peers.push(peer_addr.clone());
        } else {
            invalid_count += 1;
        }
    }
    if invalid_count > 0 {
        eprintln!(
            "⚠ Skipped {} invalid peer addresses in network.json",
            invalid_count
        );
    }

    let mut valid_trusted = Vec::new();
    let mut invalid_trusted = 0;
    for trusted in &persisted.trusted_peers {
        if trusted.node_id.is_empty() || trusted.addr.is_empty() {
            invalid_trusted += 1;
            continue;
        }
        if trusted.addr.parse::<SocketAddr>().is_err() {
            invalid_trusted += 1;
            continue;
        }
        valid_trusted.push(trusted.clone());
    }
    if invalid_trusted > 0 {
        eprintln!(
            "⚠ Skipped {} invalid trusted peers in network.json",
            invalid_trusted
        );
    }

    let mut valid_epas = Vec::new();
    let mut invalid_epas = 0;
    for epa in &persisted.epas {
        if epa.epa_id.is_empty() || epa.node_id.is_empty() {
            invalid_epas += 1;
            continue;
        }
        valid_epas.push(epa.clone());
    }
    if invalid_epas > 0 {
        eprintln!("⚠ Skipped {} invalid EPAs in network.json", invalid_epas);
    }

    Ok(PersistedData {
        peers: valid_peers,
        trusted_peers: valid_trusted,
        epas: valid_epas,
    })
}

pub fn save_data(path: &Path, data: &PersistedData) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Escrita atômica: escreve em arquivo temporário + rename
    // Isso previne corrupção se o nó crashar no meio da escrita
    let temp_path = path.with_extension("json.tmp");
    std::fs::write(&temp_path, &json)?;

    // Rename é atômico no Unix, garante que ou o arquivo antigo ou o novo existe
    #[cfg(unix)]
    std::fs::rename(&temp_path, path)?;

    // No Windows, rename não é atômico, mas é a melhor opção disponível
    #[cfg(not(unix))]
    std::fs::rename(&temp_path, path)?;

    Ok(())
}

pub fn parse_peers(peers: &[String]) -> Vec<SocketAddr> {
    peers.iter().filter_map(|s| s.parse().ok()).collect()
}

pub fn format_peers(addrs: &[SocketAddr]) -> Vec<String> {
    addrs.iter().map(|a| a.to_string()).collect()
}

/// Converte TrustedPeerList para formato persistente.
pub fn trusted_to_persisted(list: &TrustedPeerList) -> Vec<PersistedTrustedPeer> {
    list.peers()
        .iter()
        .map(|p| PersistedTrustedPeer {
            node_id: p.node_id.clone(),
            public_key: p.public_key.clone(),
            encryption_public_key: p.encryption_public_key.to_vec(),
            addr: p.addr.to_string(),
        })
        .collect()
}

/// Converte dados persistidos para TrustedPeerList.
pub fn persisted_to_trusted(data: &[PersistedTrustedPeer], max_peers: usize) -> TrustedPeerList {
    let mut list = TrustedPeerList::new(max_peers);
    for p in data {
        if let Ok(addr) = p.addr.parse::<SocketAddr>() {
            let mut enc_key = [0u8; 32];
            let key_len = p.encryption_public_key.len().min(32);
            enc_key[..key_len].copy_from_slice(&p.encryption_public_key[..key_len]);

            let peer = TrustedPeer {
                node_id: p.node_id.clone(),
                public_key: p.public_key.clone(),
                encryption_public_key: enc_key,
                addr,
                authenticated_at: chrono::Utc::now(),
            };
            list.add(peer);
        }
    }
    list
}

pub async fn save_network_state(
    data_path: &Path,
    peers: &Arc<RwLock<PeerList>>,
    epas: &Arc<RwLock<Vec<SharedEPA>>>,
    trusted_peers: &Arc<RwLock<TrustedPeerList>>,
) {
    let peer_addrs = {
        let peer_list = peers.read().await;
        format_peers(peer_list.peers())
    };
    let epa_list = {
        let epa_list = epas.read().await;
        epa_list.clone()
    };
    let trusted_persisted = {
        let trusted_list = trusted_peers.read().await;
        trusted_to_persisted(&trusted_list)
    };

    let data = PersistedData {
        peers: peer_addrs,
        epas: epa_list,
        trusted_peers: trusted_persisted,
    };

    if let Err(e) = save_data(data_path, &data) {
        eprintln!("Failed to save network state: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_create_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.json");

        let data = load_data(&path).unwrap();
        assert!(data.peers.is_empty());
        assert!(data.epas.is_empty());
        assert!(data.trusted_peers.is_empty());
    }

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.json");

        let mut data = PersistedData::default();
        data.peers.push("127.0.0.1:9001".to_string());
        data.trusted_peers.push(PersistedTrustedPeer {
            node_id: "node_a".to_string(),
            public_key: "key_a".to_string(),
            encryption_public_key: vec![1u8; 32],
            addr: "127.0.0.1:9002".to_string(),
        });

        save_data(&path, &data).unwrap();
        let loaded = load_data(&path).unwrap();

        assert_eq!(loaded.peers.len(), 1);
        assert_eq!(loaded.trusted_peers.len(), 1);
        assert_eq!(loaded.trusted_peers[0].node_id, "node_a");
    }

    #[test]
    fn parse_and_format_peers() {
        let addrs = vec![
            "127.0.0.1:9001".parse().unwrap(),
            "127.0.0.1:9002".parse().unwrap(),
        ];
        let formatted = format_peers(&addrs);
        let parsed = parse_peers(&formatted);

        assert_eq!(addrs, parsed);
    }

    #[test]
    fn trusted_peer_roundtrip() {
        let mut list = TrustedPeerList::new(10);
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let peer = TrustedPeer {
            node_id: "test_node".to_string(),
            public_key: "test_key".to_string(),
            encryption_public_key: [42u8; 32],
            addr,
            authenticated_at: chrono::Utc::now(),
        };
        list.add(peer);

        let persisted = trusted_to_persisted(&list);
        let restored = persisted_to_trusted(&persisted, 10);

        assert_eq!(restored.len(), 1);
        assert_eq!(restored.peers()[0].node_id, "test_node");
        assert_eq!(restored.peers()[0].encryption_public_key, [42u8; 32]);
    }
}
