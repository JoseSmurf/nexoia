use crate::network::epa::SharedEPA;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedData {
    pub peers: Vec<String>,
    pub epas: Vec<SharedEPA>,
}

impl Default for PersistedData {
    fn default() -> Self {
        Self {
            peers: Vec::new(),
            epas: Vec::new(),
        }
    }
}

pub fn load_data(path: &Path) -> Result<PersistedData, std::io::Error> {
    if !path.exists() {
        return Ok(PersistedData::default());
    }
    let data = std::fs::read_to_string(path)?;
    let persisted: PersistedData = serde_json::from_str(&data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(persisted)
}

pub fn save_data(path: &Path, data: &PersistedData) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)
}

pub fn parse_peers(peers: &[String]) -> Vec<SocketAddr> {
    peers.iter().filter_map(|s| s.parse().ok()).collect()
}

pub fn format_peers(addrs: &[SocketAddr]) -> Vec<String> {
    addrs.iter().map(|a| a.to_string()).collect()
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
    }

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.json");

        let mut data = PersistedData::default();
        data.peers.push("127.0.0.1:9001".to_string());

        save_data(&path, &data).unwrap();
        let loaded = load_data(&path).unwrap();

        assert_eq!(loaded.peers.len(), 1);
        assert_eq!(loaded.peers[0], "127.0.0.1:9001");
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
}
