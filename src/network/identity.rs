use crate::hash::canonical_hash;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub node_id: String,
    pub public_key: String,
    pub created_at: String,
}

impl NodeIdentity {
    pub fn generate(name: &str) -> Self {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let seed = format!("{}:{}", name, timestamp);
        let public_key = canonical_hash(&seed);
        let node_id = canonical_hash(&format!("node:{}", public_key));

        Self {
            node_id,
            public_key,
            created_at: timestamp,
        }
    }

    pub fn load_or_create(path: &Path, name: &str) -> Result<Self, std::io::Error> {
        if path.exists() {
            let data = std::fs::read_to_string(path)?;
            let identity: Self = serde_json::from_str(&data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            Ok(identity)
        } else {
            let identity = Self::generate(name);
            identity.save(path)?;
            Ok(identity)
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, data)
    }

    pub fn sign(&self, data: &str) -> String {
        let payload = format!("{}:{}", self.public_key, data);
        canonical_hash(&payload)
    }

    pub fn verify_signature(&self, data: &str, signature: &str) -> bool {
        let expected = self.sign(data);
        expected == signature
    }
}

impl fmt::Display for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Node({})", &self.node_id[..12.min(self.node_id.len())])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_creates_unique_identities() {
        let a = NodeIdentity::generate("node_a");
        let b = NodeIdentity::generate("node_b");
        assert_ne!(a.node_id, b.node_id);
    }

    #[test]
    fn sign_and_verify() {
        let node = NodeIdentity::generate("test_node");
        let data = "important evidence";
        let sig = node.sign(data);
        assert!(node.verify_signature(data, &sig));
        assert!(!node.verify_signature("tampered data", &sig));
    }

    #[test]
    fn node_id_is_unique_per_call() {
        let a = NodeIdentity::generate("same_node");
        let b = NodeIdentity::generate("same_node");
        assert_ne!(a.node_id, b.node_id);
        assert_ne!(a.public_key, b.public_key);
    }

    #[test]
    fn load_or_create_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");

        let a = NodeIdentity::load_or_create(&path, "persist_test").unwrap();
        let b = NodeIdentity::load_or_create(&path, "persist_test").unwrap();

        assert_eq!(a.node_id, b.node_id);
        assert_eq!(a.public_key, b.public_key);
    }
}
