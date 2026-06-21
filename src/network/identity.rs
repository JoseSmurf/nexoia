use crate::hash::canonical_hash;
use serde::{Deserialize, Serialize};
use std::fmt;

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
}
