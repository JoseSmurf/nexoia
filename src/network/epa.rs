use crate::hash::canonical_hash;
use crate::network::identity::NodeIdentity;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedEPA {
    pub epa_id: String,
    pub node_id: String,
    pub node_signature: String,
    pub state_hash: String,
    pub evidence_hash: String,
    pub decision_hash: String,
    pub manifest_hash: String,
    pub timestamp: String,
    pub integrity_hash: String,
}

impl SharedEPA {
    pub fn create(
        node: &NodeIdentity,
        state_json: &str,
        evidence_jsonl: &str,
        decisions_jsonl: &str,
        manifest_json: &str,
    ) -> Self {
        let state_hash = canonical_hash(state_json);
        let evidence_hash = canonical_hash(evidence_jsonl);
        let decision_hash = canonical_hash(decisions_jsonl);
        let manifest_hash = canonical_hash(manifest_json);

        let content = format!(
            "{}:{}:{}:{}:{}",
            node.node_id, state_hash, evidence_hash, decision_hash, manifest_hash
        );
        let integrity_hash = canonical_hash(&content);
        let signature = node.sign(&integrity_hash);

        Self {
            epa_id: integrity_hash[..16].to_string(),
            node_id: node.node_id.clone(),
            node_signature: signature,
            state_hash,
            evidence_hash,
            decision_hash,
            manifest_hash,
            timestamp: chrono::Utc::now().to_rfc3339(),
            integrity_hash,
        }
    }

    pub fn verify_integrity(&self) -> bool {
        let content = format!(
            "{}:{}:{}:{}:{}",
            self.node_id,
            self.state_hash,
            self.evidence_hash,
            self.decision_hash,
            self.manifest_hash
        );
        let expected = canonical_hash(&content);
        self.integrity_hash == expected
    }

    pub fn verify_signature(&self, public_key: &str) -> bool {
        let expected_signature = canonical_hash(&format!("{}:{}", public_key, self.integrity_hash));
        self.node_signature == expected_signature
    }
}

impl fmt::Display for SharedEPA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EPA({}) from {} @ {}",
            self.epa_id,
            &self.node_id[..12.min(self.node_id.len())],
            &self.timestamp[..10.min(self.timestamp.len())]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> (String, String, String, String) {
        (
            r#"{"project":"test"}"#.to_string(),
            r#"{"evidence":"data"}"#.to_string(),
            r#"{"decision":"ok"}"#.to_string(),
            r#"{"manifest":"v1"}"#.to_string(),
        )
    }

    #[test]
    fn create_and_verify() {
        let node = NodeIdentity::generate("test_node");
        let (state, evidence, decision, manifest) = sample_data();

        let epa = SharedEPA::create(&node, &state, &evidence, &decision, &manifest);
        assert!(epa.verify_integrity());
        assert!(epa.verify_signature(&node.public_key));
    }

    #[test]
    fn tampered_epa_fails_verification() {
        let node = NodeIdentity::generate("test_node");
        let (state, evidence, decision, manifest) = sample_data();

        let mut epa = SharedEPA::create(&node, &state, &evidence, &decision, &manifest);
        epa.state_hash = "tampered".to_string();

        assert!(!epa.verify_integrity());
    }

    #[test]
    fn wrong_key_fails_signature() {
        let node = NodeIdentity::generate("test_node");
        let wrong_node = NodeIdentity::generate("wrong_node");
        let (state, evidence, decision, manifest) = sample_data();

        let epa = SharedEPA::create(&node, &state, &evidence, &decision, &manifest);
        assert!(!epa.verify_signature(&wrong_node.public_key));
    }
}
