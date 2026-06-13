#![allow(dead_code)]

use crate::quality::EvidenceStrength;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceNode {
    pub node_id: String,
    pub parent_hash: Option<String>,
    pub strength: EvidenceStrength,
    pub depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceChain {
    pub nodes: Vec<ProvenanceNode>,
    pub chain_strength: EvidenceStrength,
}

pub fn aggregate_chain_strength(nodes: &[ProvenanceNode]) -> EvidenceStrength {
    nodes
        .iter()
        .map(|node| node.strength)
        .min()
        .unwrap_or(EvidenceStrength::Unverifiable)
}

#[cfg(test)]
mod tests {
    use super::{aggregate_chain_strength, ProvenanceNode};
    use crate::quality::EvidenceStrength;

    fn node(node_id: &str, strength: EvidenceStrength, depth: u32) -> ProvenanceNode {
        ProvenanceNode {
            node_id: node_id.to_string(),
            parent_hash: None,
            strength,
            depth,
        }
    }

    #[test]
    fn aggregate_chain_strength_returns_minimum_strength() {
        let nodes = vec![
            node("a", EvidenceStrength::Anchored, 0),
            node("b", EvidenceStrength::Signed, 1),
            node("c", EvidenceStrength::Witnessed, 2),
        ];

        assert_eq!(
            aggregate_chain_strength(&nodes),
            EvidenceStrength::Witnessed
        );
    }

    #[test]
    fn aggregate_chain_strength_returns_unverifiable_for_empty_chain() {
        let nodes: Vec<ProvenanceNode> = Vec::new();

        assert_eq!(
            aggregate_chain_strength(&nodes),
            EvidenceStrength::Unverifiable
        );
    }
}
