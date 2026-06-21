#![allow(dead_code)]

use crate::types::EvidenceStrength;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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

pub fn walk_provenance_chain(start: ProvenanceNode, parents: &[ProvenanceNode]) -> ProvenanceChain {
    let parent_lookup: HashMap<&str, &ProvenanceNode> = parents
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect();

    let mut nodes = Vec::new();
    let mut seen = HashSet::new();
    let mut current = start;

    loop {
        if !seen.insert(current.node_id.clone()) {
            break;
        }

        nodes.push(current.clone());

        let Some(parent_hash) = current.parent_hash.as_deref() else {
            break;
        };
        let Some(parent) = parent_lookup.get(parent_hash) else {
            break;
        };

        current = (*parent).clone();
    }

    nodes.reverse();

    let chain_strength = aggregate_chain_strength(&nodes);
    ProvenanceChain {
        nodes,
        chain_strength,
    }
}

#[cfg(test)]
mod tests {
    use super::{aggregate_chain_strength, walk_provenance_chain, ProvenanceNode};
    use crate::types::EvidenceStrength;

    fn node(
        node_id: &str,
        parent_hash: Option<&str>,
        strength: EvidenceStrength,
        depth: u32,
    ) -> ProvenanceNode {
        ProvenanceNode {
            node_id: node_id.to_string(),
            parent_hash: parent_hash.map(str::to_string),
            strength,
            depth,
        }
    }

    #[test]
    fn aggregate_chain_strength_returns_minimum_strength() {
        let nodes = vec![
            node("a", None, EvidenceStrength::Anchored, 0),
            node("b", None, EvidenceStrength::Signed, 1),
            node("c", None, EvidenceStrength::Witnessed, 2),
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

    #[test]
    fn walk_provenance_chain_single_node() {
        let root = node("root", None, EvidenceStrength::Signed, 0);

        let chain = walk_provenance_chain(root.clone(), &[]);

        assert_eq!(chain.nodes, vec![root]);
        assert_eq!(chain.chain_strength, EvidenceStrength::Signed);
    }

    #[test]
    fn walk_provenance_chain_three_nodes_weakest_in_middle() {
        let root = node("root", None, EvidenceStrength::Anchored, 0);
        let middle = node("middle", Some("root"), EvidenceStrength::Local, 1);
        let leaf = node("leaf", Some("middle"), EvidenceStrength::Signed, 2);

        let chain = walk_provenance_chain(leaf, &[middle.clone(), root.clone()]);

        assert_eq!(
            chain.nodes,
            vec![
                root,
                middle,
                node("leaf", Some("middle"), EvidenceStrength::Signed, 2)
            ]
        );
        assert_eq!(chain.chain_strength, EvidenceStrength::Local);
    }

    #[test]
    fn walk_provenance_chain_empty_chain_strength_is_unverifiable() {
        let nodes: Vec<ProvenanceNode> = Vec::new();

        assert_eq!(
            aggregate_chain_strength(&nodes),
            EvidenceStrength::Unverifiable
        );
    }
}
