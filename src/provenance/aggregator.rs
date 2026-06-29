#![allow(dead_code)]

use crate::hash::canonical_hash;
use crate::types::EvidenceStrength;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Referência a pai na cadeia de proveniência.
/// Active = link real (EPA pai ainda existe).
/// Blinded = link cego (EPA pai foi anonimizado via crypto-shredding).
/// O salt do blinding é o integrity_hash do EPA de supressão — determinístico e verificável.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProvenanceRef {
    Active(String),
    Blinded {
        blinded_hash: String,
        blinding_salt: String,
    },
}

impl ProvenanceRef {
    pub fn active(hash: String) -> Self {
        Self::Active(hash)
    }

    pub fn blind(original_hash: &str, suppression_integrity_hash: &str) -> Self {
        let salt = canonical_hash(suppression_integrity_hash);
        let blinded = canonical_hash(&format!("{original_hash}:{salt}"));
        Self::Blinded {
            blinded_hash: blinded,
            blinding_salt: salt,
        }
    }

    pub fn is_blinded(&self) -> bool {
        matches!(self, Self::Blinded { .. })
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Active(h) => h,
            Self::Blinded { blinded_hash, .. } => blinded_hash,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceNode {
    pub node_id: String,
    pub parent_ref: Option<ProvenanceRef>,
    pub strength: EvidenceStrength,
    pub depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceChain {
    pub nodes: Vec<ProvenanceNode>,
    pub chain_strength: EvidenceStrength,
}

/// Índice reverso de derivação: EPA pai → [EPAs filhos].
/// Usado para graph blinding eficiente (sem full scan).
pub struct DerivationIndex {
    children: HashMap<String, Vec<String>>,
}

impl Default for DerivationIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl DerivationIndex {
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
        }
    }

    pub fn insert(&mut self, parent_epa_id: &str, child_epa_id: &str) {
        self.children
            .entry(parent_epa_id.to_string())
            .or_default()
            .push(child_epa_id.to_string());
    }

    pub fn children_of(&self, epa_id: &str) -> Vec<&str> {
        self.children
            .get(epa_id)
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    pub fn build_from_chain_refs(nodes: &[ProvenanceNode]) -> Self {
        let mut index = Self::new();
        for node in nodes {
            if let Some(ref parent_ref) = node.parent_ref {
                let parent_id = parent_ref.as_str().to_string();
                index
                    .children
                    .entry(parent_id)
                    .or_default()
                    .push(node.node_id.clone());
            }
        }
        index
    }
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

        let Some(ref parent_ref) = current.parent_ref else {
            break;
        };
        let parent_id = parent_ref.as_str();
        let Some(parent) = parent_lookup.get(parent_id) else {
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

/// Blinda os links de proveniência de um EPA anonimizado.
/// Converte todos ProvenanceRef::Active que apontam pro EPA cego em ProvenanceRef::Blinded.
pub fn blind_derivation_links(
    nodes: &mut [ProvenanceNode],
    target_epa_id: &str,
    suppression_integrity_hash: &str,
) -> usize {
    let mut blinded_count = 0;
    for node in nodes.iter_mut() {
        if let Some(ref mut parent_ref) = node.parent_ref {
            if parent_ref.as_str() == target_epa_id {
                let original_hash = parent_ref.as_str().to_string();
                *parent_ref = ProvenanceRef::blind(&original_hash, suppression_integrity_hash);
                blinded_count += 1;
            }
        }
    }
    blinded_count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EvidenceStrength;

    fn node(
        node_id: &str,
        parent_ref: Option<ProvenanceRef>,
        strength: EvidenceStrength,
        depth: u32,
    ) -> ProvenanceNode {
        ProvenanceNode {
            node_id: node_id.to_string(),
            parent_ref,
            strength,
            depth,
        }
    }

    #[test]
    fn provenance_ref_active_as_str() {
        let r = ProvenanceRef::active("hash123".to_string());
        assert_eq!(r.as_str(), "hash123");
        assert!(!r.is_blinded());
    }

    #[test]
    fn provenance_ref_blind_creates_blinded() {
        let r = ProvenanceRef::blind("original_hash", "suppression_hash");
        assert!(r.is_blinded());
        assert_ne!(r.as_str(), "original_hash");
    }

    #[test]
    fn blind_deterministic_with_same_salt() {
        let r1 = ProvenanceRef::blind("abc", "salt");
        let r2 = ProvenanceRef::blind("abc", "salt");
        assert_eq!(r1.as_str(), r2.as_str());
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
        let middle = node(
            "middle",
            Some(ProvenanceRef::active("root".to_string())),
            EvidenceStrength::Local,
            1,
        );
        let leaf = node(
            "leaf",
            Some(ProvenanceRef::active("middle".to_string())),
            EvidenceStrength::Signed,
            2,
        );

        let chain = walk_provenance_chain(leaf, &[middle.clone(), root.clone()]);

        assert_eq!(
            chain.nodes,
            vec![
                root,
                middle,
                node(
                    "leaf",
                    Some(ProvenanceRef::active("middle".to_string())),
                    EvidenceStrength::Signed,
                    2
                )
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

    #[test]
    fn derivation_index_tracks_children() {
        let mut idx = DerivationIndex::new();
        idx.insert("epa_a", "epa_b");
        idx.insert("epa_a", "epa_c");
        idx.insert("epa_b", "epa_d");

        assert_eq!(idx.children_of("epa_a"), vec!["epa_b", "epa_c"]);
        assert_eq!(idx.children_of("epa_b"), vec!["epa_d"]);
        assert!(idx.children_of("epa_z").is_empty());
    }

    #[test]
    fn blind_derivation_links_converts_active_refs() {
        let mut nodes = vec![
            node(
                "epa_b",
                Some(ProvenanceRef::active("epa_a".to_string())),
                EvidenceStrength::Signed,
                1,
            ),
            node(
                "epa_c",
                Some(ProvenanceRef::active("epa_x".to_string())),
                EvidenceStrength::Local,
                1,
            ),
            node(
                "epa_d",
                Some(ProvenanceRef::active("epa_a".to_string())),
                EvidenceStrength::Witnessed,
                2,
            ),
        ];

        let blinded = blind_derivation_links(&mut nodes, "epa_a", "suppression_hash");

        assert_eq!(blinded, 2);
        assert!(nodes[0].parent_ref.as_ref().unwrap().is_blinded());
        assert!(!nodes[1].parent_ref.as_ref().unwrap().is_blinded());
        assert!(nodes[2].parent_ref.as_ref().unwrap().is_blinded());
    }

    #[test]
    fn blind_derivation_links_no_match_returns_zero() {
        let mut nodes = vec![node(
            "epa_b",
            Some(ProvenanceRef::active("epa_x".to_string())),
            EvidenceStrength::Signed,
            1,
        )];

        let blinded = blind_derivation_links(&mut nodes, "epa_a", "suppression_hash");
        assert_eq!(blinded, 0);
        assert!(!nodes[0].parent_ref.as_ref().unwrap().is_blinded());
    }

    #[test]
    fn build_from_chain_refs_creates_reverse_index() {
        let nodes = vec![
            node(
                "epa_b",
                Some(ProvenanceRef::active("epa_a".to_string())),
                EvidenceStrength::Signed,
                1,
            ),
            node(
                "epa_c",
                Some(ProvenanceRef::active("epa_a".to_string())),
                EvidenceStrength::Local,
                1,
            ),
        ];

        let idx = DerivationIndex::build_from_chain_refs(&nodes);
        assert_eq!(idx.children_of("epa_a"), vec!["epa_b", "epa_c"]);
    }
}
