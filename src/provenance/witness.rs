#![allow(dead_code)]

use crate::provenance::{Anchored, Signed, TypedNode};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Witness {
    pub witness_id: Uuid,
    pub witnessed_at_utc: DateTime<Utc>,
    pub kind: WitnessKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum WitnessKind {
    Cosigned,
    TimestampedByTrustedSource,
    CrossReferencedInExternalLedger,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessSet {
    witnesses: Vec<Witness>,
}

impl WitnessSet {
    pub fn new() -> Self {
        Self {
            witnesses: Vec::new(),
        }
    }

    pub fn add(&mut self, witness: Witness) {
        self.witnesses.push(witness);
    }

    pub fn len(&self) -> usize {
        self.witnesses.len()
    }

    pub fn is_empty(&self) -> bool {
        self.witnesses.is_empty()
    }

    pub fn attest<T>(
        self,
        node: TypedNode<T, Signed>,
    ) -> Result<TypedNode<T, Anchored>, InsufficientWitnessesError> {
        let witnesses = self.witnesses;

        if witnesses.len() < 2 {
            return Err(InsufficientWitnessesError::NotEnoughWitnesses);
        }

        let mut seen = HashSet::new();
        for witness in &witnesses {
            if !seen.insert(witness.witness_id) {
                return Err(InsufficientWitnessesError::DuplicateWitnessId);
            }
        }

        if !witnesses
            .iter()
            .any(|witness| matches!(witness.kind, WitnessKind::CrossReferencedInExternalLedger))
        {
            return Err(InsufficientWitnessesError::NoExternalReference);
        }

        Ok(TypedNode::new(node.node_id, node.value))
    }
}

impl Default for WitnessSet {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsufficientWitnessesError {
    NotEnoughWitnesses,
    DuplicateWitnessId,
    NoExternalReference,
}

impl fmt::Display for InsufficientWitnessesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnoughWitnesses => f.write_str("not enough witnesses"),
            Self::DuplicateWitnessId => f.write_str("duplicate witness id"),
            Self::NoExternalReference => f.write_str("no external witness reference"),
        }
    }
}

impl Error for InsufficientWitnessesError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::Signed;

    fn witness_id(seed: &str) -> Uuid {
        Uuid::new_v5(&Uuid::NAMESPACE_URL, seed.as_bytes())
    }

    fn witnessed_at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-13T12:00:00Z")
            .expect("fixed timestamp should parse")
            .with_timezone(&Utc)
    }

    fn witness(seed: &str, kind: WitnessKind) -> Witness {
        Witness {
            witness_id: witness_id(seed),
            witnessed_at_utc: witnessed_at(),
            kind,
        }
    }

    fn signed_node() -> TypedNode<String, Signed> {
        TypedNode::new(
            Uuid::new_v5(&Uuid::NAMESPACE_URL, b"signed-node"),
            "payload".to_owned(),
        )
    }

    #[test]
    fn attests_with_two_valid_witnesses() {
        let mut set = WitnessSet::new();
        set.add(witness(
            "external",
            WitnessKind::CrossReferencedInExternalLedger,
        ));
        set.add(witness("cosigned", WitnessKind::Cosigned));

        let node = signed_node();
        let anchored = set
            .attest(node.clone())
            .expect("attestation should succeed");

        assert_eq!(anchored.node_id, node.node_id);
        assert_eq!(anchored.value, node.value);
    }

    #[test]
    fn fails_with_one_witness() {
        let mut set = WitnessSet::new();
        set.add(witness(
            "external",
            WitnessKind::CrossReferencedInExternalLedger,
        ));

        let err = set
            .attest(signed_node())
            .expect_err("single witness should fail");
        assert_eq!(err, InsufficientWitnessesError::NotEnoughWitnesses);
    }

    #[test]
    fn fails_with_duplicate_witness_ids() {
        let mut set = WitnessSet::new();
        let duplicate_id = witness_id("duplicate");
        let fixed_time = witnessed_at();

        set.add(Witness {
            witness_id: duplicate_id,
            witnessed_at_utc: fixed_time,
            kind: WitnessKind::CrossReferencedInExternalLedger,
        });
        set.add(Witness {
            witness_id: duplicate_id,
            witnessed_at_utc: fixed_time,
            kind: WitnessKind::Cosigned,
        });

        let err = set
            .attest(signed_node())
            .expect_err("duplicate witness ids should fail");
        assert_eq!(err, InsufficientWitnessesError::DuplicateWitnessId);
    }

    #[test]
    fn fails_without_external_reference() {
        let mut set = WitnessSet::new();
        set.add(witness("left", WitnessKind::Cosigned));
        set.add(witness("right", WitnessKind::TimestampedByTrustedSource));

        let err = set
            .attest(signed_node())
            .expect_err("missing external witness should fail");
        assert_eq!(err, InsufficientWitnessesError::NoExternalReference);
    }
}
