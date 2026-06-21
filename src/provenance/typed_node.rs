#![allow(dead_code)]

use crate::types::EvidenceStrength;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use uuid::Uuid;

mod sealed {
    pub trait Sealed {}
}

pub trait Marker: sealed::Sealed + Copy + Clone + 'static {
    const STRENGTH: EvidenceStrength;
}

macro_rules! define_marker {
    ($marker:ident, $alias:ident, $strength:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $marker;

        impl sealed::Sealed for $marker {}

        impl Marker for $marker {
            const STRENGTH: EvidenceStrength = $strength;
        }

        pub type $alias = $marker;
    };
}

define_marker!(
    UnverifiableMarker,
    Unverifiable,
    EvidenceStrength::Unverifiable
);
define_marker!(LocalMarker, Local, EvidenceStrength::Local);
define_marker!(WitnessedMarker, Witnessed, EvidenceStrength::Witnessed);
define_marker!(SignedMarker, Signed, EvidenceStrength::Signed);
define_marker!(AnchoredMarker, Anchored, EvidenceStrength::Anchored);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedNode<T, S: Marker> {
    pub node_id: Uuid,
    pub value: T,
    #[serde(skip)]
    marker: PhantomData<S>,
}

impl<T, S: Marker> TypedNode<T, S> {
    pub fn new(node_id: Uuid, value: T) -> Self {
        Self {
            node_id,
            value,
            marker: PhantomData,
        }
    }

    pub fn strength(&self) -> EvidenceStrength {
        S::STRENGTH
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DowncastError {
    StrengthTooLow,
    WrongNodeId,
}

impl<T> From<TypedNode<T, Signed>> for TypedNode<T, Witnessed> {
    fn from(node: TypedNode<T, Signed>) -> Self {
        Self::new(node.node_id, node.value)
    }
}

impl<T> From<TypedNode<T, Anchored>> for TypedNode<T, Witnessed> {
    fn from(node: TypedNode<T, Anchored>) -> Self {
        Self::new(node.node_id, node.value)
    }
}

impl<T> TypedNode<T, Signed> {
    pub fn try_into_anchored(
        self,
        witness_node_id: Option<Uuid>,
    ) -> Result<TypedNode<T, Anchored>, DowncastError> {
        let Some(witness_node_id) = witness_node_id else {
            return Err(DowncastError::StrengthTooLow);
        };

        if witness_node_id != self.node_id {
            return Err(DowncastError::WrongNodeId);
        }

        Ok(TypedNode::new(self.node_id, self.value))
    }
}

#[cfg(test)]
mod tests {
    use super::{Anchored, DowncastError, Local, Signed, TypedNode, Unverifiable, Witnessed};
    use uuid::Uuid;

    #[test]
    fn constructs_with_each_marker_type() {
        let node_id = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"typed-node-construct");

        let unverifiable = TypedNode::<_, Unverifiable>::new(node_id, "u");
        let local = TypedNode::<_, Local>::new(node_id, "l");
        let witnessed = TypedNode::<_, Witnessed>::new(node_id, "w");
        let signed = TypedNode::<_, Signed>::new(node_id, "s");
        let anchored = TypedNode::<_, Anchored>::new(node_id, "a");

        assert_eq!(
            unverifiable.strength(),
            crate::types::EvidenceStrength::Unverifiable
        );
        assert_eq!(local.strength(), crate::types::EvidenceStrength::Local);
        assert_eq!(
            witnessed.strength(),
            crate::types::EvidenceStrength::Witnessed
        );
        assert_eq!(signed.strength(), crate::types::EvidenceStrength::Signed);
        assert_eq!(
            anchored.strength(),
            crate::types::EvidenceStrength::Anchored
        );
    }

    #[test]
    fn successful_downcast_to_witnessed_from_signed_and_anchored() {
        let node_id = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"typed-node-downcast");
        let signed = TypedNode::<_, Signed>::new(node_id, "payload");
        let anchored = TypedNode::<_, Anchored>::new(node_id, "payload");

        let signed_to_witnessed: TypedNode<_, Witnessed> = signed.into();
        let anchored_to_witnessed: TypedNode<_, Witnessed> = anchored.into();

        assert_eq!(signed_to_witnessed.node_id, node_id);
        assert_eq!(anchored_to_witnessed.node_id, node_id);
        assert_eq!(signed_to_witnessed.value, "payload");
        assert_eq!(anchored_to_witnessed.value, "payload");
    }

    #[test]
    fn try_into_anchored_requires_runtime_witness_check() {
        let node_id = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"typed-node-anchored");
        let signed = TypedNode::<_, Signed>::new(node_id, "payload");

        let anchored = signed
            .clone()
            .try_into_anchored(Some(node_id))
            .expect("witnessed anchor should succeed");

        assert_eq!(anchored.node_id, node_id);
        assert_eq!(anchored.value, "payload");

        let wrong = signed
            .clone()
            .try_into_anchored(Some(Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                b"typed-node-wrong-id",
            )))
            .expect_err("wrong node id should fail");
        assert_eq!(wrong, DowncastError::WrongNodeId);

        let low = signed
            .try_into_anchored(None)
            .expect_err("missing witness should fail");
        assert_eq!(low, DowncastError::StrengthTooLow);
    }

    #[allow(dead_code)]
    fn unsound_upcast_would_not_compile(node: TypedNode<String, Witnessed>) {
        // This would be unsound and does not compile:
        // let _: TypedNode<String, Signed> = node.into();
        let _ = node;
    }
}
