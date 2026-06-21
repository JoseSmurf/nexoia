#![allow(dead_code)]

use crate::provenance::typed_node::{
    AnchoredMarker, LocalMarker, Marker, SignedMarker, TypedNode, UnverifiableMarker,
    WitnessedMarker,
};
use uuid::Uuid;

mod sealed {
    pub trait Sealed<Rhs> {}
}

pub trait MinStrength<Rhs>: sealed::Sealed<Rhs> {
    type Output: Marker;
}

macro_rules! impl_min_strength_pair {
    ($lhs:ty, $rhs:ty => $out:ty) => {
        impl sealed::Sealed<$rhs> for $lhs {}

        impl MinStrength<$rhs> for $lhs {
            type Output = $out;
        }
    };
}

impl_min_strength_pair!(UnverifiableMarker, UnverifiableMarker => crate::provenance::Unverifiable);
impl_min_strength_pair!(UnverifiableMarker, LocalMarker => crate::provenance::Unverifiable);
impl_min_strength_pair!(UnverifiableMarker, WitnessedMarker => crate::provenance::Unverifiable);
impl_min_strength_pair!(UnverifiableMarker, SignedMarker => crate::provenance::Unverifiable);
impl_min_strength_pair!(UnverifiableMarker, AnchoredMarker => crate::provenance::Unverifiable);

impl_min_strength_pair!(LocalMarker, UnverifiableMarker => crate::provenance::Unverifiable);
impl_min_strength_pair!(LocalMarker, LocalMarker => crate::provenance::Local);
impl_min_strength_pair!(LocalMarker, WitnessedMarker => crate::provenance::Local);
impl_min_strength_pair!(LocalMarker, SignedMarker => crate::provenance::Local);
impl_min_strength_pair!(LocalMarker, AnchoredMarker => crate::provenance::Local);

impl_min_strength_pair!(WitnessedMarker, UnverifiableMarker => crate::provenance::Unverifiable);
impl_min_strength_pair!(WitnessedMarker, LocalMarker => crate::provenance::Local);
impl_min_strength_pair!(WitnessedMarker, WitnessedMarker => crate::provenance::Witnessed);
impl_min_strength_pair!(WitnessedMarker, SignedMarker => crate::provenance::Witnessed);
impl_min_strength_pair!(WitnessedMarker, AnchoredMarker => crate::provenance::Witnessed);

impl_min_strength_pair!(SignedMarker, UnverifiableMarker => crate::provenance::Unverifiable);
impl_min_strength_pair!(SignedMarker, LocalMarker => crate::provenance::Local);
impl_min_strength_pair!(SignedMarker, WitnessedMarker => crate::provenance::Witnessed);
impl_min_strength_pair!(SignedMarker, SignedMarker => crate::provenance::Signed);
impl_min_strength_pair!(SignedMarker, AnchoredMarker => crate::provenance::Signed);

impl_min_strength_pair!(AnchoredMarker, UnverifiableMarker => crate::provenance::Unverifiable);
impl_min_strength_pair!(AnchoredMarker, LocalMarker => crate::provenance::Local);
impl_min_strength_pair!(AnchoredMarker, WitnessedMarker => crate::provenance::Witnessed);
impl_min_strength_pair!(AnchoredMarker, SignedMarker => crate::provenance::Signed);
impl_min_strength_pair!(AnchoredMarker, AnchoredMarker => crate::provenance::Anchored);

fn derive_impl<U, V, W, S1, S2, F>(
    left: &TypedNode<U, S1>,
    right: &TypedNode<V, S2>,
    f: F,
) -> TypedNode<W, <S1 as MinStrength<S2>>::Output>
where
    S1: Marker + MinStrength<S2>,
    S2: Marker,
    F: Fn(&U, &V) -> W,
{
    let node_id = Uuid::new_v5(&left.node_id, right.node_id.as_bytes());
    let value = f(&left.value, &right.value);

    TypedNode::new(node_id, value)
}

pub fn derive<U, V, W, S1, S2>(
    left: &TypedNode<U, S1>,
    right: &TypedNode<V, S2>,
    f: impl Fn(&U, &V) -> W,
) -> TypedNode<W, <S1 as MinStrength<S2>>::Output>
where
    S1: Marker + MinStrength<S2>,
    S2: Marker,
{
    derive_impl(left, right, f)
}

impl<T, S1> TypedNode<T, S1>
where
    S1: Marker,
{
    pub fn derive_from<U, S2, V>(
        &self,
        other: &TypedNode<U, S2>,
        f: impl Fn(&T, &U) -> V,
    ) -> TypedNode<V, <S1 as MinStrength<S2>>::Output>
    where
        S2: Marker,
        S1: MinStrength<S2>,
    {
        derive_impl(self, other, f)
    }
}

#[cfg(test)]
mod tests {
    use super::derive;
    use crate::provenance::typed_node::Marker;
    use crate::provenance::{Anchored, Local, Signed, TypedNode, Unverifiable, Witnessed};
    use crate::types::EvidenceStrength;
    use uuid::Uuid;

    fn node_id(seed: &str) -> Uuid {
        Uuid::new_v5(&Uuid::NAMESPACE_URL, seed.as_bytes())
    }

    fn expected_node_id<U, S1, V, S2>(left: &TypedNode<U, S1>, right: &TypedNode<V, S2>) -> Uuid
    where
        S1: Marker,
        S2: Marker,
    {
        Uuid::new_v5(&left.node_id, right.node_id.as_bytes())
    }

    #[test]
    fn derive_signed_and_local_is_local() {
        let left = TypedNode::<_, Signed>::new(node_id("signed-left"), "alpha".to_owned());
        let right = TypedNode::<_, Local>::new(node_id("local-right"), "beta".to_owned());

        let derived = derive(&left, &right, |l, r| format!("{l}:{r}"));

        assert_eq!(derived.strength(), EvidenceStrength::Local);
        assert_eq!(derived.node_id, expected_node_id(&left, &right));
        assert_eq!(derived.value, "alpha:beta");
    }

    #[test]
    fn derive_anchored_and_anchored_is_anchored() {
        let left = TypedNode::<_, Anchored>::new(node_id("anchored-left"), "left".to_owned());
        let right = TypedNode::<_, Anchored>::new(node_id("anchored-right"), "right".to_owned());

        let derived = left.derive_from(&right, |l, r| format!("{l}+{r}"));

        assert_eq!(derived.strength(), EvidenceStrength::Anchored);
        assert_eq!(derived.node_id, expected_node_id(&left, &right));
        assert_eq!(derived.value, "left+right");
    }

    #[test]
    fn derive_local_and_witnessed_is_local() {
        let left = TypedNode::<_, Local>::new(node_id("local-left"), 2_u32);
        let right = TypedNode::<_, Witnessed>::new(node_id("witnessed-right"), 5_u32);

        let derived = derive(&left, &right, |l, r| l + r);

        assert_eq!(derived.strength(), EvidenceStrength::Local);
        assert_eq!(derived.node_id, expected_node_id(&left, &right));
        assert_eq!(derived.value, 7);
    }

    #[test]
    fn derive_unverifiable_wins_as_bottom() {
        let left = TypedNode::<_, Unverifiable>::new(node_id("unverifiable-left"), 1_u32);
        let right = TypedNode::<_, Signed>::new(node_id("signed-right"), 9_u32);

        let derived = derive(&left, &right, |l, r| l + r);

        assert_eq!(derived.strength(), EvidenceStrength::Unverifiable);
        assert_eq!(derived.node_id, expected_node_id(&left, &right));
        assert_eq!(derived.value, 10);
    }
}
