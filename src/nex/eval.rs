use crate::nex::ast::{Expr, Program, Stmt, Type};
use crate::provenance::typed_node::Marker;
use crate::provenance::{
    Anchored, InsufficientWitnessesError, Local, Signed, TypedNode, Unverifiable, Witness,
    WitnessKind, WitnessSet, Witnessed,
};
use crate::quality::EvidenceStrength;
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use uuid::Uuid;

pub type Env = HashMap<String, TypedNodeValue>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TypedNodeValue {
    I(i64),
    S(String),
}

impl fmt::Display for TypedNodeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::I(value) => write!(f, "{value}"),
            Self::S(value) => f.write_str(value),
        }
    }
}

impl TypedNodeValue {
    fn type_name(&self) -> &'static str {
        match self {
            Self::I(_) => "i64",
            Self::S(_) => "string",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeView {
    pub id: String,
    pub node_id: Uuid,
    pub value: TypedNodeValue,
    pub strength: EvidenceStrength,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub env: Env,
    pub entries: Vec<NodeView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    UnknownIdentifier {
        id: String,
    },
    AttestationRequiresSigned {
        id: String,
        actual: EvidenceStrength,
    },
    AttestationFailed {
        id: String,
        source: InsufficientWitnessesError,
    },
    AssertionFailed {
        node: String,
        actual: EvidenceStrength,
        expected: EvidenceStrength,
    },
    UnsupportedType {
        ty: Type,
    },
    TypeMismatch {
        id: String,
        expected: &'static str,
        actual_left: &'static str,
        actual_right: &'static str,
    },
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownIdentifier { id } => write!(f, "unknown identifier '{id}'"),
            Self::AttestationRequiresSigned { id, actual } => {
                write!(f, "attest '{id}' requires Signed, found {actual}")
            }
            Self::AttestationFailed { id, source } => {
                write!(f, "attestation failed for '{id}': {source}")
            }
            Self::AssertionFailed {
                node,
                actual,
                expected,
            } => write!(
                f,
                "assertion failed for '{node}': actual {actual} is weaker than expected {expected}"
            ),
            Self::UnsupportedType { ty } => write!(f, "unsupported derive type '{ty:?}'"),
            Self::TypeMismatch {
                id,
                expected,
                actual_left,
                actual_right,
            } => write!(
                f,
                "derive '{id}' type mismatch: expected {expected}, left was {actual_left}, right was {actual_right}"
            ),
        }
    }
}

impl Error for EvalError {}

fn node_view(
    id: String,
    node_id: Uuid,
    value: TypedNodeValue,
    strength: EvidenceStrength,
) -> NodeView {
    NodeView {
        id,
        node_id,
        value,
        strength,
    }
}

#[derive(Debug, Clone)]
struct NodeRecord {
    node_id: Uuid,
    value: TypedNodeValue,
    strength: EvidenceStrength,
}

impl NodeRecord {
    fn view(&self, id: String) -> NodeView {
        node_view(id, self.node_id, self.value.clone(), self.strength)
    }
}

pub fn eval(program: Program) -> Result<Env, EvalError> {
    execute(program).map(|result| result.env)
}

pub fn execute(program: Program) -> Result<ExecutionResult, EvalError> {
    let mut working: HashMap<String, NodeRecord> = HashMap::new();
    let mut entries = Vec::new();

    for statement in program.statements {
        match statement {
            Stmt::Node {
                id,
                value,
                strength,
            } => {
                let record = build_node(&id, value, strength, &working)?;
                entries.push(record.view(id.clone()));
                working.insert(id, record);
            }
            Stmt::Attest {
                id,
                witness_count,
                external,
            } => {
                let current = working
                    .remove(&id)
                    .ok_or_else(|| EvalError::UnknownIdentifier { id: id.clone() })?;
                let record = attest_node(&id, current, witness_count, external)?;
                entries.push(record.view(id.clone()));
                working.insert(id, record);
            }
            Stmt::Derive {
                id,
                left,
                right,
                ty,
            } => {
                let left_record = working
                    .get(&left)
                    .ok_or_else(|| EvalError::UnknownIdentifier { id: left.clone() })?;
                let right_record = working
                    .get(&right)
                    .ok_or_else(|| EvalError::UnknownIdentifier { id: right.clone() })?;
                let record = derive_node(&id, left_record, right_record, ty)?;
                entries.push(record.view(id.clone()));
                working.insert(id, record);
            }
            Stmt::Assert { id, min } => {
                let record = working
                    .get(&id)
                    .ok_or_else(|| EvalError::UnknownIdentifier { id: id.clone() })?;
                if record.strength < min {
                    return Err(EvalError::AssertionFailed {
                        node: id,
                        actual: record.strength,
                        expected: min,
                    });
                }
                entries.push(record.view(id));
            }
        }
    }

    let env = working
        .into_iter()
        .map(|(id, record)| (id, record.value))
        .collect();

    Ok(ExecutionResult { env, entries })
}

fn build_node(
    id: &str,
    value: Expr,
    strength: EvidenceStrength,
    env: &HashMap<String, NodeRecord>,
) -> Result<NodeRecord, EvalError> {
    let resolved = resolve_expr(value, env)?;
    let node_id = deterministic_node_id(id, &resolved);

    let record = match strength {
        EvidenceStrength::Unverifiable => {
            snapshot_from_node(TypedNode::<_, Unverifiable>::new(node_id, resolved))
        }
        EvidenceStrength::Local => {
            snapshot_from_node(TypedNode::<_, Local>::new(node_id, resolved))
        }
        EvidenceStrength::Witnessed => {
            snapshot_from_node(TypedNode::<_, Witnessed>::new(node_id, resolved))
        }
        EvidenceStrength::Signed => {
            snapshot_from_node(TypedNode::<_, Signed>::new(node_id, resolved))
        }
        EvidenceStrength::Anchored => {
            snapshot_from_node(TypedNode::<_, Anchored>::new(node_id, resolved))
        }
    };

    Ok(record)
}

fn attest_node(
    id: &str,
    current: NodeRecord,
    witness_count: usize,
    external: bool,
) -> Result<NodeRecord, EvalError> {
    if current.strength != EvidenceStrength::Signed {
        return Err(EvalError::AttestationRequiresSigned {
            id: id.to_string(),
            actual: current.strength,
        });
    }

    let signed = TypedNode::<_, Signed>::new(current.node_id, current.value.clone());
    let witnesses = synthetic_witness_set(current.node_id, witness_count, external);
    let anchored = witnesses
        .attest(signed)
        .map_err(|source| EvalError::AttestationFailed {
            id: id.to_string(),
            source,
        })?;

    Ok(snapshot_from_node(anchored))
}

fn derive_node(
    id: &str,
    left: &NodeRecord,
    right: &NodeRecord,
    ty: Type,
) -> Result<NodeRecord, EvalError> {
    match (left.strength, right.strength) {
        (EvidenceStrength::Unverifiable, EvidenceStrength::Unverifiable) => {
            derive_with_markers::<Unverifiable, Unverifiable>(id, left, right, ty)
        }
        (EvidenceStrength::Unverifiable, EvidenceStrength::Local) => {
            derive_with_markers::<Unverifiable, Local>(id, left, right, ty)
        }
        (EvidenceStrength::Unverifiable, EvidenceStrength::Witnessed) => {
            derive_with_markers::<Unverifiable, Witnessed>(id, left, right, ty)
        }
        (EvidenceStrength::Unverifiable, EvidenceStrength::Signed) => {
            derive_with_markers::<Unverifiable, Signed>(id, left, right, ty)
        }
        (EvidenceStrength::Unverifiable, EvidenceStrength::Anchored) => {
            derive_with_markers::<Unverifiable, Anchored>(id, left, right, ty)
        }
        (EvidenceStrength::Local, EvidenceStrength::Unverifiable) => {
            derive_with_markers::<Local, Unverifiable>(id, left, right, ty)
        }
        (EvidenceStrength::Local, EvidenceStrength::Local) => {
            derive_with_markers::<Local, Local>(id, left, right, ty)
        }
        (EvidenceStrength::Local, EvidenceStrength::Witnessed) => {
            derive_with_markers::<Local, Witnessed>(id, left, right, ty)
        }
        (EvidenceStrength::Local, EvidenceStrength::Signed) => {
            derive_with_markers::<Local, Signed>(id, left, right, ty)
        }
        (EvidenceStrength::Local, EvidenceStrength::Anchored) => {
            derive_with_markers::<Local, Anchored>(id, left, right, ty)
        }
        (EvidenceStrength::Witnessed, EvidenceStrength::Unverifiable) => {
            derive_with_markers::<Witnessed, Unverifiable>(id, left, right, ty)
        }
        (EvidenceStrength::Witnessed, EvidenceStrength::Local) => {
            derive_with_markers::<Witnessed, Local>(id, left, right, ty)
        }
        (EvidenceStrength::Witnessed, EvidenceStrength::Witnessed) => {
            derive_with_markers::<Witnessed, Witnessed>(id, left, right, ty)
        }
        (EvidenceStrength::Witnessed, EvidenceStrength::Signed) => {
            derive_with_markers::<Witnessed, Signed>(id, left, right, ty)
        }
        (EvidenceStrength::Witnessed, EvidenceStrength::Anchored) => {
            derive_with_markers::<Witnessed, Anchored>(id, left, right, ty)
        }
        (EvidenceStrength::Signed, EvidenceStrength::Unverifiable) => {
            derive_with_markers::<Signed, Unverifiable>(id, left, right, ty)
        }
        (EvidenceStrength::Signed, EvidenceStrength::Local) => {
            derive_with_markers::<Signed, Local>(id, left, right, ty)
        }
        (EvidenceStrength::Signed, EvidenceStrength::Witnessed) => {
            derive_with_markers::<Signed, Witnessed>(id, left, right, ty)
        }
        (EvidenceStrength::Signed, EvidenceStrength::Signed) => {
            derive_with_markers::<Signed, Signed>(id, left, right, ty)
        }
        (EvidenceStrength::Signed, EvidenceStrength::Anchored) => {
            derive_with_markers::<Signed, Anchored>(id, left, right, ty)
        }
        (EvidenceStrength::Anchored, EvidenceStrength::Unverifiable) => {
            derive_with_markers::<Anchored, Unverifiable>(id, left, right, ty)
        }
        (EvidenceStrength::Anchored, EvidenceStrength::Local) => {
            derive_with_markers::<Anchored, Local>(id, left, right, ty)
        }
        (EvidenceStrength::Anchored, EvidenceStrength::Witnessed) => {
            derive_with_markers::<Anchored, Witnessed>(id, left, right, ty)
        }
        (EvidenceStrength::Anchored, EvidenceStrength::Signed) => {
            derive_with_markers::<Anchored, Signed>(id, left, right, ty)
        }
        (EvidenceStrength::Anchored, EvidenceStrength::Anchored) => {
            derive_with_markers::<Anchored, Anchored>(id, left, right, ty)
        }
    }
}

fn derive_with_markers<L, R>(
    id: &str,
    left: &NodeRecord,
    right: &NodeRecord,
    ty: Type,
) -> Result<NodeRecord, EvalError>
where
    L: Marker + crate::provenance::MinStrength<R>,
    R: Marker,
{
    match ty {
        Type::I64 => match (&left.value, &right.value) {
            (TypedNodeValue::I(_), TypedNodeValue::I(_)) => {
                let left_node = TypedNode::<_, L>::new(left.node_id, left.value.clone());
                let right_node = TypedNode::<_, R>::new(right.node_id, right.value.clone());
                let derived = left_node.derive_from(&right_node, |x, y| match (x, y) {
                    (TypedNodeValue::I(lhs), TypedNodeValue::I(rhs)) => {
                        TypedNodeValue::I(lhs.wrapping_add(*rhs))
                    }
                    _ => unreachable!("type checked before derive"),
                });
                Ok(snapshot_from_node(derived))
            }
            _ => Err(EvalError::TypeMismatch {
                id: id.to_string(),
                expected: "i64",
                actual_left: left.value.type_name(),
                actual_right: right.value.type_name(),
            }),
        },
        Type::String => match (&left.value, &right.value) {
            (TypedNodeValue::S(_), TypedNodeValue::S(_)) => {
                let left_node = TypedNode::<_, L>::new(left.node_id, left.value.clone());
                let right_node = TypedNode::<_, R>::new(right.node_id, right.value.clone());
                let derived = left_node.derive_from(&right_node, |x, y| match (x, y) {
                    (TypedNodeValue::S(lhs), TypedNodeValue::S(rhs)) => {
                        TypedNodeValue::S(format!("{lhs}{rhs}"))
                    }
                    _ => unreachable!("type checked before derive"),
                });
                Ok(snapshot_from_node(derived))
            }
            _ => Err(EvalError::TypeMismatch {
                id: id.to_string(),
                expected: "string",
                actual_left: left.value.type_name(),
                actual_right: right.value.type_name(),
            }),
        },
    }
}

fn resolve_expr(
    expr: Expr,
    env: &HashMap<String, NodeRecord>,
) -> Result<TypedNodeValue, EvalError> {
    match expr {
        Expr::IntLit(value) => Ok(TypedNodeValue::I(value)),
        Expr::StrLit(value) => Ok(TypedNodeValue::S(value)),
        Expr::Ident(id) => env
            .get(&id)
            .map(|record| record.value.clone())
            .ok_or(EvalError::UnknownIdentifier { id }),
    }
}

fn deterministic_node_id(id: &str, value: &TypedNodeValue) -> Uuid {
    let seed = format!("nex|{id}|{value}");
    Uuid::new_v5(&Uuid::NAMESPACE_URL, seed.as_bytes())
}

fn snapshot_from_node<S: Marker>(node: TypedNode<TypedNodeValue, S>) -> NodeRecord {
    let strength = node.strength();
    NodeRecord {
        node_id: node.node_id,
        value: node.value,
        strength,
    }
}

fn synthetic_witness_set(node_id: Uuid, witness_count: usize, external: bool) -> WitnessSet {
    let mut set = WitnessSet::new();
    let witness_time = Utc
        .timestamp_opt(1_700_000_000, 0)
        .single()
        .expect("fixed witness timestamp");

    for idx in 0..witness_count {
        let witness_id = Uuid::new_v5(&node_id, format!("nex|witness|{idx}|{external}").as_bytes());
        let kind = if external {
            WitnessKind::CrossReferencedInExternalLedger
        } else {
            WitnessKind::Cosigned
        };
        set.add(Witness {
            witness_id,
            witnessed_at_utc: witness_time,
            kind,
        });
    }

    set
}

pub fn eval_source(source: &str) -> Result<Env, EvalError> {
    let program = super::parse(source).map_err(|err| EvalError::TypeMismatch {
        id: format!("parse-error:{err}"),
        expected: "valid nex source",
        actual_left: "parse error",
        actual_right: "parse error",
    })?;
    eval(program)
}

#[cfg(test)]
mod tests {
    use super::{eval, execute, TypedNodeValue};
    use crate::nex::parse;
    use crate::quality::EvidenceStrength;

    #[test]
    fn hello_example_produces_three_entries_and_anchored_sum() {
        let source = include_str!("../../examples/hello.nex");
        let program = parse(source).expect("hello.nex should parse");
        let execution = execute(program).expect("hello.nex should evaluate");

        assert_eq!(execution.entries.len(), 3);
        assert_eq!(
            execution.entries.last().expect("assert entry").strength,
            EvidenceStrength::Anchored
        );
        assert_eq!(execution.env.get("sum"), Some(&TypedNodeValue::I(1)));
    }

    #[test]
    fn derive_i64_values_wrapping_adds() {
        let program = parse(
            "let left = node 1 anchored\nlet right = node 2 anchored\nlet total = left derive right as i64\n",
        )
        .expect("parse");
        let execution = execute(program).expect("eval");

        assert_eq!(execution.env.get("total"), Some(&TypedNodeValue::I(3)));
        assert_eq!(
            execution.entries.last().unwrap().strength,
            EvidenceStrength::Anchored
        );
    }

    #[test]
    fn eval_returns_env_only() {
        let program = parse("let sum = node 7 signed\n").expect("parse");
        let env = eval(program).expect("eval");
        assert_eq!(env.get("sum"), Some(&TypedNodeValue::I(7)));
    }
}
