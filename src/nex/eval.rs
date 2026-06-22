use crate::nex::ast::{
    Action, Comparator, Condition, Expr, LogicalOp, Program, ReactiveAction, Stmt, Trigger, Type,
};
use crate::provenance::typed_node::Marker;
use crate::provenance::{
    Anchored, InsufficientWitnessesError, Local, Signed, TypedNode, Unverifiable, Witness,
    WitnessKind, WitnessSet, Witnessed,
};
use crate::types::EvidenceStrength;
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
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
pub struct ActionView {
    pub id: String,
    pub decision_id: Uuid,
    pub action: Action,
    pub required_strength: EvidenceStrength,
    pub actual_strength: EvidenceStrength,
    pub granted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TraceEntry {
    Node(NodeView),
    Action(ActionView),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub env: Env,
    pub entries: Vec<TraceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    UnknownIdentifier {
        id: String,
    },
    MissingImport {
        path: String,
    },
    CircularImport {
        chain: Vec<String>,
    },
    ImportError {
        path: String,
        message: String,
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
    ActionDenied {
        action: Action,
        required: EvidenceStrength,
        actual: EvidenceStrength,
        message: String,
    },
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownIdentifier { id } => write!(f, "unknown identifier '{id}'"),
            Self::MissingImport { path } => write!(f, "missing import '{path}'"),
            Self::CircularImport { chain } => {
                write!(f, "circular import detected: {}", chain.join(" -> "))
            }
            Self::ImportError { path, message } => {
                write!(f, "failed to import '{path}': {message}")
            }
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
            Self::ActionDenied {
                action,
                required,
                actual,
                message,
            } => write!(
                f,
                "action {action} denied: actual {actual} does not meet required {required}: {message}"
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
struct RuntimeState {
    node_id: Uuid,
    value: TypedNodeValue,
    strength: EvidenceStrength,
}

impl RuntimeState {
    fn view(&self, id: String) -> NodeView {
        node_view(id, self.node_id, self.value.clone(), self.strength)
    }
}

#[derive(Debug, Clone)]
struct NodeRecord {
    node_id: Uuid,
    value: TypedNodeValue,
    strength: EvidenceStrength,
}

impl NodeRecord {
    fn into_state(self) -> RuntimeState {
        RuntimeState {
            node_id: self.node_id,
            value: self.value,
            strength: self.strength,
        }
    }
}

pub fn eval(program: Program) -> Result<Env, EvalError> {
    eval_in_dir(program, Path::new("."))
}

pub fn eval_in_dir<P: AsRef<Path>>(program: Program, base_dir: P) -> Result<Env, EvalError> {
    execute_in_dir(program, base_dir).map(|result| result.env)
}

pub fn execute(program: Program) -> Result<ExecutionResult, EvalError> {
    execute_in_dir(program, Path::new("."))
}

pub fn execute_in_dir<P: AsRef<Path>>(
    program: Program,
    base_dir: P,
) -> Result<ExecutionResult, EvalError> {
    let program = expand_program(program, base_dir)?;
    execute_expanded(program)
}

pub fn expand_program<P: AsRef<Path>>(program: Program, base_dir: P) -> Result<Program, EvalError> {
    let mut visited = HashSet::new();
    let mut stack = Vec::new();
    let statements = expand_statements(
        program.statements,
        base_dir.as_ref(),
        &mut visited,
        &mut stack,
    )?;
    Ok(Program { statements })
}

fn execute_expanded(program: Program) -> Result<ExecutionResult, EvalError> {
    let mut working: HashMap<String, RuntimeState> = HashMap::new();
    let mut entries = Vec::new();
    let mut current_subject: Option<RuntimeState> = None;

    for statement in program.statements {
        match statement {
            Stmt::Use { .. } => unreachable!("imports must be expanded before evaluation"),
            Stmt::Node {
                id,
                value,
                strength,
            } => {
                let state = build_node(&id, value, strength, &working)?.into_state();
                entries.push(TraceEntry::Node(state.view(id.clone())));
                current_subject = Some(state.clone());
                working.insert(id, state);
            }
            Stmt::Attest {
                id,
                witness_count,
                external,
            } => {
                let current = working
                    .get(&id)
                    .cloned()
                    .ok_or_else(|| EvalError::UnknownIdentifier { id: id.clone() })?;
                let state = attest_node(&id, current, witness_count, external)?;
                entries.push(TraceEntry::Node(state.view(id.clone())));
                current_subject = Some(state.clone());
                working.insert(id, state);
            }
            Stmt::Derive {
                id,
                left,
                right,
                ty,
            } => {
                let left_state = working
                    .get(&left)
                    .cloned()
                    .ok_or_else(|| EvalError::UnknownIdentifier { id: left.clone() })?;
                let right_state = working
                    .get(&right)
                    .cloned()
                    .ok_or_else(|| EvalError::UnknownIdentifier { id: right.clone() })?;
                let state = derive_node(&id, &left_state, &right_state, ty)?;
                entries.push(TraceEntry::Node(state.view(id.clone())));
                current_subject = Some(state.clone());
                working.insert(id, state);
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
                entries.push(TraceEntry::Node(record.view(id)));
                current_subject = Some(record.clone());
            }
            Stmt::Act {
                id,
                action,
                requires,
            } => {
                let record = working
                    .get(&id)
                    .cloned()
                    .or_else(|| current_subject.clone())
                    .ok_or_else(|| EvalError::UnknownIdentifier { id: id.clone() })?;
                let actual = record.strength;
                let decision_id = action_decision_id(&id, action, requires);
                let granted = actual >= requires;

                entries.push(TraceEntry::Action(ActionView {
                    id,
                    decision_id,
                    action,
                    required_strength: requires,
                    actual_strength: actual,
                    granted,
                    reason: (!granted).then_some("ActionDenied".to_string()),
                }));
            }
            Stmt::On { .. } => {
                // On statements são registrados mas não executados imediatamente
                // Eles são processados pelo motor de eventos externo
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                let condition_met = evaluate_condition(&condition, &working);
                let body = if condition_met {
                    &then_body
                } else {
                    &else_body
                };

                // Executa o bloco correspondente
                for stmt in body {
                    match stmt.clone() {
                        Stmt::Act {
                            id,
                            action,
                            requires,
                        } => {
                            let record = working
                                .get(id.as_str())
                                .cloned()
                                .or_else(|| current_subject.clone())
                                .ok_or_else(|| EvalError::UnknownIdentifier { id: id.clone() })?;
                            let actual = record.strength;
                            let decision_id = action_decision_id(&id, action, requires);
                            let granted = actual >= requires;

                            entries.push(TraceEntry::Action(ActionView {
                                id,
                                decision_id,
                                action,
                                required_strength: requires,
                                actual_strength: actual,
                                granted,
                                reason: if !granted {
                                    Some("ActionDenied".to_string())
                                } else {
                                    Some("ConditionalMet".to_string())
                                },
                            }));
                        }
                        _ => {
                            // Outros statements no bloco (por enquanto só Act é suportado)
                        }
                    }
                }
            }
        }
    }

    let env = working
        .into_iter()
        .map(|(id, record)| (id, record.value))
        .collect();

    Ok(ExecutionResult { env, entries })
}

/// Avalia uma condição composta.
fn evaluate_condition(condition: &Condition, working: &HashMap<String, RuntimeState>) -> bool {
    let left_record = match working.get(&condition.left_id) {
        Some(r) => r,
        None => return false,
    };

    let left_matches = match condition.comparator {
        Comparator::Gte => left_record.strength >= condition.right_strength,
        Comparator::Lte => left_record.strength <= condition.right_strength,
        Comparator::Gt => left_record.strength > condition.right_strength,
        Comparator::Lt => left_record.strength < condition.right_strength,
        Comparator::Eq => left_record.strength == condition.right_strength,
    };

    if let Some(op) = condition.op {
        let right_record = condition.right_id.as_ref().and_then(|id| working.get(id));
        let right_matches = match (op, &condition.right_comparator, &condition.right_strength2) {
            (LogicalOp::And, Some(Comparator::Gte), Some(s2)) => {
                right_record.map_or(false, |r| r.strength >= *s2)
            }
            (LogicalOp::And, Some(Comparator::Lte), Some(s2)) => {
                right_record.map_or(false, |r| r.strength <= *s2)
            }
            (LogicalOp::And, Some(Comparator::Gt), Some(s2)) => {
                right_record.map_or(false, |r| r.strength > *s2)
            }
            (LogicalOp::And, Some(Comparator::Lt), Some(s2)) => {
                right_record.map_or(false, |r| r.strength < *s2)
            }
            (LogicalOp::And, Some(Comparator::Eq), Some(s2)) => {
                right_record.map_or(false, |r| r.strength == *s2)
            }
            (LogicalOp::Or, Some(Comparator::Gte), Some(s2)) => {
                right_record.map_or(false, |r| r.strength >= *s2)
            }
            (LogicalOp::Or, Some(Comparator::Lte), Some(s2)) => {
                right_record.map_or(false, |r| r.strength <= *s2)
            }
            (LogicalOp::Or, Some(Comparator::Gt), Some(s2)) => {
                right_record.map_or(false, |r| r.strength > *s2)
            }
            (LogicalOp::Or, Some(Comparator::Lt), Some(s2)) => {
                right_record.map_or(false, |r| r.strength < *s2)
            }
            (LogicalOp::Or, Some(Comparator::Eq), Some(s2)) => {
                right_record.map_or(false, |r| r.strength == *s2)
            }
            _ => false,
        };

        match op {
            LogicalOp::And => left_matches && right_matches,
            LogicalOp::Or => left_matches || right_matches,
        }
    } else {
        left_matches
    }
}

fn expand_statements(
    statements: Vec<Stmt>,
    base_dir: &Path,
    visited: &mut HashSet<PathBuf>,
    stack: &mut Vec<PathBuf>,
) -> Result<Vec<Stmt>, EvalError> {
    let mut imports = Vec::new();
    let mut body = Vec::new();

    for statement in statements {
        match statement {
            Stmt::Use { path } => imports.push(path),
            other => body.push(other),
        }
    }

    let mut expanded = Vec::new();

    for import in imports {
        let path = resolve_import_path(base_dir, &import);
        expanded.extend(load_import(&path, visited, stack)?);
    }

    expanded.extend(body);
    Ok(expanded)
}

fn load_import(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    stack: &mut Vec<PathBuf>,
) -> Result<Vec<Stmt>, EvalError> {
    let path = path.to_path_buf();

    if let Some(start) = stack.iter().position(|item| item == &path) {
        let mut chain = stack[start..]
            .iter()
            .map(|item| item.display().to_string())
            .collect::<Vec<_>>();
        chain.push(path.display().to_string());
        return Err(EvalError::CircularImport { chain });
    }

    if visited.contains(&path) {
        return Ok(Vec::new());
    }

    let source = fs::read_to_string(&path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            EvalError::MissingImport {
                path: path.display().to_string(),
            }
        } else {
            EvalError::ImportError {
                path: path.display().to_string(),
                message: err.to_string(),
            }
        }
    })?;

    stack.push(path.clone());
    let result = (|| -> Result<Vec<Stmt>, EvalError> {
        let program = super::parse(&source).map_err(|err| EvalError::ImportError {
            path: path.display().to_string(),
            message: err.to_string(),
        })?;
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        expand_statements(program.statements, base_dir, visited, stack)
    })();
    stack.pop();

    let statements = result?;
    visited.insert(path);
    Ok(statements)
}

fn resolve_import_path(base_dir: &Path, import: &str) -> PathBuf {
    let mut path = PathBuf::from(base_dir);

    for segment in import.split('.') {
        path.push(segment);
    }

    path.set_extension("nex");
    path
}

fn build_node(
    id: &str,
    value: Expr,
    strength: EvidenceStrength,
    env: &HashMap<String, RuntimeState>,
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
    current: RuntimeState,
    witness_count: usize,
    external: bool,
) -> Result<RuntimeState, EvalError> {
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

    Ok(snapshot_from_node(anchored).into_state())
}

fn derive_node(
    id: &str,
    left: &RuntimeState,
    right: &RuntimeState,
    ty: Type,
) -> Result<RuntimeState, EvalError> {
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
    left: &RuntimeState,
    right: &RuntimeState,
    ty: Type,
) -> Result<RuntimeState, EvalError>
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
                let strength = derived.strength();
                Ok(RuntimeState {
                    node_id: derived.node_id,
                    value: derived.value,
                    strength,
                })
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
                let strength = derived.strength();
                Ok(RuntimeState {
                    node_id: derived.node_id,
                    value: derived.value,
                    strength,
                })
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
    env: &HashMap<String, RuntimeState>,
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

fn action_decision_id(id: &str, action: Action, required: EvidenceStrength) -> Uuid {
    let seed = format!("nex-act|{id}|{action}|{required}");
    Uuid::new_v5(&Uuid::NAMESPACE_URL, seed.as_bytes())
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
    use super::{eval, execute, expand_program, ActionView, TraceEntry, TypedNodeValue};
    use crate::nex::{parse, program_hash, Action, EvalError};
    use crate::types::EvidenceStrength;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;
    use uuid::Uuid;

    #[test]
    fn hello_example_produces_four_entries_and_anchored_sum() {
        let source = include_str!("../../examples/hello.nex");
        let program = parse(source).expect("hello.nex should parse");
        let execution = execute(program).expect("hello.nex should evaluate");

        assert_eq!(execution.entries.len(), 4);
        assert_eq!(execution.env.get("sum"), Some(&TypedNodeValue::I(1)));
        assert!(matches!(
            execution.entries[0],
            TraceEntry::Node(ref node) if node.strength == EvidenceStrength::Signed
        ));
        assert!(matches!(
            execution.entries[1],
            TraceEntry::Node(ref node) if node.strength == EvidenceStrength::Anchored
        ));
        assert!(matches!(
            execution.entries[2],
            TraceEntry::Node(ref node) if node.strength == EvidenceStrength::Anchored
        ));
        assert!(matches!(
            execution.entries[3],
            TraceEntry::Action(ActionView {
                action: Action::Allow,
                required_strength: EvidenceStrength::Anchored,
                actual_strength: EvidenceStrength::Anchored,
                granted: true,
                ..
            })
        ));

        if let TraceEntry::Action(action) = &execution.entries[3] {
            assert_eq!(
                action.decision_id,
                Uuid::new_v5(&Uuid::NAMESPACE_URL, b"nex-act|sum|allow|ANCHORED")
            );
        } else {
            panic!("expected action entry");
        }
    }

    #[test]
    fn derive_i64_values_wrapping_adds() {
        let program = parse(
            "let left = node 1 anchored\nlet right = node 2 anchored\nlet total = left derive right as i64\n",
        )
        .expect("parse");
        let execution = execute(program).expect("eval");

        assert_eq!(execution.env.get("total"), Some(&TypedNodeValue::I(3)));
        assert!(matches!(
            execution.entries.last().expect("derive entry"),
            TraceEntry::Node(node) if node.strength == EvidenceStrength::Anchored
        ));
    }

    #[test]
    fn eval_returns_env_only() {
        let program = parse("let sum = node 7 signed\n").expect("parse");
        let env = eval(program).expect("eval");
        assert_eq!(env.get("sum"), Some(&TypedNodeValue::I(7)));
    }

    #[test]
    fn act_emits_action_entry_when_strength_is_sufficient() {
        let program =
            parse("let decision = node 1 anchored\nact decision = allow requires signed\n")
                .expect("parse");
        let execution = execute(program).expect("eval");

        match execution.entries.last().expect("action entry") {
            TraceEntry::Action(action) => {
                assert_eq!(action.action, Action::Allow);
                assert!(action.granted);
                assert_eq!(action.required_strength, EvidenceStrength::Signed);
                assert_eq!(action.actual_strength, EvidenceStrength::Anchored);
            }
            TraceEntry::Node(_) => panic!("expected action entry"),
        }
    }

    #[test]
    fn act_denied_when_strength_is_too_weak_records_decision() {
        let program =
            parse("let decision = node 1 signed\nact decision = deny requires anchored\n")
                .expect("parse");
        let execution = execute(program).expect("eval");

        match execution.entries.last().expect("action entry") {
            TraceEntry::Action(view) => {
                assert_eq!(view.action, Action::Deny);
                assert!(!view.granted);
                assert_eq!(view.required_strength, EvidenceStrength::Anchored);
                assert_eq!(view.actual_strength, EvidenceStrength::Signed);
                assert_eq!(view.reason.as_deref(), Some("ActionDenied"));
            }
            TraceEntry::Node(_) => panic!("expected action entry"),
        }
    }

    #[test]
    fn program_hash_is_stable_for_same_program() {
        let program = parse("let sum = node 1 signed\n").expect("parse");
        let hash_a = program_hash(&program);
        let hash_b = program_hash(&program);

        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn program_hash_changes_when_source_changes() {
        let program_a = parse("let sum = node 1 signed\n").expect("parse");
        let program_b = parse("let sum = node 2 signed\n").expect("parse");

        assert_ne!(program_hash(&program_a), program_hash(&program_b));
    }

    #[test]
    fn import_resolves_examples_lib_risk() {
        let examples_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
        let source = fs::read_to_string(examples_dir.join("check.nex")).expect("read check.nex");
        let program = parse(&source).expect("parse");
        let expanded = expand_program(program, &examples_dir).expect("expand imports");
        let execution = execute(expanded).expect("eval");

        assert_eq!(
            execution.env.get("threshold"),
            Some(&TypedNodeValue::I(700))
        );
        assert_eq!(
            execution.env.get("user_score"),
            Some(&TypedNodeValue::I(750))
        );
        assert!(matches!(
            execution.entries.last(),
            Some(TraceEntry::Action(ActionView { granted: true, .. }))
        ));
    }

    #[test]
    fn missing_import_fails_closed() {
        let dir = tempdir().expect("tempdir");
        let source = "use lib.risk\nlet sum = node 1 signed\n";
        let program = parse(source).expect("parse");
        let err = expand_program(program, dir.path()).expect_err("missing import");

        match err {
            EvalError::MissingImport { path } => {
                let normalized = path.replace('\\', "/");
                assert!(normalized.ends_with("lib/risk.nex"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn circular_import_fails_closed() {
        let dir = tempdir().expect("tempdir");
        let main_path = dir.path().join("main.nex");
        let a_path = dir.path().join("a.nex");
        let b_path = dir.path().join("b.nex");

        fs::write(&main_path, "use a\nlet sum = node 1 signed\n").expect("write main");
        fs::write(&a_path, "use b\nlet a = node 2 signed\n").expect("write a");
        fs::write(&b_path, "use a\nlet b = node 3 signed\n").expect("write b");

        let source = fs::read_to_string(&main_path).expect("read main");
        let program = parse(&source).expect("parse");
        let err = expand_program(program, dir.path()).expect_err("circular import");

        match err {
            EvalError::CircularImport { chain } => {
                assert!(chain.len() >= 3);
                assert!(chain.first().expect("chain start").ends_with("a.nex"));
                assert!(chain.last().expect("chain end").ends_with("a.nex"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
