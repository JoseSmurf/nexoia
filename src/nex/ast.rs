use crate::types::EvidenceStrength;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    pub statements: Vec<Stmt>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Action {
    Allow,
    Deny,
    Escalate,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Escalate => "escalate",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stmt {
    Use {
        path: String,
    },
    Node {
        id: String,
        value: Expr,
        strength: EvidenceStrength,
    },
    Attest {
        id: String,
        witness_count: usize,
        external: bool,
    },
    Derive {
        id: String,
        left: String,
        right: String,
        ty: Type,
    },
    Assert {
        id: String,
        min: EvidenceStrength,
    },
    Act {
        id: String,
        action: Action,
        requires: EvidenceStrength,
    },
    If {
        condition: Condition,
        then_body: Vec<Stmt>,
        else_body: Vec<Stmt>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expr {
    IntLit(i64),
    StrLit(String),
    Ident(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Type {
    I64,
    String,
}

/// Comparador para condições.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Comparator {
    Gte,
    Lte,
    Gt,
    Lt,
    Eq,
}

/// Operador lógico para composição de condições.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogicalOp {
    And,
    Or,
}

/// Condição composta: `evidence >= strength && evidence2 >= strength2`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    pub left_id: String,
    pub comparator: Comparator,
    pub right_strength: EvidenceStrength,
    pub op: Option<LogicalOp>,
    pub right_id: Option<String>,
    pub right_comparator: Option<Comparator>,
    pub right_strength2: Option<EvidenceStrength>,
}
