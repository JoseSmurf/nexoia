use crate::quality::EvidenceStrength;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    pub statements: Vec<Stmt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stmt {
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
