pub mod ast;
pub mod eval;
pub mod parser;

use blake3::Hasher;
use serde::Serialize;

pub use ast::{Action, Expr, Program, Stmt, Type};
pub use eval::{
    eval, eval_in_dir, execute, execute_in_dir, expand_program, ActionView, Env, EvalError,
    ExecutionResult, NodeView, TraceEntry, TypedNodeValue,
};
pub use parser::{parse, ParseError};

pub fn program_hash<P: Serialize>(program: &P) -> String {
    let canonical = serde_json::to_string(program).expect("serialize program");
    let mut h = Hasher::new();
    h.update(canonical.as_bytes());
    h.finalize().to_hex().to_string()
}

pub const NEX_VERSION: &str = "1.0.0";
pub const NEX_GRAMMAR_VERSION: u32 = 1;
