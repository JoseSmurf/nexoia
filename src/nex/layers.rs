//! NEX Layers — Organização em camadas da linguagem NEX
//!
//! # Arquitetura em Camadas
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │ Camada Avançada: Comportamentos Reativos        │
//! │   on <trigger> → <ações limitadas>              │
//! │   Requer: Camada Intermediária                  │
//! ├─────────────────────────────────────────────────┤
//! │ Camada Intermediária: Lógica Condicional        │
//! │   if <condição> then <senão>                    │
//! │   Requer: Camada Básica                         │
//! ├─────────────────────────────────────────────────┤
//! │ Camada Básica: Descrição de Evidências          │
//! │   let, assert, act, derive, attest              │
//! │   Não requer nenhuma outra camada               │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! # Regra de Dependência
//! Cada camada só pode usar funcionalidades das camadas inferiores.
//! Camadas superiores NÃO podem acessar internals das inferiores.

use crate::nex::ast::Stmt;

/// Nível de complexidade da linguagem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NexLayer {
    /// Básica: let, assert, act, derive, attest
    Basic,
    /// Intermediária: + if/else condicionais
    Intermediate,
    /// Avançada: + on <trigger> comportamentos reativos
    Advanced,
}

impl fmt::Display for NexLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NexLayer::Basic => write!(f, "basic"),
            NexLayer::Intermediate => write!(f, "intermediate"),
            NexLayer::Advanced => write!(f, "advanced"),
        }
    }
}

/// Verifica se uma lista de statements requer uma camada específica.
pub fn required_layer(statements: &[Stmt]) -> NexLayer {
    let mut max_layer = NexLayer::Basic;

    for stmt in statements {
        match stmt {
            Stmt::If { .. } if NexLayer::Intermediate > max_layer => {
                max_layer = NexLayer::Intermediate;
            }
            Stmt::On { .. } if NexLayer::Advanced > max_layer => {
                max_layer = NexLayer::Advanced;
            }
            _ => {}
        }
    }

    max_layer
}

/// Verifica se um programa NEX é válido para uma camada dada.
pub fn validate_layer(statements: &[Stmt], available: NexLayer) -> Result<(), LayerError> {
    let required = required_layer(statements);

    if required > available {
        return Err(LayerError::InsufficientLayer {
            required,
            available,
        });
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayerError {
    InsufficientLayer {
        required: NexLayer,
        available: NexLayer,
    },
}

impl fmt::Display for LayerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayerError::InsufficientLayer {
                required,
                available,
            } => {
                write!(
                    f,
                    "program requires {} layer, but only {} is available",
                    required, available
                )
            }
        }
    }
}

use serde::{Deserialize, Serialize};
use std::fmt;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nex::ast::{Action, Comparator, Condition, Expr, ReactiveAction, Trigger};

    #[test]
    fn basic_layer_only() {
        let stmts = vec![
            Stmt::Node {
                id: "x".to_string(),
                value: Expr::IntLit(10),
                strength: crate::types::EvidenceStrength::Signed,
            },
            Stmt::Act {
                id: "x".to_string(),
                action: Action::Allow,
                requires: crate::types::EvidenceStrength::Signed,
            },
        ];

        assert_eq!(required_layer(&stmts), NexLayer::Basic);
    }

    #[test]
    fn intermediate_layer_needed() {
        let stmts = vec![Stmt::If {
            condition: Condition {
                left_id: "x".to_string(),
                comparator: Comparator::Gte,
                right_strength: crate::types::EvidenceStrength::Signed,
                op: None,
                right_id: None,
                right_comparator: None,
                right_strength2: None,
            },
            then_body: vec![],
            else_body: vec![],
        }];

        assert_eq!(required_layer(&stmts), NexLayer::Intermediate);
    }

    #[test]
    fn advanced_layer_needed() {
        let stmts = vec![Stmt::On {
            trigger: Trigger::HeartbeatMiss { threshold: 3 },
            actions: vec![ReactiveAction::Log("test".to_string())],
        }];

        assert_eq!(required_layer(&stmts), NexLayer::Advanced);
    }

    #[test]
    fn validate_layer_passes() {
        let stmts = vec![Stmt::Node {
            id: "x".to_string(),
            value: Expr::IntLit(10),
            strength: crate::types::EvidenceStrength::Signed,
        }];

        assert!(validate_layer(&stmts, NexLayer::Basic).is_ok());
    }

    #[test]
    fn validate_layer_fails() {
        let stmts = vec![Stmt::On {
            trigger: Trigger::HeartbeatMiss { threshold: 3 },
            actions: vec![ReactiveAction::Log("test".to_string())],
        }];

        let result = validate_layer(&stmts, NexLayer::Basic);
        assert!(result.is_err());
    }
}
