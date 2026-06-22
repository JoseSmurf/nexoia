//! reactive.rs — Motor de comportamentos reativos da NEX
//!
//! Separa avaliação de regras (determinística) de execução de ações (efeitos colaterais).

use crate::nex::ast::{ReactiveAction, Trigger};
use std::fmt;

/// Evento que dispara regras reativas.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    HeartbeatMiss { count: u32 },
    ReputationBelow { value: f32 },
    PeerConnected { node_id: String },
    PeerDisconnected { node_id: String },
}

/// Ação a ser executada pelo sistema.
#[derive(Debug, Clone)]
pub enum ExecutableAction {
    Log(String),
    Emit(String),
    MarkInactive { peer: String },
    AdjustReputation { peer: String, delta: i32 },
}

/// Regra reativa parseada de um programa NEX.
#[derive(Debug, Clone)]
pub struct ReactiveRule {
    pub trigger: Trigger,
    pub actions: Vec<ReactiveAction>,
}

/// Resultado da avaliação de regras.
#[derive(Debug, Clone)]
pub struct EvaluationResult {
    pub matched: bool,
    pub actions: Vec<ExecutableAction>,
}

/// Motor de comportamentos reativos.
/// Separa avaliação de regras (determinística) de execução de ações.
pub struct ReactiveEngine {
    rules: Vec<ReactiveRule>,
}

impl ReactiveEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: ReactiveRule) {
        self.rules.push(rule);
    }

    pub fn rules(&self) -> &[ReactiveRule] {
        &self.rules
    }

    pub fn clear(&mut self) {
        self.rules.clear();
    }

    /// Avalia um evento contra todas as regras.
    /// Retorna ações a serem executadas (determinístico).
    pub fn evaluate(&self, event: &NetworkEvent) -> EvaluationResult {
        let mut matched = false;
        let mut actions = Vec::new();

        for rule in &self.rules {
            if self.matches_trigger(&rule.trigger, event) {
                matched = true;
                for action in &rule.actions {
                    if let Some(executable) = self.prepare_action(action, event) {
                        actions.push(executable);
                    }
                }
            }
        }

        EvaluationResult { matched, actions }
    }

    fn matches_trigger(&self, trigger: &Trigger, event: &NetworkEvent) -> bool {
        match (trigger, event) {
            (Trigger::HeartbeatMiss { threshold }, NetworkEvent::HeartbeatMiss { count }) => {
                count >= threshold
            }
            (Trigger::ReputationBelow { threshold }, NetworkEvent::ReputationBelow { value }) => {
                value < threshold
            }
            (Trigger::PeerConnected, NetworkEvent::PeerConnected { .. }) => true,
            (Trigger::PeerDisconnected, NetworkEvent::PeerDisconnected { .. }) => true,
            _ => false,
        }
    }

    fn prepare_action(
        &self,
        action: &ReactiveAction,
        event: &NetworkEvent,
    ) -> Option<ExecutableAction> {
        match action {
            ReactiveAction::Log(msg) => Some(ExecutableAction::Log(msg.clone())),
            ReactiveAction::Emit(event_name) => Some(ExecutableAction::Emit(event_name.clone())),
            ReactiveAction::MarkInactive { peer } => {
                if let NetworkEvent::PeerDisconnected { node_id } = event {
                    Some(ExecutableAction::MarkInactive {
                        peer: node_id.clone(),
                    })
                } else {
                    Some(ExecutableAction::MarkInactive { peer: peer.clone() })
                }
            }
            ReactiveAction::AdjustReputation { peer, delta } => {
                if let NetworkEvent::ReputationBelow { .. } = event {
                    Some(ExecutableAction::AdjustReputation {
                        peer: peer.clone(),
                        delta: *delta,
                    })
                } else {
                    Some(ExecutableAction::AdjustReputation {
                        peer: peer.clone(),
                        delta: *delta,
                    })
                }
            }
        }
    }
}

impl fmt::Display for NetworkEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkEvent::HeartbeatMiss { count } => write!(f, "heartbeat_miss({})", count),
            NetworkEvent::ReputationBelow { value } => write!(f, "reputation_below({})", value),
            NetworkEvent::PeerConnected { node_id } => write!(f, "peer_connected({})", node_id),
            NetworkEvent::PeerDisconnected { node_id } => {
                write!(f, "peer_disconnected({})", node_id)
            }
        }
    }
}

impl fmt::Display for ExecutableAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutableAction::Log(msg) => write!(f, "log(\"{}\")", msg),
            ExecutableAction::Emit(event) => write!(f, "emit({})", event),
            ExecutableAction::MarkInactive { peer } => write!(f, "marcar_inativo({})", peer),
            ExecutableAction::AdjustReputation { peer, delta } => {
                write!(f, "ajustar_reputacao({}, {})", peer, delta)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_miss_triggers_rule() {
        let mut engine = ReactiveEngine::new();
        engine.add_rule(ReactiveRule {
            trigger: Trigger::HeartbeatMiss { threshold: 3 },
            actions: vec![ReactiveAction::Log("Peer inativo".to_string())],
        });

        let event = NetworkEvent::HeartbeatMiss { count: 4 };
        let result = engine.evaluate(&event);

        assert!(result.matched);
        assert_eq!(result.actions.len(), 1);
        assert!(matches!(result.actions[0], ExecutableAction::Log(_)));
    }

    #[test]
    fn heartbeat_miss_below_threshold() {
        let mut engine = ReactiveEngine::new();
        engine.add_rule(ReactiveRule {
            trigger: Trigger::HeartbeatMiss { threshold: 3 },
            actions: vec![ReactiveAction::Log("Peer inativo".to_string())],
        });

        let event = NetworkEvent::HeartbeatMiss { count: 2 };
        let result = engine.evaluate(&event);

        assert!(!result.matched);
        assert!(result.actions.is_empty());
    }

    #[test]
    fn reputation_below_triggers() {
        let mut engine = ReactiveEngine::new();
        engine.add_rule(ReactiveRule {
            trigger: Trigger::ReputationBelow { threshold: 0.3 },
            actions: vec![ReactiveAction::Emit("alert".to_string())],
        });

        let event = NetworkEvent::ReputationBelow { value: 0.2 };
        let result = engine.evaluate(&event);

        assert!(result.matched);
        assert_eq!(result.actions.len(), 1);
    }

    #[test]
    fn multiple_rules_same_event() {
        let mut engine = ReactiveEngine::new();
        engine.add_rule(ReactiveRule {
            trigger: Trigger::HeartbeatMiss { threshold: 3 },
            actions: vec![ReactiveAction::Log("Log 1".to_string())],
        });
        engine.add_rule(ReactiveRule {
            trigger: Trigger::HeartbeatMiss { threshold: 5 },
            actions: vec![ReactiveAction::Log("Log 2".to_string())],
        });

        let event = NetworkEvent::HeartbeatMiss { count: 6 };
        let result = engine.evaluate(&event);

        assert!(result.matched);
        assert_eq!(result.actions.len(), 2);
    }

    #[test]
    fn mark_inactive_action() {
        let mut engine = ReactiveEngine::new();
        engine.add_rule(ReactiveRule {
            trigger: Trigger::HeartbeatMiss { threshold: 3 },
            actions: vec![ReactiveAction::MarkInactive {
                peer: "node_a".to_string(),
            }],
        });

        let event = NetworkEvent::HeartbeatMiss { count: 4 };
        let result = engine.evaluate(&event);

        assert!(result.matched);
        assert_eq!(result.actions.len(), 1);
        assert!(matches!(
            result.actions[0],
            ExecutableAction::MarkInactive { .. }
        ));
    }

    #[test]
    fn adjust_reputation_action() {
        let mut engine = ReactiveEngine::new();
        engine.add_rule(ReactiveRule {
            trigger: Trigger::ReputationBelow { threshold: 0.3 },
            actions: vec![ReactiveAction::AdjustReputation {
                peer: "node_b".to_string(),
                delta: -20,
            }],
        });

        let event = NetworkEvent::ReputationBelow { value: 0.2 };
        let result = engine.evaluate(&event);

        assert!(result.matched);
        assert_eq!(result.actions.len(), 1);
        assert!(matches!(
            result.actions[0],
            ExecutableAction::AdjustReputation { .. }
        ));
    }

    #[test]
    fn no_matching_rules() {
        let mut engine = ReactiveEngine::new();
        engine.add_rule(ReactiveRule {
            trigger: Trigger::PeerConnected,
            actions: vec![ReactiveAction::Log("Connected".to_string())],
        });

        let event = NetworkEvent::HeartbeatMiss { count: 5 };
        let result = engine.evaluate(&event);

        assert!(!result.matched);
        assert!(result.actions.is_empty());
    }
}
