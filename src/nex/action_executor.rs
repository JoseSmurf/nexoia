//! action_executor.rs — Executa ações determinadas pelo ReactiveEngine
//!
//! Separa avaliação de regras (puro) de execução de ações (efeitos colaterais).

use crate::network::reputation::ReputationStore;
use crate::network::transport::PeerState;
use crate::nex::reactive::ExecutableAction;
use std::collections::HashMap;
use std::net::SocketAddr;

/// Resultado da execução de ações.
#[derive(Debug, Clone)]
pub struct ExecutionReport {
    pub logs: Vec<String>,
    pub emissions: Vec<String>,
    pub peer_changes: Vec<PeerChange>,
    pub reputation_changes: Vec<ReputationChange>,
}

#[derive(Debug, Clone)]
pub struct PeerChange {
    pub peer: String,
    pub change: String,
}

#[derive(Debug, Clone)]
pub struct ReputationChange {
    pub peer: String,
    pub delta: i32,
    pub new_value: f32,
}

/// Executor de ações do sistema.
/// Recebe ações do ReactiveEngine e aplica efeitos reais.
pub struct ActionExecutor;

impl ActionExecutor {
    /// Executa uma lista de ações no sistema.
    pub fn execute(
        actions: &[ExecutableAction],
        peer_states: &mut HashMap<SocketAddr, PeerState>,
        reputation: &mut ReputationStore,
        peer_addrs: &HashMap<String, SocketAddr>,
    ) -> ExecutionReport {
        let mut report = ExecutionReport {
            logs: Vec::new(),
            emissions: Vec::new(),
            peer_changes: Vec::new(),
            reputation_changes: Vec::new(),
        };

        for action in actions {
            match action {
                ExecutableAction::Log(msg) => {
                    println!("NEX: {}", msg);
                    report.logs.push(msg.clone());
                }
                ExecutableAction::Emit(event) => {
                    report.emissions.push(event.clone());
                }
                ExecutableAction::MarkInactive { peer } => {
                    if let Some(addr) = peer_addrs.get(peer) {
                        if let Some(state) = peer_states.get_mut(addr) {
                            state.record_miss();
                            report.peer_changes.push(PeerChange {
                                peer: peer.clone(),
                                change: "marked_inactive".to_string(),
                            });
                        }
                    }
                }
                ExecutableAction::AdjustReputation { peer, delta } => {
                    let rep = reputation.get_or_create(peer);
                    if *delta > 0 {
                        for _ in 0..*delta {
                            rep.record_success();
                        }
                    } else {
                        for _ in 0..(-*delta) {
                            rep.record_failure();
                        }
                    }
                    report.reputation_changes.push(ReputationChange {
                        peer: peer.clone(),
                        delta: *delta,
                        new_value: 0.0, // Simplificado
                    });
                }
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nex::ast::Trigger;
    use crate::nex::layers::NexLayer;
    use crate::nex::reactive::{NetworkEvent, ReactiveEngine, ReactiveRule};

    #[test]
    fn execute_log_action() {
        let actions = vec![ExecutableAction::Log("Test message".to_string())];
        let mut peer_states = HashMap::new();
        let mut reputation = ReputationStore::new();
        let peer_addrs = HashMap::new();

        let report =
            ActionExecutor::execute(&actions, &mut peer_states, &mut reputation, &peer_addrs);

        assert_eq!(report.logs.len(), 1);
        assert_eq!(report.logs[0], "Test message");
    }

    #[test]
    fn execute_mark_inactive_action() {
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let mut peer_states = HashMap::new();
        peer_states.insert(addr, PeerState::new());
        let mut reputation = ReputationStore::new();
        let mut peer_addrs = HashMap::new();
        peer_addrs.insert("node_a".to_string(), addr);

        let actions = vec![ExecutableAction::MarkInactive {
            peer: "node_a".to_string(),
        }];

        let report =
            ActionExecutor::execute(&actions, &mut peer_states, &mut reputation, &peer_addrs);

        assert_eq!(report.peer_changes.len(), 1);
        assert!(peer_states.get(&addr).unwrap().consecutive_misses > 0);
    }

    #[test]
    fn execute_adjust_reputation_action() {
        let mut peer_states = HashMap::new();
        let mut reputation = ReputationStore::new();
        let peer_addrs = HashMap::new();

        let actions = vec![ExecutableAction::AdjustReputation {
            peer: "node_b".to_string(),
            delta: -10,
        }];

        let report =
            ActionExecutor::execute(&actions, &mut peer_states, &mut reputation, &peer_addrs);

        assert_eq!(report.reputation_changes.len(), 1);
        assert!(reputation.is_banned("node_b"));
    }

    #[test]
    fn full_pipeline_heartbeat_miss() {
        // Arrange
        let mut engine = ReactiveEngine::with_layer(NexLayer::Advanced);
        engine
            .add_rule(ReactiveRule {
                trigger: Trigger::HeartbeatMiss { threshold: 3 },
                actions: vec![
                    crate::nex::ast::ReactiveAction::Log("Peer inativo".to_string()),
                    crate::nex::ast::ReactiveAction::MarkInactive {
                        peer: "node_a".to_string(),
                    },
                ],
            })
            .unwrap();

        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let mut peer_states = HashMap::new();
        peer_states.insert(addr, PeerState::new());
        let mut reputation = ReputationStore::new();
        let mut peer_addrs = HashMap::new();
        peer_addrs.insert("node_a".to_string(), addr);

        // Act
        let event = NetworkEvent::HeartbeatMiss { count: 4 };
        let eval_result = engine.evaluate(&event);
        let exec_report = ActionExecutor::execute(
            &eval_result.actions,
            &mut peer_states,
            &mut reputation,
            &peer_addrs,
        );

        // Assert
        assert!(eval_result.matched);
        assert_eq!(exec_report.logs.len(), 1);
        assert_eq!(exec_report.peer_changes.len(), 1);
        assert!(peer_states.get(&addr).unwrap().consecutive_misses > 0);
    }
}
