//! checkpoint.rs — Sistema de checkpoints para persistência de estado
//!
//! Salva e carrega o estado do nó de forma atômica para evitar
//! corrupção em caso de crash. Inclui estado reativo.

use crate::network::persistence::PersistedData;
use crate::nex::reactive::ReactiveRule;
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Checkpoint do estado do nó.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub version: u32,
    pub timestamp: String,
    pub network_data: PersistedData,
    pub node_id: String,
    pub reactive_rules: Vec<ReactiveRuleSnapshot>,
}

/// Snapshot de uma regra reativa para persistência.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactiveRuleSnapshot {
    pub trigger_type: String,
    pub trigger_params: String,
    pub actions: Vec<String>,
}

impl From<&ReactiveRule> for ReactiveRuleSnapshot {
    fn from(rule: &ReactiveRule) -> Self {
        use crate::nex::ast::Trigger;

        match rule {
            ReactiveRule::Legacy { trigger, actions } => {
                let (trigger_type, trigger_params) = match trigger {
                    Trigger::HeartbeatMiss { threshold } => {
                        ("heartbeat_miss".to_string(), threshold.to_string())
                    }
                    Trigger::ReputationBelow { threshold } => {
                        ("reputation_below".to_string(), threshold.to_string())
                    }
                    Trigger::PeerConnected => ("peer_connected".to_string(), String::new()),
                    Trigger::PeerDisconnected => ("peer_disconnected".to_string(), String::new()),
                    Trigger::HandshakeCompleted => ("handshake_completed".to_string(), String::new()),
                    Trigger::HandshakeFailed => ("handshake_failed".to_string(), String::new()),
                    Trigger::SessionCreated => ("session_created".to_string(), String::new()),
                    Trigger::SessionRemoved => ("session_removed".to_string(), String::new()),
                };

                let actions_vec = actions.iter().map(|a| format!("{:?}", a)).collect();

                ReactiveRuleSnapshot {
                    trigger_type,
                    trigger_params,
                    actions: actions_vec,
                }
            }
            ReactiveRule::Block { event, threshold, window_secs, target, body: _ } => {
                ReactiveRuleSnapshot {
                    trigger_type: "block".to_string(),
                    trigger_params: format!("{:?}_{}_{}", event, threshold, window_secs),
                    actions: vec![target.clone()],
                }
            }
        }
    }
}

impl ReactiveRuleSnapshot {
    pub fn to_rule(&self) -> Option<ReactiveRule> {
        use crate::nex::ast::{ReactiveAction, Trigger};

        let trigger = match self.trigger_type.as_str() {
            "heartbeat_miss" => {
                let threshold = self.trigger_params.parse().unwrap_or(3);
                Trigger::HeartbeatMiss { threshold }
            }
            "reputation_below" => {
                let threshold = self.trigger_params.parse().unwrap_or(0.3);
                Trigger::ReputationBelow { threshold }
            }
            "peer_connected" => Trigger::PeerConnected,
            "peer_disconnected" => Trigger::PeerDisconnected,
            "handshake_completed" => Trigger::HandshakeCompleted,
            "handshake_failed" => Trigger::HandshakeFailed,
            "session_created" => Trigger::SessionCreated,
            "session_removed" => Trigger::SessionRemoved,
            _ => return None,
        };

        let actions = self
            .actions
            .iter()
            .filter_map(|a| {
                // Parse Debug format: Log("msg"), Emit("event"), MarkInactive { peer: "x" }, AdjustReputation { peer: "x", delta: N }
                if let Some(msg) = a.strip_prefix("Log(\"").and_then(|s| s.strip_suffix("\")")) {
                    Some(ReactiveAction::Log(msg.to_string()))
                } else if let Some(event) = a
                    .strip_prefix("Emit(\"")
                    .and_then(|s| s.strip_suffix("\")"))
                {
                    Some(ReactiveAction::Emit(event.to_string()))
                } else if a.starts_with("MarkInactive {") {
                    let peer = a
                        .split("peer: \"")
                        .nth(1)
                        .and_then(|s| s.split('"').next())
                        .unwrap_or("unknown")
                        .to_string();
                    Some(ReactiveAction::MarkInactive { peer })
                } else if a.starts_with("AdjustReputation {") {
                    let peer = a
                        .split("peer: \"")
                        .nth(1)
                        .and_then(|s| s.split('"').next())
                        .unwrap_or("unknown")
                        .to_string();
                    // Debug format: "AdjustReputation { peer: \"x\", delta: N }"
                    let delta = a
                        .split("delta: ")
                        .nth(1)
                        .and_then(|s| s.trim_end_matches('}').trim().parse::<i32>().ok())
                        .unwrap_or(0);
                    Some(ReactiveAction::AdjustReputation { peer, delta })
                } else {
                    None
                }
            })
            .collect();

        Some(ReactiveRule::Legacy { trigger, actions })
    }
}

/// Gerencia checkpoints do sistema.
pub struct CheckpointManager {
    checkpoint_dir: std::path::PathBuf,
}

impl CheckpointManager {
    pub fn new(checkpoint_dir: std::path::PathBuf) -> Self {
        Self { checkpoint_dir }
    }

    /// Salva checkpoint com escrita atômica (temp file + rename).
    pub fn save(&self, checkpoint: &Checkpoint) -> Result<(), std::io::Error> {
        std::fs::create_dir_all(&self.checkpoint_dir)?;

        let json = serde_json::to_string_pretty(checkpoint)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let temp_path = self.checkpoint_dir.join("checkpoint.tmp");
        let final_path = self.checkpoint_dir.join("checkpoint.json");

        std::fs::write(&temp_path, &json)?;
        std::fs::rename(&temp_path, &final_path)?;

        Ok(())
    }

    /// Carrega último checkpoint válido.
    pub fn load(&self) -> Result<Option<Checkpoint>, std::io::Error> {
        let path = self.checkpoint_dir.join("checkpoint.json");
        if !path.exists() {
            return Ok(None);
        }

        let data = std::fs::read_to_string(&path)?;
        let checkpoint: Checkpoint = serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(Some(checkpoint))
    }
}

/// Cria checkpoint a partir do estado atual do sistema.
pub fn create_checkpoint(
    node_id: &str,
    network_data: &PersistedData,
    reactive_rules: &[ReactiveRule],
) -> Checkpoint {
    let snapshots: Vec<ReactiveRuleSnapshot> = reactive_rules
        .iter()
        .map(ReactiveRuleSnapshot::from)
        .collect();

    Checkpoint {
        version: 1,
        timestamp: Utc::now().to_rfc3339(),
        network_data: network_data.clone(),
        node_id: node_id.to_string(),
        reactive_rules: snapshots,
    }
}

/// Aplica checkpoint ao estado do sistema.
#[allow(dead_code)]
pub fn apply_checkpoint(
    checkpoint: &Checkpoint,
    network_data: &mut PersistedData,
) -> Vec<ReactiveRule> {
    *network_data = checkpoint.network_data.clone();

    checkpoint
        .reactive_rules
        .iter()
        .filter_map(|s| s.to_rule())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::persistence::PersistedData;

    #[test]
    fn checkpoint_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let manager = CheckpointManager::new(dir.path().to_path_buf());

        let mut data = PersistedData::default();
        data.peers.push("127.0.0.1:9001".to_string());

        let checkpoint = create_checkpoint("test_node", &data, &[]);
        manager.save(&checkpoint).unwrap();

        let loaded = manager.load().unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().node_id, "test_node");
    }

    #[test]
    fn checkpoint_atomic_write() {
        let dir = tempfile::tempdir().unwrap();
        let manager = CheckpointManager::new(dir.path().to_path_buf());

        let data = PersistedData::default();
        let checkpoint = create_checkpoint("test_node", &data, &[]);

        manager.save(&checkpoint).unwrap();

        let final_path = dir.path().join("checkpoint.json");
        assert!(final_path.exists());

        let temp_path = dir.path().join("checkpoint.tmp");
        assert!(!temp_path.exists());
    }

    #[test]
    fn apply_checkpoint_restores_state() {
        let mut data = PersistedData::default();
        data.peers.push("127.0.0.1:9001".to_string());

        let checkpoint = create_checkpoint("test_node", &data, &[]);
        let mut new_data = PersistedData::default();

        let rules = apply_checkpoint(&checkpoint, &mut new_data);

        assert_eq!(new_data.peers.len(), 1);
        assert_eq!(new_data.peers[0], "127.0.0.1:9001");
        assert!(rules.is_empty());
    }

    #[test]
    fn checkpoint_with_reactive_rules() {
        use crate::nex::ast::{ReactiveAction, Trigger};

        let data = PersistedData::default();
        let rules = vec![ReactiveRule {
            trigger: Trigger::HeartbeatMiss { threshold: 5 },
            actions: vec![ReactiveAction::Log("test".to_string())],
        }];

        let checkpoint = create_checkpoint("test_node", &data, &rules);
        assert_eq!(checkpoint.reactive_rules.len(), 1);
        assert_eq!(checkpoint.reactive_rules[0].trigger_type, "heartbeat_miss");

        let restored = apply_checkpoint(&checkpoint, &mut PersistedData::default());
        assert_eq!(restored.len(), 1);
    }

    #[test]
    fn reactive_actions_roundtrip_all_types() {
        use crate::nex::ast::{ReactiveAction, Trigger};

        let data = PersistedData::default();
        let rules = vec![
            ReactiveRule {
                trigger: Trigger::HeartbeatMiss { threshold: 3 },
                actions: vec![
                    ReactiveAction::Log("heartbeat lost".to_string()),
                    ReactiveAction::Emit("peer_down".to_string()),
                ],
            },
            ReactiveRule {
                trigger: Trigger::ReputationBelow { threshold: 0.3 },
                actions: vec![
                    ReactiveAction::MarkInactive {
                        peer: "bad_node".to_string(),
                    },
                    ReactiveAction::AdjustReputation {
                        peer: "bad_node".to_string(),
                        delta: -10,
                    },
                ],
            },
        ];

        let checkpoint = create_checkpoint("test_node", &data, &rules);
        assert_eq!(checkpoint.reactive_rules.len(), 2);

        let restored = apply_checkpoint(&checkpoint, &mut PersistedData::default());
        assert_eq!(restored.len(), 2);

        // Verify first rule: HeartbeatMiss with Log + Emit
        assert_eq!(restored[0].trigger, Trigger::HeartbeatMiss { threshold: 3 });
        assert_eq!(restored[0].actions.len(), 2);
        assert_eq!(
            restored[0].actions[0],
            ReactiveAction::Log("heartbeat lost".to_string())
        );
        assert_eq!(
            restored[0].actions[1],
            ReactiveAction::Emit("peer_down".to_string())
        );

        // Verify second rule: ReputationBelow with MarkInactive + AdjustReputation
        assert_eq!(
            restored[1].trigger,
            Trigger::ReputationBelow { threshold: 0.3 }
        );
        assert_eq!(restored[1].actions.len(), 2);
        assert_eq!(
            restored[1].actions[0],
            ReactiveAction::MarkInactive {
                peer: "bad_node".to_string()
            }
        );
        assert_eq!(
            restored[1].actions[1],
            ReactiveAction::AdjustReputation {
                peer: "bad_node".to_string(),
                delta: -10
            }
        );
    }
}
