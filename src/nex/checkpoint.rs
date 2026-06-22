//! checkpoint.rs — Sistema de checkpoints para persistência de estado
//!
//! Salva e carrega o estado do nó de forma atômica para evitar
//! corrupção em caso de crash.

use crate::network::persistence::PersistedData;
use crate::network::reputation::ReputationStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Checkpoint do estado do nó.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub version: u32,
    pub timestamp: String,
    pub network_data: PersistedData,
    pub node_id: String,
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

    /// Lista checkpoints disponíveis.
    pub fn list(&self) -> Result<Vec<Checkpoint>, std::io::Error> {
        let mut checkpoints = Vec::new();

        if self.checkpoint_dir.exists() {
            for entry in std::fs::read_dir(&self.checkpoint_dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.extension().map_or(false, |e| e == "json") {
                    if let Ok(data) = std::fs::read_to_string(&path) {
                        if let Ok(checkpoint) = serde_json::from_str::<Checkpoint>(&data) {
                            checkpoints.push(checkpoint);
                        }
                    }
                }
            }
        }

        checkpoints.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(checkpoints)
    }
}

/// Cria checkpoint a partir do estado atual do sistema.
pub fn create_checkpoint(node_id: &str, network_data: &PersistedData) -> Checkpoint {
    Checkpoint {
        version: 1,
        timestamp: chrono::Utc::now().to_rfc3339(),
        network_data: network_data.clone(),
        node_id: node_id.to_string(),
    }
}

/// Aplica checkpoint ao estado do sistema.
pub fn apply_checkpoint(checkpoint: &Checkpoint, network_data: &mut PersistedData) {
    *network_data = checkpoint.network_data.clone();
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

        let checkpoint = create_checkpoint("test_node", &data);
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
        let checkpoint = create_checkpoint("test_node", &data);

        manager.save(&checkpoint).unwrap();

        // Verifica que o arquivo final existe
        let final_path = dir.path().join("checkpoint.json");
        assert!(final_path.exists());

        // Verifica que o arquivo temporário não existe
        let temp_path = dir.path().join("checkpoint.tmp");
        assert!(!temp_path.exists());
    }

    #[test]
    fn apply_checkpoint_restores_state() {
        let mut data = PersistedData::default();
        data.peers.push("127.0.0.1:9001".to_string());

        let checkpoint = create_checkpoint("test_node", &data);
        let mut new_data = PersistedData::default();

        apply_checkpoint(&checkpoint, &mut new_data);

        assert_eq!(new_data.peers.len(), 1);
        assert_eq!(new_data.peers[0], "127.0.0.1:9001");
    }
}
