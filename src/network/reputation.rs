use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Reputação de um nó na rede.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeReputation {
    pub node_id: String,
    pub failures: u32,
    pub successes: u32,
    pub last_seen: DateTime<Utc>,
    pub banned: bool,
    pub ban_expires_at: Option<DateTime<Utc>>,
}

impl NodeReputation {
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            failures: 0,
            successes: 0,
            last_seen: Utc::now(),
            banned: false,
            ban_expires_at: None,
        }
    }

    /// Registra uma falha. Ban após 10 falhas consecutivas.
    pub fn record_failure(&mut self) {
        self.failures += 1;
        self.last_seen = Utc::now();

        if self.failures >= 10 {
            self.banned = true;
            self.ban_expires_at = Some(Utc::now() + chrono::Duration::hours(24));
        }
    }

    /// Registra um sucesso. Reseta contador de falhas após 100 sucessos.
    pub fn record_success(&mut self) {
        self.successes += 1;
        self.last_seen = Utc::now();

        // Reset falhas após 100 sucessos
        if self.successes % 100 == 0 {
            self.failures = 0;
        }
    }

    /// Verifica se o nó está banido (e se o ban ainda é válido).
    pub fn is_banned(&self) -> bool {
        if !self.banned {
            return false;
        }

        // Verifica se o ban expirou
        if let Some(expires) = self.ban_expires_at {
            if Utc::now() > expires {
                return false; // Ban expirou
            }
        }

        true
    }
}

/// Armazenamento de reputação persistente.
pub struct ReputationStore {
    reputations: HashMap<String, NodeReputation>,
    path: Option<std::path::PathBuf>,
}

impl ReputationStore {
    pub fn new() -> Self {
        Self {
            reputations: HashMap::new(),
            path: None,
        }
    }

    pub fn with_path(path: std::path::PathBuf) -> Self {
        Self {
            reputations: HashMap::new(),
            path: Some(path),
        }
    }

    /// Carrega reputação de arquivo.
    pub fn load(&mut self) -> Result<(), std::io::Error> {
        if let Some(path) = &self.path {
            if path.exists() {
                let data = std::fs::read_to_string(path)?;
                self.reputations = serde_json::from_str(&data)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            }
        }
        Ok(())
    }

    /// Salva reputação em arquivo.
    pub fn save(&self) -> Result<(), std::io::Error> {
        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let data = serde_json::to_string_pretty(&self.reputations)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            std::fs::write(path, data)?;
        }
        Ok(())
    }

    /// Obtém ou cria reputação para um nó.
    pub fn get_or_create(&mut self, node_id: &str) -> &mut NodeReputation {
        self.reputations
            .entry(node_id.to_string())
            .or_insert_with(|| NodeReputation::new(node_id.to_string()))
    }

    /// Registra falha para um nó.
    pub fn record_failure(&mut self, node_id: &str) {
        let rep = self.get_or_create(node_id);
        rep.record_failure();
    }

    /// Registra sucesso para um nó.
    pub fn record_success(&mut self, node_id: &str) {
        let rep = self.get_or_create(node_id);
        rep.record_success();
    }

    /// Verifica se um nó está banido.
    pub fn is_banned(&self, node_id: &str) -> bool {
        self.reputations
            .get(node_id)
            .map(|r| r.is_banned())
            .unwrap_or(false)
    }

    /// Retorna todas as reputações.
    pub fn all(&self) -> &HashMap<String, NodeReputation> {
        &self.reputations
    }

    /// Retorna número de nós banidos.
    pub fn banned_count(&self) -> usize {
        self.reputations.values().filter(|r| r.is_banned()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_reputation_starts_clean() {
        let rep = NodeReputation::new("node_a".to_string());
        assert_eq!(rep.failures, 0);
        assert_eq!(rep.successes, 0);
        assert!(!rep.is_banned());
    }

    #[test]
    fn ban_after_10_failures() {
        let mut rep = NodeReputation::new("node_a".to_string());

        for _ in 0..9 {
            rep.record_failure();
            assert!(!rep.is_banned());
        }

        rep.record_failure();
        assert!(rep.is_banned());
    }

    #[test]
    fn ban_expires_after_24h() {
        let mut rep = NodeReputation::new("node_a".to_string());

        for _ in 0..10 {
            rep.record_failure();
        }

        assert!(rep.is_banned());

        // Simula passar 25 horas
        rep.ban_expires_at = Some(Utc::now() - chrono::Duration::hours(25));
        assert!(!rep.is_banned());
    }

    #[test]
    fn success_resets_failures() {
        let mut rep = NodeReputation::new("node_a".to_string());

        for _ in 0..5 {
            rep.record_failure();
        }

        for _ in 0..100 {
            rep.record_success();
        }

        assert_eq!(rep.failures, 0);
    }

    #[test]
    fn store_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reputation.json");

        {
            let mut store = ReputationStore::with_path(path.clone());
            // 10 falhas para banir
            for _ in 0..10 {
                store.record_failure("node_a");
            }
            store.record_success("node_b");
            store.save().unwrap();
        }

        let mut store2 = ReputationStore::with_path(path);
        store2.load().unwrap();

        assert!(store2.is_banned("node_a"));
        assert!(!store2.is_banned("node_b"));
    }
}
