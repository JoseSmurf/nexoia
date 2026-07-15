//! iteration.rs — IterationLog: memória de aprendizado do NexoIA
//!
//! Cada iteração do loop de auto-programação é registrada aqui.
//! Timestamp + hash BLAKE3 = prova matemática de que a iteração aconteceu.
//!
//! "Toda iteração é uma lição. Toda lição é uma prova."

use crate::hash::canonical_hash;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Estado do sistema numa iteração
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemState {
    pub build_ok: bool,
    pub warnings: usize,
    pub tests_passed: usize,
    pub tests_failed: usize,
    pub clippy_ok: bool,
    pub fmt_ok: bool,
}

/// Ação tomada pelo sistema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub tipo: String,
    pub descricao: String,
    pub arquivos: Vec<String>,
}

/// Resultado da ação
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Outcome {
    Sucesso { mensagem: String },
    Falha { erro: String },
    NenhumaAcao { motivo: String },
}

/// Uma iteração completa do loop
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iteration {
    pub id: u64,
    pub timestamp: u64,
    pub timestamp_iso: String,
    pub estado_anterior: SystemState,
    pub acao: Action,
    pub resultado: Outcome,
    pub lição: Option<String>,
    pub hash: String,
    pub hash_anterior: Option<String>,
}

/// Log de iterações — memória persistente do NexoIA
pub struct IterationLog {
    dir: PathBuf,
    counter: u64,
}

impl IterationLog {
    pub fn new(data_dir: &std::path::Path) -> Self {
        let dir = data_dir.join("iterations");
        fs::create_dir_all(&dir).ok();

        // Conta iterações existentes pra continuar de onde parou
        let counter = fs::read_dir(&dir)
            .ok()
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        e.path()
                            .extension()
                            .map(|ext| ext == "json")
                            .unwrap_or(false)
                    })
                    .count() as u64
            })
            .unwrap_or(0);

        Self { dir, counter }
    }

    /// Registra uma nova iteração
    pub fn registrar(
        &mut self,
        estado: SystemState,
        acao: Action,
        resultado: Outcome,
        lição: Option<String>,
        hash_anterior: Option<String>,
    ) -> Iteration {
        self.counter += 1;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp_iso = chrono::DateTime::from_timestamp(timestamp as i64, 0)
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339();

        let content = format!(
            "{}:{}:{}:{}:{}:{}",
            self.counter,
            timestamp,
            serde_json::to_string(&estado).unwrap_or_default(),
            serde_json::to_string(&acao).unwrap_or_default(),
            serde_json::to_string(&resultado).unwrap_or_default(),
            lição.as_deref().unwrap_or("none")
        );
        let hash = canonical_hash(&content);

        let iter = Iteration {
            id: self.counter,
            timestamp,
            timestamp_iso,
            estado_anterior: estado,
            acao,
            resultado,
            lição,
            hash: hash.clone(),
            hash_anterior,
        };

        // Salva em disco
        let filename = format!("iter_{:06}.json", self.counter);
        let filepath = self.dir.join(&filename);
        let json = serde_json::to_string_pretty(&iter).unwrap();
        fs::write(&filepath, json).ok();

        // Atualiza latest
        let latest = self.dir.join("latest.json");
        fs::write(&latest, serde_json::to_string_pretty(&iter).unwrap()).ok();

        iter
    }

    /// Lê a última iteração
    #[allow(dead_code)]
    pub fn ultima(&self) -> Option<Iteration> {
        let latest = self.dir.join("latest.json");
        let data = fs::read_to_string(latest).ok()?;
        serde_json::from_str(&data).ok()
    }

    /// Lê todas as iterações
    pub fn todas(&self) -> Vec<Iteration> {
        let mut iterations: Vec<Iteration> = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                // Ignora latest.json — só conta iterações numeradas
                if path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.starts_with("iter_"))
                    .unwrap_or(false)
                    && path.extension().map(|e| e == "json").unwrap_or(false)
                {
                    if let Ok(data) = fs::read_to_string(&path) {
                        if let Ok(iter) = serde_json::from_str(&data) {
                            iterations.push(iter);
                        }
                    }
                }
            }
        }
        iterations.sort_by_key(|i| i.id);
        iterations
    }

    /// Estatísticas do histórico
    #[allow(dead_code)]
    pub fn stats(&self) -> LogStats {
        let iters = self.todas();
        let total = iters.len();
        let sucessos = iters
            .iter()
            .filter(|i| matches!(i.resultado, Outcome::Sucesso { .. }))
            .count();
        let falhas = iters
            .iter()
            .filter(|i| matches!(i.resultado, Outcome::Falha { .. }))
            .count();
        let sem_acao = iters
            .iter()
            .filter(|i| matches!(i.resultado, Outcome::NenhumaAcao { .. }))
            .count();
        let com_lição = iters.iter().filter(|i| i.lição.is_some()).count();

        LogStats {
            total,
            sucessos,
            falhas,
            sem_acao,
            com_lição,
        }
    }

    /// Hash da cadeia de iterações (prova de integridade)
    #[allow(dead_code)]
    pub fn chain_hash(&self) -> String {
        let iters = self.todas();
        let content: String = iters.iter().map(|i| i.hash.clone()).collect();
        canonical_hash(&content)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct LogStats {
    pub total: usize,
    pub sucessos: usize,
    pub falhas: usize,
    pub sem_acao: usize,
    pub com_lição: usize,
}

impl std::fmt::Display for LogStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "iterações={}, sucessos={}, falhas={}, sem_acao={}, com_lição={}",
            self.total, self.sucessos, self.falhas, self.sem_acao, self.com_lição
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iteration_log_registra_e_le() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = IterationLog::new(dir.path());

        let estado = SystemState {
            build_ok: true,
            warnings: 0,
            tests_passed: 956,
            tests_failed: 0,
            clippy_ok: true,
            fmt_ok: true,
        };

        let ação = Action {
            tipo: "verificação".into(),
            descricao: "Health check completo".into(),
            arquivos: vec!["src/main.rs".into()],
        };

        let resultado = Outcome::Sucesso {
            mensagem: "Sistema saudável".into(),
        };

        let iter = log.registrar(estado, ação, resultado, None, None);
        assert_eq!(iter.id, 1);
        assert!(!iter.hash.is_empty());

        let ultima = log.ultima().unwrap();
        assert_eq!(ultima.id, 1);
    }

    #[test]
    fn iteration_log_chain_hash_deterministico() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let mut log1 = IterationLog::new(&path);
        let mut log2 = IterationLog::new(&path);

        let estado = SystemState {
            build_ok: true,
            warnings: 0,
            tests_passed: 100,
            tests_failed: 0,
            clippy_ok: true,
            fmt_ok: true,
        };

        let ação = Action {
            tipo: "teste".into(),
            descricao: "Teste de determinismo".into(),
            arquivos: vec![],
        };

        let resultado = Outcome::NenhumaAcao {
            motivo: "nada a fazer".into(),
        };

        log1.registrar(estado.clone(), ação.clone(), resultado.clone(), None, None);
        log2.registrar(estado, ação, resultado, None, None);

        assert_eq!(log1.chain_hash(), log2.chain_hash());
    }

    #[test]
    fn iteration_log_stats() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = IterationLog::new(dir.path());

        let estado = SystemState {
            build_ok: true,
            warnings: 0,
            tests_passed: 100,
            tests_failed: 0,
            clippy_ok: true,
            fmt_ok: true,
        };

        // Registra 3 iterações
        log.registrar(
            estado.clone(),
            Action {
                tipo: "a".into(),
                descricao: "".into(),
                arquivos: vec![],
            },
            Outcome::Sucesso {
                mensagem: "ok".into(),
            },
            Some("lição 1".into()),
            None,
        );
        log.registrar(
            estado.clone(),
            Action {
                tipo: "b".into(),
                descricao: "".into(),
                arquivos: vec![],
            },
            Outcome::Falha {
                erro: "erro".into(),
            },
            Some("lição 2".into()),
            None,
        );
        log.registrar(
            estado,
            Action {
                tipo: "c".into(),
                descricao: "".into(),
                arquivos: vec![],
            },
            Outcome::NenhumaAcao {
                motivo: "ok".into(),
            },
            None,
            None,
        );

        let stats = log.stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.sucessos, 1);
        assert_eq!(stats.falhas, 1);
        assert_eq!(stats.sem_acao, 1);
        assert_eq!(stats.com_lição, 2);
    }
}
