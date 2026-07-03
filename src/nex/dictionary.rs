//! dictionary.rs — Base de conhecimento do NexoIA
//!
//! Três níveis de certeza:
//!   Nível 3: VERIFICADO (Miri provou)
//!   Nível 2: TESTADO (testes passaram)
//!   Nível 1: HIPÓTESE (padrão detectado)
//!
//! O NexoIA consulta o nível mais alto disponível.
//! Quando aprende algo novo, tenta subir de nível com Miri.
//!
//! "Conhecimento sem verificação é opinião. Com verificação, é prova."

use crate::hash::canonical_hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Nível de certeza de um conhecimento
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum KnowledgeLevel {
    /// Hipótese — padrão detectado, ainda não verificado
    Hypothese = 1,
    /// Testado — testes passaram, sem verificação formal
    Tested = 2,
    /// Verificado — Miri provou que é seguro
    Verified = 3,
}

impl std::fmt::Display for KnowledgeLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hypothese => write!(f, "hipotese"),
            Self::Tested => write!(f, "testado"),
            Self::Verified => write!(f, "verificado"),
        }
    }
}

/// Categoria de conhecimento
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EntryCategory {
    Rust,
    Nex,
    Project,
    Learned,
}

impl std::fmt::Display for EntryCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rust => write!(f, "rust"),
            Self::Nex => write!(f, "nex"),
            Self::Project => write!(f, "project"),
            Self::Learned => write!(f, "learned"),
        }
    }
}

/// Uma entrada no dicionário
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DictionaryEntry {
    pub id: String,
    pub category: EntryCategory,
    pub level: KnowledgeLevel,
    pub pattern: String,
    pub description: String,
    pub suggestion: String,
    pub confidence: f64,
    pub miri_passed: bool,
    pub occurrences: usize,
}

/// Fonte do conhecimento
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DictionarySource {
    File(String),
    Internet,
    Learned,
}

/// Dicionário — base de conhecimento viva do NexoIA
pub struct Dictionary {
    entries: Vec<DictionaryEntry>,
    dir: PathBuf,
    #[allow(dead_code)]
    sources: HashMap<String, DictionarySource>,
}

impl Dictionary {
    /// Carrega dicionário de um diretório
    pub fn load(dir: &Path) -> Self {
        let mut entries = Vec::new();
        let mut sources = HashMap::new();

        // Carrega cada .jsonl do diretório
        if let Ok(read_dir) = fs::read_dir(dir) {
            for entry in read_dir.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
                    if let Ok(content) = fs::read_to_string(&path) {
                        let filename = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown")
                            .to_string();
                        for line in content.lines() {
                            let line = line.trim();
                            if line.is_empty() {
                                continue;
                            }
                            if let Ok(dict_entry) = serde_json::from_str::<DictionaryEntry>(line) {
                                sources.insert(
                                    dict_entry.id.clone(),
                                    DictionarySource::File(filename.clone()),
                                );
                                entries.push(dict_entry);
                            }
                        }
                    }
                }
            }
        }

        Self {
            entries,
            dir: dir.to_path_buf(),
            sources,
        }
    }

    /// Cria dicionário vazio
    #[allow(dead_code)]
    pub fn empty(dir: &Path) -> Self {
        Self {
            entries: Vec::new(),
            dir: dir.to_path_buf(),
            sources: HashMap::new(),
        }
    }

    /// Busca por padrão (case-insensitive)
    pub fn lookup(&self, query: &str) -> Vec<&DictionaryEntry> {
        let query_lower = query.to_lowercase();
        let mut results: Vec<&DictionaryEntry> = self
            .entries
            .iter()
            .filter(|e| {
                e.pattern.to_lowercase().contains(&query_lower)
                    || e.description.to_lowercase().contains(&query_lower)
                    || e.suggestion.to_lowercase().contains(&query_lower)
            })
            .collect();

        // Ordena por nível (verificado primeiro) e depois por confiança
        results.sort_by(|a, b| {
            b.level
                .cmp(&a.level)
                .then_with(|| b.confidence.partial_cmp(&a.confidence).unwrap())
        });

        results
    }

    /// Busca por clippy lint específico
    #[allow(dead_code)]
    pub fn lookup_clippy(&self, lint: &str) -> Vec<&DictionaryEntry> {
        self.entries
            .iter()
            .filter(|e| {
                e.category == EntryCategory::Rust
                    && (e.pattern.to_lowercase().contains(&lint.to_lowercase())
                        || e.id.to_lowercase().contains(&lint.to_lowercase()))
            })
            .collect()
    }

    /// Busca por nível mínimo
    #[allow(dead_code)]
    pub fn lookup_verified(&self, query: &str) -> Vec<&DictionaryEntry> {
        self.lookup(query)
            .into_iter()
            .filter(|e| e.level >= KnowledgeLevel::Verified)
            .collect()
    }

    /// Adiciona conhecimento novo (hipótese inicial)
    /// Se já existe entrada com mesmo id, atualiza. Senão, adiciona.
    pub fn learn(&mut self, entry: DictionaryEntry) {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.id == entry.id) {
            // Atualiza se o novo nível é mais alto
            if entry.level > existing.level {
                existing.level = entry.level;
                existing.confidence = entry.confidence;
                existing.miri_passed = entry.miri_passed;
            }
            existing.occurrences += 1;
        } else {
            self.entries.push(entry);
        }
    }

    /// Promove conhecimento de nível (quando Miri verifica)
    #[allow(dead_code)]
    pub fn promote(&mut self, id: &str, new_level: KnowledgeLevel) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == id) {
            entry.level = new_level;
            entry.miri_passed = new_level == KnowledgeLevel::Verified;
            if new_level == KnowledgeLevel::Verified {
                entry.confidence = 1.0;
            }
        }
    }

    /// Registra ocorrência (aumenta confiança)
    #[allow(dead_code)]
    pub fn touch(&mut self, id: &str) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == id) {
            entry.occurrences += 1;
            // Confiança sobe com ocorrências, mas nunca passa de 1.0
            entry.confidence = (entry.confidence + 0.05).min(1.0);
        }
    }

    /// Salva dicionário em disco (um arquivo .jsonl por categoria)
    pub fn save(&self) -> Result<(), String> {
        fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;

        // Agrupa por categoria
        let mut by_category: HashMap<String, Vec<&DictionaryEntry>> = HashMap::new();
        for entry in &self.entries {
            let cat = entry.category.to_string();
            by_category.entry(cat).or_default().push(entry);
        }

        for (cat, entries) in &by_category {
            let filename = format!("{}.jsonl", cat);
            let filepath = self.dir.join(&filename);
            let mut content = String::new();
            for entry in entries {
                let line = serde_json::to_string(entry).map_err(|e| e.to_string())?;
                content.push_str(&line);
                content.push('\n');
            }
            fs::write(&filepath, content).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    /// Hash de integridade do dicionário
    #[allow(dead_code)]
    pub fn integrity_hash(&self) -> String {
        let mut content = String::new();
        let mut sorted: Vec<&DictionaryEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| a.id.cmp(&b.id));
        for entry in &sorted {
            content.push_str(&entry.id);
            content.push(':');
            content.push_str(&entry.pattern);
            content.push('\n');
        }
        canonical_hash(&content)
    }

    /// Estatísticas do dicionário
    pub fn stats(&self) -> DictionaryStats {
        let total = self.entries.len();
        let verified = self
            .entries
            .iter()
            .filter(|e| e.level == KnowledgeLevel::Verified)
            .count();
        let tested = self
            .entries
            .iter()
            .filter(|e| e.level == KnowledgeLevel::Tested)
            .count();
        let hypothetical = self
            .entries
            .iter()
            .filter(|e| e.level == KnowledgeLevel::Hypothese)
            .count();
        let rust = self
            .entries
            .iter()
            .filter(|e| e.category == EntryCategory::Rust)
            .count();
        let nex = self
            .entries
            .iter()
            .filter(|e| e.category == EntryCategory::Nex)
            .count();
        let project = self
            .entries
            .iter()
            .filter(|e| e.category == EntryCategory::Project)
            .count();
        let learned = self
            .entries
            .iter()
            .filter(|e| e.category == EntryCategory::Learned)
            .count();

        DictionaryStats {
            total,
            verified,
            tested,
            hypothetical,
            rust,
            nex,
            project,
            learned,
        }
    }

    /// Número de entradas
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Dicionário está vazio?
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug)]
pub struct DictionaryStats {
    pub total: usize,
    pub verified: usize,
    pub tested: usize,
    pub hypothetical: usize,
    pub rust: usize,
    pub nex: usize,
    pub project: usize,
    pub learned: usize,
}

impl std::fmt::Display for DictionaryStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "total={}, verificados={}, testados={}, hipoteses={}, rust={}, nex={}, project={}, learned={}",
            self.total, self.verified, self.tested, self.hypothetical,
            self.rust, self.nex, self.project, self.learned
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_entry(id: &str, pattern: &str, level: KnowledgeLevel) -> DictionaryEntry {
        DictionaryEntry {
            id: id.into(),
            category: EntryCategory::Rust,
            level,
            pattern: pattern.into(),
            description: format!("Test entry: {}", pattern),
            suggestion: format!("Fix: {}", pattern),
            confidence: 0.8,
            miri_passed: level == KnowledgeLevel::Verified,
            occurrences: 1,
        }
    }

    #[test]
    fn dictionary_load_empty() {
        let dir = tempdir().unwrap();
        let dict = Dictionary::empty(dir.path());
        assert!(dict.is_empty());
        assert_eq!(dict.len(), 0);
    }

    #[test]
    fn dictionary_learn_and_lookup() {
        let dir = tempdir().unwrap();
        let mut dict = Dictionary::empty(dir.path());

        dict.learn(test_entry("r-001", "ptr_arg", KnowledgeLevel::Tested));
        dict.learn(test_entry(
            "r-002",
            "format_in_format_args",
            KnowledgeLevel::Verified,
        ));
        dict.learn(test_entry("r-003", "dead_code", KnowledgeLevel::Hypothese));

        assert_eq!(dict.len(), 3);

        let results = dict.lookup("format");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "r-002");
        assert_eq!(results[0].level, KnowledgeLevel::Verified);
    }

    #[test]
    fn dictionary_lookup_returns_highest_level_first() {
        let dir = tempdir().unwrap();
        let mut dict = Dictionary::empty(dir.path());

        dict.learn(test_entry(
            "h-001",
            "test_pattern",
            KnowledgeLevel::Hypothese,
        ));
        dict.learn(test_entry(
            "v-001",
            "test_pattern",
            KnowledgeLevel::Verified,
        ));

        let results = dict.lookup("test_pattern");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].level, KnowledgeLevel::Verified);
        assert_eq!(results[1].level, KnowledgeLevel::Hypothese);
    }

    #[test]
    fn dictionary_promote() {
        let dir = tempdir().unwrap();
        let mut dict = Dictionary::empty(dir.path());

        dict.learn(test_entry("r-001", "ptr_arg", KnowledgeLevel::Hypothese));
        dict.promote("r-001", KnowledgeLevel::Verified);

        let results = dict.lookup("ptr_arg");
        assert_eq!(results[0].level, KnowledgeLevel::Verified);
        assert!(results[0].miri_passed);
    }

    #[test]
    fn dictionary_save_and_reload() {
        let dir = tempdir().unwrap();
        {
            let mut dict = Dictionary::empty(dir.path());
            dict.learn(test_entry("r-001", "ptr_arg", KnowledgeLevel::Tested));
            dict.learn(test_entry("n-001", "let_id", KnowledgeLevel::Verified));
            dict.save().unwrap();
        }

        let dict = Dictionary::load(dir.path());
        assert_eq!(dict.len(), 2);
    }

    #[test]
    fn dictionary_no_duplicates() {
        let dir = tempdir().unwrap();
        let mut dict = Dictionary::empty(dir.path());

        dict.learn(test_entry("r-001", "ptr_arg", KnowledgeLevel::Hypothese));
        dict.learn(test_entry("r-001", "ptr_arg", KnowledgeLevel::Verified));

        // Mesmo ID → merge (atualiza nível, incrementa occurrences)
        assert_eq!(dict.len(), 1);
        let results = dict.lookup("ptr_arg");
        assert_eq!(results[0].level, KnowledgeLevel::Verified);
        assert_eq!(results[0].occurrences, 2);
    }

    #[test]
    fn dictionary_stats() {
        let dir = tempdir().unwrap();
        let mut dict = Dictionary::empty(dir.path());

        dict.learn(test_entry("r-001", "a", KnowledgeLevel::Verified));
        dict.learn(test_entry("r-002", "b", KnowledgeLevel::Tested));
        dict.learn(test_entry("n-001", "c", KnowledgeLevel::Hypothese));

        let stats = dict.stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.verified, 1);
        assert_eq!(stats.tested, 1);
        assert_eq!(stats.hypothetical, 1);
    }

    #[test]
    fn dictionary_integrity_hash_deterministico() {
        let dir = tempdir().unwrap();
        let mut dict = Dictionary::empty(dir.path());
        dict.learn(test_entry("r-001", "ptr_arg", KnowledgeLevel::Tested));

        let hash1 = dict.integrity_hash();
        let hash2 = dict.integrity_hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn dictionary_touch_increases_confidence() {
        let dir = tempdir().unwrap();
        let mut dict = Dictionary::empty(dir.path());

        dict.learn(test_entry("r-001", "ptr_arg", KnowledgeLevel::Tested));
        let before = dict.entries[0].confidence;

        dict.touch("r-001");
        let after = dict.entries[0].confidence;

        assert!(after > before);
    }
}
