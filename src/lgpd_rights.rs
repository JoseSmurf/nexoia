// lgpd_rights.rs — LGPD Nível 2: Direitos do Titular
// Indexação em memória, anonimização atômica, EPA de supressão.

use crate::hash::canonical_hash;
use crate::lgpd::LawfulBasis;
use crate::network::epa::SharedEPA;
use crate::network::identity::NodeIdentity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Referência a um EPA associado a um titular (data subject).
/// Derivado dos EPAs existentes — não é fonte de verdade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpaRef {
    pub epa_id: String,
    pub epa_hash: String,
    pub lawful_basis: LawfulBasis,
    pub purpose: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Índice LGPD: mapping data_subject_hash → lista de EPAs.
/// Reconstruído na inicialização a partir dos EPAs existentes.
pub struct LgpdIndex {
    index: HashMap<String, Vec<EpaRef>>,
}

impl Default for LgpdIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl LgpdIndex {
    pub fn new() -> Self {
        Self {
            index: HashMap::new(),
        }
    }

    /// Reconstrói o índice a partir de uma lista de EPAs.
    /// Cada EPA com LgpdMetadata.data_subject_hash é indexado.
    pub fn build_from_epas(&mut self, epas: &[SharedEPA]) {
        self.index.clear();
        for epa in epas {
            if let Some(lgpd) = extract_lgpd_from_epa(epa) {
                if let Some(ref hash) = lgpd.data_subject_hash {
                    let epa_hash = canonical_hash(&epa.integrity_hash);
                    let entry = EpaRef {
                        epa_id: epa.epa_id.clone(),
                        epa_hash,
                        lawful_basis: lgpd.lawful_basis,
                        purpose: lgpd.purpose.clone(),
                        created_at: parse_timestamp(&epa.timestamp),
                        expires_at: calc_expiry(lgpd.retention_days, &epa.timestamp),
                    };
                    self.index.entry(hash.clone()).or_default().push(entry);
                }
            }
        }
    }

    /// Busca EPAs de um titular por data_subject_hash.
    pub fn lookup(&self, data_subject_hash: &str) -> Vec<&EpaRef> {
        self.index
            .get(data_subject_hash)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Remove uma entrada do índice (após anonimização).
    pub fn remove_epa(&mut self, data_subject_hash: &str, epa_id: &str) {
        if let Some(entries) = self.index.get_mut(data_subject_hash) {
            entries.retain(|e| e.epa_id != epa_id);
            if entries.is_empty() {
                self.index.remove(data_subject_hash);
            }
        }
    }

    /// Adiciona uma entrada no índice (após criar EPA de supressão).
    pub fn insert(&mut self, data_subject_hash: String, entry: EpaRef) {
        self.index.entry(data_subject_hash).or_default().push(entry);
    }

    pub fn count(&self) -> usize {
        self.index.values().map(|v| v.len()).sum()
    }

    pub fn subjects(&self) -> Vec<&str> {
        self.index.keys().map(|s| s.as_str()).collect()
    }
}

/// Resultado de anonimização.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizationResult {
    pub original_epa_id: String,
    pub suppression_epa_id: String,
    pub fields_anonymized: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

/// Dados exportáveis de um titular (portabilidade).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TitularExport {
    pub data_subject_hash: String,
    pub epas: Vec<EpaRef>,
    pub exported_at: DateTime<Utc>,
}

/// Resultado de revogação de consentimento.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationResult {
    pub epa_id: String,
    pub revoked_at: DateTime<Utc>,
    pub lawful_basis_before: LawfulBasis,
}

// ── Funções auxiliares ─────────────────────────────────────

/// Extrai LgpdMetadata do SharedEPA.
/// Agora o EPA carrega o metadata diretamente no campo lgpd_metadata.
fn extract_lgpd_from_epa(epa: &SharedEPA) -> Option<crate::lgpd::LgpdMetadata> {
    epa.lgpd_metadata.clone()
}

fn parse_timestamp(ts: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(ts)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn calc_expiry(retention_days: u32, created_at: &str) -> DateTime<Utc> {
    let created = parse_timestamp(created_at);
    created + chrono::Duration::days(retention_days as i64)
}

/// Anonimiza dados pessoais dentro de um SharedEPA.
/// Zera state_hash, evidence_hash e preserva apenas hashes de integridade.
/// Retorna o EPA modificado e uma descrição dos campos alterados.
pub fn anonymize_epa_fields(epa: &mut SharedEPA) -> Vec<String> {
    let mut fields = Vec::new();

    if epa.encrypted_payload.is_some() {
        epa.encrypted_payload = None;
        fields.push("encrypted_payload".to_string());
    }
    if epa.ephemeral_public_key.is_some() {
        epa.ephemeral_public_key = None;
        fields.push("ephemeral_public_key".to_string());
    }

    // Zera hashes que podem conter dados derivados de dados pessoais
    let zero = "0".repeat(64);
    if epa.state_hash != zero {
        epa.state_hash = zero.clone();
        fields.push("state_hash".to_string());
    }
    if epa.evidence_hash != zero {
        epa.evidence_hash = zero;
        fields.push("evidence_hash".to_string());
    }

    fields
}

/// Cria EPA de supressão referenciando o original.
/// A supressão prova que os dados foram anonimizados.
pub fn create_suppression_epa(node: &NodeIdentity, original_epa: &SharedEPA) -> SharedEPA {
    let state_json = r#"{"lgpd_action":"suppression","status":"anonymized"}"#;
    let evidence_jsonl = format!(
        r#"{{"action":"anonymize","original_epa_id":"{}","timestamp":"{}"}}"#,
        original_epa.epa_id,
        Utc::now().to_rfc3339()
    );
    let decisions_jsonl = format!(
        r#"{{"decision":"suppress","reason":"lgpd_data_subject_request","original_epa":"{}"}}"#,
        original_epa.epa_id
    );
    let manifest_json = format!(
        r#"{{"project":"lgpd_suppression","original_epa_id":"{}","action":"data_anonymization"}}"#,
        original_epa.epa_id
    );

    SharedEPA::create(
        node,
        state_json,
        &evidence_jsonl,
        &decisions_jsonl,
        &manifest_json,
        None,
    )
}

/// Atualiza o índice: reconstrói a partir dos EPAs atuais + manifestos.
/// Chamado quando temos acesso aos manifests LGPD.
pub fn index_from_epas_with_lgpd(
    epas: &[SharedEPA],
    lgpd_map: &HashMap<String, crate::lgpd::LgpdMetadata>,
) -> HashMap<String, Vec<EpaRef>> {
    let mut index: HashMap<String, Vec<EpaRef>> = HashMap::new();
    for epa in epas {
        if let Some(lgpd) = lgpd_map.get(&epa.epa_id) {
            if let Some(ref hash) = lgpd.data_subject_hash {
                let epa_hash = canonical_hash(&epa.integrity_hash);
                let entry = EpaRef {
                    epa_id: epa.epa_id.clone(),
                    epa_hash,
                    lawful_basis: lgpd.lawful_basis,
                    purpose: lgpd.purpose.clone(),
                    created_at: parse_timestamp(&epa.timestamp),
                    expires_at: calc_expiry(lgpd.retention_days, &epa.timestamp),
                };
                index.entry(hash.clone()).or_default().push(entry);
            }
        }
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_epa_ref() -> EpaRef {
        EpaRef {
            epa_id: "abc123".to_string(),
            epa_hash: "deadbeef".to_string(),
            lawful_basis: LawfulBasis::Consentimento,
            purpose: "processamento_pedido".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(365),
        }
    }

    #[test]
    fn lgpd_index_lookup() {
        let mut idx = LgpdIndex::new();
        let entry = sample_epa_ref();
        idx.insert("hash1".to_string(), entry.clone());

        let results = idx.lookup("hash1");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].epa_id, "abc123");

        let empty = idx.lookup("nonexistent");
        assert!(empty.is_empty());
    }

    #[test]
    fn lgpd_index_remove_epa() {
        let mut idx = LgpdIndex::new();
        idx.insert("hash1".to_string(), sample_epa_ref());
        assert_eq!(idx.count(), 1);

        idx.remove_epa("hash1", "abc123");
        assert_eq!(idx.count(), 0);
        assert!(!idx.index.contains_key("hash1"));
    }

    #[test]
    fn lgpd_index_remove_only_target() {
        let mut idx = LgpdIndex::new();
        let mut entry1 = sample_epa_ref();
        entry1.epa_id = "epa1".to_string();
        let mut entry2 = sample_epa_ref();
        entry2.epa_id = "epa2".to_string();

        idx.insert("hash1".to_string(), entry1);
        idx.insert("hash1".to_string(), entry2);
        assert_eq!(idx.count(), 2);

        idx.remove_epa("hash1", "epa1");
        assert_eq!(idx.count(), 1);
        assert_eq!(idx.lookup("hash1")[0].epa_id, "epa2");
    }

    #[test]
    fn anonymize_clears_sensitive_fields() {
        let node = NodeIdentity::generate("test");
        let mut epa = SharedEPA::create(
            &node,
            r#"{"name":"João","cpf":"123"}"#,
            r#"{"evidence":"ok"}"#,
            r#"{"decision":"ok"}"#,
            r#"{"manifest":"v1"}"#,
            None,
        );
        epa.encrypted_payload = Some(vec![1, 2, 3]);
        epa.ephemeral_public_key = Some(vec![4, 5, 6]);

        let fields = anonymize_epa_fields(&mut epa);
        assert!(fields.contains(&"encrypted_payload".to_string()));
        assert!(fields.contains(&"ephemeral_public_key".to_string()));
        assert!(fields.contains(&"state_hash".to_string()));
        assert!(fields.contains(&"evidence_hash".to_string()));
        assert!(epa.encrypted_payload.is_none());
        assert!(epa.ephemeral_public_key.is_none());
        assert_eq!(epa.state_hash, "0".repeat(64));
    }

    #[test]
    fn suppression_epa_references_original() {
        let node = NodeIdentity::generate("test");
        let original = SharedEPA::create(
            &node,
            r#"{"data":"sensitive"}"#,
            r#"{"evidence":"ok"}"#,
            r#"{"decision":"ok"}"#,
            r#"{"manifest":"v1"}"#,
            None,
        );

        let suppression = create_suppression_epa(&node, &original);
        assert_ne!(suppression.epa_id, original.epa_id);
        assert!(suppression.integrity_hash != original.integrity_hash);
    }

    #[test]
    fn titular_export_serializes() {
        let export = TitularExport {
            data_subject_hash: "hash123".to_string(),
            epas: vec![sample_epa_ref()],
            exported_at: Utc::now(),
        };
        let json = serde_json::to_string(&export).unwrap();
        assert!(json.contains("hash123"));
        assert!(json.contains("exported_at"));
    }

    #[test]
    fn index_multiple_subjects() {
        let mut idx = LgpdIndex::new();
        let mut e1 = sample_epa_ref();
        e1.epa_id = "epa_a".to_string();
        let mut e2 = sample_epa_ref();
        e2.epa_id = "epa_b".to_string();

        idx.insert("subject_1".to_string(), e1);
        idx.insert("subject_2".to_string(), e2);

        assert_eq!(idx.count(), 2);
        assert_eq!(idx.subjects().len(), 2);
    }

    #[test]
    fn build_from_epas_empty() {
        let mut idx = LgpdIndex::new();
        idx.build_from_epas(&[]);
        assert_eq!(idx.count(), 0);
    }
}
