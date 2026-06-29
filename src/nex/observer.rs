//! observer.rs — NEX como olho interno do NexoIA
//!
//! Observa o estado do sistema, avalia regras NEX, gera relatórios de saúde.
//! Não é compliance. É autoconsciência matemática.

use crate::lgpd_rights::LgpdIndex;
use crate::network::epa::SharedEPA;
use crate::network::reputation::ReputationStore;
use crate::network::transport::PeerList;
use crate::provenance::{DerivationIndex, ProvenanceNode};
use crate::types::EvidenceStrength;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Severidade de um achado no relatório.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Ok,
    Warning,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::Warning => write!(f, "WARNING"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Achado individual do observador.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub check: String,
    pub severity: Severity,
    pub message: String,
    pub details: Option<String>,
}

/// Relatório completo de saúde do sistema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub timestamp: String,
    pub overall: Severity,
    pub findings: Vec<Finding>,
    pub summary: HealthSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSummary {
    pub total_checks: usize,
    pub ok: usize,
    pub warnings: usize,
    pub critical: usize,
    pub epas_count: usize,
    pub peers_count: usize,
    pub subjects_indexed: usize,
    pub derivation_links: usize,
}

/// Observador NEX — avalia regras contra o estado atual do sistema.
pub struct NexObserver {
    epas: Arc<RwLock<Vec<SharedEPA>>>,
    peer_list: Arc<RwLock<PeerList>>,
    reputation: Arc<RwLock<ReputationStore>>,
    lgpd_index: Arc<RwLock<LgpdIndex>>,
    provenance_nodes: Arc<RwLock<Vec<ProvenanceNode>>>,
    derivation_index: Arc<RwLock<DerivationIndex>>,
}

impl NexObserver {
    pub fn new(
        epas: Arc<RwLock<Vec<SharedEPA>>>,
        peer_list: Arc<RwLock<PeerList>>,
        reputation: Arc<RwLock<ReputationStore>>,
        lgpd_index: Arc<RwLock<LgpdIndex>>,
        provenance_nodes: Arc<RwLock<Vec<ProvenanceNode>>>,
        derivation_index: Arc<RwLock<DerivationIndex>>,
    ) -> Self {
        Self {
            epas,
            peer_list,
            reputation,
            lgpd_index,
            provenance_nodes,
            derivation_index,
        }
    }

    /// Gera relatório completo de saúde.
    pub async fn report(&self) -> HealthReport {
        let mut findings = Vec::new();

        // ── 1. Integridade dos EPAs ──────────────────────────────
        self.check_epa_integrity(&mut findings).await;
        // ── 2. Consistência do índice LGPD ───────────────────────
        self.check_lgpd_consistency(&mut findings).await;
        // ── 3. Saúde da rede ─────────────────────────────────────
        self.check_network_health(&mut findings).await;
        // ── 4. Integridade da cadeia de proveniência ─────────────
        self.check_provenance_integrity(&mut findings).await;
        // ── 5. Reputação dos peers ───────────────────────────────
        self.check_reputation_health(&mut findings).await;

        let ok = findings.iter().filter(|f| f.severity == Severity::Ok).count();
        let warnings = findings.iter().filter(|f| f.severity == Severity::Warning).count();
        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();

        let overall = if critical > 0 {
            Severity::Critical
        } else if warnings > 0 {
            Severity::Warning
        } else {
            Severity::Ok
        };

        let epas = self.epas.read().await;
        let peers = self.peer_list.read().await;
        let idx = self.lgpd_index.read().await;
        let deriv = self.derivation_index.read().await;

        HealthReport {
            timestamp: chrono::Utc::now().to_rfc3339(),
            overall,
            findings,
            summary: HealthSummary {
                total_checks: ok + warnings + critical,
                ok,
                warnings,
                critical,
                epas_count: epas.len(),
                peers_count: peers.len(),
                subjects_indexed: idx.subjects().len(),
                derivation_links: deriv.len(),
            },
        }
    }

    /// Verifica integridade de cada EPA (signature + hash).
    async fn check_epa_integrity(&self, findings: &mut Vec<Finding>) {
        let epas = self.epas.read().await;
        let mut invalid = 0;
        let mut expired = 0;

        for epa in epas.iter() {
            if epa.verify_full().is_err() {
                invalid += 1;
            }
            if epa.verify_timestamp().is_err() {
                expired += 1;
            }
        }

        if invalid > 0 {
            findings.push(Finding {
                check: "epa_integrity".to_string(),
                severity: Severity::Critical,
                message: format!("{invalid} EPAs com integridade comprometida"),
                details: Some("Assinatura Ed25519 ou hash inválido".to_string()),
            });
        } else {
            findings.push(Finding {
                check: "epa_integrity".to_string(),
                severity: Severity::Ok,
                message: format!("Todos {} EPAs íntegros", epas.len()),
                details: None,
            });
        }

        if expired > 0 {
            findings.push(Finding {
                check: "epa_timestamp".to_string(),
                severity: Severity::Warning,
                message: format!("{expired} EPAs com timestamp expirado"),
                details: Some("Timestamp além da janela de 5 minutos".to_string()),
            });
        }
    }

    /// Verifica consistência entre índice LGPD e EPAs em disco.
    async fn check_lgpd_consistency(&self, findings: &mut Vec<Finding>) {
        let epas = self.epas.read().await;
        let idx = self.lgpd_index.read().await;

        let epas_with_lgpd: usize = epas
            .iter()
            .filter(|e| e.lgpd_metadata.is_some())
            .count();
        let indexed = idx.count();

        if epas_with_lgpd != indexed {
            findings.push(Finding {
                check: "lgpd_consistency".to_string(),
                severity: Severity::Warning,
                message: format!(
                    "LGPD index tem {} entradas mas {} EPAs têm metadata",
                    indexed, epas_with_lgpd
                ),
                details: Some("Índice pode estar desatualizado após restart".to_string()),
            });
        } else {
            findings.push(Finding {
                check: "lgpd_consistency".to_string(),
                severity: Severity::Ok,
                message: format!("LGPD index consistente ({} EPAs indexados)", indexed),
                details: None,
            });
        }
    }

    /// Verifica saúde da rede (peers conectados).
    async fn check_network_health(&self, findings: &mut Vec<Finding>) {
        let peers = self.peer_list.read().await;
        let count = peers.len();

        if count == 0 {
            findings.push(Finding {
                check: "network_peers".to_string(),
                severity: Severity::Warning,
                message: "Nenhum peer conectado".to_string(),
                details: Some("Nó pode estar isolado da rede".to_string()),
            });
        } else {
            findings.push(Finding {
                check: "network_peers".to_string(),
                severity: Severity::Ok,
                message: format!("{} peers conectados", count),
                details: None,
            });
        }
    }

    /// Verifica integridade da cadeia de proveniência.
    async fn check_provenance_integrity(&self, findings: &mut Vec<Finding>) {
        let nodes = self.provenance_nodes.read().await;
        let deriv = self.derivation_index.read().await;

        let blinded = nodes.iter().filter(|n| {
            n.parent_ref
                .as_ref()
                .map_or(false, |p| p.is_blinded())
        }).count();
        let total_links = nodes.iter().filter(|n| n.parent_ref.is_some()).count();

        if blinded > 0 {
            findings.push(Finding {
                check: "provenance_blinding".to_string(),
                severity: Severity::Ok,
                message: format!(
                    "{} links cegados de {} totais (crypto-shredding ativo)",
                    blinded, total_links
                ),
                details: None,
            });
        } else if total_links > 0 {
            findings.push(Finding {
                check: "provenance_blinding".to_string(),
                severity: Severity::Ok,
                message: format!("{} links de proveniência, nenhum cegado", total_links),
                details: None,
            });
        }

        // Verifica se derivation index está consistente com nós
        let index_links = deriv.len();
        let node_links = total_links;
        if index_links != node_links {
            findings.push(Finding {
                check: "derivation_index_consistency".to_string(),
                severity: Severity::Warning,
                message: format!(
                    "DerivationIndex tem {} links mas ProvenanceNodes têm {}",
                    index_links, node_links
                ),
                details: Some("Índice pode estar desatualizado".to_string()),
            });
        }
    }

    /// Verifica saúde da reputação dos peers.
    async fn check_reputation_health(&self, findings: &mut Vec<Finding>) {
        let rep = self.reputation.read().await;
        let banned = rep.banned_count();

        if banned > 0 {
            findings.push(Finding {
                check: "reputation_banned".to_string(),
                severity: Severity::Warning,
                message: format!("{} peers banidos", banned),
                details: Some("Ban expira em 24h automaticamente".to_string()),
            });
        } else {
            findings.push(Finding {
                check: "reputation_banned".to_string(),
                severity: Severity::Ok,
                message: "Nenhum peer banido".to_string(),
                details: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lgpd_rights::LgpdIndex;
    use crate::network::epa::SharedEPA;
    use crate::network::identity::NodeIdentity;
    use crate::network::reputation::ReputationStore;
    use crate::network::transport::{PeerList, TrustedPeerList};
    use crate::provenance::{DerivationIndex, ProvenanceNode};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn test_state() -> (
        Arc<RwLock<Vec<SharedEPA>>>,
        Arc<RwLock<PeerList>>,
        Arc<RwLock<ReputationStore>>,
        Arc<RwLock<LgpdIndex>>,
        Arc<RwLock<Vec<ProvenanceNode>>>,
        Arc<RwLock<DerivationIndex>>,
    ) {
        (
            Arc::new(RwLock::new(Vec::new())),
            Arc::new(RwLock::new(PeerList::new(10))),
            Arc::new(RwLock::new(ReputationStore::new())),
            Arc::new(RwLock::new(LgpdIndex::new())),
            Arc::new(RwLock::new(Vec::new())),
            Arc::new(RwLock::new(DerivationIndex::new())),
        )
    }

    #[tokio::test]
    async fn empty_system_generates_report() {
        let (epas, peers, rep, idx, prov, deriv) = test_state();
        let observer = NexObserver::new(epas, peers, rep, idx, prov, deriv);

        let report = observer.report().await;
        // Rede vazia gera Warning — correto
        assert_eq!(report.overall, Severity::Warning);
        assert!(!report.findings.is_empty());
        assert_eq!(report.summary.total_checks, report.findings.len());
    }

    #[tokio::test]
    async fn epas_with_valid_signature_report_ok() {
        let (epas, peers, rep, idx, prov, deriv) = test_state();
        let node = NodeIdentity::generate("test");
        let epa = SharedEPA::create(
            &node,
            r#"{"test":"data"}"#,
            r#"{"evidence":"ok"}"#,
            r#"{"decision":"ok"}"#,
            r#"{"manifest":"v1"}"#,
            None,
        );
        epas.write().await.push(epa);

        let observer = NexObserver::new(epas, peers, rep, idx, prov, deriv);
        let report = observer.report().await;

        let integrity = report.findings.iter().find(|f| f.check == "epa_integrity").unwrap();
        assert_eq!(integrity.severity, Severity::Ok);
    }

    #[tokio::test]
    async fn no_peers_generates_warning() {
        let (epas, peers, rep, idx, prov, deriv) = test_state();
        let observer = NexObserver::new(epas, peers, rep, idx, prov, deriv);

        let report = observer.report().await;
        let network = report.findings.iter().find(|f| f.check == "network_peers").unwrap();
        assert_eq!(network.severity, Severity::Warning);
    }

    #[tokio::test]
    async fn report_serializes_to_json() {
        let (epas, peers, rep, idx, prov, deriv) = test_state();
        let observer = NexObserver::new(epas, peers, rep, idx, prov, deriv);

        let report = observer.report().await;
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("timestamp"));
        assert!(json.contains("overall"));
        assert!(json.contains("findings"));
    }
}
