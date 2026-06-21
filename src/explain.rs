//! explain.rs — Microscópio de Evidências do NEXOIA
//!
//! Opera sobre Vec<DecisionRecord> real do projeto.
//! Rastreia gargalos de MinStrength, detecta conflitos entre decisões
//! e emite diagnósticos estruturados com sugestões de elevação.
//!
//! Adicione em src/lib.rs:
//!   pub mod explain;

use crate::decision::{DecisionRecord, DecisionStatus};
use crate::types::EvidenceStrength;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Saída do explain
// ---------------------------------------------------------------------------

/// Diagnóstico de um único DecisionRecord.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDiagnosis {
    /// Hash do DecisionRecord analisado (identificador único).
    pub decision_hash: String,
    /// Status da decisão: OK, VIOLACAO, ABSTERSE.
    pub status: DecisionStatus,
    /// Força do lado esquerdo da comparação.
    pub left_strength: EvidenceStrength,
    /// Força do lado direito da comparação.
    pub right_strength: EvidenceStrength,
    /// Qual lado é o gargalo (o mais fraco).
    pub bottleneck_side: Option<BottleneckSide>,
    /// Força mínima efetiva (MinStrength aplicado).
    pub effective_strength: EvidenceStrength,
    /// Diagnóstico legível.
    pub diagnosis: String,
    /// Sugestão para elevar a força (None se já está no topo).
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BottleneckSide {
    Left,
    Right,
    Equal,
}

/// Conflito entre dois DecisionRecords com status divergente.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictRecord {
    pub decision_hash_a: String,
    pub status_a: DecisionStatus,
    pub strength_a: EvidenceStrength,
    pub decision_hash_b: String,
    pub status_b: DecisionStatus,
    pub strength_b: EvidenceStrength,
    /// Resolução conservadora: prevalece a decisão com menor força efetiva.
    pub resolution: String,
    pub winner_hash: String,
}

/// Relatório completo emitido por explain_chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainReport {
    pub diagnoses: Vec<NodeDiagnosis>,
    pub conflicts: Vec<ConflictRecord>,
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Motor de explicação
// ---------------------------------------------------------------------------

/// Ponto de entrada principal.
///
/// Recebe a lista de DecisionRecords (saída de decisions.jsonl)
/// e produz um relatório com diagnósticos e conflitos detectados.
///
/// # Exemplo
/// ```ignore
/// use nexoia::explain::{explain_chain, load_decisions_jsonl};
///
/// let records = load_decisions_jsonl("decisions.jsonl").unwrap();
/// let report = explain_chain(&records);
/// println!("{}", report.summary);
/// ```
pub fn explain_chain(records: &[DecisionRecord]) -> ExplainReport {
    let diagnoses: Vec<NodeDiagnosis> = records.iter().map(diagnose).collect();

    let conflicts = detect_conflicts(records);

    let summary = build_summary(&diagnoses, &conflicts);

    ExplainReport {
        diagnoses,
        conflicts,
        summary,
    }
}

// ---------------------------------------------------------------------------
// Helpers internos
// ---------------------------------------------------------------------------

fn diagnose(record: &DecisionRecord) -> NodeDiagnosis {
    let left = record.body.quality_left_strength;
    let right = record.body.quality_right_strength;

    // MinStrength: força efetiva = min(left, right)
    let effective_strength = left.min(right);

    let bottleneck_side = match left.cmp(&right) {
        std::cmp::Ordering::Less => Some(BottleneckSide::Left),
        std::cmp::Ordering::Greater => Some(BottleneckSide::Right),
        std::cmp::Ordering::Equal => Some(BottleneckSide::Equal),
    };

    let diagnosis = build_diagnosis(record, left, right, effective_strength, &bottleneck_side);
    let suggestion = upgrade_hint(effective_strength);

    NodeDiagnosis {
        decision_hash: record.hash.clone(),
        status: record.body.status,
        left_strength: left,
        right_strength: right,
        bottleneck_side,
        effective_strength,
        diagnosis,
        suggestion,
    }
}

fn build_diagnosis(
    record: &DecisionRecord,
    left: EvidenceStrength,
    right: EvidenceStrength,
    effective: EvidenceStrength,
    bottleneck: &Option<BottleneckSide>,
) -> String {
    let status_str = record.body.status.as_str();
    let reason = &record.body.reason_code;

    match bottleneck {
        Some(BottleneckSide::Left) => format!(
            "[{}] {}: lado esquerdo ({}) é o gargalo — direito ({}) é mais forte. \
             Força efetiva: {}. MinStrength aplicado.",
            status_str, reason, left, right, effective
        ),
        Some(BottleneckSide::Right) => format!(
            "[{}] {}: lado direito ({}) é o gargalo — esquerdo ({}) é mais forte. \
             Força efetiva: {}. MinStrength aplicado.",
            status_str, reason, right, left, effective
        ),
        Some(BottleneckSide::Equal) => format!(
            "[{}] {}: ambos os lados têm força igual ({}). \
             Força efetiva: {}.",
            status_str, reason, left, effective
        ),
        None => format!("[{}] {}: força efetiva: {}.", status_str, reason, effective),
    }
}

fn upgrade_hint(strength: EvidenceStrength) -> Option<String> {
    match strength {
        EvidenceStrength::Unverifiable => {
            Some("Adicionar fonte verificável local para elevar para LOCAL.".to_string())
        }
        EvidenceStrength::Local => Some(
            "Obter assinatura digital de autoridade conhecida para elevar para SIGNED.".to_string(),
        ),
        EvidenceStrength::Witnessed => {
            Some("Adicionar segunda testemunha independente para consolidar WITNESSED.".to_string())
        }
        EvidenceStrength::Signed => Some(
            "Ancorar em registro externo auditável (WitnessSet) para elevar para ANCHORED."
                .to_string(),
        ),
        EvidenceStrength::Anchored => None, // topo — sem sugestão
    }
}

/// Detecta pares de DecisionRecords com status divergente.
/// Conflito = dois registros no mesmo run com decisões diferentes.
fn detect_conflicts(records: &[DecisionRecord]) -> Vec<ConflictRecord> {
    let mut conflicts = Vec::new();

    for i in 0..records.len() {
        for j in (i + 1)..records.len() {
            let a = &records[i];
            let b = &records[j];

            // Conflito: mesmo run_id, status diferente
            if a.body.run_id == b.body.run_id && a.body.status != b.body.status {
                conflicts.push(build_conflict(a, b));
            }
        }
    }

    conflicts
}

fn build_conflict(a: &DecisionRecord, b: &DecisionRecord) -> ConflictRecord {
    let strength_a = a
        .body
        .quality_left_strength
        .min(a.body.quality_right_strength);
    let strength_b = b
        .body
        .quality_left_strength
        .min(b.body.quality_right_strength);

    // Conservadorismo: prevalece a decisão com menor força efetiva
    let (winner_hash, resolution) =
        if strength_a <= strength_b {
            (
                a.hash.clone(),
                format!(
                "Decisão '{}' ({}) prevalece sobre '{}' ({}) — menor força efetiva é conservadora.",
                a.body.status.as_str(), strength_a,
                b.body.status.as_str(), strength_b,
            ),
            )
        } else {
            (
                b.hash.clone(),
                format!(
                "Decisão '{}' ({}) prevalece sobre '{}' ({}) — menor força efetiva é conservadora.",
                b.body.status.as_str(), strength_b,
                a.body.status.as_str(), strength_a,
            ),
            )
        };

    ConflictRecord {
        decision_hash_a: a.hash.clone(),
        status_a: a.body.status,
        strength_a,
        decision_hash_b: b.hash.clone(),
        status_b: b.body.status,
        strength_b,
        resolution,
        winner_hash,
    }
}

fn build_summary(diagnoses: &[NodeDiagnosis], conflicts: &[ConflictRecord]) -> String {
    let total = diagnoses.len();
    let with_gap = diagnoses
        .iter()
        .filter(|d| d.bottleneck_side.as_ref() != Some(&BottleneckSide::Equal))
        .count();
    let with_hint = diagnoses.iter().filter(|d| d.suggestion.is_some()).count();
    let n_conflicts = conflicts.len();

    let mut lines = vec![
        "=== NEXOIA — Relatório de Evidências ===".to_string(),
        format!("Decisões analisadas : {}", total),
        format!("Com gargalo         : {}", with_gap),
        format!("Com sugestão        : {}", with_hint),
        format!("Conflitos detectados: {}", n_conflicts),
        String::new(),
    ];

    for d in diagnoses {
        lines.push(format!("  {}", d.diagnosis));
        if let Some(s) = &d.suggestion {
            lines.push(format!("    → Sugestão: {}", s));
        }
    }

    if !conflicts.is_empty() {
        lines.push(String::new());
        lines.push("--- Conflitos ---".to_string());
        for c in conflicts {
            lines.push(format!(
                "  {} ({:?}) vs {} ({:?})",
                &c.decision_hash_a[..8.min(c.decision_hash_a.len())],
                c.status_a,
                &c.decision_hash_b[..8.min(c.decision_hash_b.len())],
                c.status_b,
            ));
            lines.push(format!("    → {}", c.resolution));
        }
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Utilitário: carrega decisions.jsonl
// ---------------------------------------------------------------------------

/// Lê decisions.jsonl e retorna Vec<DecisionRecord>.
/// Cada linha deve ser um JSON válido de DecisionRecord.
pub fn load_decisions_jsonl(path: &str) -> Result<Vec<DecisionRecord>, Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let record: DecisionRecord =
            serde_json::from_str(trimmed).map_err(|e| format!("Linha {}: {}", i + 1, e))?;
        records.push(record);
    }

    Ok(records)
}

// ---------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{DecisionBody, DecisionRecord, DecisionStatus};
    use crate::quality::ResolutionReport;
    use crate::types::EvidenceStrength;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_record(
        status: DecisionStatus,
        left: EvidenceStrength,
        right: EvidenceStrength,
        run_id: Uuid,
    ) -> DecisionRecord {
        let resolution_hash = format!("{}-{}", left, right);
        let body = DecisionBody {
            decision_id: Uuid::new_v4(),
            run_id,
            created_at_utc: Utc::now(),
            status,
            reason_code: "TEST".to_string(),
            message: "test record".to_string(),
            state_hash: "state_hash".to_string(),
            quality_left_strength: left,
            quality_right_strength: right,
            quality_report: ResolutionReport {
                chosen_side: "left".to_string(),
                reason_code: "LEFT_STRONGER".to_string(),
                message: "test".to_string(),
                left_strength: left,
                right_strength: right,
                resolution_hash,
            },
        };
        DecisionRecord {
            hash: format!("{:x}", Uuid::new_v4().as_u128()),
            body,
        }
    }

    #[test]
    fn test_gargalo_lado_direito() {
        // Signed + Local = Local (MinStrength: direito é o gargalo)
        let run = Uuid::new_v4();
        let records = vec![make_record(
            DecisionStatus::Ok,
            EvidenceStrength::Signed,
            EvidenceStrength::Local,
            run,
        )];

        let report = explain_chain(&records);
        let d = &report.diagnoses[0];

        assert_eq!(d.effective_strength, EvidenceStrength::Local);
        assert_eq!(d.bottleneck_side, Some(BottleneckSide::Right));
        assert!(d.suggestion.is_some());
        println!("{}", report.summary);
    }

    #[test]
    fn test_gargalo_lado_esquerdo() {
        // Local + Signed = Local (MinStrength: esquerdo é o gargalo)
        let run = Uuid::new_v4();
        let records = vec![make_record(
            DecisionStatus::Ok,
            EvidenceStrength::Local,
            EvidenceStrength::Signed,
            run,
        )];

        let report = explain_chain(&records);
        let d = &report.diagnoses[0];

        assert_eq!(d.effective_strength, EvidenceStrength::Local);
        assert_eq!(d.bottleneck_side, Some(BottleneckSide::Left));
    }

    #[test]
    fn test_sem_gargalo_anchored() {
        let run = Uuid::new_v4();
        let records = vec![make_record(
            DecisionStatus::Ok,
            EvidenceStrength::Anchored,
            EvidenceStrength::Anchored,
            run,
        )];

        let report = explain_chain(&records);
        let d = &report.diagnoses[0];

        assert_eq!(d.effective_strength, EvidenceStrength::Anchored);
        assert!(d.suggestion.is_none()); // topo — sem sugestão
    }

    #[test]
    fn test_conflito_mesmo_run() {
        let run = Uuid::new_v4();
        let records = vec![
            make_record(
                DecisionStatus::Ok,
                EvidenceStrength::Signed,
                EvidenceStrength::Signed,
                run,
            ),
            make_record(
                DecisionStatus::Violacao,
                EvidenceStrength::Local,
                EvidenceStrength::Local,
                run,
            ),
        ];

        let report = explain_chain(&records);

        assert_eq!(report.conflicts.len(), 1);
        // VIOLACAO (Local) prevalece sobre OK (Signed) — mais conservador
        let c = &report.conflicts[0];
        assert_eq!(c.winner_hash, records[1].hash);
        println!("{}", report.summary);
    }

    #[test]
    fn test_lei_conservacao() {
        // Anchored + Witnessed = Witnessed — nunca aumenta
        let run = Uuid::new_v4();
        let records = vec![make_record(
            DecisionStatus::Ok,
            EvidenceStrength::Anchored,
            EvidenceStrength::Witnessed,
            run,
        )];

        let report = explain_chain(&records);
        let d = &report.diagnoses[0];

        // Força efetiva nunca pode ser maior que o menor input
        assert!(d.effective_strength <= EvidenceStrength::Witnessed);
    }
}
