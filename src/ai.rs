//! ai.rs — Motor de Análise de Evidências do NEXOIA
//!
//! Analisa a estrutura do state JSON para determinar a força da evidência.
//! Motor determinístico baseado em regras — mesmo input = mesmo output.

use std::fmt;

use crate::defense::ValidationError;
use crate::types::{EvidenceProvider, EvidenceStrength, NexAssertion};

#[derive(Debug, Clone, PartialEq)]
pub enum AIError {
    InputValidationError(ValidationError),
    InvalidJson(String),
}

impl fmt::Display for AIError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AIError::InputValidationError(e) => {
                write!(f, "dado bruto rejeitado pela defesa: {}", e)
            }
            AIError::InvalidJson(e) => write!(f, "JSON inválido: {}", e),
        }
    }
}

impl std::error::Error for AIError {}

/// Fatores de evidência detectados na análise.
#[derive(Debug, Clone, Default)]
struct EvidenceFactors {
    has_lgpd_metadata: bool,
    has_data_subject_hash: bool,
    has_consent_id: bool,
    has_dpia_ref: bool,
    has_valid_timestamp: bool,
    has_deterministic_id: bool,
    has_threshold: bool,
    has_input_value: bool,
    input_value_meets_threshold: bool,
    purpose_quality: PurposeQuality,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
enum PurposeQuality {
    #[default]
    Empty,
    Generic,
    Specific,
}

/// Motor de análise de evidências.
/// Analisa a estrutura do state JSON para determinar força da evidência.
pub struct EvidenceEngine {
    confidence_threshold: f32,
}

impl EvidenceEngine {
    pub fn new(threshold: f32) -> Self {
        Self {
            confidence_threshold: threshold.clamp(0.0, 1.0),
        }
    }

    fn analyze_factors(&self, json: &serde_json::Value) -> EvidenceFactors {
        let mut factors = EvidenceFactors::default();

        // Verifica LGPD metadata
        if let Some(lgpd) = json.get("lgpd") {
            factors.has_lgpd_metadata = true;
            factors.has_data_subject_hash = lgpd.get("data_subject_hash").is_some();
            factors.has_consent_id = lgpd.get("consent_id").is_some();
            factors.has_dpia_ref = lgpd.get("dpia_ref").is_some();

            // Avalia qualidade do propósito
            if let Some(purpose) = lgpd.get("purpose").and_then(|v| v.as_str()) {
                factors.purpose_quality = evaluate_purpose(purpose);
            }
        }

        // Verifica timestamp válido
        if let Some(ts) = json.get("generated_at_utc").and_then(|v| v.as_str()) {
            factors.has_valid_timestamp = chrono::DateTime::parse_from_rfc3339(ts).is_ok();
        }

        // Verifica run_id determinístico
        if let Some(run_id) = json.get("run_id").and_then(|v| v.as_str()) {
            factors.has_deterministic_id =
                !run_id.is_empty() && run_id != "00000000-0000-0000-0000-000000000000";
        }

        // Verifica threshold e input_value
        if let Some(threshold) = json.get("threshold").and_then(|v| v.as_i64()) {
            factors.has_threshold = threshold > 0;
        }

        if let Some(input_value) = json.get("input_value").and_then(|v| v.as_i64()) {
            factors.has_input_value = true;
            if let Some(threshold) = json.get("threshold").and_then(|v| v.as_i64()) {
                factors.input_value_meets_threshold = input_value >= threshold;
            }
        }

        factors
    }

    fn calculate_score(&self, factors: &EvidenceFactors) -> f32 {
        let mut score: f32 = 0.0;

        // Base: dados estruturados presentes
        if factors.has_deterministic_id {
            score += 0.10;
        }
        if factors.has_valid_timestamp {
            score += 0.10;
        }

        // LGPD compliance
        if factors.has_lgpd_metadata {
            score += 0.15;
            if factors.has_data_subject_hash {
                score += 0.10;
            }
            if factors.has_consent_id {
                score += 0.10;
            }
            if factors.has_dpia_ref {
                score += 0.05;
            }

            // Qualidade do propósito
            match factors.purpose_quality {
                PurposeQuality::Specific => score += 0.10,
                PurposeQuality::Generic => score += 0.05,
                PurposeQuality::Empty => {}
            }
        }

        // Dados de avaliação presentes
        if factors.has_threshold {
            score += 0.05;
        }
        if factors.has_input_value {
            score += 0.05;
        }

        // Input atende threshold (evidência positiva)
        if factors.input_value_meets_threshold {
            score += 0.15;
        }

        score.clamp(0.0, 1.0)
    }
}

impl EvidenceProvider for EvidenceEngine {
    type Error = AIError;

    fn translate(&self, raw: &str, max_bytes: usize) -> Result<NexAssertion, AIError> {
        if let Err(e) = crate::defense::validate_raw_input(raw, max_bytes) {
            return Err(AIError::InputValidationError(e));
        }

        let json: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| AIError::InvalidJson(e.to_string()))?;

        let factors = self.analyze_factors(&json);
        let score = self.calculate_score(&factors);

        let strength = if score < self.confidence_threshold {
            EvidenceStrength::Unverifiable
        } else if score >= 0.75 {
            EvidenceStrength::Anchored
        } else if score >= 0.55 {
            EvidenceStrength::Signed
        } else if score >= 0.35 {
            EvidenceStrength::Witnessed
        } else {
            EvidenceStrength::Local
        };

        // Context ID determinístico baseado no conteúdo
        let context_id = if let Some(run_id) = json.get("run_id").and_then(|v| v.as_str()) {
            format!("ctx_{}", &run_id[..8.min(run_id.len())])
        } else {
            format!("ctx_{:08x}", crc32_hash(raw))
        };

        Ok(NexAssertion {
            context_id,
            evidence_strength: strength,
            confidence: score,
        })
    }

    fn fingerprint(&self) -> &str {
        "evidence_engine_v1"
    }
}

fn evaluate_purpose(purpose: &str) -> PurposeQuality {
    let trimmed = purpose.trim();
    if trimmed.is_empty() {
        return PurposeQuality::Empty;
    }
    // Propósitos genéricos demais
    const GENERIC: &[&str] = &["test", "teste", "debug", "exemplo", "example", "default"];
    if GENERIC.iter().any(|g| trimmed.eq_ignore_ascii_case(g)) {
        PurposeQuality::Generic
    }
    // Propósitos com pelo menos 2 palavras são considerados específicos
    else if trimmed.split_whitespace().count() >= 2 || trimmed.len() >= 15 {
        PurposeQuality::Specific
    } else {
        PurposeQuality::Generic
    }
}

/// CRC32 simples para geração determinística de context_id.
fn crc32_hash(input: &str) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for byte in input.bytes() {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Mantém compatibilidade com código existente.
pub type MockEngine = EvidenceEngine;

#[cfg(test)]
mod tests {
    use super::*;

    fn full_state_json() -> String {
        serde_json::json!({
            "project": "nexoia",
            "run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "generated_at_utc": "2026-06-29T12:00:00Z",
            "scenario": "AUTO",
            "subject": "compliance-check",
            "threshold": 50,
            "input_value": 75,
            "lgpd": {
                "lawful_basis": "consentimento",
                "purpose": "processamento de pedidos do cliente",
                "retention_days": 365,
                "data_subject_hash": "abc123def456",
                "consent_id": "consent_001",
                "dpia_ref": "dpia-2026-001"
            }
        })
        .to_string()
    }

    fn minimal_state_json() -> String {
        serde_json::json!({
            "project": "nexoia",
            "run_id": "00000000-0000-0000-0000-000000000000",
            "generated_at_utc": "invalid",
            "scenario": "AUTO",
            "subject": "test",
            "threshold": 0,
            "input_value": null
        })
        .to_string()
    }

    #[test]
    fn full_state_produces_high_strength() {
        let engine = EvidenceEngine::new(0.30);
        let result = engine.translate(&full_state_json(), 1_048_576).unwrap();
        assert!(
            result.evidence_strength >= EvidenceStrength::Signed,
            "Expected Signed or higher, got {}",
            result.evidence_strength
        );
        assert!(result.confidence >= 0.55);
    }

    #[test]
    fn minimal_state_produces_low_strength() {
        let engine = EvidenceEngine::new(0.50);
        let result = engine.translate(&minimal_state_json(), 1_048_576).unwrap();
        assert!(
            result.evidence_strength <= EvidenceStrength::Local,
            "Expected Local or lower, got {}",
            result.evidence_strength
        );
    }

    #[test]
    fn rejects_empty_input() {
        let engine = EvidenceEngine::new(0.70);
        assert!(engine.translate("", 1_048_576).is_err());
    }

    #[test]
    fn rejects_invalid_json() {
        let engine = EvidenceEngine::new(0.70);
        assert!(engine.translate("not json at all", 1_048_576).is_err());
    }

    #[test]
    fn rejects_oversized_input() {
        let engine = EvidenceEngine::new(0.70);
        let big = "x".repeat(2_000_000);
        assert!(engine.translate(&big, 1_048_576).is_err());
    }

    #[test]
    fn deterministic_same_input_same_output() {
        let engine = EvidenceEngine::new(0.30);
        let a = engine.translate(&full_state_json(), 1_048_576).unwrap();
        let b = engine.translate(&full_state_json(), 1_048_576).unwrap();
        assert_eq!(a.evidence_strength, b.evidence_strength);
        assert_eq!(a.confidence, b.confidence);
        assert_eq!(a.context_id, b.context_id);
    }

    #[test]
    fn lgpd_metadata_increases_score() {
        let without_lgpd = serde_json::json!({
            "project": "nexoia",
            "run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "generated_at_utc": "2026-06-29T12:00:00Z",
            "scenario": "AUTO",
            "subject": "check",
            "threshold": 50,
            "input_value": 60
        })
        .to_string();

        let with_lgpd = serde_json::json!({
            "project": "nexoia",
            "run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "generated_at_utc": "2026-06-29T12:00:00Z",
            "scenario": "AUTO",
            "subject": "check",
            "threshold": 50,
            "input_value": 60,
            "lgpd": {
                "lawful_basis": "consentimento",
                "purpose": "processamento de dados",
                "retention_days": 365,
                "data_subject_hash": "hash123"
            }
        })
        .to_string();

        let engine = EvidenceEngine::new(0.10);
        let a = engine.translate(&without_lgpd, 1_048_576).unwrap();
        let b = engine.translate(&with_lgpd, 1_048_576).unwrap();
        assert!(
            b.confidence > a.confidence,
            "LGPD metadata should increase confidence: {} vs {}",
            b.confidence,
            a.confidence
        );
    }

    #[test]
    fn input_meeting_threshold_increases_score() {
        let meets = serde_json::json!({
            "project": "nexoia",
            "run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "generated_at_utc": "2026-06-29T12:00:00Z",
            "scenario": "AUTO",
            "subject": "check",
            "threshold": 50,
            "input_value": 80
        })
        .to_string();

        let fails = serde_json::json!({
            "project": "nexoia",
            "run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "generated_at_utc": "2026-06-29T12:00:00Z",
            "scenario": "AUTO",
            "subject": "check",
            "threshold": 50,
            "input_value": 20
        })
        .to_string();

        let engine = EvidenceEngine::new(0.10);
        let a = engine.translate(&meets, 1_048_576).unwrap();
        let b = engine.translate(&fails, 1_048_576).unwrap();
        assert!(
            a.confidence > b.confidence,
            "Meeting threshold should increase confidence: {} vs {}",
            a.confidence,
            b.confidence
        );
    }

    #[test]
    fn fingerprint_is_stable() {
        let engine = EvidenceEngine::new(0.70);
        assert_eq!(engine.fingerprint(), "evidence_engine_v1");
    }
}
