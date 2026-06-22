//! ai.rs — Camada de Inferência Local e Validação Criptográfica do NEXOIA
use std::fmt;

use crate::defense::ValidationError;
use crate::types::{EvidenceProvider, EvidenceStrength, NexAssertion};

#[derive(Debug, Clone, PartialEq)]
pub enum AIError {
    InputValidationError(ValidationError),
}

impl fmt::Display for AIError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AIError::InputValidationError(e) => {
                write!(f, "dado bruto rejeitado pela defesa: {}", e)
            }
        }
    }
}

impl std::error::Error for AIError {}

pub struct MockEngine {
    confidence_threshold: f32,
}

impl MockEngine {
    pub fn new(threshold: f32) -> Self {
        Self {
            confidence_threshold: threshold.clamp(0.0, 1.0),
        }
    }
}

impl EvidenceProvider for MockEngine {
    type Error = AIError;

    fn translate(&self, raw: &str, max_bytes: usize) -> Result<NexAssertion, AIError> {
        if let Err(e) = crate::defense::validate_raw_input(raw, max_bytes) {
            return Err(AIError::InputValidationError(e));
        }

        let score = if raw.contains("anchored") || raw.contains("external") {
            0.95f32
        } else if raw.contains("signed") {
            0.80f32
        } else if raw.contains("witness") {
            0.65f32
        } else if raw.contains("local") {
            0.50f32
        } else {
            0.30f32
        };

        let strength = if score < self.confidence_threshold {
            EvidenceStrength::Unverifiable
        } else if score >= 0.90 {
            EvidenceStrength::Anchored
        } else if score >= 0.75 {
            EvidenceStrength::Signed
        } else if score >= 0.60 {
            EvidenceStrength::Witnessed
        } else {
            EvidenceStrength::Local
        };

        Ok(NexAssertion {
            context_id: format!("ctx_{}", &raw[..8.min(raw.len())]),
            evidence_strength: strength,
            confidence: score,
        })
    }

    fn fingerprint(&self) -> &str {
        "mock_engine_v1"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_engine_anchored() {
        let engine = MockEngine::new(0.70);
        let result = engine.translate("test anchored data", 1_048_576);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().evidence_strength,
            EvidenceStrength::Anchored
        );
    }

    #[test]
    fn mock_engine_low_confidence() {
        let engine = MockEngine::new(0.70);
        let result = engine.translate("random unknown data", 1_048_576);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().evidence_strength,
            EvidenceStrength::Unverifiable
        );
    }

    #[test]
    fn mock_engine_rejects_empty() {
        let engine = MockEngine::new(0.70);
        let result = engine.translate("", 1_048_576);
        assert!(result.is_err());
    }
}
