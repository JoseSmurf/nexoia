//! ai.rs — Camada de Inferência Local e Validação Criptográfica do NEXOIA
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;

use crate::defense::ValidationError;
use crate::types::{EvidenceProvider, EvidenceStrength, NexAssertion};

#[derive(Debug, Clone, PartialEq)]
pub enum AIError {
    ModelEmpty,
    ModelExceedsLimit { limit: usize, actual: usize },
    InferenceFailed(String),
    InputValidationError(ValidationError),
    IoError(String),
    ModelIntegrityViolation { expected: String, actual: String },
}

impl fmt::Display for AIError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AIError::ModelEmpty => write!(f, "erro: arquivo do modelo de IA está vazio"),
            AIError::ModelExceedsLimit { limit, actual } => {
                write!(
                    f,
                    "modelo excede teto de segurança: {} bytes (máximo: {})",
                    actual, limit
                )
            }
            AIError::InferenceFailed(s) => write!(f, "falha interna na inferência: {}", s),
            AIError::InputValidationError(e) => {
                write!(f, "dado bruto rejeitado pela defesa: {}", e)
            }
            AIError::IoError(s) => write!(f, "falha de I/O ao ler arquivo do modelo: {}", s),
            AIError::ModelIntegrityViolation { expected, actual } => {
                write!(
                    f,
                    "VIOLAÇÃO CRIPTOGRÁFICA: Hash BLAKE3 ({}) diverge do esperado ({})",
                    actual, expected
                )
            }
        }
    }
}

impl std::error::Error for AIError {}

pub struct LocalAIEngine {
    model_path: String,
    model_hash: String,
    confidence_threshold: f32,
    model_bytes: Arc<Vec<u8>>,
}

impl LocalAIEngine {
    pub fn new(
        model_path: &str,
        expected_hash: &str,
        threshold: f32,
        max_model_bytes: usize,
    ) -> Result<Self, AIError> {
        let file = File::open(model_path).map_err(|e| AIError::IoError(e.to_string()))?;
        let metadata = file
            .metadata()
            .map_err(|e| AIError::IoError(e.to_string()))?;
        let file_size = metadata.len() as usize;

        if file_size == 0 {
            return Err(AIError::ModelEmpty);
        }
        if file_size > max_model_bytes {
            return Err(AIError::ModelExceedsLimit {
                limit: max_model_bytes,
                actual: file_size,
            });
        }

        let mut buffer = Vec::with_capacity(file_size);
        file.take(max_model_bytes as u64)
            .read_to_end(&mut buffer)
            .map_err(|e| AIError::IoError(e.to_string()))?;

        let actual_calculated_hash = blake3::hash(&buffer).to_hex().to_string();

        if actual_calculated_hash != expected_hash {
            return Err(AIError::ModelIntegrityViolation {
                expected: expected_hash.to_string(),
                actual: actual_calculated_hash,
            });
        }

        Ok(Self {
            model_path: model_path.to_string(),
            model_hash: actual_calculated_hash,
            confidence_threshold: threshold.clamp(0.0, 1.0),
            model_bytes: Arc::new(buffer),
        })
    }
}

impl EvidenceProvider for LocalAIEngine {
    type Error = AIError;

    fn translate(&self, raw: &str, max_bytes: usize) -> Result<NexAssertion, AIError> {
        if let Err(e) = crate::defense::validate_raw_input(raw, max_bytes) {
            return Err(AIError::InputValidationError(e));
        }

        let mock_score = 0.95f32;
        let strength = if mock_score < self.confidence_threshold {
            EvidenceStrength::Unverifiable
        } else {
            EvidenceStrength::Anchored
        };

        Ok(NexAssertion {
            context_id: String::from("ctx_01"),
            evidence_strength: strength,
            confidence: mock_score,
        })
    }

    fn fingerprint(&self) -> &str {
        &self.model_hash
    }
}
