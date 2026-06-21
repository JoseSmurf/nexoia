//! types.rs — Vocabulário compartilhado do NEXOIA
//!
//! Tipos e trait que definem a fronteira entre camadas de entrada (IA, sensor,
//! humano) e o core de decisão determinístico.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStrength {
    Unverifiable,
    Local,
    Witnessed,
    Signed,
    Anchored,
}

impl EvidenceStrength {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unverifiable => "UNVERIFIABLE",
            Self::Local => "LOCAL",
            Self::Witnessed => "WITNESSED",
            Self::Signed => "SIGNED",
            Self::Anchored => "ANCHORED",
        }
    }
}

impl fmt::Display for EvidenceStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NexAssertion {
    pub context_id: String,
    pub evidence_strength: EvidenceStrength,
    pub confidence: f32,
}

pub trait EvidenceProvider {
    type Error: std::error::Error;
    fn translate(&self, raw: &str, max_bytes: usize) -> Result<NexAssertion, Self::Error>;
    fn fingerprint(&self) -> &str;
}
