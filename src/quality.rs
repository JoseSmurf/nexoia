use crate::hash::canonical_hash;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStrength {
    Unverifiable, // Level 0 - no material proof
    Local,        // Level 1 - local evidence
    Witnessed,    // Level 2 - witnessed
    Signed,       // Level 3 - signed
    Anchored,     // Level 4 - externally anchored
}

impl EvidenceStrength {
    fn as_str(self) -> &'static str {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionReport {
    pub chosen_side: String,
    pub reason_code: String,
    pub message: String,
    pub left_strength: EvidenceStrength,
    pub right_strength: EvidenceStrength,
    pub resolution_hash: String,
}

pub fn evaluate(evidence_hash: &str, kind: &str) -> EvidenceStrength {
    let evidence_hash = evidence_hash.trim();
    let kind = kind.trim().to_ascii_lowercase();

    if evidence_hash.is_empty() {
        return EvidenceStrength::Unverifiable;
    }

    if kind.contains("anchored") || kind.contains("external") {
        EvidenceStrength::Anchored
    } else if kind.contains("signed") {
        EvidenceStrength::Signed
    } else if kind.contains("witness") {
        EvidenceStrength::Witnessed
    } else {
        EvidenceStrength::Local
    }
}

pub fn resolve_quality_divergence(
    left_strength: EvidenceStrength,
    right_strength: EvidenceStrength,
) -> ResolutionReport {
    let (chosen_side, reason_code, message) = match left_strength.cmp(&right_strength) {
        std::cmp::Ordering::Greater => (
            "left".to_string(),
            "LEFT_STRONGER".to_string(),
            format!(
                "left side wins with {} over right side {}",
                left_strength, right_strength
            ),
        ),
        std::cmp::Ordering::Less => (
            "right".to_string(),
            "RIGHT_STRONGER".to_string(),
            format!(
                "right side wins with {} over left side {}",
                right_strength, left_strength
            ),
        ),
        std::cmp::Ordering::Equal => (
            "tie".to_string(),
            "EQUAL_STRENGTH".to_string(),
            format!("both sides have the same strength: {}", left_strength),
        ),
    };

    let resolution_hash = canonical_hash(&format!(
        "{chosen_side}|{reason_code}|{message}|{}|{}",
        left_strength.as_str(),
        right_strength.as_str()
    ));

    ResolutionReport {
        chosen_side,
        reason_code,
        message,
        left_strength,
        right_strength,
        resolution_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::{evaluate, resolve_quality_divergence, EvidenceStrength};

    #[test]
    fn evaluate_maps_known_kinds() {
        assert_eq!(evaluate("abcd", "signed"), EvidenceStrength::Signed);
        assert_eq!(evaluate("abcd", "witness"), EvidenceStrength::Witnessed);
        assert_eq!(evaluate("abcd", "anchored"), EvidenceStrength::Anchored);
        assert_eq!(evaluate("", "signed"), EvidenceStrength::Unverifiable);
    }

    #[test]
    fn resolve_prefers_stronger_side() {
        let report = resolve_quality_divergence(EvidenceStrength::Signed, EvidenceStrength::Local);
        assert_eq!(report.chosen_side, "left");
        assert_eq!(report.reason_code, "LEFT_STRONGER");
        assert!(!report.resolution_hash.is_empty());
    }
}
