use crate::hash::canonical_hash;
use crate::types::EvidenceStrength;
use serde::{Deserialize, Serialize};

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

    match kind.as_str() {
        "anchored" | "external" => EvidenceStrength::Anchored,
        "signed" => EvidenceStrength::Signed,
        "witness" | "witnessed" => EvidenceStrength::Witnessed,
        "local" => EvidenceStrength::Local,
        _ => EvidenceStrength::Unverifiable,
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
    use super::{evaluate, resolve_quality_divergence};
    use crate::types::EvidenceStrength;

    #[test]
    fn evaluate_maps_known_kinds() {
        assert_eq!(evaluate("abcd", "signed"), EvidenceStrength::Signed);
        assert_eq!(evaluate("abcd", "witness"), EvidenceStrength::Witnessed);
        assert_eq!(evaluate("abcd", "anchored"), EvidenceStrength::Anchored);
        assert_eq!(evaluate("abcd", "local"), EvidenceStrength::Local);
        assert_eq!(evaluate("", "signed"), EvidenceStrength::Unverifiable);
    }

    #[test]
    fn evaluate_unknown_kind_returns_unverifiable() {
        assert_eq!(evaluate("abcd", "unknown"), EvidenceStrength::Unverifiable);
        assert_eq!(evaluate("abcd", "typo"), EvidenceStrength::Unverifiable);
        assert_eq!(evaluate("abcd", ""), EvidenceStrength::Unverifiable);
    }

    #[test]
    fn evaluate_negated_strings_return_unverifiable() {
        assert_eq!(
            evaluate("abcd", "non_anchored"),
            EvidenceStrength::Unverifiable
        );
        assert_eq!(
            evaluate("abcd", "not_signed"),
            EvidenceStrength::Unverifiable
        );
        assert_eq!(evaluate("abcd", "unsigned"), EvidenceStrength::Unverifiable);
        assert_eq!(
            evaluate("abcd", "unwitnessed"),
            EvidenceStrength::Unverifiable
        );
    }

    #[test]
    fn resolve_prefers_stronger_side() {
        let report = resolve_quality_divergence(EvidenceStrength::Signed, EvidenceStrength::Local);
        assert_eq!(report.chosen_side, "left");
        assert_eq!(report.reason_code, "LEFT_STRONGER");
        assert!(!report.resolution_hash.is_empty());
    }

    #[test]
    fn resolve_right_wins() {
        let report = resolve_quality_divergence(EvidenceStrength::Local, EvidenceStrength::Signed);
        assert_eq!(report.chosen_side, "right");
        assert_eq!(report.reason_code, "RIGHT_STRONGER");
        assert!(!report.resolution_hash.is_empty());
    }

    #[test]
    fn resolve_tie() {
        let report =
            resolve_quality_divergence(EvidenceStrength::Witnessed, EvidenceStrength::Witnessed);
        assert_eq!(report.chosen_side, "tie");
        assert_eq!(report.reason_code, "EQUAL_STRENGTH");
        assert!(!report.resolution_hash.is_empty());
    }
}
