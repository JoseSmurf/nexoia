use crate::decision::DecisionRecord;
use crate::quality::{resolve_quality_divergence, EvidenceStrength, ResolutionReport};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SyncContract {
    pub left: DecisionRecord,
    pub right: DecisionRecord,
}

#[allow(dead_code)]
impl SyncContract {
    pub fn new(left: DecisionRecord, right: DecisionRecord) -> Self {
        Self { left, right }
    }

    pub fn resolve(&self) -> ResolutionReport {
        resolve_quality_divergence(self.left_strength(), self.right_strength())
    }

    fn left_strength(&self) -> EvidenceStrength {
        self.left.body.quality_left_strength
    }

    fn right_strength(&self) -> EvidenceStrength {
        self.right.body.quality_right_strength
    }
}

#[cfg(test)]
mod tests {
    use super::SyncContract;
    use crate::decision::{DecisionBody, DecisionRecord, DecisionStatus};
    use crate::quality::{resolve_quality_divergence, EvidenceStrength};
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_record(tag: &str, strength: EvidenceStrength) -> DecisionRecord {
        let body = DecisionBody {
            decision_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, format!("decision-{tag}").as_bytes()),
            run_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, format!("run-{tag}").as_bytes()),
            created_at_utc: Utc::now(),
            status: DecisionStatus::Ok,
            reason_code: format!("REASON_{tag}"),
            message: format!("message {tag}"),
            state_hash: format!("state_hash_{tag}"),
            quality_left_strength: strength,
            quality_right_strength: strength,
            quality_report: resolve_quality_divergence(strength, strength),
        };

        DecisionRecord::new(body).expect("decision record")
    }

    #[test]
    fn resolve_left_wins() {
        let contract = SyncContract::new(
            sample_record("left", EvidenceStrength::Signed),
            sample_record("right", EvidenceStrength::Local),
        );

        let report = contract.resolve();

        assert_eq!(report.chosen_side, "left");
        assert_eq!(report.reason_code, "LEFT_STRONGER");
    }

    #[test]
    fn resolve_right_wins() {
        let contract = SyncContract::new(
            sample_record("left", EvidenceStrength::Local),
            sample_record("right", EvidenceStrength::Signed),
        );

        let report = contract.resolve();

        assert_eq!(report.chosen_side, "right");
        assert_eq!(report.reason_code, "RIGHT_STRONGER");
    }

    #[test]
    fn resolve_tie() {
        let contract = SyncContract::new(
            sample_record("left", EvidenceStrength::Witnessed),
            sample_record("right", EvidenceStrength::Witnessed),
        );

        let report = contract.resolve();

        assert_eq!(report.chosen_side, "tie");
        assert_eq!(report.reason_code, "EQUAL_STRENGTH");
    }
}
