use crate::hash::canonical_hash;
use crate::quality::{evaluate as quality_evaluate, EvidenceStrength, ResolutionReport};
use crate::state::{Scenario, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionStatus {
    Ok,
    Violacao,
    Absterse,
}

impl DecisionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Violacao => "VIOLACAO",
            Self::Absterse => "ABSTERSE",
        }
    }
}

impl fmt::Display for DecisionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionBody {
    pub decision_id: Uuid,
    pub run_id: Uuid,
    pub created_at_utc: DateTime<Utc>,
    pub status: DecisionStatus,
    pub reason_code: String,
    pub message: String,
    pub state_hash: String,
    pub quality_left_strength: EvidenceStrength,
    pub quality_right_strength: EvidenceStrength,
    pub quality_report: ResolutionReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    #[serde(flatten)]
    pub body: DecisionBody,
    pub hash: String,
}

impl DecisionBody {
    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn hash(&self) -> Result<String, serde_json::Error> {
        Ok(canonical_hash(&self.canonical_json()?))
    }
}

impl DecisionRecord {
    pub fn new(body: DecisionBody) -> Result<Self, serde_json::Error> {
        let hash = body.hash()?;
        Ok(Self { body, hash })
    }
}

pub fn evaluate(
    state: &State,
    state_hash: String,
    left_kind: &str,
    right_kind: &str,
) -> Result<DecisionRecord, serde_json::Error> {
    let created_at_utc = Utc::now();
    let decision_id = Uuid::new_v5(&state.run_id, b"decision");
    let (status, reason_code, message) = classify(state);
    let left_strength = quality_evaluate(&state_hash, left_kind);
    let right_strength = quality_evaluate(&state_hash, right_kind);
    let quality_report = crate::quality::resolve_quality_divergence(left_strength, right_strength);
    let body = DecisionBody {
        decision_id,
        run_id: state.run_id,
        created_at_utc,
        status,
        reason_code,
        message,
        state_hash,
        quality_left_strength: left_strength,
        quality_right_strength: right_strength,
        quality_report,
    };
    DecisionRecord::new(body)
}

fn classify(state: &State) -> (DecisionStatus, String, String) {
    match state.scenario {
        Scenario::Ok => (
            DecisionStatus::Ok,
            "SCENARIO_OK".to_string(),
            "scenario override requested an OK result".to_string(),
        ),
        Scenario::Violacao => (
            DecisionStatus::Violacao,
            "SCENARIO_VIOLACAO".to_string(),
            "scenario override requested a VIOLACAO result".to_string(),
        ),
        Scenario::Absterse => (
            DecisionStatus::Absterse,
            "SCENARIO_ABSTERSE".to_string(),
            "scenario override requested an ABSTERSE result".to_string(),
        ),
        Scenario::Auto => match state.input_value {
            None => (
                DecisionStatus::Absterse,
                "MISSING_INPUT_VALUE".to_string(),
                "no input_value was provided, so the system abstains".to_string(),
            ),
            Some(value) if value >= state.threshold => (
                DecisionStatus::Ok,
                "THRESHOLD_MET".to_string(),
                format!("input_value {value} met threshold {}", state.threshold),
            ),
            Some(value) => (
                DecisionStatus::Violacao,
                "THRESHOLD_BREACH".to_string(),
                format!("input_value {value} is below threshold {}", state.threshold),
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, evaluate, DecisionStatus};
    use crate::state::{Scenario, State};
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_state(scenario: Scenario, input_value: Option<i64>) -> State {
        State {
            project: "nexoia".to_string(),
            run_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, b"nexoia-test"),
            generated_at_utc: Utc::now(),
            scenario,
            subject: "subject".to_string(),
            threshold: 50,
            input_value,
        }
    }

    #[test]
    fn classify_auto_ok() {
        let state = sample_state(Scenario::Auto, Some(60));
        let (status, reason_code, _) = classify(&state);
        assert_eq!(status, DecisionStatus::Ok);
        assert_eq!(reason_code, "THRESHOLD_MET");
    }

    #[test]
    fn classify_auto_violacao() {
        let state = sample_state(Scenario::Auto, Some(10));
        let (status, reason_code, _) = classify(&state);
        assert_eq!(status, DecisionStatus::Violacao);
        assert_eq!(reason_code, "THRESHOLD_BREACH");
    }

    #[test]
    fn classify_absterse() {
        let state = sample_state(Scenario::Absterse, None);
        let (status, reason_code, _) = classify(&state);
        assert_eq!(status, DecisionStatus::Absterse);
        assert_eq!(reason_code, "SCENARIO_ABSTERSE");
    }

    #[test]
    fn evaluate_uses_dynamic_kinds_signed_vs_local() {
        let state = sample_state(Scenario::Ok, Some(60));
        let decision =
            evaluate(&state, "state_hash".to_string(), "signed", "local").expect("decision");
        assert!(!decision.hash.is_empty());
        assert_eq!(decision.body.status, DecisionStatus::Ok);
        assert_eq!(
            decision.body.quality_left_strength,
            crate::quality::EvidenceStrength::Signed
        );
        assert_eq!(
            decision.body.quality_right_strength,
            crate::quality::EvidenceStrength::Local
        );
        assert!(!decision.body.quality_report.resolution_hash.is_empty());
    }

    #[test]
    fn evaluate_uses_dynamic_kinds_witness_vs_anchored() {
        let state = sample_state(Scenario::Ok, Some(60));
        let decision =
            evaluate(&state, "state_hash".to_string(), "witness", "anchored").expect("decision");
        assert_eq!(
            decision.body.quality_left_strength,
            crate::quality::EvidenceStrength::Witnessed
        );
        assert_eq!(
            decision.body.quality_right_strength,
            crate::quality::EvidenceStrength::Anchored
        );
        assert_eq!(decision.body.quality_report.chosen_side, "right");
        assert_eq!(decision.body.quality_report.reason_code, "RIGHT_STRONGER");
    }

    #[test]
    fn evaluate_uses_dynamic_kinds_tie_on_equal_strength() {
        let state = sample_state(Scenario::Ok, Some(60));
        let decision =
            evaluate(&state, "state_hash".to_string(), "signed", "signed").expect("decision");
        assert_eq!(decision.body.quality_report.chosen_side, "tie");
        assert_eq!(decision.body.quality_report.reason_code, "EQUAL_STRENGTH");
        assert_eq!(
            decision.body.quality_left_strength,
            crate::quality::EvidenceStrength::Signed
        );
        assert_eq!(
            decision.body.quality_right_strength,
            crate::quality::EvidenceStrength::Signed
        );
    }
}
