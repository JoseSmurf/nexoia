use crate::hash::canonical_hash;
use crate::quality::{evaluate as quality_evaluate, ResolutionReport};
use crate::state::{Scenario, State};
use crate::types::EvidenceStrength;
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
        Scenario::Auto => classify_auto(state),
    }
}

fn classify_auto(state: &State) -> (DecisionStatus, String, String) {
    let input_value = match state.input_value {
        None => {
            return (
                DecisionStatus::Absterse,
                "MISSING_INPUT_VALUE".to_string(),
                "no input_value was provided, so the system abstains".to_string(),
            );
        }
        Some(v) => v,
    };

    let mut score = DecisionScore::new();

    // Fator 1: Threshold comparison (peso principal)
    let margin = input_value - state.threshold;
    let margin_pct = if state.threshold != 0 {
        (margin as f64 / state.threshold as f64) * 100.0
    } else {
        if input_value > 0 {
            100.0
        } else {
            0.0
        }
    };

    if margin >= 0 {
        // Base 25 (suficiente para OK) + bônus proporcional
        let bonus = (margin_pct / 10.0).min(10.0);
        score.add_positive(
            25.0 + bonus,
            format!(
                "input_value {input_value} meets threshold {} (margin: {margin}, {margin_pct:.1}%)",
                state.threshold
            ),
        );
    } else {
        score.add_negative(
            margin_pct.abs().min(100.0),
            format!(
            "input_value {input_value} below threshold {} (deficit: {margin}, {margin_pct:.1}%)",
            state.threshold
        ),
        );
    }

    // Fator 2: LGPD compliance
    if let Some(ref lgpd) = state.lgpd {
        match lgpd.validate() {
            Ok(()) => {
                score.add_positive(15.0, "LGPD metadata is valid".to_string());
                if lgpd.data_subject_hash.is_some() {
                    score.add_positive(5.0, "data subject identified".to_string());
                }
                if lgpd.consent_id.is_some() {
                    score.add_positive(5.0, "consent documented".to_string());
                }
            }
            Err(e) => {
                score.add_negative(20.0, format!("LGPD metadata invalid: {}", e));
            }
        }
    }

    // Fator 3: Threshold quality (threshold muito baixo = suspeito)
    if state.threshold <= 0 {
        score.add_negative(10.0, "threshold is zero or negative".to_string());
    }

    score.resolve()
}

/// Score multifator para decisões.
struct DecisionScore {
    positive: f64,
    negative: f64,
    positive_reasons: Vec<String>,
    negative_reasons: Vec<String>,
}

impl DecisionScore {
    fn new() -> Self {
        Self {
            positive: 0.0,
            negative: 0.0,
            positive_reasons: Vec::new(),
            negative_reasons: Vec::new(),
        }
    }

    fn add_positive(&mut self, weight: f64, reason: String) {
        self.positive += weight;
        self.positive_reasons.push(reason);
    }

    fn add_negative(&mut self, weight: f64, reason: String) {
        self.negative += weight;
        self.negative_reasons.push(reason);
    }

    fn resolve(self) -> (DecisionStatus, String, String) {
        let net = self.positive - self.negative;

        // Thresholds calibrados:
        //   OK       >= 25  (threshold met + optional LGPD boost)
        //   Violacao <= -10 (threshold breach or critical LGPD failure)
        //   Absterse       (inconclusive / borderline)
        if net >= 25.0 {
            let reasons = self.positive_reasons.join("; ");
            (
                DecisionStatus::Ok,
                "MULTIFACTOR_OK".to_string(),
                format!("decision score {net:.1} (positive: {reasons})"),
            )
        } else if net <= -10.0 {
            let reasons = self.negative_reasons.join("; ");
            (
                DecisionStatus::Violacao,
                "MULTIFACTOR_VIOLACAO".to_string(),
                format!("decision score {net:.1} (negative: {reasons})"),
            )
        } else {
            let all = self
                .positive_reasons
                .iter()
                .chain(self.negative_reasons.iter())
                .cloned()
                .collect::<Vec<_>>()
                .join("; ");
            (
                DecisionStatus::Absterse,
                "MULTIFACTOR_INCONCLUSIVE".to_string(),
                format!("decision score {net:.1} — inconclusive ({all})"),
            )
        }
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
            lgpd: None,
        }
    }

    #[test]
    fn classify_auto_ok() {
        let state = sample_state(Scenario::Auto, Some(60));
        let (status, reason_code, _) = classify(&state);
        assert_eq!(status, DecisionStatus::Ok);
        assert_eq!(reason_code, "MULTIFACTOR_OK");
    }

    #[test]
    fn classify_auto_violacao() {
        let state = sample_state(Scenario::Auto, Some(10));
        let (status, reason_code, _) = classify(&state);
        assert_eq!(status, DecisionStatus::Violacao);
        assert_eq!(reason_code, "MULTIFACTOR_VIOLACAO");
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
            crate::types::EvidenceStrength::Signed
        );
        assert_eq!(
            decision.body.quality_right_strength,
            crate::types::EvidenceStrength::Local
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
            crate::types::EvidenceStrength::Witnessed
        );
        assert_eq!(
            decision.body.quality_right_strength,
            crate::types::EvidenceStrength::Anchored
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
            crate::types::EvidenceStrength::Signed
        );
        assert_eq!(
            decision.body.quality_right_strength,
            crate::types::EvidenceStrength::Signed
        );
    }

    #[test]
    fn classify_auto_multifactor_ok() {
        let mut state = sample_state(Scenario::Auto, Some(80));
        state.threshold = 50;
        let (status, reason_code, _) = classify(&state);
        assert_eq!(status, DecisionStatus::Ok);
        assert_eq!(reason_code, "MULTIFACTOR_OK");
    }

    #[test]
    fn classify_auto_multifactor_violacao() {
        let mut state = sample_state(Scenario::Auto, Some(10));
        state.threshold = 50;
        let (status, reason_code, _) = classify(&state);
        assert_eq!(status, DecisionStatus::Violacao);
        assert_eq!(reason_code, "MULTIFACTOR_VIOLACAO");
    }

    #[test]
    fn classify_auto_with_lgpd_boosts_score() {
        let mut state = sample_state(Scenario::Auto, Some(55));
        state.threshold = 50;
        state.lgpd = Some(crate::lgpd::LgpdMetadata {
            lawful_basis: crate::lgpd::LawfulBasis::Consentimento,
            purpose: "processamento de pedidos".to_string(),
            retention_days: 365,
            data_subject_hash: Some("hash123".to_string()),
            consent_id: Some("consent_001".to_string()),
            dpia_ref: None,
        });
        let (status, _, _) = classify(&state);
        assert_eq!(status, DecisionStatus::Ok);
    }

    #[test]
    fn classify_auto_invalid_lgpd_hurts_score() {
        let mut state = sample_state(Scenario::Auto, Some(55));
        state.threshold = 50;
        state.lgpd = Some(crate::lgpd::LgpdMetadata {
            lawful_basis: crate::lgpd::LawfulBasis::Consentimento,
            purpose: "".to_string(),
            retention_days: 0,
            data_subject_hash: None,
            consent_id: None,
            dpia_ref: None,
        });
        let (status, reason_code, _) = classify(&state);
        assert_eq!(status, DecisionStatus::Absterse);
        assert_eq!(reason_code, "MULTIFACTOR_INCONCLUSIVE");
    }

    #[test]
    fn classify_auto_borderline_with_lgpd_can_tip_to_ok() {
        let mut state = sample_state(Scenario::Auto, Some(53));
        state.threshold = 50;
        state.lgpd = Some(crate::lgpd::LgpdMetadata {
            lawful_basis: crate::lgpd::LawfulBasis::Contrato,
            purpose: "execucao de contrato comercial".to_string(),
            retention_days: 730,
            data_subject_hash: Some("hash456".to_string()),
            consent_id: None,
            dpia_ref: None,
        });
        // margin=3, margin_pct=6% → score 6 + 15 + 5 = 26 >= 25 → OK
        let (status, _, _) = classify(&state);
        assert_eq!(status, DecisionStatus::Ok);
    }
}
