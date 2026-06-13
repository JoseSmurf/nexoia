use crate::decision::{DecisionRecord, DecisionStatus};
use crate::hash::canonical_hash;
use crate::state::State;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceKind {
    StateSnapshot,
    DecisionAttestation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBody {
    pub evidence_id: Uuid,
    pub run_id: Uuid,
    pub recorded_at_utc: DateTime<Utc>,
    pub kind: EvidenceKind,
    pub subject: String,
    pub status: DecisionStatus,
    pub reason_code: String,
    pub message: String,
    pub state_hash: String,
    pub decision_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    #[serde(flatten)]
    pub body: EvidenceBody,
    pub hash: String,
}

impl EvidenceBody {
    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn hash(&self) -> Result<String, serde_json::Error> {
        Ok(canonical_hash(&self.canonical_json()?))
    }
}

impl EvidenceRecord {
    pub fn new(body: EvidenceBody) -> Result<Self, serde_json::Error> {
        let hash = body.hash()?;
        Ok(Self { body, hash })
    }
}

pub fn build_records(
    state: &State,
    decision: &DecisionRecord,
) -> Result<Vec<EvidenceRecord>, serde_json::Error> {
    let snapshot_body = EvidenceBody {
        evidence_id: Uuid::new_v5(&state.run_id, b"state_snapshot"),
        run_id: state.run_id,
        recorded_at_utc: state.generated_at_utc,
        kind: EvidenceKind::StateSnapshot,
        subject: state.subject.clone(),
        status: decision.body.status,
        reason_code: decision.body.reason_code.clone(),
        message: decision.body.message.clone(),
        state_hash: decision.body.state_hash.clone(),
        decision_hash: decision.hash.clone(),
    };

    let attestation_body = EvidenceBody {
        evidence_id: Uuid::new_v5(&state.run_id, b"decision_attestation"),
        run_id: state.run_id,
        recorded_at_utc: decision.body.created_at_utc,
        kind: EvidenceKind::DecisionAttestation,
        subject: state.subject.clone(),
        status: decision.body.status,
        reason_code: decision.body.reason_code.clone(),
        message: decision.body.message.clone(),
        state_hash: decision.body.state_hash.clone(),
        decision_hash: decision.hash.clone(),
    };

    Ok(vec![
        EvidenceRecord::new(snapshot_body)?,
        EvidenceRecord::new(attestation_body)?,
    ])
}

#[cfg(test)]
mod tests {
    use super::{build_records, EvidenceBody, EvidenceKind};
    use crate::decision::evaluate;
    use crate::state::{Scenario, State};
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_state() -> State {
        State {
            project: "nexoia".to_string(),
            run_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, b"nexoia-evidence"),
            generated_at_utc: Utc::now(),
            scenario: Scenario::Ok,
            subject: "subject".to_string(),
            threshold: 50,
            input_value: Some(60),
        }
    }

    #[test]
    fn evidence_body_hash_is_present() {
        let body = EvidenceBody {
            evidence_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, b"nexoia-evidence-body"),
            run_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, b"nexoia-evidence-run"),
            recorded_at_utc: Utc::now(),
            kind: EvidenceKind::StateSnapshot,
            subject: "subject".to_string(),
            status: crate::decision::DecisionStatus::Ok,
            reason_code: "THRESHOLD_MET".to_string(),
            message: "ok".to_string(),
            state_hash: "state_hash".to_string(),
            decision_hash: "decision_hash".to_string(),
        };
        assert!(!body.hash().expect("hash").is_empty());
    }

    #[test]
    fn build_records_creates_two_evidence_lines() {
        let state = sample_state();
        let decision =
            evaluate(&state, "state_hash".to_string(), "signed", "local").expect("decision");
        let records = build_records(&state, &decision).expect("records");
        assert_eq!(records.len(), 2);
        assert!(!records[0].hash.is_empty());
        assert!(!records[1].hash.is_empty());
    }
}
