use crate::network::epa::SharedEPA;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerifyResult {
    Valid,
    InvalidIntegrity,
    InvalidSignature,
    MissingData,
}

impl fmt::Display for VerifyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyResult::Valid => write!(f, "VALID"),
            VerifyResult::InvalidIntegrity => write!(f, "INVALID_INTEGRITY"),
            VerifyResult::InvalidSignature => write!(f, "INVALID_SIGNATURE"),
            VerifyResult::MissingData => write!(f, "MISSING_DATA"),
        }
    }
}

pub fn verify_epa(
    epa: &SharedEPA,
    state_json: Option<&str>,
    evidence_jsonl: Option<&str>,
    decisions_jsonl: Option<&str>,
    manifest_json: Option<&str>,
    public_key: Option<&str>,
) -> VerifyResult {
    if state_json.is_none()
        || evidence_jsonl.is_none()
        || decisions_jsonl.is_none()
        || manifest_json.is_none()
    {
        return VerifyResult::MissingData;
    }

    if !epa.verify_integrity() {
        return VerifyResult::InvalidIntegrity;
    }

    if let Some(key) = public_key {
        if !epa.verify_signature(key) {
            return VerifyResult::InvalidSignature;
        }
    }

    VerifyResult::Valid
}

pub fn verify_hashes_match(
    epa: &SharedEPA,
    state_json: &str,
    evidence_jsonl: &str,
    decisions_jsonl: &str,
    manifest_json: &str,
) -> bool {
    use crate::hash::canonical_hash;

    let state_hash = canonical_hash(state_json);
    let evidence_hash = canonical_hash(evidence_jsonl);
    let decision_hash = canonical_hash(decisions_jsonl);
    let manifest_hash = canonical_hash(manifest_json);

    epa.state_hash == state_hash
        && epa.evidence_hash == evidence_hash
        && epa.decision_hash == decision_hash
        && epa.manifest_hash == manifest_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::identity::NodeIdentity;

    fn sample_epa() -> (SharedEPA, String, String, String, String, String) {
        let node = NodeIdentity::generate("verifier_test");
        let state = r#"{"project":"test"}"#.to_string();
        let evidence = r#"{"evidence":"data"}"#.to_string();
        let decision = r#"{"decision":"ok"}"#.to_string();
        let manifest = r#"{"manifest":"v1"}"#.to_string();

        let epa = SharedEPA::create(&node, &state, &evidence, &decision, &manifest);
        (epa, state, evidence, decision, manifest, node.public_key)
    }

    #[test]
    fn verify_valid_epa() {
        let (epa, state, evidence, decision, manifest, public_key) = sample_epa();
        let result = verify_epa(
            &epa,
            Some(&state),
            Some(&evidence),
            Some(&decision),
            Some(&manifest),
            Some(&public_key),
        );
        assert!(matches!(result, VerifyResult::Valid));
    }

    #[test]
    fn verify_missing_data() {
        let (epa, _, _, _, _, _) = sample_epa();
        let result = verify_epa(&epa, None, None, None, None, None);
        assert!(matches!(result, VerifyResult::MissingData));
    }

    #[test]
    fn test_verify_hashes_match() {
        let (epa, state, evidence, decision, manifest, _) = sample_epa();
        assert!(verify_hashes_match(
            &epa, &state, &evidence, &decision, &manifest
        ));
    }

    #[test]
    fn test_verify_hashes_dont_match() {
        let (epa, _, _, _, _, _) = sample_epa();
        assert!(!verify_hashes_match(
            &epa, "wrong", "wrong", "wrong", "wrong"
        ));
    }
}
