use crate::network::epa::{SharedEPA, VerifyError};
use crate::network::identity;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerifyResult {
    Valid,
    InvalidIntegrity,
    InvalidSignature,
    TimestampExpired,
    TimestampTooNew,
    MissingData,
}

impl fmt::Display for VerifyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyResult::Valid => write!(f, "VALID"),
            VerifyResult::InvalidIntegrity => write!(f, "INVALID_INTEGRITY"),
            VerifyResult::InvalidSignature => write!(f, "INVALID_SIGNATURE"),
            VerifyResult::TimestampExpired => write!(f, "TIMESTAMP_EXPIRED"),
            VerifyResult::TimestampTooNew => write!(f, "TIMESTAMP_TOO_NEW"),
            VerifyResult::MissingData => write!(f, "MISSING_DATA"),
        }
    }
}

/// Verifica EPA completo: integridade + assinatura Ed25519 + timestamp.
pub fn verify_epa(epa: &SharedEPA) -> VerifyResult {
    match epa.verify_full() {
        Ok(()) => VerifyResult::Valid,
        Err(VerifyError::IntegrityFailed) => VerifyResult::InvalidIntegrity,
        Err(VerifyError::SignatureFailed) => VerifyResult::InvalidSignature,
        Err(VerifyError::TimestampExpired) => VerifyResult::TimestampExpired,
        Err(VerifyError::TimestampTooNew) => VerifyResult::TimestampTooNew,
        Err(VerifyError::TimestampInvalid) => VerifyResult::InvalidIntegrity,
        Err(VerifyError::MissingPublicKey) => VerifyResult::InvalidSignature,
    }
}

/// Verifica apenas a assinatura Ed25519 (para testes).
pub fn verify_signature_only(public_key_hex: &str, data: &[u8], signature: &[u8]) -> bool {
    identity::verify_signature(public_key_hex, data, signature).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::identity::NodeIdentity;

    #[test]
    fn verify_valid_epa() {
        let node = NodeIdentity::generate("verifier_test");
        let state = r#"{"project":"test"}"#;
        let evidence = r#"{"evidence":"data"}"#;
        let decision = r#"{"decision":"ok"}"#;
        let manifest = r#"{"manifest":"v1"}"#;

        let epa = SharedEPA::create(&node, state, evidence, decision, manifest);
        let result = verify_epa(&epa);
        assert!(matches!(result, VerifyResult::Valid));
    }

    #[test]
    fn verify_tampered_epa() {
        let node = NodeIdentity::generate("verifier_test");
        let (state, evidence, decision, manifest) = (
            r#"{"project":"test"}"#.to_string(),
            r#"{"evidence":"data"}"#.to_string(),
            r#"{"decision":"ok"}"#.to_string(),
            r#"{"manifest":"v1"}"#.to_string(),
        );

        let mut epa = SharedEPA::create(&node, &state, &evidence, &decision, &manifest);
        epa.state_hash = "tampered".to_string();

        let result = verify_epa(&epa);
        assert!(matches!(result, VerifyResult::InvalidIntegrity));
    }
}
