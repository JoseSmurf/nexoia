#[cfg(test)]
mod integration_tests {
    use nexoia::ai::{AIError, EvidenceEngine};
    use nexoia::defense::{validate_raw_input, RateLimiter};
    use nexoia::types::{EvidenceProvider, EvidenceStrength};
    use std::time::Duration;

    #[test]
    fn pipeline_end_to_end_anchored() {
        let limiter = RateLimiter::new(100, Duration::from_secs(60));
        let engine = EvidenceEngine::new(0.30);

        let raw = serde_json::json!({
            "project": "nexoia",
            "run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "generated_at_utc": "2026-06-29T12:00:00Z",
            "scenario": "AUTO",
            "subject": "compliance-check",
            "threshold": 50,
            "input_value": 80,
            "lgpd": {
                "lawful_basis": "consentimento",
                "purpose": "processamento de pedidos do cliente",
                "retention_days": 365,
                "data_subject_hash": "abc123",
                "consent_id": "consent_001",
                "dpia_ref": "dpia-2026-001"
            }
        })
        .to_string();

        assert!(validate_raw_input(&raw, 1_048_576).is_ok());
        assert!(limiter.check("nexoia"));

        let assertion = engine.translate(&raw, 1_048_576).unwrap();
        assert!(
            assertion.evidence_strength >= EvidenceStrength::Signed,
            "Expected Signed or higher with full LGPD metadata, got {}",
            assertion.evidence_strength
        );
        assert!(assertion.confidence >= 0.55);
    }

    #[test]
    fn pipeline_end_to_end_signed() {
        let engine = EvidenceEngine::new(0.30);

        let raw = serde_json::json!({
            "project": "nexoia",
            "run_id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
            "generated_at_utc": "2026-06-29T12:00:00Z",
            "scenario": "AUTO",
            "subject": "test",
            "threshold": 50,
            "input_value": 60,
            "lgpd": {
                "lawful_basis": "contrato",
                "purpose": "execucao de contrato",
                "retention_days": 365,
                "data_subject_hash": "hash456"
            }
        })
        .to_string();

        let assertion = engine.translate(&raw, 1_048_576).unwrap();
        assert!(
            assertion.evidence_strength >= EvidenceStrength::Witnessed,
            "Expected Witnessed or higher with LGPD, got {}",
            assertion.evidence_strength
        );
    }

    #[test]
    fn pipeline_end_to_end_low_confidence() {
        let engine = EvidenceEngine::new(0.50);

        let raw = serde_json::json!({
            "project": "nexoia",
            "run_id": "00000000-0000-0000-0000-000000000000",
            "generated_at_utc": "invalid",
            "scenario": "AUTO",
            "subject": "test",
            "threshold": 0,
            "input_value": null
        })
        .to_string();

        let assertion = engine.translate(&raw, 1_048_576).unwrap();
        assert_eq!(assertion.evidence_strength, EvidenceStrength::Unverifiable);
        assert!(assertion.confidence < 0.50);
    }

    #[test]
    fn defense_rejects_empty_input() {
        assert!(validate_raw_input("", 1_048_576).is_err());
    }

    #[test]
    fn defense_rejects_oversized_input() {
        let big = "x".repeat(2_000_000);
        assert!(validate_raw_input(&big, 1_048_576).is_err());
    }

    #[test]
    fn defense_rejects_null_bytes() {
        let bad = "hello\x00world";
        assert!(validate_raw_input(bad, 1_048_576).is_err());
    }

    #[test]
    fn ai_rejects_empty_input() {
        let engine = EvidenceEngine::new(0.70);
        let result = engine.translate("", 1_048_576);
        assert!(matches!(result, Err(AIError::InputValidationError(_))));
    }

    #[test]
    fn ai_rejects_invalid_json() {
        let engine = EvidenceEngine::new(0.70);
        let result = engine.translate("not valid json", 1_048_576);
        assert!(matches!(result, Err(AIError::InvalidJson(_))));
    }

    #[test]
    fn rate_limiter_blocks_after_limit() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));

        assert!(limiter.check("source_a"));
        assert!(limiter.check("source_a"));
        assert!(!limiter.check("source_a"));
    }

    #[test]
    fn rate_limiter_allows_different_sources() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));

        assert!(limiter.check("source_a"));
        assert!(limiter.check("source_b"));
        assert!(!limiter.check("source_a"));
    }
}
