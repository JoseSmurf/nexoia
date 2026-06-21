#[cfg(test)]
mod integration_tests {
    use nexoia::ai::{AIError, MockEngine};
    use nexoia::defense::{validate_raw_input, RateLimiter};
    use nexoia::types::{EvidenceProvider, EvidenceStrength};
    use std::time::Duration;

    #[test]
    fn pipeline_end_to_end_anchored() {
        let limiter = RateLimiter::new(100, Duration::from_secs(60));
        let engine = MockEngine::new(0.70);

        let raw = r#"{"subject":"nexoia","scenario":"anchored","value":42}"#;

        assert!(validate_raw_input(raw, 1_048_576).is_ok());
        assert!(limiter.check("nexoia"));

        let assertion = engine.translate(raw, 1_048_576).unwrap();
        assert_eq!(assertion.evidence_strength, EvidenceStrength::Anchored);
        assert!(assertion.confidence >= 0.90);
    }

    #[test]
    fn pipeline_end_to_end_signed() {
        let engine = MockEngine::new(0.70);

        let raw = r#"{"subject":"test","scenario":"signed","value":10}"#;

        let assertion = engine.translate(raw, 1_048_576).unwrap();
        assert_eq!(assertion.evidence_strength, EvidenceStrength::Signed);
        assert!(assertion.confidence >= 0.75);
    }

    #[test]
    fn pipeline_end_to_end_low_confidence() {
        let engine = MockEngine::new(0.70);

        let raw = r#"{"subject":"unknown","scenario":"unknown","value":0}"#;

        let assertion = engine.translate(raw, 1_048_576).unwrap();
        assert_eq!(assertion.evidence_strength, EvidenceStrength::Unverifiable);
        assert!(assertion.confidence < 0.70);
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
    fn ai_rejects_invalid_input() {
        let engine = MockEngine::new(0.70);
        let result = engine.translate("", 1_048_576);
        assert!(matches!(result, Err(AIError::InputValidationError(_))));
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
