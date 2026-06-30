#[cfg(test)]
mod verify_chain_tests {
    use chrono::{DateTime, Utc};
    use nexoia::ai::EvidenceEngine;
    use nexoia::decision::{DecisionBody, DecisionRecord, DecisionStatus};
    use nexoia::defense::validate_raw_input;
    use nexoia::evidence::{EvidenceBody, EvidenceKind, EvidenceRecord};
    use nexoia::hash::canonical_hash;
    use nexoia::quality::resolve_quality_divergence;
    use nexoia::types::{EvidenceProvider, EvidenceStrength};
    use std::fs;
    use tempfile::tempdir;
    use uuid::Uuid;

    fn build_state_json(run_id: Uuid) -> String {
        serde_json::json!({
            "project": "nexoia",
            "run_id": run_id,
            "generated_at_utc": "2026-06-29T12:00:00Z",
            "scenario": "AUTO",
            "subject": "compliance-check",
            "threshold": 50,
            "input_value": 80,
            "lgpd": {
                "lawful_basis": "consentimento",
                "purpose": "processamento de pedidos do cliente",
                "retention_days": 365,
                "data_subject_hash": "abc123def456",
                "consent_id": "consent_001",
                "dpia_ref": "dpia-2026-001"
            }
        })
        .to_string()
    }

    fn build_decision(run_id: Uuid, state_hash: &str) -> DecisionRecord {
        let body = DecisionBody {
            decision_id: Uuid::new_v5(&run_id, b"decision"),
            run_id,
            created_at_utc: DateTime::parse_from_rfc3339("2026-06-29T12:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            status: DecisionStatus::Ok,
            reason_code: "MULTIFACTOR_OK".to_string(),
            message: "decision score 30.0".to_string(),
            state_hash: state_hash.to_string(),
            quality_left_strength: EvidenceStrength::Signed,
            quality_right_strength: EvidenceStrength::Local,
            quality_report: resolve_quality_divergence(
                EvidenceStrength::Signed,
                EvidenceStrength::Local,
            ),
        };
        DecisionRecord::new(body).expect("decision record")
    }

    fn build_evidence(run_id: Uuid, decision_hash: &str) -> Vec<EvidenceRecord> {
        let snapshot = EvidenceBody {
            evidence_id: Uuid::new_v5(&run_id, b"state_snapshot"),
            run_id,
            recorded_at_utc: DateTime::parse_from_rfc3339("2026-06-29T12:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            kind: EvidenceKind::StateSnapshot,
            subject: "compliance-check".to_string(),
            status: DecisionStatus::Ok,
            reason_code: "MULTIFACTOR_OK".to_string(),
            message: "decision score 30.0".to_string(),
            state_hash: "state_hash".to_string(),
            decision_hash: decision_hash.to_string(),
        };
        let attestation = EvidenceBody {
            evidence_id: Uuid::new_v5(&run_id, b"decision_attestation"),
            run_id,
            recorded_at_utc: DateTime::parse_from_rfc3339("2026-06-29T12:00:01Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            kind: EvidenceKind::DecisionAttestation,
            subject: "compliance-check".to_string(),
            status: DecisionStatus::Ok,
            reason_code: "MULTIFACTOR_OK".to_string(),
            message: "decision score 30.0".to_string(),
            state_hash: "state_hash".to_string(),
            decision_hash: decision_hash.to_string(),
        };
        vec![
            EvidenceRecord::new(snapshot).expect("evidence"),
            EvidenceRecord::new(attestation).expect("evidence"),
        ]
    }

    fn build_manifest(
        run_id: Uuid,
        state_json: &str,
        evidence_jsonl: &str,
        decisions_jsonl: &str,
    ) -> String {
        serde_json::json!({
            "project": "nexoia",
            "run_id": run_id,
            "generated_at_utc": "2026-06-29T12:00:00Z",
            "status": "OK",
            "reason_code": "MULTIFACTOR_OK",
            "message": "decision score 30.0",
            "artifacts": [
                {
                    "path": "state.json",
                    "hash": canonical_hash(state_json),
                    "bytes": state_json.len(),
                },
                {
                    "path": "evidence.jsonl",
                    "hash": canonical_hash(evidence_jsonl),
                    "bytes": evidence_jsonl.len(),
                },
                {
                    "path": "decisions.jsonl",
                    "hash": canonical_hash(decisions_jsonl),
                    "bytes": decisions_jsonl.len(),
                }
            ]
        })
        .to_string()
    }

    fn to_jsonl<T: serde::Serialize>(items: &[T]) -> String {
        items
            .iter()
            .map(|item| serde_json::to_string(item).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn full_pipeline_to_verify_chain_proves_valid_evidence() {
        let dir = tempdir().expect("tempdir");
        let run_id = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"e2e-verify-chain");

        // 1. Build state
        let state_json = build_state_json(run_id);
        assert!(validate_raw_input(&state_json, 1_048_576).is_ok());

        // 2. Score with EvidenceEngine
        let engine = EvidenceEngine::new(0.30);
        let assertion = engine.translate(&state_json, 1_048_576).unwrap();
        assert!(
            assertion.evidence_strength >= EvidenceStrength::Signed,
            "Expected Signed or higher with full LGPD, got {}",
            assertion.evidence_strength
        );

        // 3. Build decision
        let state_hash = canonical_hash(&state_json);
        let decision = build_decision(run_id, &state_hash);

        // 4. Build evidence chain
        let evidence = build_evidence(run_id, &decision.hash);
        let evidence_jsonl = to_jsonl(&evidence);
        let decisions_jsonl = to_jsonl(&[decision]);

        // 5. Build manifest
        let manifest_json = build_manifest(run_id, &state_json, &evidence_jsonl, &decisions_jsonl);

        // 6. Write all artifacts
        fs::write(dir.path().join("state.json"), &state_json).unwrap();
        fs::write(dir.path().join("evidence.jsonl"), &evidence_jsonl).unwrap();
        fs::write(dir.path().join("decisions.jsonl"), &decisions_jsonl).unwrap();
        fs::write(dir.path().join("manifest.json"), &manifest_json).unwrap();

        // 7. Verify the chain — THE MOMENT OF TRUTH
        let report = nexoia::provenance::verify::run(dir.path()).expect("chain verification");

        assert_eq!(report.entries.len(), 1, "should have one decision entry");
        assert!(
            report.entries[0].valid,
            "chain should be VALID — reason: {} — {}",
            report.entries[0].reason_code, report.entries[0].message
        );
        assert_eq!(report.entries[0].reason_code, "VERIFIED");
        assert!(
            report.entries[0].recomputed_strength >= EvidenceStrength::Signed,
            "recomputed strength should be Signed or higher, got {}",
            report.entries[0].recomputed_strength
        );
    }

    #[test]
    fn tampered_state_fails_chain_verification() {
        let dir = tempdir().expect("tempdir");
        let run_id = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"e2e-tampered");

        let state_json = build_state_json(run_id);
        let state_hash = canonical_hash(&state_json);
        let decision = build_decision(run_id, &state_hash);
        let evidence = build_evidence(run_id, &decision.hash);
        let evidence_jsonl = to_jsonl(&evidence);
        let decisions_jsonl = to_jsonl(&[decision]);
        let manifest_json = build_manifest(run_id, &state_json, &evidence_jsonl, &decisions_jsonl);

        // Write artifacts BUT tamper with state.json
        let tampered_state = state_json.replace("80", "999");
        fs::write(dir.path().join("state.json"), &tampered_state).unwrap();
        fs::write(dir.path().join("evidence.jsonl"), &evidence_jsonl).unwrap();
        fs::write(dir.path().join("decisions.jsonl"), &decisions_jsonl).unwrap();
        fs::write(dir.path().join("manifest.json"), &manifest_json).unwrap();

        // Verify should FAIL because manifest hash doesn't match tampered state
        let result = nexoia::provenance::verify::run(dir.path());
        assert!(result.is_err(), "tampered state should fail verification");
    }

    #[test]
    fn missing_evidence_fails_chain_verification() {
        let dir = tempdir().expect("tempdir");
        let run_id = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"e2e-no-evidence");

        let state_json = build_state_json(run_id);
        let state_hash = canonical_hash(&state_json);
        let decision = build_decision(run_id, &state_hash);
        let evidence = build_evidence(run_id, &decision.hash);
        let evidence_jsonl = to_jsonl(&evidence);
        let decisions_jsonl = to_jsonl(&[decision]);
        let manifest_json = build_manifest(run_id, &state_json, &evidence_jsonl, &decisions_jsonl);

        // Write manifest + decisions but NOT evidence
        fs::write(dir.path().join("state.json"), &state_json).unwrap();
        fs::write(dir.path().join("decisions.jsonl"), &decisions_jsonl).unwrap();
        fs::write(dir.path().join("manifest.json"), &manifest_json).unwrap();

        let report = nexoia::provenance::verify::run(dir.path()).expect("verify should not error");
        assert_eq!(report.entries.len(), 1);
        assert!(!report.entries[0].valid);
        assert_eq!(report.entries[0].reason_code, "NO_EVIDENCE");
    }

    #[test]
    fn witness_attestation_upgrades_compliance() {
        use nexoia::provenance::witness::{Witness, WitnessKind, WitnessSet};
        use nexoia::provenance::TypedNode;

        let node_id = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, b"witness-test");
        let signed = TypedNode::new(node_id, "payload".to_owned());

        // Without witnesses — cannot attest
        let empty_set = WitnessSet::new();
        assert!(empty_set.attest(signed.clone()).is_err());

        // With 2 witnesses including external ledger — attestation succeeds
        let mut set = WitnessSet::new();
        set.add(Witness {
            witness_id: uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, b"w1"),
            witnessed_at_utc: chrono::Utc::now(),
            kind: WitnessKind::CrossReferencedInExternalLedger,
        });
        set.add(Witness {
            witness_id: uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, b"w2"),
            witnessed_at_utc: chrono::Utc::now(),
            kind: WitnessKind::Cosigned,
        });

        let anchored = set.attest(signed).expect("attestation should succeed");
        assert_eq!(anchored.node_id, node_id);
    }
}
