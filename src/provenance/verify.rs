use crate::decision::DecisionStatus;
use crate::evidence::{EvidenceKind, EvidenceRecord};
use crate::hash::canonical_hash;
use crate::provenance::aggregator::{walk_provenance_chain, ProvenanceNode, ProvenanceRef};
use crate::types::EvidenceStrength;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyEntry {
    pub decision_id: Uuid,
    pub declared_strength: EvidenceStrength,
    pub recomputed_strength: EvidenceStrength,
    pub valid: bool,
    pub reason_code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyReport {
    pub entries: Vec<VerifyEntry>,
}

#[derive(Debug, Clone)]
pub struct VerifyError {
    message: String,
}

impl VerifyError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for VerifyError {}

#[derive(Debug, Clone, Deserialize)]
struct ArtifactSummary {
    path: String,
    hash: String,
    bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct QualityReportArtifact {
    chosen_side: String,
    reason_code: String,
    message: String,
    left_strength: EvidenceStrength,
    right_strength: EvidenceStrength,
    resolution_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
struct DecisionArtifact {
    decision_id: Uuid,
    run_id: Uuid,
    created_at_utc: DateTime<Utc>,
    status: DecisionStatus,
    reason_code: String,
    message: String,
    state_hash: String,
    #[serde(default)]
    quality_left_strength: Option<EvidenceStrength>,
    #[serde(default)]
    quality_right_strength: Option<EvidenceStrength>,
    #[serde(default)]
    quality_report: Option<QualityReportArtifact>,
    hash: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Manifest {
    project: String,
    run_id: Uuid,
    generated_at_utc: DateTime<Utc>,
    status: DecisionStatus,
    reason_code: String,
    message: String,
    artifacts: Vec<ArtifactSummary>,
}

pub fn verify_directory(root: impl AsRef<Path>) -> Result<VerifyReport, VerifyError> {
    let root = root.as_ref();
    let manifest = load_manifest(root)?;
    let decisions_text = read_required_text(&root.join("decisions.jsonl"))?;
    let decisions = parse_jsonl::<DecisionArtifact>(&decisions_text, "decisions.jsonl")?;
    let evidence_path = root.join("evidence.jsonl");
    let evidence_text = read_optional_text(&evidence_path)?;
    let evidence_records =
        parse_optional_jsonl::<EvidenceRecord>(&evidence_text, "evidence.jsonl")?;

    validate_manifest_artifact(&manifest, "decisions.jsonl", &decisions_text, true)?;
    if let Ok(state_text) = read_required_text(&root.join("state.json")) {
        validate_manifest_artifact(&manifest, "state.json", &state_text, false)?;
    }
    if let Some(text) = evidence_text.as_deref() {
        if !text.trim().is_empty() {
            validate_manifest_artifact(&manifest, "evidence.jsonl", text, true)?;
        }
    }

    if decisions
        .iter()
        .any(|decision| decision.run_id != manifest.run_id)
    {
        return Err(VerifyError::new(format!(
            "decisions.jsonl contains a run_id that does not match manifest run_id {}",
            manifest.run_id
        )));
    }
    if evidence_records
        .iter()
        .any(|evidence| evidence.body.run_id != manifest.run_id)
    {
        return Err(VerifyError::new(format!(
            "evidence.jsonl contains a run_id that does not match manifest run_id {}",
            manifest.run_id
        )));
    }

    let evidence_by_decision = group_evidence_by_decision(&evidence_records);
    let entries = decisions
        .iter()
        .map(|decision| {
            let declared_strength = declared_strength(decision);
            let Some(chain) = evidence_by_decision.get(&decision.hash) else {
                return VerifyEntry {
                    decision_id: decision.decision_id,
                    declared_strength,
                    recomputed_strength: EvidenceStrength::Unverifiable,
                    valid: false,
                    reason_code: "NO_EVIDENCE".to_string(),
                    message: "no evidence chain found".to_string(),
                };
            };

            if chain.is_empty() {
                return VerifyEntry {
                    decision_id: decision.decision_id,
                    declared_strength,
                    recomputed_strength: EvidenceStrength::Unverifiable,
                    valid: false,
                    reason_code: "NO_EVIDENCE".to_string(),
                    message: "no evidence chain found".to_string(),
                };
            }

            let recomputed_strength = recompute_chain_strength(chain);
            let valid = recomputed_strength >= declared_strength;
            let (reason_code, message) = if valid {
                (
                    "VERIFIED".to_string(),
                    format!(
                        "recomputed strength {} satisfied declared strength {}",
                        recomputed_strength, declared_strength
                    ),
                )
            } else {
                (
                    "CHAIN_TOO_WEAK".to_string(),
                    format!(
                        "recomputed strength {} is below declared strength {}",
                        recomputed_strength, declared_strength
                    ),
                )
            };

            VerifyEntry {
                decision_id: decision.decision_id,
                declared_strength,
                recomputed_strength,
                valid,
                reason_code,
                message,
            }
        })
        .collect();

    Ok(VerifyReport { entries })
}

fn load_manifest(root: &Path) -> Result<Manifest, VerifyError> {
    let path = root.join("manifest.json");
    let text = read_required_text(&path)?;
    serde_json::from_str(&text)
        .map_err(|err| VerifyError::new(format!("failed to parse {}: {}", path.display(), err)))
}

fn read_required_text(path: &Path) -> Result<String, VerifyError> {
    fs::read_to_string(path)
        .map_err(|err| VerifyError::new(format!("failed to read {}: {}", path.display(), err)))
}

fn read_optional_text(path: &Path) -> Result<Option<String>, VerifyError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(VerifyError::new(format!(
            "failed to read {}: {}",
            path.display(),
            err
        ))),
    }
}

fn parse_jsonl<T>(text: &str, label: &str) -> Result<Vec<T>, VerifyError>
where
    T: for<'de> Deserialize<'de>,
{
    let reader = BufReader::new(text.as_bytes());
    let mut items = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|err| {
            VerifyError::new(format!(
                "failed to read {label} line {}: {}",
                index + 1,
                err
            ))
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let item = serde_json::from_str(trimmed).map_err(|err| {
            VerifyError::new(format!(
                "failed to parse {label} line {}: {}",
                index + 1,
                err
            ))
        })?;
        items.push(item);
    }
    Ok(items)
}

fn parse_optional_jsonl<T>(text: &Option<String>, label: &str) -> Result<Vec<T>, VerifyError>
where
    T: for<'de> Deserialize<'de>,
{
    match text {
        Some(text) if !text.trim().is_empty() => parse_jsonl(text, label),
        _ => Ok(Vec::new()),
    }
}

fn validate_manifest_artifact(
    manifest: &Manifest,
    path: &str,
    contents: &str,
    required: bool,
) -> Result<(), VerifyError> {
    let artifact = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.path == path);
    match (artifact, required) {
        (Some(artifact), _) => {
            let actual_hash = canonical_hash(contents);
            let actual_bytes = contents.len();
            if artifact.hash != actual_hash {
                return Err(VerifyError::new(format!(
                    "manifest hash mismatch for {path}: expected {}, got {}",
                    artifact.hash, actual_hash
                )));
            }
            if artifact.bytes != actual_bytes {
                return Err(VerifyError::new(format!(
                    "manifest byte count mismatch for {path}: expected {}, got {}",
                    artifact.bytes, actual_bytes
                )));
            }
            Ok(())
        }
        (None, true) => Err(VerifyError::new(format!(
            "manifest does not list required artifact {path}"
        ))),
        (None, false) => Ok(()),
    }
}

fn group_evidence_by_decision(
    evidence_records: &[EvidenceRecord],
) -> HashMap<String, Vec<EvidenceRecord>> {
    let mut grouped: HashMap<String, Vec<EvidenceRecord>> = HashMap::new();
    for record in evidence_records {
        grouped
            .entry(record.body.decision_hash.clone())
            .or_default()
            .push(record.clone());
    }

    for records in grouped.values_mut() {
        records.sort_by(|left, right| {
            left.body
                .recorded_at_utc
                .cmp(&right.body.recorded_at_utc)
                .then_with(|| kind_rank(left.body.kind).cmp(&kind_rank(right.body.kind)))
                .then_with(|| left.body.evidence_id.cmp(&right.body.evidence_id))
        });
    }

    grouped
}

fn kind_rank(kind: EvidenceKind) -> u8 {
    match kind {
        EvidenceKind::StateSnapshot => 0,
        EvidenceKind::DecisionAttestation => 1,
    }
}

fn recompute_chain_strength(chain: &[EvidenceRecord]) -> EvidenceStrength {
    if chain.is_empty() {
        return EvidenceStrength::Unverifiable;
    }

    let nodes: Vec<ProvenanceNode> = chain
        .iter()
        .enumerate()
        .map(|(index, record)| ProvenanceNode {
            node_id: record.body.evidence_id.to_string(),
            parent_ref: index.checked_sub(1).map(|parent_index| {
                ProvenanceRef::active(chain[parent_index].body.evidence_id.to_string())
            }),
            strength: evidence_kind_strength(record.body.kind),
            depth: index as u32,
        })
        .collect();

    let start = nodes.last().cloned().expect("non-empty chain");
    let parents = &nodes[..nodes.len() - 1];
    let walked = walk_provenance_chain(start, parents);
    walked.chain_strength
}

fn evidence_kind_strength(kind: EvidenceKind) -> EvidenceStrength {
    match kind {
        EvidenceKind::StateSnapshot => EvidenceStrength::Signed,
        EvidenceKind::DecisionAttestation => EvidenceStrength::Anchored,
    }
}

fn declared_strength(decision: &DecisionArtifact) -> EvidenceStrength {
    match (
        decision.quality_left_strength,
        decision.quality_right_strength,
        decision.quality_report.as_ref(),
    ) {
        (Some(left), Some(right), Some(report)) => match report.chosen_side.as_str() {
            "left" => left,
            "right" => right,
            "tie" => left.max(right),
            _ => left.max(right),
        },
        (Some(left), Some(right), None) => left.max(right),
        _ => EvidenceStrength::Signed,
    }
}

pub fn run(root: impl AsRef<Path>) -> Result<VerifyReport, VerifyError> {
    verify_directory(root)
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::decision::{DecisionBody, DecisionRecord, DecisionStatus};
    use crate::evidence::{EvidenceBody, EvidenceKind, EvidenceRecord};
    use crate::quality::resolve_quality_divergence;
    use crate::types::EvidenceStrength;
    use chrono::{DateTime, Utc};
    use serde_json::Value;
    use std::fs;
    use tempfile::tempdir;
    use uuid::Uuid;

    fn sample_manifest_json(
        run_id: Uuid,
        state_json: &str,
        evidence_jsonl: &str,
        decisions_jsonl: &str,
    ) -> String {
        let artifacts = vec![
            serde_json::json!({
                "path": "state.json",
                "hash": crate::hash::canonical_hash(state_json),
                "bytes": state_json.len(),
            }),
            serde_json::json!({
                "path": "evidence.jsonl",
                "hash": crate::hash::canonical_hash(evidence_jsonl),
                "bytes": evidence_jsonl.len(),
            }),
            serde_json::json!({
                "path": "decisions.jsonl",
                "hash": crate::hash::canonical_hash(decisions_jsonl),
                "bytes": decisions_jsonl.len(),
            }),
        ];

        serde_json::json!({
            "project": "nexoia",
            "run_id": run_id,
            "generated_at_utc": "2026-06-13T12:00:00Z",
            "status": "OK",
            "reason_code": "THRESHOLD_MET",
            "message": "input_value 60 met threshold 50",
            "artifacts": artifacts,
        })
        .to_string()
    }

    fn sample_decision(run_id: Uuid) -> DecisionRecord {
        let body = DecisionBody {
            decision_id: Uuid::new_v5(&run_id, b"decision"),
            run_id,
            created_at_utc: DateTime::parse_from_rfc3339("2026-06-13T12:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            status: DecisionStatus::Ok,
            reason_code: "THRESHOLD_MET".to_string(),
            message: "input_value 60 met threshold 50".to_string(),
            state_hash: "state_hash".to_string(),
            quality_left_strength: EvidenceStrength::Signed,
            quality_right_strength: EvidenceStrength::Local,
            quality_report: resolve_quality_divergence(
                EvidenceStrength::Signed,
                EvidenceStrength::Local,
            ),
        };

        DecisionRecord::new(body).expect("decision record")
    }

    fn sample_evidence(run_id: Uuid, decision_hash: &str) -> Vec<EvidenceRecord> {
        let snapshot = EvidenceBody {
            evidence_id: Uuid::new_v5(&run_id, b"state_snapshot"),
            run_id,
            recorded_at_utc: DateTime::parse_from_rfc3339("2026-06-13T12:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            kind: EvidenceKind::StateSnapshot,
            subject: "default-evaluation".to_string(),
            status: DecisionStatus::Ok,
            reason_code: "THRESHOLD_MET".to_string(),
            message: "input_value 60 met threshold 50".to_string(),
            state_hash: "state_hash".to_string(),
            decision_hash: decision_hash.to_string(),
        };
        let attestation = EvidenceBody {
            evidence_id: Uuid::new_v5(&run_id, b"decision_attestation"),
            run_id,
            recorded_at_utc: DateTime::parse_from_rfc3339("2026-06-13T12:00:01Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            kind: EvidenceKind::DecisionAttestation,
            subject: "default-evaluation".to_string(),
            status: DecisionStatus::Ok,
            reason_code: "THRESHOLD_MET".to_string(),
            message: "input_value 60 met threshold 50".to_string(),
            state_hash: "state_hash".to_string(),
            decision_hash: decision_hash.to_string(),
        };

        vec![
            EvidenceRecord::new(snapshot).expect("evidence"),
            EvidenceRecord::new(attestation).expect("evidence"),
        ]
    }

    #[test]
    fn verify_directory_reports_valid_decision() {
        let temp = tempdir().expect("tempdir");
        let run_id = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"verify-run");
        let decision = sample_decision(run_id);
        let evidence = sample_evidence(run_id, &decision.hash);

        let state_json = serde_json::json!({
            "project": "nexoia",
            "run_id": run_id,
            "generated_at_utc": "2026-06-13T12:00:00Z",
            "scenario": "OK",
            "subject": "default-evaluation",
            "threshold": 50,
            "input_value": 60
        })
        .to_string();
        let evidence_jsonl = format!(
            "{}\n{}\n",
            serde_json::to_string(&evidence[0]).expect("json"),
            serde_json::to_string(&evidence[1]).expect("json")
        );
        let decisions_jsonl = format!("{}\n", serde_json::to_string(&decision).expect("json"));
        let manifest_json =
            sample_manifest_json(run_id, &state_json, &evidence_jsonl, &decisions_jsonl);

        fs::write(temp.path().join("manifest.json"), manifest_json).expect("manifest");
        fs::write(temp.path().join("evidence.jsonl"), evidence_jsonl).expect("evidence");
        fs::write(temp.path().join("decisions.jsonl"), decisions_jsonl).expect("decisions");

        let report = run(temp.path()).expect("verify");
        assert_eq!(report.entries.len(), 1);
        assert!(report.entries[0].valid);
        assert_eq!(report.entries[0].reason_code, "VERIFIED");

        let json: Value = serde_json::to_value(&report).expect("json value");
        assert_eq!(json["entries"][0]["valid"], Value::Bool(true));
    }

    #[test]
    fn verify_directory_marks_missing_evidence_as_no_evidence() {
        let temp = tempdir().expect("tempdir");
        let run_id = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"verify-run-empty");
        let decision = sample_decision(run_id);
        let state_json = serde_json::json!({
            "project": "nexoia",
            "run_id": run_id,
            "generated_at_utc": "2026-06-13T12:00:00Z",
            "scenario": "OK",
            "subject": "default-evaluation",
            "threshold": 50,
            "input_value": 60
        })
        .to_string();
        let evidence_jsonl = String::new();
        let decisions_jsonl = format!("{}\n", serde_json::to_string(&decision).expect("json"));
        let manifest_json =
            sample_manifest_json(run_id, &state_json, &evidence_jsonl, &decisions_jsonl);

        fs::write(temp.path().join("manifest.json"), manifest_json).expect("manifest");
        fs::write(temp.path().join("evidence.jsonl"), evidence_jsonl).expect("evidence");
        fs::write(temp.path().join("decisions.jsonl"), decisions_jsonl).expect("decisions");

        let report = run(temp.path()).expect("verify");
        assert_eq!(report.entries.len(), 1);
        assert!(!report.entries[0].valid);
        assert_eq!(report.entries[0].reason_code, "NO_EVIDENCE");
        assert_eq!(report.entries[0].message, "no evidence chain found");
    }
}
