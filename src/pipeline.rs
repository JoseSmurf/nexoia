// pipeline.rs — EPA pipeline, network state persistence, and helpers
// Lock order: see GLOBAL LOCK ORDER in src/main.rs

use crate::decision::{DecisionRecord, DecisionStatus};
use crate::hash::canonical_hash;
use crate::lgpd::{parse_lgpd_basis, LgpdMetadata};
use crate::limits::MAX_EPA_ENTRIES;
use crate::network::epa::SharedEPA;
use crate::network::identity::NodeIdentity;
use crate::network::persistence;
use crate::network::transport::{PeerList, TrustedPeerList};
use crate::state::State;
use crate::types::EvidenceProvider;
use serde::Serialize;
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactSummary {
    path: String,
    hash: String,
    bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Manifest {
    project: String,
    pub run_id: uuid::Uuid,
    pub generated_at_utc: chrono::DateTime<chrono::Utc>,
    pub status: DecisionStatus,
    pub reason_code: String,
    pub message: String,
    artifacts: Vec<ArtifactSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lgpd: Option<LgpdMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lgpd_hash: Option<String>,
}

pub async fn run_pipeline(
    node: &NodeIdentity,
    peers: &Arc<RwLock<PeerList>>,
    epas: &Arc<RwLock<Vec<SharedEPA>>>,
    trusted_peers: &Arc<RwLock<TrustedPeerList>>,
    data_path: &Path,
    lgpd_index: Option<Arc<RwLock<crate::lgpd_rights::LgpdIndex>>>,
    provenance_nodes: &Arc<RwLock<Vec<crate::provenance::ProvenanceNode>>>,
) -> Result<(), Box<dyn Error>> {
    let limiter = crate::defense::RateLimiter::new(100, Duration::from_secs(60));
    let engine = crate::ai::EvidenceEngine::new(0.30);

    let mut state = State::from_env()?;

    if let Ok(basis_raw) = std::env::var("NEXOIA_LGPD_BASIS") {
        let purpose = std::env::var("NEXOIA_LGPD_PURPOSE")
            .map_err(|_| "NEXOIA_LGPD_PURPOSE required when NEXOIA_LGPD_BASIS is set")?;
        let retention: u32 = std::env::var("NEXOIA_LGPD_RETENTION_DAYS")
            .map_err(|_| "NEXOIA_LGPD_RETENTION_DAYS required when NEXOIA_LGPD_BASIS is set")?
            .parse()
            .map_err(|e| format!("invalid NEXOIA_LGPD_RETENTION_DAYS: {e}"))?;
        let data_subject_hash = std::env::var("NEXOIA_LGPD_DATA_SUBJECT_HASH").ok();
        let dpia_ref = std::env::var("NEXOIA_LGPD_DPIA_REF").ok();
        let consent_id = std::env::var("NEXOIA_LGPD_CONSENT_ID").ok();
        let lawful_basis = parse_lgpd_basis(&basis_raw)?;
        let lgpd = LgpdMetadata {
            lawful_basis,
            purpose,
            retention_days: retention,
            data_subject_hash,
            dpia_ref,
            consent_id,
        };
        lgpd.validate()?;
        state.lgpd = Some(lgpd);
    }

    let state_json = serde_json::to_string_pretty(&state)?;

    crate::defense::validate_raw_input(&state_json, 1_048_576)?;

    if !limiter.check(&state.subject) {
        return Err("rate limit exceeded for subject".into());
    }

    let assertion = engine.translate(&state_json, 1_048_576)?;
    let kind = match assertion.evidence_strength {
        crate::types::EvidenceStrength::Anchored => "anchored",
        crate::types::EvidenceStrength::Signed => "signed",
        crate::types::EvidenceStrength::Witnessed => "witness",
        crate::types::EvidenceStrength::Local => "local",
        crate::types::EvidenceStrength::Unverifiable => "local",
    };

    write_text("state.json", &state_json)?;
    let state_hash = canonical_hash(&state_json);

    let decision = crate::decision::evaluate(&state, state_hash.clone(), kind, "local")?;
    let evidence_records = crate::evidence::build_records(&state, &decision)?;

    let evidence_jsonl = write_jsonl_string(&evidence_records)?;
    write_text("evidence.jsonl", &evidence_jsonl)?;

    let decisions_jsonl = write_jsonl_string(std::slice::from_ref(&decision))?;
    write_text("decisions.jsonl", &decisions_jsonl)?;

    let report = crate::explain::explain_chain(std::slice::from_ref(&decision));
    let explain_json = serde_json::to_string_pretty(&report)?;
    write_text("explain.json", &explain_json)?;
    println!("{}", report.summary);

    let manifest = build_manifest(
        &state,
        &decision,
        &state_json,
        &evidence_jsonl,
        &decisions_jsonl,
    );
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    write_text("manifest.json", &manifest_json)?;

    println!("{}", decision.body.status);
    println!("{}", decision.body.reason_code);
    println!("{}", decision.body.message);

    let epa = SharedEPA::create(
        node,
        &state_json,
        &evidence_jsonl,
        &decisions_jsonl,
        &manifest_json,
        state.lgpd.clone(),
    );

    println!("\nEPA created: {}", epa);

    {
        let mut epa_list = epas.write().await;
        if epa_list.len() >= MAX_EPA_ENTRIES {
            let _evicted = epa_list.remove(0);
            eprintln!(
                "EPA list: evicting oldest EPA to make room (max={})",
                MAX_EPA_ENTRIES
            );
        }
        epa_list.push(epa.clone());
    }

    // Insere EPA no índice LGPD se houver metadata
    if let Some(ref index) = lgpd_index {
        if let Some(ref lgpd) = epa.lgpd_metadata {
            if let Some(ref subject_hash) = lgpd.data_subject_hash {
                let epa_hash = canonical_hash(&epa.integrity_hash);
                let entry = crate::lgpd_rights::EpaRef {
                    epa_id: epa.epa_id.clone(),
                    epa_hash,
                    lawful_basis: lgpd.lawful_basis,
                    purpose: lgpd.purpose.clone(),
                    created_at: chrono::DateTime::parse_from_rfc3339(&epa.timestamp)
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                        .unwrap_or_else(|_| chrono::Utc::now()),
                    expires_at: {
                        let created = chrono::DateTime::parse_from_rfc3339(&epa.timestamp)
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                            .unwrap_or_else(|_| chrono::Utc::now());
                        created + chrono::Duration::days(lgpd.retention_days as i64)
                    },
                };
                let mut idx = index.write().await;
                idx.insert(subject_hash.clone(), entry);
            }
        }
    }

    persistence::save_network_state(data_path, peers, epas, trusted_peers, provenance_nodes).await;

    let peer_list = peers.read().await;
    if !peer_list.is_empty() {
        println!("Sharing EPA with {} peers...", peer_list.len());
    } else {
        println!("No peers connected yet. EPA stored locally.");
    }

    Ok(())
}

pub fn build_manifest(
    state: &State,
    decision: &DecisionRecord,
    state_json: &str,
    evidence_jsonl: &str,
    decisions_jsonl: &str,
) -> Manifest {
    let (lgpd, lgpd_hash) = match &state.lgpd {
        Some(meta) => {
            let json = serde_json::to_string(meta).expect("lgpd metadata serializes");
            (Some(meta.clone()), Some(canonical_hash(&json)))
        }
        None => (None, None),
    };

    Manifest {
        project: state.project.clone(),
        run_id: state.run_id,
        generated_at_utc: state.generated_at_utc,
        status: decision.body.status,
        reason_code: decision.body.reason_code.clone(),
        message: decision.body.message.clone(),
        artifacts: vec![
            ArtifactSummary {
                path: "state.json".to_string(),
                hash: canonical_hash(state_json),
                bytes: state_json.len(),
            },
            ArtifactSummary {
                path: "evidence.jsonl".to_string(),
                hash: canonical_hash(evidence_jsonl),
                bytes: evidence_jsonl.len(),
            },
            ArtifactSummary {
                path: "decisions.jsonl".to_string(),
                hash: canonical_hash(decisions_jsonl),
                bytes: decisions_jsonl.len(),
            },
        ],
        lgpd,
        lgpd_hash,
    }
}

fn write_text(path: impl AsRef<Path>, contents: &str) -> Result<(), Box<dyn Error>> {
    std::fs::write(path, contents)?;
    Ok(())
}

fn write_jsonl_string<T: Serialize>(items: &[T]) -> Result<String, Box<dyn Error>> {
    let mut output = String::new();
    for item in items {
        let line = serde_json::to_string(item)?;
        output.push_str(&line);
        output.push('\n');
    }
    Ok(output)
}
