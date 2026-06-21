mod ai;
mod decision;
mod defense;
mod evidence;
mod explain;
mod hash;
mod network;
mod provenance;
mod quality;
mod state;
mod types;

use crate::decision::{DecisionRecord, DecisionStatus};
use crate::hash::canonical_hash;
use crate::network::api::{self, ApiState};
use crate::network::epa::SharedEPA;
use crate::network::identity::NodeIdentity;
use crate::network::transport::{NetworkMessage, PeerList, UdpTransport};
use crate::state::State;
use crate::types::EvidenceProvider;
use serde::Serialize;
use std::error::Error;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize)]
struct ArtifactSummary {
    path: String,
    hash: String,
    bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
struct Manifest {
    project: String,
    run_id: uuid::Uuid,
    generated_at_utc: chrono::DateTime<chrono::Utc>,
    status: DecisionStatus,
    reason_code: String,
    message: String,
    artifacts: Vec<ArtifactSummary>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let node = NodeIdentity::generate("nexoia_node");
    println!("Node ID: {}", node.node_id);

    let api_port: u16 = std::env::var("NEXOIA_API_PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()?;
    let udp_port: u16 = std::env::var("NEXOIA_UDP_PORT")
        .unwrap_or_else(|_| "9000".to_string())
        .parse()?;

    let api_addr: SocketAddr = ([127, 0, 0, 1], api_port).into();
    let udp_addr: SocketAddr = ([127, 0, 0, 1], udp_port).into();

    let epas: Arc<RwLock<Vec<SharedEPA>>> = Arc::new(RwLock::new(Vec::new()));
    let peers: Arc<RwLock<PeerList>> = Arc::new(RwLock::new(PeerList::new(10)));

    let api_state = ApiState {
        node_id: node.node_id.clone(),
        public_key: node.public_key.clone(),
        epas: Arc::clone(&epas),
    };

    let udp_socket = UdpTransport::bind(udp_addr).await?;
    println!("UDP listening on {}", udp_addr);

    let node_clone = node.clone();
    let epas_clone = Arc::clone(&epas);
    let peers_clone = Arc::clone(&peers);

    tokio::spawn(async move {
        run_udp_listener(udp_socket, node_clone, epas_clone, peers_clone).await;
    });

    let node_for_api = node.clone();
    tokio::spawn(async move {
        if let Err(e) = api::create_api(api_state, api_addr).await {
            eprintln!("API error: {}", e);
        }
    });
    println!("API listening on http://{}", api_addr);

    run_pipeline(&node, &peers).await?;

    println!("\nNode running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;

    Ok(())
}

async fn run_pipeline(
    node: &NodeIdentity,
    peers: &Arc<RwLock<PeerList>>,
) -> Result<(), Box<dyn Error>> {
    let limiter = defense::RateLimiter::new(100, Duration::from_secs(60));
    let engine = ai::MockEngine::new(0.70);

    let state = State::from_env()?;
    let state_json = serde_json::to_string_pretty(&state)?;

    defense::validate_raw_input(&state_json, 1_048_576)?;

    if !limiter.check(&state.subject) {
        return Err("rate limit exceeded for subject".into());
    }

    let assertion = engine.translate(&state_json, 1_048_576)?;
    let kind = match assertion.evidence_strength {
        types::EvidenceStrength::Anchored => "anchored",
        types::EvidenceStrength::Signed => "signed",
        types::EvidenceStrength::Witnessed => "witness",
        types::EvidenceStrength::Local => "local",
        types::EvidenceStrength::Unverifiable => "local",
    };

    write_text("state.json", &state_json)?;
    let state_hash = canonical_hash(&state_json);

    let decision = decision::evaluate(&state, state_hash.clone(), kind, "local")?;
    let evidence_records = evidence::build_records(&state, &decision)?;

    let evidence_jsonl = write_jsonl_string(&evidence_records)?;
    write_text("evidence.jsonl", &evidence_jsonl)?;

    let decisions_jsonl = write_jsonl_string(std::slice::from_ref(&decision))?;
    write_text("decisions.jsonl", &decisions_jsonl)?;

    let report = explain::explain_chain(std::slice::from_ref(&decision));
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
    );

    println!("\nEPA created: {}", epa);

    let peer_list = peers.read().await;
    if !peer_list.is_empty() {
        println!("Sharing EPA with {} peers...", peer_list.len());
    } else {
        println!("No peers connected yet. EPA stored locally.");
    }

    Ok(())
}

async fn run_udp_listener(
    mut transport: UdpTransport,
    node: NodeIdentity,
    epas: Arc<RwLock<Vec<SharedEPA>>>,
    peers: Arc<RwLock<PeerList>>,
) {
    loop {
        match transport.recv().await {
            Ok((msg, addr)) => match msg {
                NetworkMessage::Discover { node_id, address } => {
                    println!("Discovered node: {} at {}", node_id, address);
                    if let Ok(peer_addr) = address.parse::<SocketAddr>() {
                        let mut peer_list = peers.write().await;
                        if peer_list.add(peer_addr) {
                            let pong = NetworkMessage::Pong {
                                node_id: node.node_id.clone(),
                            };
                            let _ = transport.send(&pong, peer_addr).await;
                        }
                    }
                }
                NetworkMessage::Ping { node_id } => {
                    println!("Ping from {}", node_id);
                    let pong = NetworkMessage::Pong {
                        node_id: node.node_id.clone(),
                    };
                    let _ = transport.send(&pong, addr).await;
                }
                NetworkMessage::Pong { node_id } => {
                    println!("Pong from {}", node_id);
                }
                NetworkMessage::EPA(epa) => {
                    if epa.verify_integrity() {
                        let mut epa_list = epas.write().await;
                        epa_list.push(epa.clone());
                        println!("Received valid EPA: {}", epa);
                    } else {
                        println!("Rejected invalid EPA from {}", addr);
                    }
                }
            },
            Err(e) => {
                eprintln!("UDP error: {}", e);
            }
        }
    }
}

fn build_manifest(
    state: &State,
    decision: &DecisionRecord,
    state_json: &str,
    evidence_jsonl: &str,
    decisions_jsonl: &str,
) -> Manifest {
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
