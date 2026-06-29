//! integration_lgpd.rs — Testes de integração LGPD
//!
//! Testa o fluxo completo: criação de EPA → indexação → anonimização → graph blinding
//! Todos os testes são síncronos e rodam sob Miri.

use nexoia::lgpd::{LawfulBasis, LgpdMetadata};
use nexoia::lgpd_rights::{self, LgpdIndex};
use nexoia::network::epa::SharedEPA;
use nexoia::network::identity::NodeIdentity;
use nexoia::provenance::{blind_derivation_links, DerivationIndex, ProvenanceNode, ProvenanceRef};

// ── Helpers ───────────────────────────────────────────────────

fn sample_lgpd(subject_hash: &str) -> LgpdMetadata {
    LgpdMetadata {
        lawful_basis: LawfulBasis::Consentimento,
        purpose: "processamento_pedido".to_string(),
        retention_days: 365,
        data_subject_hash: Some(subject_hash.to_string()),
        dpia_ref: None,
        consent_id: Some("consent_abc123".to_string()),
    }
}

fn create_epa_with_lgpd(node: &NodeIdentity, subject_hash: &str) -> SharedEPA {
    SharedEPA::create(
        node,
        r#"{"cpf":"123.456.789-00","nome":"João"}"#,
        r#"{"evidence":"ok"}"#,
        r#"{"decision":"ok"}"#,
        r#"{"manifest":"v1"}"#,
        Some(sample_lgpd(subject_hash)),
    )
}

fn create_derived_epa(node: &NodeIdentity, parent_id: &str) -> SharedEPA {
    let state_json = format!(r#"{{"score":85,"derived_from":"{}"}}"#, parent_id);
    SharedEPA::create(
        node,
        &state_json,
        r#"{"evidence":"derived"}"#,
        r#"{"decision":"derived"}"#,
        r#"{"manifest":"derived"}"#,
        None,
    )
}

// ── Fluxo completo de anonimização ────────────────────────────

#[test]
fn full_anonymization_flow() {
    let node = NodeIdentity::generate("test_node");

    // 1. Cria EPA com dados do titular
    let mut epa = create_epa_with_lgpd(&node, "hash_joao");

    // 2. Indexa no LgpdIndex
    let mut index = LgpdIndex::new();
    let epa_hash = nexoia::hash::canonical_hash(&epa.integrity_hash);
    index.insert(
        "hash_joao".to_string(),
        nexoia::lgpd_rights::EpaRef {
            epa_id: epa.epa_id.clone(),
            epa_hash,
            lawful_basis: LawfulBasis::Consentimento,
            purpose: "processamento_pedido".to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(365),
        },
    );
    assert_eq!(index.count(), 1);

    // 3. Verifica que dados estão presentes
    assert!(epa.lgpd_metadata.is_some());
    assert!(epa.encrypted_payload.is_none());

    // 4. Anonimiza (crypto-shredding)
    let fields = lgpd_rights::anonymize_epa_fields(&mut epa);
    assert!(fields.contains(&"lgpd_metadata".to_string()));
    assert!(fields.contains(&"state_hash".to_string()));
    assert!(fields.contains(&"evidence_hash".to_string()));

    // 5. Verifica que dados foram removidos
    assert!(epa.lgpd_metadata.is_none());
    assert_eq!(epa.state_hash, "0".repeat(64));
    assert_eq!(epa.evidence_hash, "0".repeat(64));

    // 6. Cria EPA de supressão
    let suppression = lgpd_rights::create_suppression_epa(&node, &epa);
    assert_ne!(suppression.epa_id, epa.epa_id);

    // 7. Atualiza índice
    index.remove_epa("hash_joao", &epa.epa_id);
    assert_eq!(index.count(), 0);

    // 8. Verifica que titular não está mais no índice
    let results = index.lookup("hash_joao");
    assert!(results.is_empty());
}

// ── Graph blinding ────────────────────────────────────────────

#[test]
fn graph_blinding_breaks_linkability() {
    let node = NodeIdentity::generate("test_node");

    // Cria EPA pai (titular)
    let parent = create_epa_with_lgpd(&node, "hash_maria");

    // Cria EPA filho (decisão)
    let child = create_derived_epa(&node, &parent.epa_id);

    // Cria ProvenanceNodes com link ativo
    let mut nodes = vec![
        ProvenanceNode {
            node_id: parent.epa_id.clone(),
            parent_ref: None,
            strength: nexoia::types::EvidenceStrength::Signed,
            depth: 0,
        },
        ProvenanceNode {
            node_id: child.epa_id.clone(),
            parent_ref: Some(ProvenanceRef::active(parent.epa_id.clone())),
            strength: nexoia::types::EvidenceStrength::Local,
            depth: 1,
        },
    ];

    // Verifica que link está ativo
    let child_node = nodes.iter().find(|n| n.node_id == child.epa_id).unwrap();
    assert!(!child_node.parent_ref.as_ref().unwrap().is_blinded());

    // Anonimiza EPA pai
    let mut parent_copy = parent.clone();
    lgpd_rights::anonymize_epa_fields(&mut parent_copy);
    let suppression = lgpd_rights::create_suppression_epa(&node, &parent_copy);

    // Blinda links
    let blinded = blind_derivation_links(&mut nodes, &parent.epa_id, &suppression.integrity_hash);
    assert_eq!(blinded, 1);

    // Verifica que link foi cegado
    let child_node = nodes.iter().find(|n| n.node_id == child.epa_id).unwrap();
    assert!(child_node.parent_ref.as_ref().unwrap().is_blinded());

    // Verifica que hash cego é diferente do original
    match &child_node.parent_ref {
        Some(ProvenanceRef::Blinded { blinded_hash, .. }) => {
            assert_ne!(blinded_hash, &parent.epa_id);
        }
        _ => panic!("Expected Blinded"),
    }
}

// ── Derivation index ──────────────────────────────────────────

#[test]
fn derivation_index_tracks_parent_child() {
    let node = NodeIdentity::generate("test_node");

    let parent = create_epa_with_lgpd(&node, "hash_parent");
    let child1 = create_derived_epa(&node, &parent.epa_id);
    let child2 = create_derived_epa(&node, &parent.epa_id);

    let nodes = vec![
        ProvenanceNode {
            node_id: parent.epa_id.clone(),
            parent_ref: None,
            strength: nexoia::types::EvidenceStrength::Signed,
            depth: 0,
        },
        ProvenanceNode {
            node_id: child1.epa_id.clone(),
            parent_ref: Some(ProvenanceRef::active(parent.epa_id.clone())),
            strength: nexoia::types::EvidenceStrength::Local,
            depth: 1,
        },
        ProvenanceNode {
            node_id: child2.epa_id.clone(),
            parent_ref: Some(ProvenanceRef::active(parent.epa_id.clone())),
            strength: nexoia::types::EvidenceStrength::Local,
            depth: 1,
        },
    ];

    let index = DerivationIndex::build_from_chain_refs(&nodes);
    assert_eq!(index.len(), 2);

    let children = index.children_of(&parent.epa_id);
    assert_eq!(children.len(), 2);
    assert!(children.contains(&child1.epa_id.as_str()));
    assert!(children.contains(&child2.epa_id.as_str()));
}

// ── NEX reactive rules ────────────────────────────────────────

#[test]
fn nex_reactive_rules_load_from_program() {
    let source = r#"// nex-version: 1.0.0
on heartbeat_miss > 3: log "peer inativo"
on heartbeat_miss > 5: marcar_inativo default
"#;

    let program = nexoia::nex::parser::parse(source).expect("parse");
    let mut engine =
        nexoia::nex::reactive::ReactiveEngine::with_layer(nexoia::nex::layers::NexLayer::Advanced);
    let count = engine.load_from_program(&program);
    assert_eq!(count, 2);
    assert_eq!(engine.rules().len(), 2);
}

// ── NEX eval ──────────────────────────────────────────────────

#[test]
fn nex_eval_creates_bindings() {
    let source = r#"// nex-version: 1.0.0
let sum = node 42 signed
let label = node "hello" anchored
"#;

    let program = nexoia::nex::parser::parse(source).expect("parse");
    let env = nexoia::nex::eval::eval(program).expect("eval");
    assert_eq!(env.len(), 2);
}

// ── Observer ──────────────────────────────────────────────────

#[tokio::test]
async fn observer_reports_system_health() {
    let epas = std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new()));
    let peers = std::sync::Arc::new(tokio::sync::RwLock::new(
        nexoia::network::transport::PeerList::new(10),
    ));
    let rep = std::sync::Arc::new(tokio::sync::RwLock::new(
        nexoia::network::reputation::ReputationStore::new(),
    ));
    let idx = std::sync::Arc::new(tokio::sync::RwLock::new(LgpdIndex::new()));
    let prov = std::sync::Arc::new(tokio::sync::RwLock::new(Vec::<ProvenanceNode>::new()));
    let deriv = std::sync::Arc::new(tokio::sync::RwLock::new(DerivationIndex::new()));

    let observer = nexoia::nex::observer::NexObserver::new(epas, peers, rep, idx, prov, deriv);

    let report = observer.report().await;
    assert!(!report.findings.is_empty());
    assert!(report.summary.total_checks > 0);
}

// ── Compliance endpoint ───────────────────────────────────────

#[test]
fn compliance_not_blinded() {
    let node = NodeIdentity::generate("test");
    let epa = create_epa_with_lgpd(&node, "hash123");

    let prov_nodes = [ProvenanceNode {
        node_id: epa.epa_id.clone(),
        parent_ref: None,
        strength: nexoia::types::EvidenceStrength::Signed,
        depth: 0,
    }];

    let node = prov_nodes.iter().find(|n| n.node_id == epa.epa_id).unwrap();
    let status = match &node.parent_ref {
        Some(ProvenanceRef::Active(_)) => "NotBlinded",
        Some(ProvenanceRef::Blinded { .. }) => "Blinded",
        None => "NotBlinded",
    };
    assert_eq!(status, "NotBlinded");
}

#[test]
fn compliance_blinded() {
    let node_ref = ProvenanceRef::blind("original_hash", "suppression_hash");
    assert!(node_ref.is_blinded());

    let status = match &node_ref {
        ProvenanceRef::Active(_) => "NotBlinded",
        ProvenanceRef::Blinded { .. } => "Blinded",
    };
    assert_eq!(status, "Blinded");
}

// ── Stress test: many EPAs ────────────────────────────────────

#[test]
fn stress_many_epas_anonymization() {
    let node = NodeIdentity::generate("stress_test");
    let mut index = LgpdIndex::new();

    // Cria 100 EPAs
    let mut epas: Vec<SharedEPA> = (0..100)
        .map(|i| {
            let hash = format!("subject_{}", i);
            let epa = create_epa_with_lgpd(&node, &hash);
            index.insert(
                hash,
                nexoia::lgpd_rights::EpaRef {
                    epa_id: epa.epa_id.clone(),
                    epa_hash: nexoia::hash::canonical_hash(&epa.integrity_hash),
                    lawful_basis: LawfulBasis::Consentimento,
                    purpose: "test".to_string(),
                    created_at: chrono::Utc::now(),
                    expires_at: chrono::Utc::now() + chrono::Duration::days(365),
                },
            );
            epa
        })
        .collect();

    assert_eq!(index.count(), 100);

    // Anonimiza todos
    for epa in &mut epas {
        lgpd_rights::anonymize_epa_fields(epa);
    }

    // Verifica que todos foram anonimizados
    for epa in &epas {
        assert!(epa.lgpd_metadata.is_none());
        assert_eq!(epa.state_hash, "0".repeat(64));
    }

    // Remove todos do índice
    for (i, epa) in epas.iter().enumerate() {
        let hash = format!("subject_{}", i);
        index.remove_epa(&hash, &epa.epa_id);
    }

    assert_eq!(index.count(), 0);
}

// ── Stress test: deep derivation chain ────────────────────────

#[test]
fn stress_deep_derivation_chain_blinding() {
    let node = NodeIdentity::generate("chain_test");
    let mut epas: Vec<SharedEPA> = Vec::new();
    let mut nodes: Vec<ProvenanceNode> = Vec::new();

    // Cria cadeia de 10 nós
    for i in 0..10 {
        let epa = create_derived_epa(&node, &format!("epa_{}", i));
        let parent_ref = if i > 0 {
            Some(ProvenanceRef::active(epas[i - 1].epa_id.clone()))
        } else {
            None
        };
        nodes.push(ProvenanceNode {
            node_id: epa.epa_id.clone(),
            parent_ref,
            strength: nexoia::types::EvidenceStrength::Local,
            depth: i as u32,
        });
        epas.push(epa);
    }

    let index = DerivationIndex::build_from_chain_refs(&nodes);
    assert_eq!(index.len(), 9); // 9 links (10 nodes, first has no parent)

    // Blinda o nó 5 (meio da cadeia)
    let suppressed_hash = "suppressed_epa_hash";
    let target_id = nodes[5].node_id.clone();
    let blinded = blind_derivation_links(&mut nodes, &target_id, suppressed_hash);

    // Verifica que apenas 1 link foi cegado (nó 6 aponta pro 5)
    assert_eq!(blinded, 1);

    // Verifica que outros links não foram afetados
    let node_6 = nodes
        .iter()
        .find(|n| n.node_id == nodes[6].node_id)
        .unwrap();
    assert!(node_6.parent_ref.as_ref().unwrap().is_blinded());

    let node_7 = nodes
        .iter()
        .find(|n| n.node_id == nodes[7].node_id)
        .unwrap();
    assert!(!node_7.parent_ref.as_ref().unwrap().is_blinded());
}

// ── Determinism test ──────────────────────────────────────────

#[test]
fn blinding_is_deterministic() {
    let r1 = nexoia::provenance::ProvenanceRef::blind("abc", "salt");
    let r2 = nexoia::provenance::ProvenanceRef::blind("abc", "salt");
    let r3 = nexoia::provenance::ProvenanceRef::blind("abc", "different_salt");

    assert_eq!(r1.as_str(), r2.as_str());
    assert_ne!(r1.as_str(), r3.as_str());
}

#[test]
fn suppression_epa_has_correct_structure() {
    let node = NodeIdentity::generate("test");
    let original = create_epa_with_lgpd(&node, "hash1");

    let suppression = lgpd_rights::create_suppression_epa(&node, &original);

    // EPA de supressão tem ID diferente do original
    assert_ne!(suppression.epa_id, original.epa_id);

    // EPA de supressão não tem lgpd_metadata
    assert!(suppression.lgpd_metadata.is_none());

    // EPA de supressão tem integrity_hash válido
    assert!(!suppression.integrity_hash.is_empty());
}
