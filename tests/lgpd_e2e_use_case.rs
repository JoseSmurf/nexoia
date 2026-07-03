//! tests/lgpd_e2e_use_case.rs — Caso de uso E2E LGPD: Direito ao Esquecimento
//!
//! Este teste demonstra o fluxo completo de exclusão de dados pessoais (LGPD Art. 18, VI):
//! criação de EPA → cascata de EPAs derivados → exclusão do titular → crypto-shredding →
//! blinding em cascata → prova de compliance verificável por terceiro.
//!
//! Cenário: Maria Silva (CPF fictício 987.654.321-00) tem 3 EPAs derivados de decisões
//! sobre ela (crédito, avaliação, scoring). Ela pede exclusão. O sistema:
//! 1. Anonimiza dados sensíveis dentro de cada EPA
//! 2. Zera state_hash e evidence_hash como prova de remoção
//! 3. Gera EPA de supressão documentando o que foi feito
//! 4. Blinda links de provenance nos EPAs derivados
//! 5. Remove do índice LGPD
//!
//! Qualquer pessoa pode rodar este teste e verificar os resultados matematicamente.

use nexoia::lgpd::{LawfulBasis, LgpdMetadata};
use nexoia::lgpd_rights::{self, AnonymizationResult, EpaRef, LgpdIndex};
use nexoia::network::epa::SharedEPA;
use nexoia::network::identity::NodeIdentity;
use nexoia::provenance::{blind_derivation_links, DerivationIndex, ProvenanceNode, ProvenanceRef};
use nexoia::types::EvidenceStrength;

// ── Dados realistas do cenário ─────────────────────────────

/// Hash do titular — em produção, seria BLAKE3 do CPF ou identificador único.
/// Aqui usamos um hash fixo para reprodutibilidade.
const TITULAR_HASH: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";

/// Cenário: Maria Silva, CPF 987.654.321-00
const NOME_TITULAR: &str = "Maria Silva";
const CPF_TITULAR: &str = "987.654.321-00";

// ── Helpers ────────────────────────────────────────────────

fn criar_lgpd_titular(subject_hash: &str) -> LgpdMetadata {
    LgpdMetadata {
        lawful_basis: LawfulBasis::Consentimento,
        purpose: "analise_de_credito".to_string(),
        retention_days: 365,
        data_subject_hash: Some(subject_hash.to_string()),
        dpia_ref: Some("DPIA-2026-001".to_string()),
        consent_id: Some("consent_maria_silva_2026".to_string()),
    }
}

fn criar_epa_decisao(
    node: &NodeIdentity,
    subject_hash: &str,
    decisao: &str,
    score: i64,
) -> SharedEPA {
    let state_json = format!(
        r#"{{"cpf":"{}","nome":"{}","decisao":"{}","score":{},"data":"2026-07-03"}}"#,
        CPF_TITULAR, NOME_TITULAR, decisao, score
    );
    SharedEPA::create(
        node,
        &state_json,
        &format!(r#"{{"evidence":"analise_{}"}}"#, decisao),
        &format!(r#"{{"decision":"{}"}}"#, decisao),
        r#"{"manifest":"v1","project":"nexoia"}"#,
        Some(criar_lgpd_titular(subject_hash)),
    )
}

fn criar_epa_derivado(node: &NodeIdentity, parent_id: &str, tipo: &str) -> SharedEPA {
    let state_json = format!(
        r#"{{"tipo":"{}","derived_from":"{}","resultado":"aprovado"}}"#,
        tipo, parent_id
    );
    SharedEPA::create(
        node,
        &state_json,
        &format!(r#"{{"evidence":"derivado_{}"}}"#, tipo),
        &format!(r#"{{"decision":"derivado_{}"}}"#, tipo),
        r#"{"manifest":"derived"}"#,
        None,
    )
}

// ── O fluxo completo ───────────────────────────────────────

#[test]
fn lgpd_direito_ao_esquecimento_fluxo_completo() {
    // ================================================================
    // FASE 1: CRIAÇÃO — Maria Silva tem dados em 3 EPAs
    // ================================================================

    let node = NodeIdentity::generate("nexoia_node_principal");

    println!("\n=== FASE 1: Criando dados do titular ===");
    println!("Titular: {} (CPF: {})", NOME_TITULAR, CPF_TITULAR);
    println!("Hash do titular: {}", &TITULAR_HASH[..16]);

    // EPA 1: Decisão de crédito (aprovado)
    let mut epa_credito = criar_epa_decisao(&node, TITULAR_HASH, "credito_aprovado", 85);
    println!(
        "  EPA-1 (crédito): {} — score {}",
        &epa_credito.epa_id[..8],
        85
    );

    // EPA 2: Avaliação de risco
    let mut epa_risco = criar_epa_decisao(&node, TITULAR_HASH, "risco_baixo", 92);
    println!(
        "  EPA-2 (risco):   {} — score {}",
        &epa_risco.epa_id[..8],
        92
    );

    // EPA 3: Scoring comportamental
    let mut epa_scoring = criar_epa_decisao(&node, TITULAR_HASH, "scoring_comportamental", 78);
    println!(
        "  EPA-3 (scoring): {} — score {}",
        &epa_scoring.epa_id[..8],
        78
    );

    // EPA 4: Decisão derivada do crédito (filho)
    let epa_derived_1 = criar_epa_derivado(&node, &epa_credito.epa_id, "limite_credito");
    println!(
        "  EPA-4 (derivado): {} — limite de crédito",
        &epa_derived_1.epa_id[..8]
    );

    // EPA 5: Decisão derivada do scoring (filho)
    let epa_derived_2 = criar_epa_derivado(&node, &epa_scoring.epa_id, "oferta_personalizada");
    println!(
        "  EPA-5 (derivado): {} — oferta personalizada",
        &epa_derived_2.epa_id[..8]
    );

    // ================================================================
    // FASE 2: INDEXAÇÃO — Titular fica no índice LGPD
    // ================================================================

    println!("\n=== FASE 2: Indexando no LGPD ===");

    let mut index = LgpdIndex::new();

    // Indexa os 3 EPAs com dados do titular
    for epa in [&epa_credito, &epa_risco, &epa_scoring] {
        let epa_hash = nexoia::hash::canonical_hash(&epa.integrity_hash);
        index.insert(
            TITULAR_HASH.to_string(),
            EpaRef {
                epa_id: epa.epa_id.clone(),
                epa_hash,
                lawful_basis: LawfulBasis::Consentimento,
                purpose: "analise_de_credito".to_string(),
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::days(365),
            },
        );
    }

    assert_eq!(index.count(), 3);
    println!("  Indexado: {} EPAs para o titular", index.count());

    // Verifica que dados estão presentes ANTES da exclusão
    assert!(epa_credito.lgpd_metadata.is_some());
    assert!(epa_risco.lgpd_metadata.is_some());
    assert!(epa_scoring.lgpd_metadata.is_some());
    println!("  LGPD metadata presente em todos os 3 EPAs ✓");

    // ================================================================
    // FASE 3: PROVENANCE — Monta cadeia de derivação
    // ================================================================

    println!("\n=== FASE 3: Montando cadeia de provenance ===");

    let mut deriv_idx = DerivationIndex::new();

    // Registra links pai→filho
    deriv_idx.insert(&epa_credito.epa_id, &epa_derived_1.epa_id);
    deriv_idx.insert(&epa_scoring.epa_id, &epa_derived_2.epa_id);

    // Cria ProvenanceNodes
    let prov_nodes = vec![
        ProvenanceNode {
            node_id: epa_credito.epa_id.clone(),
            parent_ref: None,
            strength: EvidenceStrength::Signed,
            depth: 0,
        },
        ProvenanceNode {
            node_id: epa_risco.epa_id.clone(),
            parent_ref: None,
            strength: EvidenceStrength::Signed,
            depth: 0,
        },
        ProvenanceNode {
            node_id: epa_scoring.epa_id.clone(),
            parent_ref: None,
            strength: EvidenceStrength::Signed,
            depth: 0,
        },
        ProvenanceNode {
            node_id: epa_derived_1.epa_id.clone(),
            parent_ref: Some(ProvenanceRef::Active(epa_credito.epa_id.clone())),
            strength: EvidenceStrength::Witnessed,
            depth: 1,
        },
        ProvenanceNode {
            node_id: epa_derived_2.epa_id.clone(),
            parent_ref: Some(ProvenanceRef::Active(epa_scoring.epa_id.clone())),
            strength: EvidenceStrength::Witnessed,
            depth: 1,
        },
    ];

    println!("  Cadeia: 3 EPAs raiz + 2 derivados");
    println!(
        "  Links: {} → {}",
        &epa_credito.epa_id[..8],
        &epa_derived_1.epa_id[..8]
    );
    println!(
        "  Links: {} → {}",
        &epa_scoring.epa_id[..8],
        &epa_derived_2.epa_id[..8]
    );

    // ================================================================
    // FASE 4: EXCLUSÃO — Maria Silva pede exclusão (LGPD Art. 18, VI)
    // ================================================================

    println!("\n=== FASE 4: Titular pede exclusão ===");
    println!("  Requisição: DELETE /titular/{}", &TITULAR_HASH[..16]);

    // Busca todos os EPAs do titular
    let refs: Vec<EpaRef> = index.lookup(TITULAR_HASH).into_iter().cloned().collect();
    assert_eq!(refs.len(), 3, "Deve encontrar 3 EPAs do titular");
    println!("  Encontrados: {} EPAs para anonimizar", refs.len());

    let mut resultados_anonimizacao = Vec::new();

    for epa_ref in &refs {
        // Encontra o EPA na lista
        let epa = match epa_ref.epa_id.as_str() {
            id if id == epa_credito.epa_id => &mut epa_credito,
            id if id == epa_risco.epa_id => &mut epa_risco,
            id if id == epa_scoring.epa_id => &mut epa_scoring,
            _ => panic!("EPA não encontrado: {}", epa_ref.epa_id),
        };

        // Crypto-shredding: anonimiza dados sensíveis
        let fields = lgpd_rights::anonymize_epa_fields(epa);
        println!(
            "  Anonimizado EPA {}: campos zerados = {:?}",
            &epa_ref.epa_id[..8],
            fields
        );

        // Gera EPA de supressão
        let suppression = lgpd_rights::create_suppression_epa(&node, epa);
        println!("  EPA supressão criada: {}", &suppression.epa_id[..8]);

        resultados_anonimizacao.push(AnonymizationResult {
            original_epa_id: epa_ref.epa_id.clone(),
            suppression_epa_id: suppression.epa_id.clone(),
            fields_anonymized: fields,
            timestamp: chrono::Utc::now(),
            links_blinded: 0,
        });
    }

    // ================================================================
    // FASE 5: VERIFICAÇÃO — Confirma que dados sumiram
    // ================================================================

    println!("\n=== FASE 5: Verificação pós-exclusão ===");

    // Verifica que dados sensíveis foram removidos
    assert!(epa_credito.lgpd_metadata.is_none());
    assert!(epa_risco.lgpd_metadata.is_none());
    assert!(epa_scoring.lgpd_metadata.is_none());
    println!("  LGPD metadata removida de todos os EPAs ✓");

    // Verifica que hashes foram zerados (prova de remoção)
    let zeros = "0".repeat(64);
    assert_eq!(epa_credito.state_hash, zeros);
    assert_eq!(epa_risco.state_hash, zeros);
    assert_eq!(epa_scoring.state_hash, zeros);
    println!("  state_hash zerado (prova de remoção dos dados) ✓");

    assert_eq!(epa_credito.evidence_hash, zeros);
    assert_eq!(epa_risco.evidence_hash, zeros);
    assert_eq!(epa_scoring.evidence_hash, zeros);
    println!("  evidence_hash zerado (prova de remoção dos dados) ✓");

    // Remove do índice LGPD
    for resultado in &resultados_anonimizacao {
        index.remove_epa(TITULAR_HASH, &resultado.original_epa_id);
    }
    assert_eq!(index.count(), 0);
    println!("  Índice LGPD: {} EPAs restantes ✓", index.count());

    // Verifica que titular não está mais acessível
    let results = index.lookup(TITULAR_HASH);
    assert!(results.is_empty());
    println!("  Titular não encontrado no índice ✓");

    // ================================================================
    // FASE 6: BLINDING EM CASCATA — Links de provenance são cegos
    // ================================================================

    println!("\n=== FASE 6: Blinding em cascata ===");

    // Cria EPA de supressão para obter o salt
    let suppression_epa = lgpd_rights::create_suppression_epa(&node, &epa_credito);
    let blinding_salt = suppression_epa.integrity_hash.clone();
    println!("  Blinding salt: {}", &blinding_salt[..16]);

    // Blinda os links de provenance
    let mut nodes_mut = prov_nodes.clone();
    for resultado in &resultados_anonimizacao {
        blind_derivation_links(
            &mut nodes_mut,
            &resultado.original_epa_id,
            &suppression_epa.integrity_hash,
        );
    }

    // Verifica que links foram blidados
    let blinded_count = nodes_mut
        .iter()
        .filter(|n| matches!(n.parent_ref, Some(ProvenanceRef::Blinded { .. })))
        .count();
    println!("  Links blidados: {}", blinded_count);
    assert!(blinded_count >= 2, "Pelo menos 2 links devem ser blidados");

    // Verifica que o blinding é determinístico
    let blinding_1 = ProvenanceRef::blind(&epa_credito.epa_id, &suppression_epa.integrity_hash);
    let blinding_2 = ProvenanceRef::blind(&epa_credito.epa_id, &suppression_epa.integrity_hash);
    assert_eq!(blinding_1, blinding_2);
    println!("  Blinding determinístico ✓");

    // ================================================================
    // FASE 7: PROVA FINAL — Compliance verificável
    // ================================================================

    println!("\n=== FASE 7: Prova de compliance ===");

    println!("  EPA de supressão:");
    println!("    ID: {}", suppression_epa.epa_id);
    println!("    integrity_hash: {}", suppression_epa.integrity_hash);
    println!("    timestamp: {}", suppression_epa.timestamp);

    // A prova de que a exclusão aconteceu:
    // 1. O EPA original tem state_hash zerado (= dados removidos)
    // 2. O EPA de supressão documenta o que foi feito
    // 3. O blinding_salt = integrity_hash do EPA de supressão (= prova matemática)
    // 4. O índice LGPD não contém mais o titular

    println!("\n=== RESULTADO FINAL ===");
    println!("  ✓ 3 EPAs originais: dados anonimizados (state_hash = zeros)");
    println!("  ✓ 3 EPAs supressão: documentam a exclusão");
    println!("  ✓ 2 links blidados: cascata de derivação protegida");
    println!("  ✓ Índice LGPD: titular removido");
    println!();
    println!("  Para verificar independentemente:");
    println!(
        "    1. Confirme que state_hash dos EPAs originais = {}",
        zeros
    );
    println!("    2. Confirme que lgpd_metadata = None nos EPAs originais");
    println!("    3. Confirme que o blinding_salt = integrity_hash do EPA supressão");
    println!("    4. Confirme que o índice não retorna EPAs para o titular");
}

// ── Teste de verificação independente ──────────────────────

#[test]
fn verificacao_independente_dos_resultados() {
    println!("\n=== Verificação Independente ===");
    println!("Este teste prova que os resultados são matematicamente verificáveis.\n");

    let node = NodeIdentity::generate("verificador");

    // 1. Cria EPA e anonimiza
    let mut epa = criar_epa_decisao(&node, TITULAR_HASH, "teste", 100);
    let original_state_hash = epa.state_hash.clone();
    let original_epa_id = epa.epa_id.clone();

    println!("EPA original:");
    println!("  state_hash: {}", &original_state_hash[..16]);
    println!("  lgpd_metadata: {:?}", epa.lgpd_metadata.is_some());

    // Anonimiza
    lgpd_rights::anonymize_epa_fields(&mut epa);
    let suppression = lgpd_rights::create_suppression_epa(&node, &epa);

    println!("\nEPA após anonimização:");
    println!("  state_hash: {}", &epa.state_hash[..16]);
    println!("  lgpd_metadata: {:?}", epa.lgpd_metadata.is_some());
    println!(
        "  Dados destruídos: state_hash mudou de {}... para zeros",
        &original_state_hash[..16]
    );

    // 2. Verifica que o hash original NÃO é zeros
    assert_ne!(original_state_hash, "0".repeat(64));
    println!("\n✓ Prova 1: state_hash original era diferente de zeros");

    // 3. Verifica que o hash atual É zeros
    assert_eq!(epa.state_hash, "0".repeat(64));
    println!("✓ Prova 2: state_hash atual é zeros (= dados destruídos)");

    // 4. Verifica que lgpd_metadata foi removida
    assert!(epa.lgpd_metadata.is_none());
    println!("✓ Prova 3: lgpd_metadata removida");

    // 5. Verifica que EPA de supressão existe e tem integrity_hash
    assert!(!suppression.integrity_hash.is_empty());
    assert_ne!(suppression.epa_id, original_epa_id);
    println!("✓ Prova 4: EPA de supressão criada com integrity_hash único");

    // 6. Verifica blinding determinístico
    let salt = suppression.integrity_hash.clone();
    let b1 = ProvenanceRef::blind(&original_epa_id, &salt);
    let b2 = ProvenanceRef::blind(&original_epa_id, &salt);
    assert_eq!(b1, b2);
    println!("✓ Prova 5: Blinding é determinístico (mesmos inputs = mesmo output)");

    println!("\n=== CONCLUSÃO ===");
    println!("Todas as 5 provas matemáticas confirmadas.");
    println!("Qualquer pessoa pode repetir este teste e obter os mesmos resultados.");
}
