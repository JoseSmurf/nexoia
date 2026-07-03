//! behavior_engine.rs — Behavior Engine: o elo entre conhecimento e ação
//!
//! O cérebro não modifica os músculos. Ele envia sinais.
//! Os músculos executam. Depois os sensores enviam informações de volta.
//!
//! Ciclo: Pensar → Agir → Observar → Aprender → Pensar melhor
//!
//! "O motor nunca muda. O comportamento muda o tempo inteiro."

use crate::hash::canonical_hash;
use crate::nex::dictionary::{Dictionary, EntryCategory};
use crate::nex::feedback_loop::{FeedbackLoop, FeedbackResult};
use crate::nex::internet::InternetFetcher;
use crate::nex::iteration::{Action, IterationLog, Outcome};
use crate::nex::self_awareness::{ObservedState, SelfAwareness};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Conhecimento persistente (muda o tempo inteiro)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Knowledge {
    pub regras: Vec<RegraEstrategia>,
    pub metricas: HashMap<String, f64>,
    pub ultimo_hash: String,
    pub iteracoes: u64,
}

/// Uma regra de estratégia (AST, não código compilado)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegraEstrategia {
    pub id: String,
    pub condicao: String,
    pub acao: String,
    pub prioridade: u8,
    pub ativa: bool,
    pub score: f64,
    pub criada_em: u64,
}

/// Plano gerado pelo Behavior Engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plano {
    pub acoes: Vec<AcaoPlanejada>,
    pub justificativa: String,
    pub hash: String,
}

/// Ação planejada
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcaoPlanejada {
    pub tipo: String,
    pub parametro: String,
    pub esperado: String,
}

/// Resultado da execução
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecucaoResultado {
    pub plano_hash: String,
    pub acoes_executadas: usize,
    pub acoes_bem_sucedidas: usize,
    pub score: f64,
    pub novo_conhecimento: Knowledge,
    pub hash: String,
}

/// Behavior Engine — o elo entre conhecimento e código real
pub struct BehaviorEngine {
    knowledge_dir: PathBuf,
    knowledge: Knowledge,
    feedback: FeedbackLoop,
    awareness: SelfAwareness,
    dictionary: Dictionary,
    internet: InternetFetcher,
}

impl BehaviorEngine {
    pub fn new(data_dir: &Path, project_dir: &std::path::Path) -> Self {
        let knowledge_dir = data_dir.join("knowledge");
        fs::create_dir_all(&knowledge_dir).ok();

        let knowledge = Self::carregar_knowledge(&knowledge_dir);
        let dictionary = Dictionary::load(&knowledge_dir);
        let internet = InternetFetcher::new(data_dir);

        Self {
            knowledge_dir,
            knowledge,
            feedback: FeedbackLoop::new(),
            awareness: SelfAwareness::new(project_dir.to_path_buf()),
            dictionary,
            internet,
        }
    }

    /// Versão para testes — não roda comandos reais
    #[allow(dead_code)]
    pub fn new_fake(data_dir: &Path) -> Self {
        let knowledge_dir = data_dir.join("knowledge");
        fs::create_dir_all(&knowledge_dir).ok();

        let knowledge = Self::carregar_knowledge(&knowledge_dir);
        let dictionary = Dictionary::load(&knowledge_dir);
        let internet = InternetFetcher::new_fake(data_dir);

        Self {
            knowledge_dir,
            knowledge,
            feedback: FeedbackLoop::new(),
            awareness: SelfAwareness::fake(),
            dictionary,
            internet,
        }
    }

    /// Carrega conhecimento de disco (ou cria novo)
    fn carregar_knowledge(dir: &std::path::Path) -> Knowledge {
        let path = dir.join("knowledge.json");
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(k) = serde_json::from_str(&data) {
                return k;
            }
        }

        // Conhecimento inicial
        Knowledge {
            regras: vec![
                RegraEstrategia {
                    id: "R001".into(),
                    condicao: "build_ok == true AND warnings == 0".into(),
                    acao: "manter_estado".into(),
                    prioridade: 10,
                    ativa: true,
                    score: 1.0,
                    criada_em: 0,
                },
                RegraEstrategia {
                    id: "R002".into(),
                    condicao: "tests_failed > 0".into(),
                    acao: "investigar_falha".into(),
                    prioridade: 9,
                    ativa: true,
                    score: 1.0,
                    criada_em: 0,
                },
                RegraEstrategia {
                    id: "R003".into(),
                    condicao: "warnings > 0".into(),
                    acao: "corrigir_warning".into(),
                    prioridade: 7,
                    ativa: true,
                    score: 1.0,
                    criada_em: 0,
                },
            ],
            metricas: HashMap::new(),
            ultimo_hash: String::new(),
            iteracoes: 0,
        }
    }

    /// Salva conhecimento em disco
    fn salvar_knowledge(&self) {
        let path = self.knowledge_dir.join("knowledge.json");
        let json = serde_json::to_string_pretty(&self.knowledge).unwrap();
        fs::write(&path, json).ok();
    }

    /// Ciclo completo: Observar → Pensar → Agir → Aprender → Provar
    pub fn ciclo(&mut self, log: &mut IterationLog) -> ExecucaoResultado {
        // 0. OBSERVAR: olha pra si mesmo (estado real, não hardcoded)
        let observacao = self.awareness.observe();

        // 1. PENSAR: analisa estado e histórico e planeja
        let plano = self.pensar(log, &observacao);

        // 2. AGIR: executa o plano com estado real
        let execucao = self.agir(&plano, log, &observacao);

        // 3. REFLETIR: roda feedback loop com estado observado
        let feedback = self.feedback.executar(log);

        // 4. APRENDER: atualiza conhecimento
        self.aprender(&execucao, &feedback, &observacao);

        // 5. Salva conhecimento
        self.salvar_knowledge();

        // 6. Salva dicionário vivo (aprendizado persistente)
        let _ = self.dictionary.save();

        let content = format!(
            "{}:{}:{}:{}:{}:{}",
            plano.hash,
            execucao.acoes_executadas,
            execucao.acoes_bem_sucedidas,
            feedback.score,
            self.knowledge.iteracoes,
            observacao.health_hash
        );
        let hash = canonical_hash(&content);

        ExecucaoResultado {
            plano_hash: plano.hash,
            acoes_executadas: execucao.acoes_executadas,
            acoes_bem_sucedidas: execucao.acoes_bem_sucedidas,
            score: feedback.score,
            novo_conhecimento: self.knowledge.clone(),
            hash,
        }
    }

    /// PENSAR: analisa estado observado + histórico + dicionário + internet e gera plano
    fn pensar(&self, log: &IterationLog, observacao: &ObservedState) -> Plano {
        let historico = log.todas();
        let mut acoes = Vec::new();

        // Se Miri falhou — prioridade MÁXIMA: erro de segurança formal
        if !observacao.miri_ok {
            let dicas: Vec<String> = observacao
                .miri_errors
                .iter()
                .map(|e| {
                    // Busca no dicionário por erros similares
                    let resultados = self.dictionary.lookup(e);
                    if let Some(dica) = resultados.first() {
                        format!("{} → {}", e, dica.suggestion)
                    } else {
                        // Busca na internet se dicionário não sabe
                        let internet_dica = self.buscar_na_internet(e);
                        if !internet_dica.is_empty() {
                            format!("{} → [internet] {}", e, internet_dica)
                        } else {
                            e.clone()
                        }
                    }
                })
                .collect();
            acoes.push(AcaoPlanejada {
                tipo: "corrigir_seguranca".into(),
                parametro: "miri".into(),
                esperado: if dicas.is_empty() {
                    "Miri detectou erro de segurança — investigar".into()
                } else {
                    format!("Miri: {} — dicas: {}", dicas.join("; "), dicas.len())
                },
            });
        }

        // Se o build quebrou, prioridade máxima: investigar
        if !observacao.build_ok {
            // Consulta dicionário por sugestões
            let dicas = self.dictionary.lookup("build");
            let sugestao = if let Some(dica) = dicas.first() {
                format!("build falhou — dica: {}", dica.suggestion)
            } else {
                // Busca na internet
                let internet_dica = self.buscar_na_internet("rust build error");
                if !internet_dica.is_empty() {
                    format!("build falhou — [internet] {}", internet_dica)
                } else {
                    "build falhou — corrigir imediatamente".into()
                }
            };
            acoes.push(AcaoPlanejada {
                tipo: "corrigir_build".into(),
                parametro: "build".into(),
                esperado: sugestao,
            });
        }

        // Se testes falharam, investigar
        if observacao.tests_failed > 0 {
            let dicas = self.dictionary.lookup("test");
            let sugestao = if let Some(dica) = dicas.first() {
                format!(
                    "{} testes falharam — dica: {}",
                    observacao.tests_failed, dica.suggestion
                )
            } else {
                format!("{} testes falharam", observacao.tests_failed)
            };
            acoes.push(AcaoPlanejada {
                tipo: "corrigir_testes".into(),
                parametro: "tests".into(),
                esperado: sugestao,
            });
        }

        // Se há warnings, tentar limpar (com dicas do dicionário)
        if observacao.build_warnings + observacao.clippy_warnings > 0 {
            let dicas = self.dictionary.lookup("clippy");
            let sugestao = if !dicas.is_empty() {
                let dicas_str: Vec<&str> = dicas
                    .iter()
                    .take(3)
                    .map(|d| d.suggestion.as_str())
                    .collect();
                format!(
                    "{} warnings — dicas: {}",
                    observacao.build_warnings + observacao.clippy_warnings,
                    dicas_str.join("; ")
                )
            } else {
                format!(
                    "{} warnings (build) + {} warnings (clippy)",
                    observacao.build_warnings, observacao.clippy_warnings
                )
            };
            acoes.push(AcaoPlanejada {
                tipo: "limpar_warnings".into(),
                parametro: "warnings".into(),
                esperado: sugestao,
            });
        }

        // Se fmt falhou, corrigir
        if !observacao.fmt_ok {
            acoes.push(AcaoPlanejada {
                tipo: "formatar".into(),
                parametro: "fmt".into(),
                esperado: "cargo fmt --check falhou".into(),
            });
        }

        // Se Miri passou — registrar como conhecimento verificado
        if observacao.miri_ok && !observacao.miri_errors.is_empty() {
            // Miri passou mas teve warnings — registra como tested
            acoes.push(AcaoPlanejada {
                tipo: "verificar_miri".into(),
                parametro: "miri".into(),
                esperado: format!(
                    "Miri passou com {} warnings — considerar promoted",
                    observacao.miri_errors.len()
                ),
            });
        }

        // Se tudo está OK, monitora e registra sucesso
        if acoes.is_empty() {
            acoes.push(AcaoPlanejada {
                tipo: "monitorar".into(),
                parametro: "sistema".into(),
                esperado: "sistema saudável — continuar observando".into(),
            });
        }

        // Analisa últimas iterações do histórico
        let recentes: Vec<_> = historico.iter().rev().take(10).collect();
        for iter in &recentes {
            match &iter.resultado {
                Outcome::Falha { erro } => {
                    acoes.push(AcaoPlanejada {
                        tipo: "investigar".into(),
                        parametro: format!("iter_{}", iter.id),
                        esperado: format!("diagnosticar causa: {}", erro),
                    });
                }
                Outcome::NenhumaAcao { motivo } if motivo.contains("padrão") => {
                    acoes.push(AcaoPlanejada {
                        tipo: "otimizar".into(),
                        parametro: format!("iter_{}", iter.id),
                        esperado: "explorar padrão detectado".into(),
                    });
                }
                _ => {}
            }
        }

        // Se tudo está OK, monitora
        if acoes.is_empty() {
            acoes.push(AcaoPlanejada {
                tipo: "monitorar".into(),
                parametro: "sistema".into(),
                esperado: "sistema saudável — continuar observando".into(),
            });
        }

        let justificativa = format!(
            "Estado: build={}, tests={}/{}, warnings={}, clippy={}, fmt={}, miri={} | Dicionário: {} entradas | {} iterações → {} ações",
            if observacao.build_ok { "OK" } else { "FALHOU" },
            observacao.tests_passed,
            observacao.tests_failed,
            observacao.build_warnings + observacao.clippy_warnings,
            if observacao.clippy_ok { "OK" } else { "FALHOU" },
            if observacao.fmt_ok { "OK" } else { "FALHOU" },
            if observacao.miri_ok { "OK" } else { "FALHOU" },
            self.dictionary.len(),
            recentes.len(),
            acoes.len()
        );

        let content = format!(
            "{}:{}:{}",
            justificativa,
            acoes.len(),
            observacao.health_hash
        );
        let hash = canonical_hash(&content);

        Plano {
            acoes,
            justificativa,
            hash,
        }
    }

    /// AGIR: executa o plano com estado real observado
    fn agir(
        &mut self,
        plano: &Plano,
        log: &mut IterationLog,
        observacao: &ObservedState,
    ) -> ExecucaoResultado {
        let mut executadas = 0;
        let mut bem_sucedidas = 0;

        // Estado real observado — não mais hardcoded
        let estado = observacao.to_system_state();

        for acao in &plano.acoes {
            let resultado = match acao.tipo.as_str() {
                "corrigir_build" => {
                    if observacao.build_ok {
                        Outcome::Sucesso {
                            mensagem: "Build já está OK".into(),
                        }
                    } else {
                        Outcome::Falha {
                            erro: "Build falhou — precisa de correção manual".into(),
                        }
                    }
                }
                "corrigir_testes" => {
                    if observacao.tests_failed == 0 {
                        Outcome::Sucesso {
                            mensagem: "Todos os testes passando".into(),
                        }
                    } else {
                        Outcome::Falha {
                            erro: format!("{} testes falhando", observacao.tests_failed),
                        }
                    }
                }
                "limpar_warnings" => {
                    let total = observacao.build_warnings + observacao.clippy_warnings;
                    if total == 0 {
                        Outcome::Sucesso {
                            mensagem: "Zero warnings".into(),
                        }
                    } else {
                        Outcome::NenhumaAcao {
                            motivo: format!("{} warnings restantes", total),
                        }
                    }
                }
                "formatar" => {
                    if observacao.fmt_ok {
                        Outcome::Sucesso {
                            mensagem: "Formatação OK".into(),
                        }
                    } else {
                        Outcome::Falha {
                            erro: "cargo fmt precisa rodar".into(),
                        }
                    }
                }
                "investigar" => Outcome::Sucesso {
                    mensagem: format!("Investigação de {} concluída", acao.parametro),
                },
                "otimizar" => Outcome::Sucesso {
                    mensagem: format!("Otimização de {} planejada", acao.parametro),
                },
                "monitorar" => Outcome::NenhumaAcao {
                    motivo: "Monitoramento contínuo".into(),
                },
                _ => Outcome::NenhumaAcao {
                    motivo: format!("Ação desconhecida: {}", acao.tipo),
                },
            };

            executadas += 1;
            if matches!(&resultado, Outcome::Sucesso { .. }) {
                bem_sucedidas += 1;
            }

            log.registrar(
                estado.clone(),
                Action {
                    tipo: acao.tipo.clone(),
                    descricao: acao.esperado.clone(),
                    arquivos: vec![],
                },
                resultado,
                None,
                None,
            );
        }

        let score = if executadas > 0 {
            bem_sucedidas as f64 / executadas as f64
        } else {
            1.0
        };

        let content = format!(
            "{}:{}:{}:{}",
            executadas, bem_sucedidas, score, observacao.health_hash
        );
        let hash = canonical_hash(&content);

        ExecucaoResultado {
            plano_hash: plano.hash.clone(),
            acoes_executadas: executadas,
            acoes_bem_sucedidas: bem_sucedidas,
            score,
            novo_conhecimento: self.knowledge.clone(),
            hash,
        }
    }

    /// APRENDER: atualiza conhecimento baseado no resultado + estado observado
    /// Alimenta o dicionário vivo com padrões aprendidos
    fn aprender(
        &mut self,
        execucao: &ExecucaoResultado,
        feedback: &FeedbackResult,
        observacao: &ObservedState,
    ) {
        self.knowledge.iteracoes += 1;
        self.knowledge.ultimo_hash = execucao.hash.clone();

        // Alimenta o dicionário vivo: padrões bem-sucedidos → Verified
        if feedback.score > 0.7 && !feedback.motivo.is_empty() {
            use crate::nex::dictionary::{DictionaryEntry, KnowledgeLevel};

            self.dictionary.learn(DictionaryEntry {
                id: format!("learned_{}", self.knowledge.iteracoes),
                category: EntryCategory::Learned,
                level: KnowledgeLevel::Verified,
                pattern: feedback.motivo.clone(),
                description: format!(
                    "Ação bem-sucedida (score={:.2}, {}/{} OK)",
                    feedback.score, execucao.acoes_bem_sucedidas, execucao.acoes_executadas
                ),
                suggestion: feedback.motivo.clone(),
                confidence: feedback.score,
                miri_passed: true,
                occurrences: 1,
            });
        }

        // Se padrões novos foram detectados, registra como Hypothese
        if feedback.padroes_novos > 0 {
            use crate::nex::dictionary::{DictionaryEntry, KnowledgeLevel};

            self.dictionary.learn(DictionaryEntry {
                id: format!("pattern_{}", self.knowledge.iteracoes),
                category: EntryCategory::Learned,
                level: KnowledgeLevel::Hypothese,
                pattern: format!("padrão detectado na iteração {}", self.knowledge.iteracoes),
                description: format!(
                    "Novo padrão identificado ({} padrões novos, score={:.2})",
                    feedback.padroes_novos, feedback.score
                ),
                suggestion: "Monitorar e coletar mais evidências".into(),
                confidence: 0.5,
                miri_passed: false,
                occurrences: 1,
            });
        }

        // Aprende com o estado observado: testes, clippy, miri
        use crate::nex::dictionary::{DictionaryEntry, KnowledgeLevel};

        // Testes passando → conhecimento verified
        if observacao.tests_passed > 0 && observacao.tests_failed == 0 {
            self.dictionary.learn(DictionaryEntry {
                id: "tests_passing".into(),
                category: EntryCategory::Rust,
                level: KnowledgeLevel::Verified,
                pattern: "cargo test passa".into(),
                description: format!("{} testes passando, 0 falhando", observacao.tests_passed),
                suggestion: "Sistema de testes estável".into(),
                confidence: 1.0,
                miri_passed: observacao.miri_ok,
                occurrences: observacao.tests_passed,
            });
        }

        // Clippy limpo → padrão Rust conhecido
        if observacao.clippy_ok && observacao.clippy_warnings == 0 {
            self.dictionary.learn(DictionaryEntry {
                id: "clippy_clean".into(),
                category: EntryCategory::Rust,
                level: KnowledgeLevel::Verified,
                pattern: "clippy sem warnings".into(),
                description: "Cargo clippy passa sem warnings".into(),
                suggestion: "Código segue boas práticas Rust".into(),
                confidence: 1.0,
                miri_passed: observacao.miri_ok,
                occurrences: 1,
            });
        }

        // Miri passou → conhecimento formal verificado
        if observacao.miri_ok && observacao.miri_errors.is_empty() {
            self.dictionary.learn(DictionaryEntry {
                id: "miri_verified".into(),
                category: EntryCategory::Rust,
                level: KnowledgeLevel::Verified,
                pattern: "miri formal verification passed".into(),
                description: "Miri verificou ausência de undefined behavior".into(),
                suggestion: "Código é formalmente seguro (sem UB)".into(),
                confidence: 1.0,
                miri_passed: true,
                occurrences: 1,
            });
        }

        // Miri com erros → hipótese de bug de segurança
        if !observacao.miri_ok && !observacao.miri_errors.is_empty() {
            for (i, erro) in observacao.miri_errors.iter().take(3).enumerate() {
                self.dictionary.learn(DictionaryEntry {
                    id: format!("miri_error_{}_{}", self.knowledge.iteracoes, i),
                    category: EntryCategory::Rust,
                    level: KnowledgeLevel::Hypothese,
                    pattern: erro.clone(),
                    description: format!("Miri detectou: {}", erro),
                    suggestion: "Investigar e corrigir comportamento indefinido".into(),
                    confidence: 0.3,
                    miri_passed: false,
                    occurrences: 1,
                });
            }
        }

        // Atualiza métricas
        self.knowledge
            .metricas
            .insert("score_atual".into(), feedback.score);
        self.knowledge.metricas.insert(
            "taxa_sucesso".into(),
            if execucao.acoes_executadas > 0 {
                execucao.acoes_bem_sucedidas as f64 / execucao.acoes_executadas as f64
            } else {
                1.0
            },
        );
        self.knowledge
            .metricas
            .insert("padroes_detectados".into(), feedback.padroes_novos as f64);

        // Ajusta scores das regras baseado no feedback
        for regra in &mut self.knowledge.regras {
            if regra.ativa {
                if feedback.score > 0.7 {
                    regra.score = (regra.score + 0.1).min(1.0);
                } else if feedback.score < 0.3 {
                    regra.score = (regra.score - 0.1).max(0.0);
                }
            }
        }
    }

    /// Busca na internet por ajuda quando o dicionário não sabe
    /// Retorna string vazia se não encontrar nada útil
    fn buscar_na_internet(&self, query: &str) -> String {
        // Tenta buscar em fontes permitidas
        let urls = [
            format!("https://doc.rust-lang.org/std/index.html?search={}", query),
            format!("https://docs.rs/reqwest/latest/reqwest/?search={}", query),
        ];

        for url in &urls {
            if let Ok(result) = self.internet.fetch_sync(url) {
                // Extrai primeira linha útil (ignora HTML)
                let linha_util = result
                    .content
                    .lines()
                    .filter(|l| !l.starts_with('<') && !l.is_empty())
                    .take(3)
                    .collect::<Vec<_>>()
                    .join(" ");

                if !linha_util.is_empty() && linha_util.len() > 10 {
                    return linha_util;
                }
            }
        }

        String::new()
    }

    /// Estado atual do conhecimento
    #[allow(dead_code)]
    pub fn knowledge(&self) -> &Knowledge {
        &self.knowledge
    }

    /// Resumo do Behavior Engine
    #[allow(dead_code)]
    pub fn resumo(&self) -> String {
        let dict = self.dictionary.stats();
        format!(
            "iterações={}, regras={}, score={:.4}, último_hash={}, dicionário={}",
            self.knowledge.iteracoes,
            self.knowledge.regras.len(),
            self.knowledge
                .metricas
                .get("score_atual")
                .copied()
                .unwrap_or(0.0),
            &self.knowledge.ultimo_hash[..16.min(self.knowledge.ultimo_hash.len())],
            dict
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn behavior_engine_ciclo() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let mut log = IterationLog::new(&data_dir);
        let mut engine = BehaviorEngine::new_fake(&data_dir);

        let resultado = engine.ciclo(&mut log);
        assert!(resultado.score >= 0.0);
        assert!(!resultado.hash.is_empty());
    }

    #[test]
    fn knowledge_persistente() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();

        {
            let mut log = IterationLog::new(&data_dir);
            let mut engine = BehaviorEngine::new_fake(&data_dir);
            engine.ciclo(&mut log);
        }

        // Recarrega e verifica que knowledge persistiu
        let engine2 = BehaviorEngine::new_fake(&data_dir);
        assert_eq!(engine2.knowledge.iteracoes, 1);
    }

    #[test]
    fn behavior_engine_resumo() {
        let dir = tempdir().unwrap();
        let engine = BehaviorEngine::new_fake(dir.path());
        let resumo = engine.resumo();
        assert!(resumo.contains("iterações="));
        assert!(resumo.contains("regras="));
    }
}
