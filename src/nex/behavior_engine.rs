//! behavior_engine.rs — Behavior Engine: o elo entre conhecimento e ação
//!
//! O cérebro não modifica os músculos. Ele envia sinais.
//! Os músculos executam. Depois os sensores enviam informações de volta.
//!
//! Ciclo: Pensar → Agir → Observar → Aprender → Pensar melhor
//!
//! "O motor nunca muda. O comportamento muda o tempo inteiro."

use crate::hash::canonical_hash;
use crate::nex::feedback_loop::{FeedbackLoop, FeedbackResult};
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
}

impl BehaviorEngine {
    pub fn new(data_dir: &Path, project_dir: &std::path::Path) -> Self {
        let knowledge_dir = data_dir.join("knowledge");
        fs::create_dir_all(&knowledge_dir).ok();

        let knowledge = Self::carregar_knowledge(&knowledge_dir);

        Self {
            knowledge_dir,
            knowledge,
            feedback: FeedbackLoop::new(),
            awareness: SelfAwareness::new(project_dir.to_path_buf()),
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
        self.aprender(&execucao, &feedback);

        // 5. Salva conhecimento
        self.salvar_knowledge();

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

    /// PENSAR: analisa estado observado + histórico e gera plano
    fn pensar(&self, log: &IterationLog, observacao: &ObservedState) -> Plano {
        let historico = log.todas();
        let mut acoes = Vec::new();

        // Se o build quebrou, prioridade máxima: investigar
        if !observacao.build_ok {
            acoes.push(AcaoPlanejada {
                tipo: "corrigir_build".into(),
                parametro: "build".into(),
                esperado: "build falhou — corrigir imediatamente".into(),
            });
        }

        // Se testes falharam, investigar
        if observacao.tests_failed > 0 {
            acoes.push(AcaoPlanejada {
                tipo: "corrigir_testes".into(),
                parametro: "tests".into(),
                esperado: format!("{} testes falharam", observacao.tests_failed),
            });
        }

        // Se há warnings, tentar limpar
        if observacao.build_warnings + observacao.clippy_warnings > 0 {
            acoes.push(AcaoPlanejada {
                tipo: "limpar_warnings".into(),
                parametro: "warnings".into(),
                esperado: format!(
                    "{} warnings (build) + {} warnings (clippy)",
                    observacao.build_warnings, observacao.clippy_warnings
                ),
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
                Outcome::NenhumaAcao { motivo } => {
                    if motivo.contains("padrão") {
                        acoes.push(AcaoPlanejada {
                            tipo: "otimizar".into(),
                            parametro: format!("iter_{}", iter.id),
                            esperado: "explorar padrão detectado".into(),
                        });
                    }
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
            "Estado observado: build={}, tests={}/{}, warnings={}, clippy={}, fmt={} | {} iterações analisadas → {} ações planejadas",
            if observacao.build_ok { "OK" } else { "FALHOU" },
            observacao.tests_passed,
            observacao.tests_failed,
            observacao.build_warnings + observacao.clippy_warnings,
            if observacao.clippy_ok { "OK" } else { "FALHOU" },
            if observacao.fmt_ok { "OK" } else { "FALHOU" },
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

    /// APRENDER: atualiza conhecimento baseado no resultado
    fn aprender(&mut self, execucao: &ExecucaoResultado, feedback: &FeedbackResult) {
        self.knowledge.iteracoes += 1;
        self.knowledge.ultimo_hash = execucao.hash.clone();

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

    /// Estado atual do conhecimento
    #[allow(dead_code)]
    pub fn knowledge(&self) -> &Knowledge {
        &self.knowledge
    }

    /// Resumo do Behavior Engine
    #[allow(dead_code)]
    pub fn resumo(&self) -> String {
        format!(
            "iterações={}, regras={}, score={:.4}, último_hash={}",
            self.knowledge.iteracoes,
            self.knowledge.regras.len(),
            self.knowledge
                .metricas
                .get("score_atual")
                .copied()
                .unwrap_or(0.0),
            &self.knowledge.ultimo_hash[..16.min(self.knowledge.ultimo_hash.len())]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_project_dir() -> PathBuf {
        std::env::var("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    }

    #[test]
    fn behavior_engine_ciclo() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let project = test_project_dir();
        let mut log = IterationLog::new(&data_dir);
        let mut engine = BehaviorEngine::new(&data_dir, &project);

        let resultado = engine.ciclo(&mut log);
        assert!(resultado.score >= 0.0);
        assert!(!resultado.hash.is_empty());
    }

    #[test]
    fn knowledge_persistente() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let project = test_project_dir();

        {
            let mut log = IterationLog::new(&data_dir);
            let mut engine = BehaviorEngine::new(&data_dir, &project);
            engine.ciclo(&mut log);
        }

        // Recarrega e verifica que knowledge persistiu
        let engine2 = BehaviorEngine::new(&data_dir, &project);
        assert_eq!(engine2.knowledge.iteracoes, 1);
    }

    #[test]
    fn behavior_engine_resumo() {
        let dir = tempdir().unwrap();
        let project = test_project_dir();
        let engine = BehaviorEngine::new(dir.path(), &project);
        let resumo = engine.resumo();
        assert!(resumo.contains("iterações="));
        assert!(resumo.contains("regras="));
    }
}
