//! feedback_loop.rs — Ciclo de aprendizado
//!
//! Responde: "O que aprendi? O que devo fazer diferente?"
//!
//! Fluxo: Executar → Resultado → Bom? → Guardar → Atualizar padrões
//!        → Atualizar regras → Nova tentativa
//!
//! "Sem feedback, não há aprendizado. Sem aprendizado, não há evolução."

use crate::hash::canonical_hash;
use crate::nex::iteration::{Iteration, IterationLog, Outcome, SystemState};
use crate::nex::pattern_detector::PatternDetector;
use crate::nex::rule_adjuster::RuleAdjuster;

/// Resultado de uma iteração do feedback loop
#[derive(Debug, Clone)]
pub struct FeedbackResult {
    #[allow(dead_code)]
    pub iteration_id: u64,
    pub padroes_novos: usize,
    #[allow(dead_code)]
    pub ajustes_sugeridos: usize,
    #[allow(dead_code)]
    pub ajustes_aplicados: usize,
    pub score: f64,
    pub motivo: String,
    #[allow(dead_code)]
    pub hash: String,
}

/// O ciclo de aprendizado completo
pub struct FeedbackLoop {
    detector: PatternDetector,
    adjuster: RuleAdjuster,
    last_score: f64,
    total_iterations: usize,
}

impl Default for FeedbackLoop {
    fn default() -> Self {
        Self::new()
    }
}

impl FeedbackLoop {
    pub fn new() -> Self {
        Self {
            detector: PatternDetector::new().com_thresholds(3, 0.5),
            adjuster: RuleAdjuster::new(),
            last_score: 0.0,
            total_iterations: 0,
        }
    }

    /// Executa uma iteração completa do ciclo
    pub fn executar(&mut self, log: &mut IterationLog) -> FeedbackResult {
        self.total_iterations += 1;

        // 1. Lê histórico
        let historico = log.todas();

        // 2. Alimenta detector com todas as iterações
        for iter in &historico {
            self.detector.alimentar(iter);
        }

        // 3. Detecta padrões
        let padroes = self.detector.detectar(&historico);
        let padroes_novos = padroes.len();

        // 4. Analisa e sugere ajustes
        let ajustes = self.adjuster.analisar(&padroes);
        let ajustes_sugeridos = ajustes.len();

        // 5. Aplica ajustes (com confiança > 0.7)
        let mut ajustes_aplicados = 0;
        for ajuste in &ajustes {
            if ajuste.confianca > 0.7 {
                self.adjuster.aplicar(ajuste);
                ajustes_aplicados += 1;
            }
        }

        // 6. Calcula score
        let score = self.calcular_score(&historico, &padroes);
        let delta = score - self.last_score;
        self.last_score = score;

        // 7. Registra iteração
        let estado = if let Some(ultima) = historico.last() {
            ultima.estado_anterior.clone()
        } else {
            SystemState {
                build_ok: true,
                warnings: 0,
                tests_passed: 0,
                tests_failed: 0,
                clippy_ok: true,
                fmt_ok: true,
            }
        };

        let acao = crate::nex::iteration::Action {
            tipo: "feedback_loop".into(),
            descricao: format!(
                "padroes={}, ajustes_sugeridos={}, ajustes_aplicados={}, score={:.4}, delta={:+.4}",
                padroes_novos, ajustes_sugeridos, ajustes_aplicados, score, delta
            ),
            arquivos: vec![],
        };

        let resultado = if ajustes_aplicados > 0 {
            Outcome::Sucesso {
                mensagem: format!("{} ajustes aplicados", ajustes_aplicados),
            }
        } else if padroes_novos > 0 {
            Outcome::NenhumaAcao {
                motivo: format!(
                    "{} padrões detectados, nenhum ajuste necessário",
                    padroes_novos
                ),
            }
        } else {
            Outcome::NenhumaAcao {
                motivo: "Nenhum padrão novo detectado".into(),
            }
        };

        let hash_anterior = historico.last().map(|i| i.hash.clone());
        let iter = log.registrar(estado, acao, resultado, None, hash_anterior);

        let content = format!(
            "{}:{}:{}:{}:{}:{}",
            iter.id, padroes_novos, ajustes_sugeridos, ajustes_aplicados, score, delta
        );
        let hash = canonical_hash(&content);

        FeedbackResult {
            iteration_id: iter.id,
            padroes_novos,
            ajustes_sugeridos,
            ajustes_aplicados,
            score,
            motivo: if ajustes_aplicados > 0 {
                format!("{} ajustes aplicados", ajustes_aplicados)
            } else if padroes_novos > 0 {
                format!("{} padrões detectados", padroes_novos)
            } else {
                "nenhuma mudança".into()
            },
            hash,
        }
    }

    /// Calcula score baseado no histórico
    fn calcular_score(
        &self,
        historico: &[Iteration],
        padroes: &[crate::nex::pattern_detector::Pattern],
    ) -> f64 {
        if historico.is_empty() {
            return 0.0;
        }

        let sucessos = historico
            .iter()
            .filter(|i| matches!(i.resultado, Outcome::Sucesso { .. }))
            .count();
        let falhas = historico
            .iter()
            .filter(|i| matches!(i.resultado, Outcome::Falha { .. }))
            .count();

        let taxa_sucesso = sucessos as f64 / historico.len() as f64;
        let bonus_padroes = padroes.len() as f64 * 0.01;
        let penalidade_falhas = falhas as f64 * 0.05;

        (taxa_sucesso + bonus_padroes - penalidade_falhas).max(0.0)
    }

    /// Resumo do ciclo
    #[allow(dead_code)]
    pub fn resumo(&self) -> String {
        format!(
            "iterações={}, score={:.4}, detector={}, regras={}, ajustes={}",
            self.total_iterations,
            self.last_score,
            self.detector.resumo(),
            self.adjuster.num_regras(),
            self.adjuster.num_ajustes()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn feedback_loop_executa() {
        let dir = tempdir().unwrap();
        let mut log = IterationLog::new(dir.path());
        let mut loop_ = FeedbackLoop::new();

        // Registra algumas iterações iniciais
        for i in 0..5 {
            let estado = SystemState {
                build_ok: true,
                warnings: 0,
                tests_passed: 100 + i,
                tests_failed: 0,
                clippy_ok: true,
                fmt_ok: true,
            };
            log.registrar(
                estado,
                crate::nex::iteration::Action {
                    tipo: "verificacao".into(),
                    descricao: format!("iter {}", i),
                    arquivos: vec![],
                },
                Outcome::Sucesso {
                    mensagem: "ok".into(),
                },
                None,
                None,
            );
        }

        let result = loop_.executar(&mut log);
        assert!(result.score >= 0.0);
        assert!(!result.hash.is_empty());
    }

    #[test]
    fn feedback_loop_score_melhora() {
        let dir = tempdir().unwrap();
        let mut log = IterationLog::new(dir.path());
        let mut loop_ = FeedbackLoop::new();

        // Iterações com sucesso
        for _i in 0..10 {
            log.registrar(
                SystemState {
                    build_ok: true,
                    warnings: 0,
                    tests_passed: 100,
                    tests_failed: 0,
                    clippy_ok: true,
                    fmt_ok: true,
                },
                crate::nex::iteration::Action {
                    tipo: "fix".into(),
                    descricao: "".into(),
                    arquivos: vec![],
                },
                Outcome::Sucesso {
                    mensagem: "ok".into(),
                },
                None,
                None,
            );
        }

        let result = loop_.executar(&mut log);
        assert!(result.score > 0.5); // Alta taxa de sucesso
    }
}
