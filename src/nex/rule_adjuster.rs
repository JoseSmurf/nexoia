//! rule_adjuster.rs — Ajuste automático de regras
//!
//! Responde: "Como melhorar minhas regras?"
//!
//! Nunca modifica código Rust. Modifica ASTs — estruturas de dados
//! que representam regras. Estruturas podem ser modificadas com segurança.
//!
//! "Uma regra é um dado. Dados podem ser mutados. Código compilado não."

use crate::nex::pattern_detector::Pattern;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Tipo de ajuste
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AjusteKind {
    /// Ajusta limiar numérico (ex: timeout de 50 para 120)
    AjustarLimiar,
    /// Adiciona condição (ex: CPU > 90% → adicionar AND memória > 80%)
    AdicionarCondicao,
    /// Remove condição obsoleta
    RemoverCondicao,
    /// Troca estratégia (ex: busca linear → HashMap)
    TrocarEstrategia,
    /// Não há ajuste necessário
    Nenhum,
}

/// Uma regra representada como AST
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Regra {
    /// Condição simples: campo, operador, valor
    Condicao {
        campo: String,
        operador: String,
        valor: f64,
    },
    /// Combinação AND de regras
    E(Vec<Regra>),
    /// Combinação OR de regras
    Ou(Vec<Regra>),
    /// Negação de regra
    Nao(Box<Regra>),
    /// Ação a ser executada quando regra é verdadeira
    Acao {
        condicao: Box<Regra>,
        acao: String,
    },
}

/// Resultado de um ajuste
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AjusteResultado {
    pub kind: AjusteKind,
    pub regra_antes: Regra,
    pub regra_depois: Regra,
    pub justificativa: String,
    pub confianca: f64,
}

/// Módulo de ajuste de regras
pub struct RuleAdjuster {
    regras: Vec<Regra>,
    historico_ajustes: Vec<AjusteResultado>,
    max_historico: usize,
}

impl RuleAdjuster {
    pub fn new() -> Self {
        Self {
            regras: Vec::new(),
            historico_ajustes: Vec::new(),
            max_historico: 1000,
        }
    }

    pub fn com_regras(regras: Vec<Regra>) -> Self {
        Self {
            regras,
            historico_ajustes: Vec::new(),
            max_historico: 1000,
        }
    }

    /// Analisa padrões e sugere ajustes
    pub fn analisar(&self, padroes: &[Pattern]) -> Vec<AjusteResultado> {
        let mut ajustes = Vec::new();

        for padrao in padroes {
            // Padrão de recorrência → pode ajustar limiar
            if padrao.frequencia > 10 && padrao.confianca > 0.8 {
                ajustes.push(AjusteResultado {
                    kind: AjusteKind::AjustarLimiar,
                    regra_antes: Regra::Condicao {
                        campo: padrao.evidencia.first().cloned().unwrap_or_default(),
                        operador: ">".into(),
                        valor: 0.0,
                    },
                    regra_depois: Regra::Condicao {
                        campo: padrao.evidencia.first().cloned().unwrap_or_default(),
                        operador: ">".into(),
                        valor: padrao.confianca * 100.0,
                    },
                    justificativa: format!(
                        "Padrão recorrente detectado: {} (freq={}, conf={:.2})",
                        padrao.descricao, padrao.frequencia, padrao.confianca
                    ),
                    confianca: padrao.confianca,
                });
            }

            // Padrão causal → pode adicionar condição
            if padrao.kind == crate::nex::pattern_detector::PatternKind::Causalidade
                && padrao.confianca > 0.7
            {
                ajustes.push(AjusteResultado {
                    kind: AjusteKind::AdicionarCondicao,
                    regra_antes: Regra::Condicao {
                        campo: "default".into(),
                        operador: ">".into(),
                        valor: 0.0,
                    },
                    regra_depois: Regra::E(vec![
                        Regra::Condicao {
                            campo: "default".into(),
                            operador: ">".into(),
                            valor: 0.0,
                        },
                        Regra::Condicao {
                            campo: padrao.evidencia.first().cloned().unwrap_or_default(),
                            operador: "contains".into(),
                            valor: 1.0,
                        },
                    ]),
                    justificativa: format!(
                        "Causalidade detectada: {}",
                        padrao.descricao
                    ),
                    confianca: padrao.confianca,
                });
            }
        }

        ajustes
    }

    /// Aplica um ajuste às regras
    pub fn aplicar(&mut self, ajuste: &AjusteResultado) {
        self.historico_ajustes.push(ajuste.clone());
        if self.historico_ajustes.len() > self.max_historico {
            self.historico_ajustes.remove(0);
        }
    }

    /// Número de regras
    pub fn num_regras(&self) -> usize {
        self.regras.len()
    }

    /// Número de ajustes feitos
    pub fn num_ajustes(&self) -> usize {
        self.historico_ajustes.len()
    }
}

impl Regra {
    /// Avalia a regra contra um contexto
    pub fn avaliar(&self, ctx: &HashMap<String, f64>) -> bool {
        match self {
            Regra::Condicao {
                campo,
                operador,
                valor,
            } => {
                let v = ctx.get(campo).copied().unwrap_or(0.0);
                match operador.as_str() {
                    ">" => v > *valor,
                    ">=" => v >= *valor,
                    "<" => v < *valor,
                    "<=" => v <= *valor,
                    "==" => (v - *valor).abs() < f64::EPSILON,
                    "!=" => (v - *valor).abs() >= f64::EPSILON,
                    _ => false,
                }
            }
            Regra::E(regras) => regras.iter().all(|r| r.avaliar(ctx)),
            Regra::Ou(regras) => regras.iter().any(|r| r.avaliar(ctx)),
            Regra::Nao(regra) => !regra.avaliar(ctx),
            Regra::Acao { condicao, .. } => condicao.avaliar(ctx),
        }
    }

    /// Profundidade da AST
    pub fn profundidade(&self) -> usize {
        match self {
            Regra::Condicao { .. } => 1,
            Regra::E(regras) | Regra::Ou(regras) => {
                1 + regras.iter().map(|r| r.profundidade()).max().unwrap_or(0)
            }
            Regra::Nao(r) => 1 + r.profundidade(),
            Regra::Acao { condicao, .. } => 1 + condicao.profundidade(),
        }
    }

    /// Número de nós na AST
    pub fn num_nos(&self) -> usize {
        match self {
            Regra::Condicao { .. } => 1,
            Regra::E(regras) | Regra::Ou(regras) => {
                1 + regras.iter().map(|r| r.num_nos()).sum::<usize>()
            }
            Regra::Nao(r) => 1 + r.num_nos(),
            Regra::Acao { condicao, .. } => 1 + condicao.num_nos(),
        }
    }
}

impl std::fmt::Display for Regra {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Regra::Condicao {
                campo,
                operador,
                valor,
            } => write!(f, "{campo} {operador} {valor}"),
            Regra::E(regras) => {
                let parts: Vec<String> = regras.iter().map(|r| format!("({r})")).collect();
                write!(f, "{}", parts.join(" AND "))
            }
            Regra::Ou(regras) => {
                let parts: Vec<String> = regras.iter().map(|r| format!("({r})")).collect();
                write!(f, "{}", parts.join(" OR "))
            }
            Regra::Nao(r) => write!(f, "NOT ({r})"),
            Regra::Acao { condicao, acao } => write!(f, "IF {condicao} THEN {acao}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regra_avaliacao_simples() {
        let regra = Regra::Condicao {
            campo: "cpu".into(),
            operador: ">".into(),
            valor: 80.0,
        };
        let mut ctx = HashMap::new();
        ctx.insert("cpu".into(), 90.0);
        assert!(regra.avaliar(&ctx));

        ctx.insert("cpu".into(), 70.0);
        assert!(!regra.avaliar(&ctx));
    }

    #[test]
    fn regra_avaliacao_and() {
        let regra = Regra::E(vec![
            Regra::Condicao {
                campo: "cpu".into(),
                operador: ">".into(),
                valor: 80.0,
            },
            Regra::Condicao {
                campo: "ram".into(),
                operador: ">".into(),
                valor: 70.0,
            },
        ]);

        let mut ctx = HashMap::new();
        ctx.insert("cpu".into(), 90.0);
        ctx.insert("ram".into(), 80.0);
        assert!(regra.avaliar(&ctx));

        ctx.insert("ram".into(), 60.0);
        assert!(!regra.avaliar(&ctx));
    }

    #[test]
    fn regra_profundidade() {
        let regra = Regra::E(vec![
            Regra::Condicao {
                campo: "a".into(),
                operador: ">".into(),
                valor: 1.0,
            },
            Regra::Ou(vec![
                Regra::Condicao {
                    campo: "b".into(),
                    operador: ">".into(),
                    valor: 2.0,
                },
                Regra::Condicao {
                    campo: "c".into(),
                    operador: ">".into(),
                    valor: 3.0,
                },
            ]),
        ]);
        assert_eq!(regra.profundidade(), 3);
        assert_eq!(regra.num_nos(), 5);
    }

    #[test]
    fn rule_adjuster_analisa_padroes() {
        use crate::nex::pattern_detector::{Pattern, PatternKind};

        let padroes = vec![Pattern {
            kind: PatternKind::Recorrencia,
            descricao: "build=ok aparece 15 vezes".into(),
            frequencia: 15,
            confianca: 0.9,
            evidencia: vec!["build=ok".into()],
        }];

        let adjuster = RuleAdjuster::new();
        let ajustes = adjuster.analisar(&padroes);
        assert_eq!(ajustes.len(), 1);
        assert_eq!(ajustes[0].kind, AjusteKind::AjustarLimiar);
    }
}
