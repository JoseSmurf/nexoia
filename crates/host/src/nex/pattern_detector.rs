//! pattern_detector.rs — Detecção de padrões no histórico
//!
//! Responde: "O que acontece repetidamente?"
//!
//! Arquitetura: History → Feature Extractor → PatternDetector → Knowledge
//! Padrões são detectados como frequência + causalidade + correlação.
//!
//! "Todo padrão é uma hipótese. Toda hipótese precisa de evidência."

use crate::nex::iteration::Iteration;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Tipo de padrão detectado
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PatternKind {
    /// Mesmo resultado sempre após mesma ação
    Recorrencia,
    /// Ação A sempre precede resultado B
    Causalidade,
    /// Dois resultados aparecem juntos
    Correlacao,
    /// Padrão aparece em intervalos regulares
    Periodicidade,
}

/// Um padrão detectado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub kind: PatternKind,
    pub descricao: String,
    pub frequencia: usize,
    pub confianca: f64,
    pub evidencia: Vec<String>,
}

/// Feature extraída de uma iteração
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Feature {
    pub categoria: String,
    pub valor: String,
}

/// Detector de padrões
pub struct PatternDetector {
    features: HashMap<Feature, usize>,
    #[allow(dead_code)]
    padroes: Vec<Pattern>,
    min_frequencia: usize,
    min_confianca: f64,
}

impl Default for PatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternDetector {
    pub fn new() -> Self {
        Self {
            features: HashMap::new(),
            padroes: Vec::new(),
            min_frequencia: 3,
            min_confianca: 0.6,
        }
    }

    pub fn com_thresholds(mut self, min_freq: usize, min_conf: f64) -> Self {
        self.min_frequencia = min_freq;
        self.min_confianca = min_conf;
        self
    }

    /// Extrai features de uma iteração
    pub fn extrair_features(iter: &Iteration) -> Vec<Feature> {
        let mut features = Vec::new();

        // Features do estado
        features.push(Feature {
            categoria: "build".into(),
            valor: if iter.estado_anterior.build_ok {
                "ok"
            } else {
                "fail"
            }
            .into(),
        });
        features.push(Feature {
            categoria: "tests".into(),
            valor: if iter.estado_anterior.tests_failed == 0 {
                "pass".into()
            } else {
                "fail".into()
            },
        });
        features.push(Feature {
            categoria: "warnings".into(),
            valor: if iter.estado_anterior.warnings == 0 {
                "clean".into()
            } else {
                format!("w{}", iter.estado_anterior.warnings)
            },
        });

        // Features da ação
        features.push(Feature {
            categoria: "acao_tipo".into(),
            valor: iter.acao.tipo.clone(),
        });

        // Features do resultado
        match &iter.resultado {
            crate::nex::iteration::Outcome::Sucesso { .. } => {
                features.push(Feature {
                    categoria: "resultado".into(),
                    valor: "sucesso".into(),
                });
            }
            crate::nex::iteration::Outcome::Falha { .. } => {
                features.push(Feature {
                    categoria: "resultado".into(),
                    valor: "falha".into(),
                });
            }
            crate::nex::iteration::Outcome::NenhumaAcao { .. } => {
                features.push(Feature {
                    categoria: "resultado".into(),
                    valor: "neutro".into(),
                });
            }
        }

        features
    }

    /// Alimenta o detector com uma iteração
    pub fn alimentar(&mut self, iter: &Iteration) {
        let features = Self::extrair_features(iter);
        for feature in features {
            *self.features.entry(feature).or_insert(0) += 1;
        }
    }

    /// Detecta padrões no histórico acumulado
    pub fn detectar(&self, historico: &[Iteration]) -> Vec<Pattern> {
        let mut padroes = Vec::new();

        // Padrão 1: Recorrência (mesma feature sempre aparece)
        for (feature, freq) in &self.features {
            if *freq >= self.min_frequencia {
                let confianca = *freq as f64 / historico.len() as f64;
                if confianca >= self.min_confianca {
                    padroes.push(Pattern {
                        kind: PatternKind::Recorrencia,
                        descricao: format!(
                            "{}={} aparece {} vezes ({:.0}%)",
                            feature.categoria,
                            feature.valor,
                            freq,
                            confianca * 100.0
                        ),
                        frequencia: *freq,
                        confianca,
                        evidencia: vec![format!("feature={}:{}", feature.categoria, feature.valor)],
                    });
                }
            }
        }

        // Padrão 2: Causalidade (ação X sempre segue de estado Y)
        let mut causal_pairs: HashMap<(String, String), usize> = HashMap::new();
        for iter in historico {
            let estado_key = format!(
                "build:{}:tests:{}",
                iter.estado_anterior.build_ok,
                iter.estado_anterior.tests_failed == 0
            );
            let pair = (estado_key, iter.acao.tipo.clone());
            *causal_pairs.entry(pair).or_insert(0) += 1;
        }

        for ((estado, acao), freq) in &causal_pairs {
            if *freq >= self.min_frequencia {
                padroes.push(Pattern {
                    kind: PatternKind::Causalidade,
                    descricao: format!(
                        "Quando {}, ação '{}' é executada {} vezes",
                        estado, acao, freq
                    ),
                    frequencia: *freq,
                    confianca: *freq as f64 / historico.len() as f64,
                    evidencia: vec![format!("causal:{}→{}", estado, acao)],
                });
            }
        }

        // Padrão 3: Correlação (resultado X aparece com Feature Y)
        let mut corr_pairs: HashMap<(String, String), usize> = HashMap::new();
        for iter in historico {
            let resultado = match &iter.resultado {
                crate::nex::iteration::Outcome::Sucesso { .. } => "sucesso",
                crate::nex::iteration::Outcome::Falha { .. } => "falha",
                crate::nex::iteration::Outcome::NenhumaAcao { .. } => "neutro",
            };
            let pair = (iter.acao.tipo.clone(), resultado.to_string());
            *corr_pairs.entry(pair).or_insert(0) += 1;
        }

        for ((acao, resultado), freq) in &corr_pairs {
            if *freq >= self.min_frequencia {
                padroes.push(Pattern {
                    kind: PatternKind::Correlacao,
                    descricao: format!("Ação '{}' resulta em '{}' {} vezes", acao, resultado, freq),
                    frequencia: *freq,
                    confianca: *freq as f64 / historico.len() as f64,
                    evidencia: vec![format!("corr:{}→{}", acao, resultado)],
                });
            }
        }

        // Ordena por confiança
        padroes.sort_by(|a, b| b.confianca.partial_cmp(&a.confianca).unwrap());
        padroes
    }

    /// Resumo do detector
    #[allow(dead_code)]
    pub fn resumo(&self) -> String {
        format!(
            "features={}, padroes_detectados={}, min_freq={}, min_conf={:.2}",
            self.features.len(),
            self.padroes.len(),
            self.min_frequencia,
            self.min_confianca
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nex::iteration::*;

    fn criar_iter(tipo: &str, resultado: Outcome) -> Iteration {
        Iteration {
            id: 1,
            timestamp: 0,
            timestamp_iso: "2026-01-01T00:00:00Z".into(),
            estado_anterior: SystemState {
                build_ok: true,
                warnings: 0,
                tests_passed: 100,
                tests_failed: 0,
                clippy_ok: true,
                fmt_ok: true,
            },
            acao: Action {
                tipo: tipo.into(),
                descricao: "".into(),
                arquivos: vec![],
            },
            resultado,
            lição: None,
            hash: "abc123".into(),
            hash_anterior: None,
        }
    }

    #[test]
    fn detector_extrai_features() {
        let iter = criar_iter(
            "verificacao",
            Outcome::Sucesso {
                mensagem: "ok".into(),
            },
        );
        let features = PatternDetector::extrair_features(&iter);
        assert!(features
            .iter()
            .any(|f| f.categoria == "build" && f.valor == "ok"));
        assert!(features
            .iter()
            .any(|f| f.categoria == "resultado" && f.valor == "sucesso"));
    }

    #[test]
    fn detector_detecta_recorrencia() {
        let mut detector = PatternDetector::new().com_thresholds(3, 0.5);
        let historico: Vec<Iteration> = (0..5)
            .map(|i| {
                let mut iter = criar_iter(
                    "verificacao",
                    Outcome::Sucesso {
                        mensagem: "ok".into(),
                    },
                );
                iter.id = i;
                iter
            })
            .collect();

        for iter in &historico {
            detector.alimentar(iter);
        }

        let padroes = detector.detectar(&historico);
        assert!(!padroes.is_empty());
        assert!(padroes.iter().any(|p| p.kind == PatternKind::Recorrencia));
    }

    #[test]
    fn detector_detecta_causalidade() {
        let mut detector = PatternDetector::new().com_thresholds(3, 0.3);
        let historico: Vec<Iteration> = (0..5)
            .map(|i| {
                let mut iter = criar_iter(
                    "fix",
                    Outcome::Sucesso {
                        mensagem: "ok".into(),
                    },
                );
                iter.id = i;
                iter
            })
            .collect();

        for iter in &historico {
            detector.alimentar(iter);
        }

        let padroes = detector.detectar(&historico);
        assert!(padroes.iter().any(|p| p.kind == PatternKind::Causalidade));
    }
}
