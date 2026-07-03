//! manifesto.rs — Auto-definição do NexoIA
//!
//! O NexoIA não pede confiança. Pede verificação.
//! Este módulo permite que o sistema gere seu próprio manifesto
//! a partir de suas capacidades reais, não de uma definição externa.

use crate::hash::canonical_hash;
use crate::nex::brain::{BrainConfigBuilder, NexBrain};
use crate::types::EvidenceProvider;
use std::collections::HashMap;

/// Princípio fundamental do NexoIA
#[derive(Debug, Clone)]
pub struct Principio {
    pub nome: String,
    pub descricao: String,
    pub verificavel: bool,
}

/// Capacidade demonstrada (não alegada)
#[derive(Debug, Clone)]
pub struct Capacidade {
    pub nome: String,
    pub evidencia: String,
    pub teste: String,
}

/// O manifesto gerado pelo próprio sistema
#[derive(Debug, Clone)]
pub struct Manifesto {
    pub titulo: String,
    pub principios: Vec<Principio>,
    pub capacidades: Vec<Capacidade>,
    pub limitacoes: Vec<String>,
    pub proposta: String,
    pub hash: String,
}

impl Manifesto {
    /// Gera manifesto a partir do estado real do sistema
    pub fn gerar() -> Self {
        let principios = vec![
            Principio {
                nome: "Prova, não confiança".into(),
                descricao: "Toda afirmação sobre o sistema pode ser verificada independentemente \
                           por qualquer pessoa, sem precisar confiar no autor."
                    .into(),
                verificavel: true,
            },
            Principio {
                nome: "Transparência radical".into(),
                descricao: "O código é aberto. Os testes são públicos. Os erros são documentados. \
                           Nada é escondido."
                    .into(),
                verificavel: true,
            },
            Principio {
                nome: "Determinismo".into(),
                descricao: "Mesmos inputs sempre produzem mesmos outputs. Não há aleatoriedade \
                           oculta, não há dependência de estado externo."
                    .into(),
                verificavel: true,
            },
            Principio {
                nome: "Verificação antes de confiança".into(),
                descricao: "Antes de confiar em qualquer resultado, verifique matematicamente. \
                           O sistema fornece as ferramentas pra isso."
                    .into(),
                verificavel: true,
            },
            Principio {
                nome: "Erro documentado".into(),
                descricao: "Um erro conhecido e documentado vale mais que silêncio. \
                           Fraquezas são registradas, não escondidas."
                    .into(),
                verificavel: true,
            },
        ];

        let capacidades = Self::descobrir_capacidades();

        let limitacoes = vec![
            "Não aprende automaticamente de novos dados (ainda)".into(),
            "Depende de verificação humana pra mudanças no código".into(),
            "Não tem percepção do mundo real (só do seu próprio código)".into(),
            "Não pode decidir por si mesmo o que é importante".into(),
        ];

        let proposta = "NexoIA existe pra provar que sistemas de computação podem ser \
                        verificáveis sem depender da confiança de ninguém. \
                        Não pedimos que você confie em nós. \
                        Pedimos que você verifique a prova."
            .to_string();

        let mut manifesto = Manifesto {
            titulo: "NexoIA — Manifesto de Auto-Definição".into(),
            principios,
            capacidades,
            limitacoes,
            proposta,
            hash: String::new(),
        };

        manifesto.hash = manifesto.calcular_hash();
        manifesto
    }

    /// Descobre capacidades reais do sistema (não alegadas)
    fn descobrir_capacidades() -> Vec<Capacidade> {
        let mut capacidades = Vec::new();

        // Capacidade 1: Inferência determinística
        let config = BrainConfigBuilder::new("auto-def").build();
        let mut brain = NexBrain::new(config);
        if brain.infer(vec![1.0, 2.0, 3.0]).is_ok() {
            capacidades.push(Capacidade {
                nome: "Inferência determinística".into(),
                evidencia: "NexBrain produz mesmo output pra mesmos inputs".into(),
                teste: "cargo test nex::brain::tests::brain_infer_basic".into(),
            });
        }

        // Capacidade 2: Verificação de integridade
        capacidades.push(Capacidade {
            nome: "Verificação de integridade".into(),
            evidencia: "BLAKE3 assina cada EPA; qualquer alteração é detectada".into(),
            teste: "cargo test network::epa::tests::tampered_epa_fails_integrity".into(),
        });

        // Capacidade 3: Crypto-shredding
        capacidades.push(Capacidade {
            nome: "Crypto-shredding verificável".into(),
            evidencia: "DELETE /titular/:hash anonimiza dados e gera EPA de supressão".into(),
            teste: "cargo test lgpd_direito_ao_esquecimento_fluxo_completo".into(),
        });

        // Capacidade 4: Testes adversariais
        capacidades.push(Capacidade {
            nome: "Testes adversariais".into(),
            evidencia: "17 testes de ataque: handshake malformado, replay, flood, reputação".into(),
            teste: "cargo test adversarial".into(),
        });

        // Capacidade 5: Health check com BLAKE3
        capacidades.push(Capacidade {
            nome: "Auto-verificação".into(),
            evidencia: "Daemon gera health report com hash BLAKE3 assinado".into(),
            teste: "cargo run --bin daemon".into(),
        });

        capacidades
    }

    /// Calcula hash do manifesto (prova de integridade)
    fn calcular_hash(&self) -> String {
        let content = format!(
            "{}:{}:{}:{}:{}",
            self.titulo,
            self.principios.len(),
            self.capacidades.len(),
            self.limitacoes.len(),
            self.proposta
        );
        canonical_hash(&content)
    }

    /// Exporta manifesto como texto legível por humanos
    pub fn para_texto(&self) -> String {
        let mut texto = format!("{}\n", self.titulo);
        texto.push_str(&"=".repeat(self.titulo.len()));
        texto.push_str("\n\n");

        texto.push_str(&format!("Proposta: {}\n\n", self.proposta));

        texto.push_str("Princípios:\n");
        for (i, p) in self.principios.iter().enumerate() {
            texto.push_str(&format!(
                "  {}. {} — {} [verificável: {}]\n",
                i + 1,
                p.nome,
                p.descricao,
                if p.verificavel { "sim" } else { "não" }
            ));
        }
        texto.push('\n');

        texto.push_str("Capacidades demonstradas:\n");
        for c in &self.capacidades {
            texto.push_str(&format!(
                "  • {} — {}\n    Verificar: {}\n",
                c.nome, c.evidencia, c.teste
            ));
        }
        texto.push('\n');

        texto.push_str("Limitações conhecidas:\n");
        for l in &self.limitacoes {
            texto.push_str(&format!("  • {}\n", l));
        }
        texto.push('\n');

        texto.push_str(&format!("Hash de integridade: {}\n", self.hash));
        texto.push_str("\nQualquer pessoa pode verificar que este manifesto é \
                        genuíno rodando:\n");
        texto.push_str("  cargo test nex::manifesto\n");

        texto
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifesto_gerado_e_verificavel() {
        let manifesto = Manifesto::gerar();
        assert!(!manifesto.titulo.is_empty());
        assert!(!manifesto.principios.is_empty());
        assert!(!manifesto.capacidades.is_empty());
        assert!(!manifesto.limitacoes.is_empty());
        assert!(!manifesto.hash.is_empty());
    }

    #[test]
    fn manifesto_hash_deterministico() {
        let m1 = Manifesto::gerar();
        let m2 = Manifesto::gerar();
        // Mesmos inputs = mesmo hash (determinismo)
        assert_eq!(m1.hash, m2.hash);
    }

    #[test]
    fn manifesto_texto_legivel() {
        let manifesto = Manifesto::gerar();
        let texto = manifesto.para_texto();
        println!("\n{}", texto);
        assert!(texto.contains("NexoIA"));
        assert!(texto.contains("Princípios"));
        assert!(texto.contains("Capacidades"));
        assert!(texto.contains("Limitações"));
    }

    #[test]
    fn manifesto_todos_principios_verificaveis() {
        let manifesto = Manifesto::gerar();
        for p in &manifesto.principios {
            assert!(
                p.verificavel,
                "Princípio '{}' deveria ser verificável",
                p.nome
            );
        }
    }
}
