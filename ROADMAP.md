# ROADMAP.md — NexoIA

Visão de longo prazo. Itens aqui são **intenções**, não trabalho em andamento.

---

## Fase 5: EPA Verifier (crate standalone)

**Objetivo:** Criar um crate mínimo e independente para verificação de EPAs por terceiros.

**Por que:** Hoje, verificar um EPA requer rodar o nó completo ou importar o crate inteiro. Auditores, reguladores e devs externos precisam de uma ferramenta leve que:
- Aceite um arquivo EPA (JSON)
- Verifique assinatura Ed25519 + integridade BLAKE3 + timestamp
- Retorne resultado verificável (ok/erro com motivo)
- Não dependa de tokio, axum, ou qualquer infraestrutura de rede

**Formato:** `cargo install nexoia-verifier` ou `use nexoia_verifier::verify_epa(json)`

**Status:** Conceito. Não iniciado.

---

## Fase 6: Agente de Manutenção Assistida por IA (conceito)

**Objetivo:** Agente que propõe mudanças ao código com supervisão humana obrigatória.

**Princípios:**
- **Não autônomo** — toda mudança precisa de aprovação humana antes de commit
- **Orientado pelas regras do AGENTS.md** — lock order, integração obrigatória, testes
- **Transparencia** — mostra exatamente o que vai mudar e por quê
- **Reversível** — cada mudança é um commit atômico que pode ser revertido

**Casos de uso:**
- Atualizar dependências (cargo update + testes automáticos)
- Identificar dead code que pode ser removido (com verificação contra AGENTS.md)
- Sugerir otimizações de performance com benchmarks
- Atualizar números em documentação (testes, linhas de código)

**Status:** Conceito. Não iniciado. Requer pesquisa sobre limites de autonomia segura.

---

## Itens Resolvidos (histórico)

- ✅ Fase 1: Sincronização e verdade verificável (commits, docs audit, CI)
- ✅ Fase 2: Testes adversariais de rede + THREAT_MODEL.md
- ✅ Fase 3: ReactiveRuleSnapshot roundtrip completo + roadmap
- 🔄 Fase 4: Caso de uso E2E LGPD (próxima)
