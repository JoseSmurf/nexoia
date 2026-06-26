# AGENTS.md — NexoIA

Instruções para IAs de código (GitHub Copilot, Cursor, Claude Code, Codex, etc).

---

## Visão Geral

**NexoIA** é um motor de computação determinística em Rust (~11.200 linhas) que gera **EPAs (Evidence Proof Artifacts)**:

```
BLAKE3(input) + Ed25519(signature) + timestamp anti-replay = prova matemática imutável
```

Não é log. Não é auditoria. É **prova**. Qualquer pessoa verifica sem confiar em ninguém.

**Insight central**: prova e confiança são coisas diferentes. Todo sistema de auditoria funciona com confiança. NexoIA funciona com verificação.

**LGPD não pede que você faça o certo. Pede que você PROVE.**

---

## Estado Atual

- 618 testes verdes
- LGPD Nível 1 (metadata) + Nível 2 (direitos do titular) implementados
- 4 endpoints LGPD: `GET /titular/:hash/dados`, `GET /titular/:hash/export`, `DELETE /titular/:hash`, `POST /titular/:hash/revogar`
- Rede P2P com 15 módulos (handshake, heartbeat, reputação, sessão, transporte seguro)
- Linguagem NEX (DSL para compliance) com parser, avaliador, motor reativo
- Rate limiter sharded com 64 shards

---

## Comandos

```bash
# Build & Test (ordem CI obrigatória)
cargo fmt --check          # Formatação (CI enforced — deve passar antes de build/test)
cargo build                # Build
cargo test                 # Todos os testes

# Run
cargo run                  # Nó único
cargo run --bin nex -- examples/hello.nex   # Interpretador NEX
cargo run --bin verify                      # Verificação de EPA

# Multi-node
NEXOIA_API_PORT=3001 NEXOIA_UDP_PORT=9001 NEXOIA_BOOTSTRAP_PEERS=127.0.0.1:9000 cargo run

# Com LGPD
NEXOIA_LGPD_BASIS=consentimento NEXOIA_LGPD_PURPOSE=processamento NEXOIA_LGPD_RETENTION_DAYS=365 cargo run
```

---

## Arquitetura

| Arquivo | Propósito | Linhas |
|---------|-----------|--------|
| `src/main.rs` | Entry point + pipeline + rede P2P | 318 |
| `src/lib.rs` | Re-exports de todos os módulos | 13 |
| `src/pipeline.rs` | Orquestração state→EPA + manifest LGPD | 195 |
| `src/state.rs` | State de execução + LGPD metadata | 129 |
| `src/lgpd.rs` | LawfulBasis, LgpdMetadata, validate() | 191 |
| `src/lgpd_rights.rs` | EpaRef, LgpdIndex, anonimização, EPA de supressão | — |
| `src/defense.rs` | Validação + RateLimiter sharded 64 shards | 229 |
| `src/decision.rs` | Classificação determinística OK/VIOLACAO/ABSTERSE | 230 |
| `src/explain.rs` | Diagnóstico + conflitos + load_decisions_jsonl | 404 |
| `src/types.rs` | EvidenceStrength, NexAssertion, EvidenceProvider | 42 |
| `src/hash.rs` | BLAKE3 canônico | 20 |
| `src/limits.rs` | Constantes anti-DoS | 36 |
| `src/ai.rs` | MockEngine placeholder | 96 |
| `src/quality.rs` | Avaliação de evidência | 124 |
| `src/evidence.rs` | Criação de registros de evidência | 136 |

### Módulos Críticos (NUNCA DELETAR)

```
src/nex/              — LINGUAGEM NEX (DSL para compliance)
  ast.rs              — AST (Program, Stmt, Action, Expr, Trigger)         122
  parser.rs           — Lexer + parser manual                               1.158
  eval.rs             — Avaliador + executor + imports                      923
  layers.rs           — Camadas Basic/Intermediate/Advanced                 163
  reactive.rs         — Motor reativo eventos→regras→ações                  358
  checkpoint.rs       — Checkpoints atômicos                                200
  action_executor.rs  — Execução de ações reativas                          170

src/network/          — 15 MÓDULOS P2P
  identity.rs         — NodeIdentity, Ed25519, X25519, ML-KEM
  crypto.rs           — Criptografia
  crypto_key.rs       — Chaves criptográficas
  epa.rs              — SharedEPA, create, create_encrypted
  handshake.rs        — Autenticação mútua challenge-response
  handshake_runner.rs — Execução do handshake
  heartbeat.rs        — Monitoramento de peers (30s interval, 5min timeout)
  session.rs          — SessionManager, sessões ativas
  transport.rs        — UdpTransport, PeerList, TrustedPeerList, NetworkMessage
  secure_transport.rs — Transporte seguro
  reputation.rs       — ReputationStore, ban automático após 10 falhas
  persistence.rs      — Persistência JSON
  api.rs              — REST API (Axum), RateLimiter
  listener.rs         — Discovery broadcast UDP
  verify.rs           — Verificação de EPA

src/provenance/       — Provenance tracking
```

---

## Lock Order (CRÍTICO — Previne Deadlocks)

```
╔══════════════════════════════════════════╗
║           GLOBAL LOCK ORDER             ║
║  1. peer_states  (heartbeat tracking)   ║
║  2. sessions     (SessionManager)       ║
║  3. peers        (PeerList/TrustedPeer) ║
║  4. reputation   (ReputationStore)      ║
╚══════════════════════════════════════════╝
```

**Sempre** adquirir locks nesta ordem. **Nunca** inverter.

---

## EvidenceStrength (Hierarquia de Prova)

```
Unverifiable < Local < Witnessed < Signed < Anchored
```

Força efetiva de uma decisão = `min(left, right)`. Conservadorismo é feature, não bug.

---

## Linguagem NEX

DSL tipada para nós de evidência. Ver `docs/NEX_GRAMMAR.md` e `docs/NEX_SEMANTICS.md`.

**Constructos principais:**

```nex
let id = node expr strength     # Cria nó de evidência
assert id >= strength           # Gate de força
act id = action requires strength  # Registro de decisão
```

---

## Rede P2P

- **Identidade**: Ed25519 (assinatura) + X25519 (ECDH) + ML-KEM (PQC)
- **Handshake**: Challenge-response mútuo
- **Heartbeat**: 30s interval, timeout 5min
- **Reputação**: Ban automático após 10 falhas consecutivas
- **Transporte**: UDP com criptografia AES-GCM/ChaCha20Poly1305
- **Discovery**: Broadcast UDP
- **API REST**: Axum com rate limiter sharded (64 shards)

---

## LGPD

### Variáveis de Ambiente

| Variável | Obrigatório | Valores / Default |
|----------|-------------|-------------------|
| `NEXOIA_LGPD_BASIS` | Sim* | `consentimento`, `contrato`, `obrigacao_legal`, `interesse_legitimo`, `vida_fisica`, `funcao_publica`, `interesse_vital` |
| `NEXOIA_LGPD_PURPOSE` | Sim* | String livre |
| `NEXOIA_LGPD_RETENTION_DAYS` | Sim* | Inteiro |
| `NEXOIA_LGPD_DATA_SUBJECT_HASH` | Não | Hash do titular |
| `NEXOIA_LGPD_DPIA_REF` | Não | Referência DPIA |
| `NEXOIA_LGPD_CONSENT_ID` | Não | ID do consentimento |

*Obrigatório quando `LGPD_BASIS` está setado.

### Endpoints

| Método | Rota | Descrição |
|--------|------|-----------|
| `GET` | `/titular/:hash/dados` | Consulta dados do titular |
| `GET` | `/titular/:hash/export` | Exporta dados (portabilidade) |
| `DELETE` | `/titular/:hash` | Supressão (anonimiza + EPA de supressão) |
| `POST` | `/titular/:hash/revogar` | Revogação de consentimento |

### Regra de Anonimização

**EPA NUNCA é deletado.** Quando titular pede exclusão:
1. Anonimiza dados **dentro** do EPA
2. Gera **NOVO EPA de supressão** provando a anonimização

---

## Convenções

- **Determinístico e reproduzível** — mesmos inputs = mesmos outputs
- **BLAKE3** para todo hashing canônico (não SHA256, não MD5)
- **JSONL** para evidence e decisions
- **Rust edition 2021**
- Todos outputs devem ser verificáveis independentemente

---

## Integração (Regras Obrigatórias)

### Regra: Feature sem integração não está pronta

Escrever código + testes **NÃO** é suficiente. A feature só está pronta quando:

1. Está conectada a quem vai chamá-la (pipeline, API, outro módulo)
2. Tem teste de integração (não só unitário)
3. O fluxo E2E funciona (input → processamento → output verificável)

### Checklist de integração (antes de commitar)

- [ ] A função/struct está sendo chamada por alguém? Se não, **POR QUÊ?**
- [ ] Se é API pública (endpoint), o handler está registrada no router?
- [ ] Se é módulo novo, está importado e usado em `main.rs` ou `pipeline.rs`?
- [ ] Se gera dados, quem consome esses dados? Está acessível?
- [ ] Se é feature LGPD, os dados estão indexados no `LgpdIndex`?
- [ ] Se modifica EPA, a mudança é visível via API `GET /epa/list`?
- [ ] Se adiciona env var, está documentada na seção Env vars?

### Regra: Não criar módulo "pra depois"

Se você cria uma função e não conecta agora, documente:
- **QUANDO** vai conectar (qual feature depende dela)
- **ONDE** ela se conecta (qual módulo/pipeline/API)
- **POR QUE** não conectou agora (dependência externa? API não existe ainda?)

**Exemplo correto:**
```rust
// TODO(connect): create_encrypted() precisa ser chamada por POST /epa/encrypted
// que ainda não existe. Quando endpoint for criado, chamar SharedEPA::create_encrypted()
// dentro do handler. Depende de: recipient_public_key via API request body.
pub fn create_encrypted(...) { ... }
```

**Exemplo errado:**
```rust
// TODO: implementar depois
pub fn create_encrypted(...) { ... }
```

### Regra: Pipeline é o centro

O pipeline (`src/pipeline.rs`) é o fluxo principal:
```
State → Defense → AI → Quality → Decision → Evidence → EPA → Manifest → Rede
```

Tudo que se conecta ao pipeline se conecta ao produto.
Tudo que **não** se conecta ao pipeline é infraestrutura morta.

Antes de commitar feature nova, pergunte:
> **"Onde isso se encaixa no pipeline?"**

### Regra: Teste de integração > teste unitário

- Unit test prova que a **função** funciona.
- Integration test prova que o **sistema** funciona.

Para cada feature nova, escreva pelo menos 1 teste que:
1. Cria input real (não mock)
2. Passa pelo pipeline
3. Verifica output final (EPA, manifest, API response)

### Regra: Visibilidade via API

Se o módulo produz dados, esses dados precisam ser acessíveis via API:

| Dados | Endpoint |
|-------|----------|
| EPAs | `GET /epa/list` |
| Decisões | `GET /epa/:id/verify` |
| Titular | `GET /titular/:hash/dados` |
| Health | `GET /health` |

---

## Regras Críticas (O QUE NÃO FAZER)

### ❌ NUNCA deletar
- Funções, structs, enums ou módulos de:
  - `src/nex/`
  - `src/network/`
  - `src/provenance/`
  - `src/explain.rs`
  - `src/types.rs`

### ❌ NÃO assumir "dead code"
- "Não chamado hoje" ≠ "dead code" — É "não conectado ainda"
- Funções não conectadas que **NÃO deletar**:
  - `create_encrypted()`
  - `load_decisions_jsonl()`
  - `verify_signature_only()`
  - `send_raw()`
  - `broadcast()`

### ❌ NUNCA inverter lock order
- Ordem: `peer_states` → `sessions` → `peers` → `reputation`

### ❌ NUNCA usar hashing não-canônico
- Apenas BLAKE3 via `src/hash.rs`

### ❌ NUNCA mutar EPA existente
- EPA é imutável. Supressão = novo EPA de prova.

---

## Variáveis de Ambiente Completas

### Configuração do Nó

| Variável | Default | Descrição |
|----------|---------|-----------|
| `NEXOIA_API_PORT` | 8080 | Porta REST API |
| `NEXOIA_UDP_PORT` | 9000 | Porta UDP P2P |
| `NEXOIA_BROADCAST_PORT` | 9001 | Porta broadcast discovery |
| `NEXOIA_MAX_PEERS` | 10 | Máximo de peers |
| `NEXOIA_NODE_NAME` | nexoia-node | Nome do nó |
| `NEXOIA_DATA_DIR` | data | Diretório de dados |
| `NEXOIA_PASSPHRASE` | (nenhum) | **Recomendado em produção** |
| `NEXOIA_DISABLE_ENCRYPTION` | false | Desabilita criptografia |
| `NEXOIA_BOOTSTRAP_PEERS` | (nenhum) | Peers iniciais `ip:port` |

### Pipeline

| Variável | Default | Descrição |
|----------|---------|-----------|
| `NEXOIA_SCENARIO` | auto | `auto`, `ok`, `violacao`, `absterse` |
| `NEXOIA_SUBJECT` | default-evaluation | Subject da avaliação |
| `NEXOIA_THRESHOLD` | 50 | Threshold de decisão |
| `NEXOIA_INPUT_VALUE` | 60 | Valor de entrada |

### LGPD (ver seção LGPD acima)

---

## Dependências Rust Principais

```
blake3, ed25519-dalek, serde, serde_json, tokio, axum,
chrono, uuid, aes-gcm, chacha20poly1305, ml-kem,
x25519-dalek, rusqlite
```

---

## Referências

- `docs/NEX_GRAMMAR.md` — Gramática da linguagem NEX
- `docs/NEX_SEMANTICS.md` — Semântica da linguagem NEX
- `examples/hello.nex` — Exemplo básico NEX