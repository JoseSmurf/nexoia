# NexoIA

Prova matemática, não confiança. NexoIA é um motor de computação determinística que gera **EPAs (Evidence Proof Artifacts)** — provas imutáveis de o que aconteceu, verificáveis por qualquer pessoa sem confiar em ninguém.

```
BLAKE3(input) + Ed25519(signature) + timestamp anti-replay = prova matemática
```

## Por que importa

Todo sistema de auditoria funciona com confiança. Você confia que o log não foi alterado, que o timestamp está correto, que quem assinou é quem diz ser. NexoIA não pede confiança — pede verificação. Qualquer pessoa pode pegar um EPA e provar, matematicamente, que ele é válido.

**LGPD não pede que você faça o certo. Pede que você PROVE.**

## Arquitetura

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              NexoIA Node                                 │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────── NEX Language ───────────────────────────────┐  │
│  │  Camada Básica:      let, assert, act, derive, attest             │  │
│  │  Camada Intermediária: + if/else condicionais                     │  │
│  │  Camada Avançada:    + on <trigger> comportamentos reativos        │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                    │                                     │
│                                    ▼                                     │
│  ┌──────────── Pipeline Determinístico ───────────────────────────────┐  │
│  │                                                                    │  │
│  │  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌──────────┐         │  │
│  │  │ defense │──▶│   ai    │──▶│ quality │──▶│ decision │         │  │
│  │  │ (valida)│   │(Evidence│   │(avalia) │   │(classif.)│         │  │
│  │  │         │   │ Engine) │   │         │   │          │         │  │
│  │  └─────────┘   └─────────┘   └─────────┘   └────┬─────┘         │  │
│  │       │                                          │                │  │
│  │       ▼                                          ▼                │  │
│  │  ┌─────────┐                              ┌──────────────┐       │  │
│  │  │  state  │                              │   evidence   │       │  │
│  │  │(determin│                              │  (BLAKE3     │       │  │
│  │  │  -istic)│                              │   hashed)    │       │  │
│  │  └─────────┘                              └──────┬───────┘       │  │
│  │                                                  │               │  │
│  │                                                  ▼               │  │
│  │                                          ┌──────────────┐       │  │
│  │                                          │   manifest   │       │  │
│  │                                          │  (EPA final) │       │  │
│  │                                          └──────────────┘       │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                    │                                     │
│                    ┌───────────────┼───────────────┐                     │
│                    ▼               ▼               ▼                     │
│  ┌────────────────────┐ ┌─────────────────┐ ┌──────────────────────┐    │
│  │    Provenance      │ │      LGPD       │ │    Observer          │    │
│  │  ┌──────────────┐  │ │  ┌───────────┐  │ │  ┌──────────────┐   │    │
│  │  │ TypedNode    │  │ │  │ LgpdIndex │  │ │  │ NexObserver   │   │    │
│  │  │ <T, S>       │  │ │  │ (titular) │  │ │  │ (health      │   │    │
│  │  │ compile-time │  │ │  │           │  │ │  │  reports)    │   │    │
│  │  │ strength     │  │ │  │ Crypto-   │  │ │  │              │   │    │
│  │  └──────────────┘  │ │  │ shredding │  │ │  │ 5 áreas:     │   │    │
│  │  ┌──────────────┐  │ │  └───────────┘  │ │  │ EPA, LGPD,   │   │    │
│  │  │ Derivation   │  │ └─────────────────┘ │  │ network,     │   │    │
│  │  │ Index        │  │                     │  │ provenance,  │   │    │
│  │  │ (graph       │  │                     │  │ reputation   │   │    │
│  │  │  blinding)   │  │                     │  └──────────────┘   │    │
│  │  └──────────────┘  │                     └──────────────────────┘    │
│  └────────────────────┘                                                 │
│                                    │                                     │
│                                    ▼                                     │
│  ┌──────────────────────── Network Layer ─────────────────────────────┐  │
│  │                                                                    │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │  │
│  │  │ identity │  │   epa    │  │ transport│  │     api (REST)   │  │  │
│  │  │ Ed25519  │  │ sign +   │  │ UDP +    │  │ 14 endpoints     │  │  │
│  │  │ X25519   │  │ encrypt  │  │ heartbeat│  │ + TLS (opt-in)   │  │  │
│  │  │ ML-KEM   │  │          │  │ + handsh.│  │ + rate limiter   │  │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘  │  │
│  │                                                                    │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │  │
│  │  │reputation│  │ session  │  │ witness  │  │    compliance    │  │  │
│  │  │ (ban     │  │ (anti-   │  │ (external│  │  (math proof of  │  │  │
│  │  │  auto)   │  │  replay) │  │  ledger) │  │   blinding)     │  │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌──────────────────── Persistência ─────────────────────────────────┐  │
│  │  identity.json  network.json  reputation.json  checkpoints/      │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Nó único (para testes locais)
cargo run

# Nó 2 conectando ao Nó 1
NEXOIA_API_PORT=3001 NEXOIA_UDP_PORT=9001 \
NEXOIA_BOOTSTRAP_PEERS=127.0.0.1:9000 cargo run
```

## Rodando Múltiplos Nós

### Exemplo: 3 nós locais

**Terminal 1 — Nó 1 (bootstrap):**
```bash
NEXOIA_API_PORT=3000 NEXOIA_UDP_PORT=9000 \
NEXOIA_NODE_NAME=node_alpha cargo run
```

**Terminal 2 — Nó 2 (conecta ao Nó 1):**
```bash
NEXOIA_API_PORT=3001 NEXOIA_UDP_PORT=9001 \
NEXOIA_BOOTSTRAP_PEERS=127.0.0.1:9000 \
NEXOIA_NODE_NAME=node_beta cargo run
```

**Terminal 3 — Nó 3 (conecta ao Nó 1 e 2):**
```bash
NEXOIA_API_PORT=3002 NEXOIA_UDP_PORT=9002 \
NEXOIA_BOOTSTRAP_PEERS=127.0.0.1:9000,127.0.0.1:9001 \
NEXOIA_NODE_NAME=node_gamma cargo run
```

### Com Passphrase (recomendado)

```bash
NEXOIA_PASSPHRASE="minha-senha-forte" cargo run
```

### Verificando a rede

```bash
curl http://localhost:8080/health          # Health check
curl http://localhost:8080/node           # Info do nó
curl http://localhost:8080/epa/list       # Listar EPAs
curl http://localhost:8080/verify-chain   # Verificar cadeia de provenance
curl http://localhost:8080/compliance/<epa_id>  # Prova matemática de blinding
```

## Variáveis de Ambiente

### Configuração do Nó

| Variável | Default | Descrição | Exemplo |
|----------|---------|-----------|---------|
| `NEXOIA_API_PORT` | `8080` | Porta da API HTTP | `3001` |
| `NEXOIA_UDP_PORT` | `9000` | Porta UDP P2P | `9001` |
| `NEXOIA_BROADCAST_PORT` | `9001` | Porta de broadcast | `9002` |
| `NEXOIA_MAX_PEERS` | `10` | Máximo de peers | `20` |
| `NEXOIA_NODE_NAME` | `nexoia-node` | Nome do nó | `node_alpha` |
| `NEXOIA_DATA_DIR` | `data` | Diretório de dados | `/var/lib/nexoia` |
| `NEXOIA_PASSPHRASE` | (nenhuma) | Passphrase para chaves | `"senha-forte"` |
| `NEXOIA_DISABLE_ENCRYPTION` | `""` | Desabilitar encriptação (`1`) | `1` |
| `NEXOIA_BOOTSTRAP_PEERS` | (nenhum) | Peers iniciais | `"host1:9000,host2:9000"` |

### Pipeline

| Variável | Default | Descrição | Exemplo |
|----------|---------|-----------|---------|
| `NEXOIA_SCENARIO` | `auto` | `auto`, `ok`, `violacao`, `absterse` | `ok` |
| `NEXOIA_SUBJECT` | `default-evaluation` | Subject da avaliação | `user-123` |
| `NEXOIA_THRESHOLD` | `50` | Threshold de decisão | `75` |
| `NEXOIA_INPUT_VALUE` | `60` | Valor de entrada | `80` |

### LGPD

| Variável | Obrigatório | Descrição | Exemplo |
|----------|-------------|-----------|---------|
| `NEXOIA_LGPD_BASIS` | Sim* | Base legal | `consentimento` |
| `NEXOIA_LGPD_PURPOSE` | Sim* | Finalidade | `processamento` |
| `NEXOIA_LGPD_RETENTION_DAYS` | Sim* | Dias de retenção | `365` |
| `NEXOIA_LGPD_DATA_SUBJECT_HASH` | Não | Hash do titular | `abc123...` |

*Obrigatório quando `NEXOIA_LGPD_BASIS` está setado.

### NEX Rules

| Variável | Default | Descrição | Exemplo |
|----------|---------|-----------|---------|
| `NEXOIA_NEX_RULES` | (nenhum) | Caminho para arquivo `.nex` | `rules.nex` |

### TLS (opt-in)

| Variável | Default | Descrição | Exemplo |
|----------|---------|-----------|---------|
| `NEXOIA_TLS_CERT` | (nenhum) | Caminho para certificado TLS | `cert.pem` |
| `NEXOIA_TLS_KEY` | (nenhum) | Caminho para chave privada TLS | `key.pem` |

## Boas Práticas de Segurança

### Passphrase

- **Em produção:** Sempre use `NEXOIA_PASSPHRASE` para criptografar as chaves privadas.
- **Em desenvolvimento:** Pode rodar sem passphrase, mas o nó exibirá um aviso.
- **Arquivo `identity.json`:** Mesmo com passphrase, proteja o arquivo com permissões restritas (0600 no Unix).

### Deploy

- Execute cada nó com `NEXOIA_NODE_NAME` único.
- Use `NEXOIA_DATA_DIR` separado para cada nó.
- Configure `NEXOIA_BOOTSTRAP_PEERS` para nós em redes diferentes.
- Monitore os logs para detectar peers inativos ou banidos.

### Chaves

- **Ed25519:** Assinatura de EPAs e handshake.
- **X25519:** Encriptação de payload entre peers.
- **ML-KEM (Kyber):** Post-quantum key encapsulation no handshake.
- Chaves geradas automaticamente na primeira execução.
- Com passphrase, criptografadas com PBKDF2 + AES-256-GCM.

## Mecanismos de Segurança

| Mecanismo | Descrição |
|-----------|-----------|
| **Handshake** | Autenticação mútua challenge-response com Ed25519 + ML-KEM |
| **Encriptação** | X25519 + ChaCha20-Poly1305 (ou AES-GCM) |
| **Heartbeat** | Monitoramento a cada 30s, timeout em 5min |
| **Reputação** | Ban automático após 10 falhas, expira em 24h |
| **Rate Limiting** | 100 req/min por IP (sharded, 64 shards) |
| **Timestamp** | Validação bidirecional (5min atrás, 2min futuro) |
| **Post-Quantum** | ML-KEM no handshake (futuro: ML-DSA nas assinaturas) |

## API HTTP

| Endpoint | Método | Descrição |
|----------|--------|-----------|
| `/health` | GET | Health check |
| `/node` | GET | Info do nó |
| `/epa/list` | GET | Lista de EPAs |
| `/epa` | POST | Enviar EPA |
| `/epa/encrypted` | POST | Enviar EPA encriptada |
| `/epa/:id/verify` | POST | Verificar EPA (completo) |
| `/epa/:id/verify-quick` | GET | Verificação rápida |
| `/epa/:id/witness` | POST | Adicionar testemunha externa |
| `/verify-chain` | GET | Verificar cadeia de provenance |
| `/compliance/:epa_id` | GET | Prova matemática de blinding |
| `/titular/:hash/dados` | GET | Dados do titular (LGPD) |
| `/titular/:hash/export` | GET | Exportar dados (portabilidade) |
| `/titular/:hash` | DELETE | Supressão (crypto-shredding) |
| `/titular/:hash/revogar` | POST | Revogar consentimento |

## Persistência

| Arquivo | Conteúdo |
|---------|----------|
| `data/identity.json` | Identidade do nó (chaves Ed25519, X25519, ML-KEM) |
| `data/network.json` | Peers, EPAs, TrustedPeerList, ProvenanceNodes |
| `data/reputation.json` | Reputação de nós |
| `data/checkpoints/checkpoint.json` | Checkpoint atômico (estado + regras reativas) |

## LGPD

### Regra de Anonimização

**EPA NUNCA é deletado.** Quando titular pede exclusão:
1. Anonimiza dados **dentro** do EPA (zera state_hash e evidence_hash)
2. Gera **NOVO EPA de supressão** provando a anonimização
3. Reconstrói DerivationIndex e blinda links de provenance

### Fluxo Automático

```
env vars → State.lgpd → Pipeline → SharedEPA(lgpd_metadata)
                                        ↓
                                  lgpd_index.insert()
                                        ↓
                              GET /titular/:hash/dados
                              DELETE /titular/:hash → anonimiza → EPA supressão
```

### Caso de Uso Completo: Direito ao Esquecimento

O arquivo `tests/lgpd_e2e_use_case.rs` demonstra o fluxo completo de exclusão (LGPD Art. 18, VI) com dados realistas — de criação do EPA até a prova matemática de exclusão verificável por terceiro.

Para rodar e verificar:
```bash
cargo test lgpd_direito_ao_esquecimento_fluxo_completo -- --nocapture
```

Documentação completa: `docs/LGPD_E2E_USE_CASE.md`

## Linguagem NEX

DSL tipada para nós de evidência com 3 camadas:

```nex
# Camada Básica
let id = node "dados" strength Signed
assert id >= Signed
act id = decision requires Signed

# Camada Intermediária
if id >= Signed then
  act id = decision requires Anchored

# Camada Avançada
on heartbeat_miss threshold 3 → log "Peer inativo"
on reputation_below 0.3 → mark_inactive peer
```

## Testes

```bash
cargo test
```

**Resultado verificado em 2026-07-03:** 942 testes, 0 falhas, 2 ignorados, 0 warnings (`cargo build --release 2>&1 | grep warning` retorna vazio).

Comando para verificação independente:
```bash
cargo test 2>&1 | grep "test result:"
cargo build --release 2>&1 | grep warning
```

## Roadmap

Visão de longo prazo — itens registrados como intenção, não trabalho em andamento. Ver `ROADMAP.md` para detalhes.

- **Fase 5:** EPA Verifier — crate standalone mínimo para verificação por terceiros
- **Fase 6:** Agente de manutenção assistida por IA com supervisão humana obrigatória

## Licença

MIT
