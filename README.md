# NexoIA

Rede de auditoria descentralizada. Nós executam pipeline determinístico local e compartilham EPAs (Evidence-Proof-Artifacts) verificáveis e encriptados.

## Arquitetura

```
┌─────────────────────────────────────────────────────────────────┐
│                         NexoIA Node                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐     │
│  │ defense │───▶│   ai    │───▶│ quality │───▶│decision │     │
│  │ (valida)│    │(traduz) │    │(avalia) │    │(decide) │     │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘     │
│       │                                            │            │
│       ▼                                            ▼            │
│  ┌─────────┐                                 ┌─────────┐       │
│  │  state  │                                 │ evidence│       │
│  └─────────┘                                 └─────────┘       │
│                                                 │               │
│                                                 ▼               │
│                                          ┌─────────────┐       │
│                                          │   manifest   │       │
│                                          └─────────────┘       │
│                                                 │               │
│                                                 ▼               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                      network                            │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │   │
│  │  │ identity │  │   epa    │  │ transport│  │   api  │ │   │
│  │  │ (crypto) │  │ (sign+   │  │ (UDP+HB) │  │ (REST) │ │   │
│  │  │          │  │  encrypt)│  │          │  │        │ │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └────────┘ │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Nó 1 (escuta na porta 9000)
cargo run

# Nó 2 (conecta ao Nó 1 via bootstrap)
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

### Com Passphrase (recomendado em produção)

```bash
NEXOIA_PASSPHRASE="minha-senha-forte" cargo run
```

### Verificando a rede

```bash
# Health check
curl http://localhost:3000/health

# Info do nó
curl http://localhost:3000/node

# Listar EPAs
curl http://localhost:3000/epa/list
```

## Variáveis de Ambiente

| Variável | Default | Descrição |
|----------|---------|-----------|
| `NEXOIA_API_PORT` | `3000` | Porta da API HTTP |
| `NEXOIA_UDP_PORT` | `9000` | Porta UDP |
| `NEXOIA_BROADCAST_PORT` | `9001` | Porta de broadcast para peer discovery |
| `NEXOIA_MAX_PEERS` | `10` | Máximo de peers conectados |
| `NEXOIA_NODE_NAME` | `nexoia_node` | Nome do nó |
| `NEXOIA_DATA_DIR` | `.nexoia` | Diretório de persistência |
| `NEXOIA_PASSPHRASE` | (nenhuma) | Passphrase para criptografar chave privada |
| `NEXOIA_DISABLE_ENCRYPTION` | `false` | Desabilitar encriptação de EPA (debug) |
| `NEXOIA_BOOTSTRAP_PEERS` | (nenhum) | Peers iniciais (ex: `host1:9000,host2:9000`) |

## Segurança

| Camada | Mecanismo |
|--------|-----------|
| Identidade | Ed25519 (assinatura) + X25519 (encriptação) |
| Chave privada | PBKDF2 + AES-256-GCM (com passphrase) |
| EPA | Assinatura Ed25519 + timestamp bidirecional |
| Transporte | ChaCha20-Poly1305 (entre trusted peers) |
| Handshake | Challenge-response com Ed25519 |
| Rate limiting | 100 req/min por IP na API HTTP |
| Reputação | Ban após 10 falhas, expira em 24h |
| Heartbeat | Detecção de peers inativos (30s interval, 5min timeout) |

## Persistência

- `.nexoia/identity.json` — Identidade (chaves criptografadas com passphrase)
- `.nexoia/network.json` — Peers, EPAs e TrustedPeerList
- `.nexoia/reputation.json` — Reputação de nós

## Testes

```bash
cargo test
```

## Licença

MIT
