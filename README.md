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
# Nó 1
cargo run

# Nó 2 (outro terminal, porta diferente)
NEXOIA_API_PORT=3001 NEXOIA_UDP_PORT=9001 cargo run

# Nó 2 conectando ao Nó 1 via bootstrap
NEXOIA_API_PORT=3001 NEXOIA_UDP_PORT=9001 \
NEXOIA_BOOTSTRAP_PEERS=127.0.0.1:9000 cargo run
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
| `NEXOIA_BOOTSTRAP_PEERS` | (nenhum) | Lista de peers iniciais (ex: `host1:9000,host2:9000`) |

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
| Heartbeat | Detecção de peers inativos (5min timeout) |

## API HTTP

### Endpoints

| Endpoint | Método | Descrição | Response |
|----------|--------|-----------|----------|
| `/health` | GET | Health check | `{"status": "ok"}` |
| `/node` | GET | Info do nó | `{"node_id": "...", "epa_count": 0}` |
| `/epa/list` | GET | Lista de EPAs | `[{epa_object}, ...]` |
| `/epa` | POST | Enviar EPA | `{"status": "accepted"}` |
| `/epa/:id/verify` | POST | Verificar EPA | `{"result": "VALID"}` |

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
