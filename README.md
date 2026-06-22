# NexoIA

Rede de auditoria descentralizada. Nós executam pipeline determinístico local e compartilham EPAs (Evidence-Proof-Artifacts) verificáveis.

## Quick Start

```bash
# Nó 1
cargo run

# Nó 2 (outro terminal)
NEXOIA_API_PORT=3001 NEXOIA_UDP_PORT=9001 cargo run
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

## API HTTP

| Endpoint | Método | Descrição |
|----------|--------|-----------|
| `/health` | GET | Health check |
| `/node` | GET | Info do nó |
| `/epa/list` | GET | Lista de EPAs recebidos |
| `/epa` | POST | Enviar EPA |
| `/epa/:id/verify` | POST | Verificar EPA |

## Arquitetura

```
State → defense (valida) → ai (traduz) → quality (avalia) → decision (decide) → evidence → manifest → network
```

## Persistência

- `identity.json` — Identidade do nó (sobrevive restarts)
- `network.json` — Peers e EPAs (sobrevive restarts)

## Testes

```bash
cargo test
```

## Licença

MIT
