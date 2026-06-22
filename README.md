# NexoIA

Rede de auditoria descentralizada. Nós executam pipeline determinístico local e compartilham EPAs (Evidence-Proof-Artifacts) verificáveis.

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
│  │  └──────────┘  └──────────┘  └──────────┘  └────────┘ │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │  Other Nodes    │
                    │  (UDP/API)      │
                    └─────────────────┘
```

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

### Endpoints

| Endpoint | Método | Descrição | Response |
|----------|--------|-----------|----------|
| `/health` | GET | Health check | `{"status": "ok", "message": "..."}` |
| `/node` | GET | Info do nó | `{"node_id": "...", "epa_count": 0}` |
| `/epa/list` | GET | Lista de EPAs | `[{epa_object}, ...]` |
| `/epa` | POST | Enviar EPA | `{"status": "accepted", "message": "..."}` |
| `/epa/:id/verify` | POST | Verificar EPA | `{"result": "VALID", "epa_id": "..."}` |

### Exemplos

```bash
# Health check
curl http://localhost:3000/health

# Ver info do nó
curl http://localhost:3000/node

# Listar EPAs
curl http://localhost:3000/epa/list

# Enviar EPA
curl -X POST http://localhost:3000/epa \
  -H "Content-Type: application/json" \
  -d @epa.json

# Verificar EPA
curl -X POST http://localhost:3000/epa/abc123/verify \
  -H "Content-Type: application/json" \
  -d '{"state_json": "...", "evidence_jsonl": "..."}'
```

## Persistência

- `.nexoia/identity.json` — Identidade do nó (sobrevive restarts)
- `.nexoia/network.json` — Peers e EPAs (sobrevive restarts)

## Testes

```bash
cargo test
```

## Licença

MIT
