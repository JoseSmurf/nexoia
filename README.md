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
curl http://localhost:3000/health    # Health check
curl http://localhost:3000/node     # Info do nó
curl http://localhost:3000/epa/list # Listar EPAs
```

## Variáveis de Ambiente

| Variável | Default | Descrição | Exemplo |
|----------|---------|-----------|---------|
| `NEXOIA_API_PORT` | `3000` | Porta da API HTTP | `3001` |
| `NEXOIA_UDP_PORT` | `9000` | Porta UDP | `9001` |
| `NEXOIA_BROADCAST_PORT` | `9001` | Porta de broadcast | `9002` |
| `NEXOIA_MAX_PEERS` | `10` | Máximo de peers | `20` |
| `NEXOIA_NODE_NAME` | `nexoia_node` | Nome do nó | `node_alpha` |
| `NEXOIA_DATA_DIR` | `.nexoia` | Diretório de dados | `/var/lib/nexoia` |
| `NEXOIA_PASSPHRASE` | (nenhuma) | Passphrase para chaves | `"senha-forte"` |
| `NEXOIA_DISABLE_ENCRYPTION` | `false` | Desabilitar encriptação | `true` |
| `NEXOIA_BOOTSTRAP_PEERS` | (nenhum) | Peers iniciais | `"host1:9000,host2:9000"` |

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

- **Ed25519:** Usada para assinatura de EPAs e handshake.
- **X25519:** Usada para encriptação de payload entre peers.
- Ambas as chaves são geradas automaticamente na primeira execução.
- Com passphrase, as chaves são criptografadas com PBKDF2 + AES-256-GCM.

## Mecanismos de Segurança

| Mecanismo | Descrição |
|-----------|-----------|
| **Handshake** | Autenticação mútua via challenge-response com Ed25519 |
| **Encriptação** | Payload EPA criptografado com X25519 + ChaCha20-Poly1305 |
| **Heartbeat** | Monitoramento de peers a cada 30s, timeout em 5min |
| **Reputação** | Ban automático após 10 falhas consecutivas, expira em 24h |
| **Rate Limiting** | 100 requisições/min por IP na API HTTP |
| **Timestamp** | Validação bidirecional (5min atrás, 2min futuro) |
| **Ed25519** | Assinatura de EPAs e verificação de identidade |
| **X25519** | Troca de chaves para encriptação de payload |

## Persistência

| Arquivo | Conteúdo |
|---------|----------|
| `.nexoia/identity.json` | Identidade do nó (chaves) |
| `.nexoia/network.json` | Peers, EPAs e TrustedPeerList |
| `.nexoia/reputation.json` | Reputação de nós |

## API HTTP

| Endpoint | Método | Descrição |
|----------|--------|-----------|
| `/health` | GET | Health check |
| `/node` | GET | Info do nó |
| `/epa/list` | GET | Lista de EPAs |
| `/epa` | POST | Enviar EPA |
| `/epa/:id/verify` | POST | Verificar EPA |

## Testes

```bash
cargo test
```

## Licença

MIT
