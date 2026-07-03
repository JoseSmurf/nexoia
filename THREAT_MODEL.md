# THREAT_MODEL.md — NexoIA

Resultado dos testes adversariais da Fase 2. Testes que falharam expõem fraquezas reais.

---

## Testes Adversariais (2026-07-03)

**17 testes executados, 14 passaram, 3 falharam.**

### Testes que PASSARAM (defesas efetivas)

| Teste | O que valida | Status |
|-------|-------------|--------|
| `truncated_payload_rejected` | Handshake com 2 bytes rejeitado | ✅ OK |
| `malformed_json_rejected` | JSON malformado rejeitado | ✅ OK |
| `empty_payload_rejected` | Payload vazio rejeitado | ✅ OK |
| `invalid_message_type_rejected` | Tipo inválido rejeitado | ✅ OK |
| `duplicate_epa_rejected` | EPAs têm IDs únicos | ✅ OK |
| `rate_limiter_blocks_after_threshold` | Rate limiter bloqueia após limite | ✅ OK |
| `rate_limiter_independent_per_source` | Rate limiter por fonte independente | ✅ OK |
| `flood_of_peers_limited_by_peerlist` | PeerList impõe limite de capacidade | ✅ OK |
| `false_reports_cannot_ban_innocent` | 9 falhas não causam ban | ✅ OK |
| `ban_requires_exact_10_failures` | Ban requer exatamente 10 falhas | ✅ OK |
| `ban_expires_after_24_hours` | Ban expira após 24h | ✅ OK |
| `reputation_success_resets_only_after_100` | Success só reseta após 100 | ✅ OK |
| `tampered_epa_detected` | EPA adulterado é detectado | ✅ OK |
| `network_message_json_roundtrip` | Mensagens sobrevivem JSON roundtrip | ✅ OK |

### Testes que FALHARAM (fraquezas expostas)

#### 1. `timestamp_rejects_old_message` e `timestamp_rejects_future_message`

**Problema:** `verify_signature()` não valida o campo `timestamp`. Apenas verifica a assinatura Ed25519.

**Impacto:** Um atacante pode enviar um EPA com timestamp antigo ou futuro e a assinatura continua válida. A validação de timestamp só acontece em camadas superiores (handshake, pipeline), não na verificação de integridade do EPA.

**Severidade:** Média — a validação de timestamp existe em `epa.rs` (`verify_timestamp()`), mas `verify_signature()` não a chama.

**Recomendação:** Adicionar `verify_timestamp()` como pré-requisito em `verify_signature()`, ou documentar que `verify_signature()` é apenas verificação criptográfica (não temporal).

**Estado:** Aceitar como limitação conhecida OU implementar fix.

#### 2. `reputation_coordinated_attack_resistance`

**Problema:** Após 10 falhas e ban, 100 successos resetam o contador `failures` para 0, MAS o campo `banned` continua `true` até o ban expirar (24h).

**Impacto:** Um nó pode ter 0 falhas mas ainda estar banido se o ban não expirou. O ban é "sticky" — mesmo com 100 successos, o nó fica banido por 24h completas.

**Severidade:** Baixa — é uma feature, não bug. Previne que um atacante faça 10 falhas, 1 success, e volte imediatamente.

**Recomendação:** Documentar como comportamento intencional. O sistema prioriza segurança sobre disponibilidade.

**Estado:** Aceitar como limitação conhecida.

---

## Defesas Implementadas

| Camada | Mecanismo | Status |
|--------|-----------|--------|
| Transporte | Length-prefix framing (4 bytes BE + payload) | ✅ Implementado |
| Transporte | Buffer pool zero-copy (BytesMut) | ✅ Implementado |
| Rate Limiting | 100 req/min por IP, 64 shards | ✅ Implementado |
| Reputação | Ban após 10 falhas, expira em 24h | ✅ Implementado |
| EPA | Assinatura Ed25519 + integridade BLAKE3 | ✅ Implementado |
| EPA | Timestamp anti-replay (5min back, 2min future) | ⚠️ Existe mas não em verify_signature() |
| Handshake | Challenge-response mútuo | ✅ Implementado |
| Criptografia | ChaCha20-Poly1305 | ✅ Implementado |
| Post-Quantum | ML-KEM no handshake | ✅ Implementado |

---

## Lacunas Identificadas

1. **verify_signature() não valida timestamp** — considerar adicionar
2. **Ban é sticky por 24h** — mesmo com 100 successos, ban persiste (intencional?)
3. **Testes de rede sob estresse** — não testamos throughput real (apenas unitário)
4. **Replay de mensagens** — IDs únicos previnem EPA replay, mas nonce de handshake não está sendo testado
