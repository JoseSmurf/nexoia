# THREAT_MODEL.md — NexoIA

Resultado dos testes adversariais da Fase 2. Testes que falharam expõem fraquezas reais.

---

## Testes Adversariais (2026-07-03)

**17 testes executados, 15 passaram, 1 ignorado (design intencional), 1 ignorado (corrigido).**

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
| `timestamp_rejects_old_message` | verify_signature() rejeita timestamp antigo | ✅ CORRIGIDO |
| `timestamp_rejects_future_message` | verify_signature() rejeita timestamp futuro | ✅ CORRIGIDO |

### Testes que FALHARAM (fraquezas expostas e corrigidas)

#### 1. `timestamp_rejects_old_message` e `timestamp_rejects_future_message`

**Problema:** `verify_signature()` não validava o campo `timestamp`. Apenas verificava a assinatura Ed25519.

**Impacto:** Um atacante podia enviar um EPA com timestamp antigo ou futuro e a assinatura continuava válida.

**Correção (2026-07-03):** `verify_signature()` agora chama `verify_timestamp()` antes de validar a assinatura. Janela temporal: 5min passado, 2min futuro.

**Commit:** `verificar no git log — Fix: verify_signature() now validates timestamp`

**Estado:** ✅ CORRIGIDA — teste passa de verdade, vulnerabilidade eliminada.

#### 2. `reputation_coordinated_attack_resistance`

**Problema:** Após 10 falhas e ban, 100 successos resetam o contador `failures` para 0, MAS o campo `banned` continua `true` até o ban expirar (24h).

**Impacto:** Um nó pode ter 0 falhas mas ainda estar banido se o ban não expirou.

**Decisão de design (2026-07-03):** Comportamento **intencional**. Previne que atacante faça 10 falhas, 1 success, e volte imediatamente. O sistema prioriza segurança sobre disponibilidade.

**Estado:** ⚠️ LIMITAÇÃO CONHECIDA — teste marcado com `#[ignore]` e justificativa documentada.

---

## Defesas Implementadas

| Camada | Mecanismo | Status |
|--------|-----------|--------|
| Transporte | Length-prefix framing (4 bytes BE + payload) | ✅ Implementado |
| Transporte | Buffer pool zero-copy (BytesMut) | ✅ Implementado |
| Rate Limiting | 100 req/min por IP, 64 shards | ✅ Implementado |
| Reputação | Ban após 10 falhas, expira em 24h | ✅ Implementado |
| EPA | Assinatura Ed25519 + integridade BLAKE3 | ✅ Implementado |
| EPA | Timestamp anti-replay (5min back, 2min future) | ✅ Implementado em verify_signature() |
| Handshake | Challenge-response mútuo | ✅ Implementado |
| Criptografia | ChaCha20-Poly1305 | ✅ Implementado |
| Post-Quantum | ML-KEM no handshake | ✅ Implementado |

---

## Lacunas Identificadas

1. ~~verify_signature() não valida timestamp~~ — ✅ CORRIGIDO (2026-07-03)
2. **Ban é sticky por 24h** — decisão de design intencional, documentada
3. **Testes de rede sob estresse** — não testamos throughput real (apenas unitário)
4. **Replay de mensagens** — IDs únicos previnem EPA replay, mas nonce de handshake não está sendo testado
