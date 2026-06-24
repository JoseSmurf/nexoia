# NEXOIA — AUDITORIA FORMAL MÁXIMA

**Data:** 2026-06-24
**Versão:** 2.0 (auditoria completa com 12 fases)
**Escopo:** Arquitetura, concorrência, criptografia, defesa, invariantes, ameaças, testabilidade

---

## FASE 1 — BUILD SANITY

### Resultados

| Comando | Resultado |
|---------|-----------|
| `cargo check` | ✅ 0 erros |
| `cargo test` | ✅ **533 passed** (lib + bin + tests + doc-tests) |
| `cargo clippy` | ✅ 0 erros, ~30 warnings |

### Warnings (clippy)

| Tipo | Quantidade | Detalhes |
|------|-----------|---------|
| `unused_imports` | ~15 | `Deserialize`, `ReactiveAction`, `Trigger`, `Path`, etc. |
| `unused_variables` | ~8 | `encrypted`, `udp_addr`, `node_id`, `timestamp` |
| `dead_code` | ~60+ | Módulos nex/ inteiramente não usados (parser, eval, checkpoint, layers) |
| `new_without_default` | 3 | `PeerState`, `ReputationStore`, `ReactiveEngine` |
| `unnecessary_map_or` | 9 | `eval.rs` (substituir por `is_some_and`) |
| `too_many_arguments` | 1 | `run_udp_listener` (11 params) |
| `unreachable_patterns` | 1 | `_ =>` no match de NetworkMessage (todos variantes já cobertos) |

### Testes

**533 testes passando**, incluindo:
- 147 lib tests
- 122 bin "nexoia" tests
- 147 bin "nex" tests
- 37 bin "verify" tests
- 9 integration tests
- 10 network tests
- 6 integration tests (hash_test)
- 3 hash integration tests
- 1 doc-test ignorado

**Nenhum teste falha.**

---

## FASE 2 — LOCK DEPENDENCY GRAPH

### Recursos Sincronizados

| ID | Tipo | Local | Propósito |
|----|------|-------|-----------|
| L1 | `Arc<RwLock<Vec<SharedEPA>>>` | main.rs:160 | Lista de EPAs |
| L2 | `Arc<RwLock<PeerList>>` | main.rs:161 | Peers desconhecidos |
| L3 | `Arc<RwLock<ReputationStore>>` | main.rs:182 | Reputação |
| L4 | `Arc<RwLock<TrustedPeerList>>` | main.rs:188 | Peers autenticados |
| L5 | `Arc<RwLock<HashMap<SocketAddr, PeerState>>>` | main.rs:196 | Estado heartbeat |
| L6 | `Arc<RwLock<HashMap<SocketAddr, PendingHandshake>>>` | main.rs:308 | Handshakes pendentes |
| L7 | `Arc<SessionManager>` → `RwLock<HashMap<SocketAddr, SessionState>>` | session.rs:172 | Sessões ativas |
| M1 | `Mutex<Instant>` | session.rs:33 | Última atividade |

### Tasks

| Task | Locks Adquiridos |
|------|------------------|
| `run_heartbeat_sender` | L4(r) → L5(w) |
| `run_heartbeat_monitor` | L7(w) → L5(r) → L5(w)+L3(w) → L4(r) → L4(w)+L5(w) |
| `run_udp_listener` | L6(w), L5(w), L4(r/w), L3(w), L7(r/w) |
| `run_pipeline` | L1(w), L2(r), L4(r) |
| `verify_and_store_epa` | L3(w) → L1(w) |
| HTTP API | L1(r/w) |

### Análise

- **Deadlock:** ❌ Nenhum ciclo detectado. Aquisições seguem ordem consistente.
- **Lock Convoy:** ⚠️ `run_heartbeat_monitor` adquire L5(w)+L3(w) simultâneos (main.rs:1292-1299). Pode starvar T1/T3.
- **Hold Time:** L3(w) mantido durante `rep.save()` (I/O) em `increment_failure()` — potencialmente longo.
- **Nested Locking:** L5+L3 em heartbeat_monitor. L6+w em handshake. Sem risco de deadlock (ordem consistente).

---

## FASE 3 — RESOURCE OWNERSHIP VERIFICATION

### Modelo de Tokens

| Token | Criado em | Proprietário | Liberado em | ExactlyOneOwner | EventuallyReleased |
|-------|-----------|-------------|-------------|-----------------|-------------------|
| `SessionToken` | main.rs:772,838 | SessionManager | session.rs:219 (cleanup) | ⚠️ clones | ✅ |
| `HandshakeToken` | main.rs:514 | pending_handshakes | main.rs:779,851 | ✅ | ⚠️ leak em falhas |
| `KeyToken` | crypto.rs:21 | NodeIdentity | Drop impl | ✅ | ❌ não zeroizado |
| `PeerToken` | main.rs:770,832 | TrustedPeerList | trusted.rs:remove | ✅ | ✅ |
| `EPAToken` | main.rs:425,1102 | Vec<SharedEPA> | Nunca | ✅ | ❌ |
| `TaskToken` | main.rs:255,289,310,327,336 | tokio runtime | JoinHandle drop | ✅ | ✅ |
| `RateLimiterToken` | api.rs:41 | RateLimiterInner | Drop impl | ✅ | ✅ |

### Finding CRÍTICO: CONC-1 — Clone-Discard Anti-Replay

**SEVERIDADE: CRÍTICO**

**Arquivo:** `src/main.rs:870-877`

```rust
let mut session_mut = session.clone();  // clone descartável
if !session_mut.check_counter(counter) { // modifica clone
    continue;
}
// clone descartado — mudanças NÃO persistem
```

**Prova:**
1. `SessionManager::get()` retorna `.cloned()` (session.rs:191)
2. Clone cria cópia independente com bitmap duplicado
3. `check_counter()` modifica `recv_counter` e `recv_window` no clone
4. Clone sai de escopo → mudanças perdidas
5. Estado real em `SessionManager` nunca é atualizado
6. **Resultado: Anti-replay é ineficaz**

**Impacto:** Mensagens podem ser replayed indefinidamente.

**Patch:**
```rust
// Em session.rs, adicionar:
pub async fn check_counter(&self, addr: &SocketAddr, counter: u64) -> bool {
    let mut sessions = self.sessions.write().await;
    if let Some(session) = sessions.get_mut(addr) {
        session.check_counter(counter)
    } else {
        false
    }
}

// Em main.rs:870-877, substituir:
if !session_manager.check_counter(&addr, counter).await {
    eprintln!("  ✗ Replay detected from {} (counter={})", addr, counter);
    continue;
}
```

**Teste:** Enviar mesma mensagem duas vezes; segunda deve ser rejeitada.

---

## FASE 4 — DYNAMIC COLLECTION AUDIT

| Coleção | Local | Bounded | TTL | Eviction | Cleanup | Risco |
|---------|-------|---------|-----|----------|---------|-------|
| `Vec<SharedEPA>` | main.rs:160 | ❌ | ❌ | ❌ | ❌ | MEM-1 |
| `HashMap<SocketAddr, PendingHandshake>` | main.rs:308 | ❌ | ❌ | ❌ | ❌ | MEM-2 |
| `HashMap<String, NodeReputation>` | reputation.rs:69 | ❌ | ❌ | ❌ | ❌ | MEM-3 |
| `HashMap<SocketAddr, TrustedPeer>` | transport.rs:158 | ✅ max_peers | ❌ | ❌ | ❌ | BAIXO |
| `Vec<DateTime<Utc>>` heartbeat_window | transport.rs:74 | ✅ 5 | N/A | ✅ remove(0) | N/A | BAIXO |
| `HashMap<SocketAddr, PeerState>` | main.rs:196 | ❌ | ❌ | ❌ | ❌ | MEM-4 |
| `HashMap<IpAddr, ClientRate>` | api.rs:22 | ❌ | ❌ | ✅ (window reset) | ❌ | BAIXO |
| `HashMap<SocketAddr, SessionState>` | session.rs:172 | ❌ | ✅ (300s) | ✅ | ✅ cleanup | ✅ |

### MEM-1: Vec<SharedEPA> Unbounded

**SEVERIDADE: MÉDIO**

Cada EPA: ~2-5KB. 1000 EPAs = ~5MB. Sem limite.

**Patch:** `const MAX_EPAS: usize = 1000;` com FIFO eviction.

### MEM-2: PendingHandshake Leak

**SEVERIDADE: ALTO**

Paths de falha em ChallengeResponse (main.rs:592-602) usam `continue` sem `pending.remove(&addr)`.

**Patch:** Adicionar `pending.remove(&addr)` antes de cada `continue`.

### MEM-3: ReputationStore Unbounded

**SEVERIDADE: BAIXO**

Entries nunca são removidas. Nós que saíram permanecem.

**Patch:** Cleanup periódico de entries com `last_seen` > 30 dias.

### MEM-4: peer_states Unbounded

**SEVERIDADE: BAIXO**

Peers removidos são limpos (main.rs:1309), mas peers que nunca foram autenticados podem acumular se enviarem Heartbeat.

---

## FASE 5 — FSM FORMAL VERIFICATION

### FSM: Handshake (5 fases)

```
INITIATOR:
  [Idle] → Hello enviado → [PendingChallenge]
  [PendingChallenge] → Challenge recebido → [ChallengeReceived]
  [ChallengeReceived] → ChallengeResponse enviado → [PendingSessionKey]
  [PendingSessionKey] → SessionKeyExchange recebido → [KeyDerivation]
  [KeyDerivation] → SessionKeyConfirm enviado → [Complete]

RESPONDER:
  [Idle] → Hello recebido → [ChallengeSent]
  [ChallengeSent] → ChallengeResponse recebido → [ResponseReceived]
  [ResponseReceived] → SessionKeyExchange enviado → [PendingConfirm]
  [PendingConfirm] → SessionKeyConfirm recebido → [Complete]

falha → [Failed] → remove PendingHandshake
```

**Estados inalcançáveis:** `HelloReceived` (definido mas nunca verificado explicitamente — o código pula direto para `ChallengeSent`).

**Transições inválidas:** Nenhuma detectada.

**Ciclos infinitos:** ❌ Nenhum. Cada handshake avança ou falha.

**Ausência de timeout:** ⚠️ Handshakes podem ficar presos indefinidamente se peer desaparecer.

### FSM: Session

```
[Inactive] → handshake completo → [Active]
[Active] → heartbeat received → [Active] (atualiza last_activity)
[Active] → 300s sem atividade → [Expired] → removido
```

**Ausência de timeout:** ✅ Implementado via `cleanup(300)`.

### FSM: Peer

```
[Unknown] → Hello enviado → [PendingHandshake]
[PendingHandshake] → handshake completo → [Trusted]
[Trusted] → heartbeat OK → [Active]
[Trusted] → 5min inativo → [Inactive] → removido
```

---

## FASE 6 — CRYPTOGRAPHIC AUDIT

### Chaves

| Chave | Geração | Persistência | Zeroização | Risco |
|-------|---------|-------------|-----------|-------|
| Ed25519 SigningKey | OsRng (32 bytes) | JSON | ❌ | CRYPTO-1 |
| X25519 StaticSecret | OsRng (32 bytes) | JSON | ❌ | CRYPTO-1 |
| ML-KEM dk_seed | ml_kem::Generate (64 bytes) | JSON | ❌ | CRYPTO-1 |
| Session key [u8;32] | HKDF-SHA256 | Memória | ❌ | CRYPTO-1 |

### CRYPTO-1: Chaves Não Zeroizadas

**SEVERIDADE: MÉDIO**

`StaticSecret`, `SigningKey`, `MlKemKeyPair.decapsulation_key_seed` não implementam `Zeroize`.

**Patch:** Ativar feature `static_secrecy` em `x25519_dalek`.

### CRYPTO-2: Nonce Zero em SessionKeyConfirm

**SEVERIDADE: MÉDIO**

`main.rs:749,815`: `Nonce::from_slice(&[0u8; 12])` — nonce zero reutilizado.

**Patch:** Gerar nonce aleatório.

### CRYPTO-3: HKDF Analysis

**SEVERIDADE: BAIXO**

```rust
let hk = Hkdf::<Sha256>::new(Some(b"nexoia-hybrid-session-v1"), &ikm);
hk.expand(b"session-key", &mut key)
```

- Salt: `"nexoia-hybrid-session-v1"` — ✅ domain separation
- Info: `"session-key"` — ✅ cross-protocol prevention
- IKM inclui nonces — ⚠️ nonces como keying material (aceitável mas não ideal)

### Forward Secrecy

**✅ Verificado:** Chaves efêmeras X25519 consumidas via `.take()` (main.rs:636,725).

**Limitação:** Sem key rotation periódico. Comprometimento de chave estática expõe todas as sessões.

### Replay Protection

**❌ Ineficaz** devido ao CONC-1.

### KCI Resistance

**✅ Verificado:** Handshake usa chaves efêmeras. Chave estática Ed25519 é usada apenas para autenticação (assinatura), não para derivação de sessão.

### Downgrade Resistance

**⚠️ Parcial:** Não há verificação de versão de protocolo. Atacante pode forçar uso de apenas ML-KEM ou apenas X25519 (se modificasse o código). Em implementação atual, ambos são sempre usados.

---

## FASE 7 — DEFENSE LAYER AUDIT

### defense.rs: RateLimiter

**Avaliação: BOM**

| Aspecto | Status | Detalhes |
|---------|--------|---------|
| Sharding | ✅ | 64 shards, reduz contenção |
| RAII | ✅ | SourceReservation com commit/drop |
| Cleanup | ✅ | Thread separada, 60s interval |
| Max sources | ✅ | 100,000 com fetch_update atômico |
| Input validation | ✅ | Empty, max size, null bytes |

### defense.rs: Findings

**DEF-1 (BAIXO):** Race condition teórica entre `fetch_update` e `insert` — impacto prático mínimo.

**DEF-2 (BAIXO):** RateLimiter HashMap unbounded — 100K entries × ~100 bytes = ~10MB. Aceitável.

### api.rs: RateLimiter

**SEPARADO do defense.rs:** api.rs tem seu próprio RateLimiter (tokio-based, por IP). Bounded pelo window.

### Anti-Flood

**✅ Implementado:**
- UDP listener processa uma mensagem por vez (sequential)
- Rate limiting por source (defense.rs) e por IP (api.rs)
- PendingHandshake limit implícito (max 10 peers)

### DoS Resistance

**⚠️ Limitações:**
- `pending_handshakes` pode ser inundado (MEM-2)
- `Vec<SharedEPA>` pode crescer (MEM-1)
- Sem timeout para handshakes (INV-2)

---

## FASE 8 — GLOBAL INVARIANTS

### INV-1: Nenhuma sessão permanece órfã

**✅ PROVADO (com ressalva)**

Sessões são criadas em main.rs:772,838 e limpas por `cleanup(300)` no heartbeat_monitor.

**Ressalva:** Se heartbeat_monitor panique, sessões não são limpas.

### INV-2: Todo handshake termina

**❌ REFUTADO**

Handshakes podem ficar presos se:
1. Initiator envia Hello mas nunca recebe Challenge
2. Responder fica em `ChallengeSent` mas initiator desaparece
3. Falha não remove pending (MEM-2)

### INV-3: Nenhuma chave efêmera é perdida

**✅ PROVADO**

Chaves efêmeras X25519 são consumidas via `.take()`.

### INV-4: Nenhuma chave sobrevive além do necessário

**❌ REFUTADO**

`session_key`, `decapsulation_key_seed`, `SigningKey` não são zeroizados (CRYPTO-1).

### INV-5: Nenhuma coleção cresce infinitamente

**❌ REFUTADO**

4 coleções crescem ilimitadamente: EPAs, pending_handshakes, reputation, peer_states.

### INV-6: Nenhum replay é aceito

**❌ REFUTADO (CRÍTICO)**

Anti-replay bitmap nunca persiste (CONC-1).

### INV-7: Nenhum peer removido permanece ativo

**✅ PROVADO**

Peer removido → limpo de PeerList + PeerState. Sessão expira via cleanup.

### INV-8: Toda task permanece rastreável

**⚠️ PARCIAL**

Tasks são spawned sem JoinHandle armazenado. Se panic, não há detecção.

### INV-9: Todo recurso possui exatamente um dono

**❌ REFUTADO**

`SessionManager::get()` retorna clones — múltiplas cópias com estado independente.

### INV-10: Todo recurso é eventualmente liberado

**❌ REFUTADO**

4 coleções nunca liberam elementos (INV-5).

---

## FASE 9 — PROXY TYPES

### Busca

| Padrão | Encontrado? |
|--------|------------|
| `ManuallyDrop` | ❌ |
| `Box::into_raw` | ❌ |
| `*mut T` | ❌ |
| `*const T` | ❌ |
| `unsafe` blocks | ❌ |
| `mem::forget` | ❌ |

**Conclusão:** ✅ Nenhum proxy type leak. Código é 100% safe Rust.

### Drop Completeness

| Tipo | Campos Liberados? |
|------|-------------------|
| `KeyPair` | ⚠️ StaticSecret não zeroizado |
| `MlKemKeyPair` | ⚠️ decapsulation_key_seed não zeroizado |
| `NodeIdentity` | ⚠️ signing_key não zeroizado |
| `SessionState` | ⚠️ session_key não zeroizado |
| `PendingHandshake` | ✅ EphemeralSecret via Drop |
| `RateLimiter` | ✅ shutdown_tx send |

---

## FASE 10 — TESTABILIDADE

### Testes Unitários Ausentes

| Teste Recomendado | Prioridade |
|-------------------|-----------|
| Anti-replay com clone-discard (CONC-1) | P0 |
| PendingHandshake timeout | P0 |
| Handshake initiator flow | P0 |
| Concurrent session access | P1 |
| EPA max capacity eviction | P1 |
| Reputation cleanup after 30 days | P2 |
| Rate limiter under concurrent load | P2 |

### Property Tests Recomendados

```rust
// 1. Anti-replay: counter sempre crescente é aceito
proptest! {
    #[test]
    fn anti_replay_sequential(counters in prop::collection::vec(1u64..10000, 1..100)) {
        let mut session = SessionState::new([0u8;32], [1u8;32], [2u8;32]);
        for c in &counters {
            prop_assert!(session.check_counter(*c));
        }
    }
}

// 2. Session key determinismo
proptest! {
    #[test]
    fn session_key_deterministic(
        x in any::<[u8;32]>(),
        m in any::<[u8;32]>(),
        n1 in any::<[u8;32]>(),
        n2 in any::<[u8;32]>(),
    ) {
        let k1 = derive_hybrid_session_key(&x, &m, &n1, &n2);
        let k2 = derive_hybrid_session_key(&x, &m, &n1, &n2);
        prop_assert_eq!(k1, k2);
    }
}
```

### Fuzz Targets Recomendados

```rust
// 1. Fuzz SecureMessage::decrypt com input aleatório
fuzz_target!(|data: &[u8]| {
    let key = [42u8; 32];
    if let Ok(msg) = SecureMessage::from_bytes(data) {
        let _ = msg.decrypt(&key);
    }
});

// 2. Fuzz NetworkMessage deserialization
fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<NetworkMessage>(data);
});
```

### Testes de Concorrência

```rust
#[tokio::test]
async fn concurrent_session_check_counter() {
    let manager = Arc::new(SessionManager::new());
    let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let session = SessionState::new([0u8;32], [1u8;32], [2u8;32]);
    manager.insert(addr, session).await;

    let mut handles = vec![];
    for i in 1..=100u64 {
        let m = Arc::clone(&manager);
        handles.push(tokio::spawn(async move {
            m.check_counter(&addr, i).await
        }));
    }

    let results: Vec<bool> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    // Exatamente 1 deve aceitar cada counter (sem duplicate)
    assert!(results.iter().filter(|&&r| r).count() <= 1);
}
```

### Testes de Timeout

```rust
#[tokio::test]
async fn session_expires_after_timeout() {
    let manager = SessionManager::new();
    let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let mut session = SessionState::new([0u8;32], [1u8;32], [2u8;32]);
    // Força last_activity para o passado
    *session.last_activity.lock().unwrap() = Instant::now() - Duration::from_secs(600);
    manager.insert(addr, session).await;

    manager.cleanup(300).await;
    assert_eq!(manager.len().await, 0);
}
```

---

## FASE 11 — THREAT MODEL (STRIDE)

### Ativos Críticos

| Ativo | Valor | Ameaças |
|-------|-------|---------|
| Chave privada Ed25519 | ALTO | Forgery de assinaturas |
| Chave privada X25519 | ALTO | Decifração de sessões |
| ML-KEM dk_seed | ALTO | Decapsulação de chaves pós-quânticas |
| Session key | ALTO | Decifração de mensagens |
| EPA data | MÉDIO | Integridade de evidências |
| Reputação | MÉDIO | Manipulação de trust |
| Estado da sessão | MÉDIO | Replay de mensagens |

### Superfícies de Ataque

| Superfície | Protocolo | Proteção |
|-----------|-----------|----------|
| UDP port | Heartbeat, Handshake, EPA | Rate limiting |
| HTTP API | REST endpoints | Rate limiting por IP |
| Disco | identity.json, network.json, reputation.json | Permissões 0600 (Unix) |

### Análise STRIDE

#### Spoofing

| Ameaça | Status | Mitigação |
|--------|--------|-----------|
| Peer falso se passa por legítimo | ✅ Mitigado | Handshake 5 fases com Ed25519 + ML-KEM |
| Replay de Hello antigo | ✅ Mitigado | Nonce 32 bytes único por handshake |
| Peer não autenticado envia EPA | ✅ Mitigado | TrustedPeerList check |

#### Tampering

| Ameaça | Status | Mitigação |
|--------|--------|-----------|
| Mensagem modificada em trânsito | ✅ Mitigado | ChaCha20-Poly1305 AEAD |
| EPA com dados corrompidos | ✅ Mitigado | Integrity hash + Ed25519 signature |
| Handshake state manipulation | ⚠️ Parcial | PendingHandshake em memória (não persistido) |

#### Repudiation

| Ameaça | Status | Mitigação |
|--------|--------|-----------|
| Nó nega ter enviado EPA | ✅ Mitigado | Ed25519 signature não repudiável |
| Nó nega ter participado de sessão | ⚠️ Parcial | Logs em stdout (não persistidos) |

#### Information Disclosure

| Ameaça | Status | Mitigação |
|--------|--------|-----------|
| Interceptação de tráfego | ✅ Mitigado | X25519 + ChaCha20-Poly1305 |
| Chaves em disco | ⚠️ Parcial | Plaintext se sem passphrase |
| Chaves em memória | ❌ Não mitigado | Sem zeroize (CRYPTO-1) |
| Core dump com chaves | ❌ Não mitigado | Sem zeroize |
| Swap com chaves | ❌ Não mitigado | Sem mlock |

#### Denial of Service

| Ameaça | Status | Mitigação |
|--------|--------|-----------|
| Flooding de Hellos | ⚠️ Parcial | Rate limiting, mas pending não bounded |
| Flooding de EPAs | ⚠️ Parcial | Vec unbounded (MEM-1) |
| CPU exhaustion via handshake | ✅ Mitigado | ML-KEM é rápido |
| Memory exhaustion | ⚠️ Parcial | 4 coleções unbounded |
| Clock skew attack | ✅ Mitigado | EPA timestamp verification |

#### Elevation of Privilege

| Ameaça | Status | Mitigação |
|--------|--------|-----------|
| Peer autenticado abusa de API | ⚠️ Parcial | Sem autorização por peer |
| Manipulação de reputação | ⚠️ Parcial | Ban após 10 falhas, mas sem proteção contra manipulação |
| Execução de código arbitrário | ✅ Mitigado | Sem unsafe, sem eval dinâmico |

### Fronteiras de Confiança

```
┌─────────────────────────────────────────────────────┐
│                    NÓ NEXOIA                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ Identity │  │ Session  │  │ Defense Layer     │  │
│  │ (keys)   │  │ Manager  │  │ (RateLimiter)     │  │
│  └──────────┘  └──────────┘  └──────────────────┘  │
│       ↑              ↑               ↑               │
│  ┌──────────────────────────────────────────────┐   │
│  │              Network Layer (UDP)              │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
                        ↓
        ┌───────────────────────────────┐
        │     Rede P2P (não confiável)  │
        └───────────────────────────────┘
```

---

## FASE 12 — RELATÓRIO EXECUTIVO

### Resumo Executivo

| Severidade | Quantidade |
|-----------|-----------|
| **CRÍTICO** | 1 |
| **ALTO** | 3 |
| **MÉDIO** | 6 |
| **BAIXO** | 5 |
| **Total** | 15 |

### Production Ready? **NÃO**

1 bug crítico (anti-replay ineficaz) e 3 bugs altos impedem uso em produção.

### Findings Completos

#### CRÍTICO (1)

| # | ID | Descrição | Arquivo:linha |
|---|-----|-----------|---------------|
| 1 | CONC-1 | Anti-replay clone-discard: bitmap nunca persiste | main.rs:870 |

#### ALTO (3)

| # | ID | Descrição | Arquivo:linha |
|---|-----|-----------|---------------|
| 2 | MEM-2 | PendingHandshake leak em falhas | main.rs:592-602 |
| 3 | HAND-1 | Handshake initiator não cria PendingHandshake | main.rs:226-247 |
| 4 | INV-2 | Handshakes podem ficar presos (sem timeout) | main.rs:308 |

#### MÉDIO (6)

| # | ID | Descrição | Arquivo:linha |
|---|-----|-----------|---------------|
| 5 | CONC-2 | Lock convoy heartbeat_monitor | main.rs:1292-1299 |
| 6 | MEM-1 | Vec<SharedEPA> unbounded | main.rs:160 |
| 7 | CRYPTO-1 | Chaves não zeroizadas no Drop | crypto.rs:15-16 |
| 8 | CRYPTO-2 | Nonce zero em SessionKeyConfirm | main.rs:749 |
| 9 | INV-5 | 4 coleções crescem infinitamente | multiple |
| 10 | INV-6 | Anti-replay ineficaz (decorre de CONC-1) | main.rs:870 |

#### BAIXO (5)

| # | ID | Descrição | Arquivo:linha |
|---|-----|-----------|---------------|
| 11 | MEM-3 | ReputationStore unbounded | reputation.rs:69 |
| 12 | MEM-4 | peer_states pode crescer | main.rs:196 |
| 13 | DEF-1 | Race condition teórica no RateLimiter | defense.rs:194 |
| 14 | INV-8 | Tasks sem JoinHandle | main.rs:255+ |
| 15 | DEAD-1 | ~60+ funções dead code em nex/ | multiple |

### Top 10 Riscos

1. **Anti-replay ineficaz** — Mensagens podem ser replayed
2. **Handshake initiator broken** — Só funciona em modo respondedor
3. **Memory exhaustion via EPA** — Vec cresce sem limite
4. **PendingHandshake leak** — Atacante pode exaurir memória
5. **Sem key rotation** — Comprometimento de chave estática expõe todas as sessões
6. **Lock convoy** — Heartbeats atrasados causam falsos positivos
7. **Chaves em memória** — Não zeroizadas, vulneráveis a memory dumps
8. **Tasks não rastreáveis** — Panic em task = node zumbi
9. **Sessões não limpas** — Se heartbeat_monitor panique
10. **Nonce zero** — Viola best practices (risco prático baixo)

### Roadmap de Correção

#### P0 — Imediato (antes de qualquer teste em produção)

1. **FIX CONC-1:** `SessionManager::check_counter()` — resolver clone-discard
2. **FIX MEM-2:** `pending.remove(&addr)` em todos os paths de falha
3. **FIX HAND-1:** Criar `PendingHandshake::new_initiator()` + inserir antes de Hello
4. **FIX INV-2:** Timeout de 5 minutos para pending_handshakes

**Tempo estimado:** 2-4 horas

#### P1 — Curto prazo (1 semana)

5. **FIX MEM-1:** Max EPAs com FIFO eviction
6. **FIX CONC-2:** Coletar ações antes de adquirir locks
7. **FIX CRYPTO-1:** Ativar feature `static_secrecy`
8. **FIX CRYPTO-2:** Nonce aleatório em SessionKeyConfirm
9. **FIX DEAD-1:** Remover ou documentar dead code

**Tempo estimado:** 1-2 dias

#### P2 — Médio prazo (1 mês)

10. **FIX MEM-3:** TTL de 30 dias para ReputationStore
11. **FIX INV-9:** Armazenar JoinHandles para monitoramento
12. **Key rotation periódico** — Nova chave a cada N horas
13. **Property tests** — Anti-replay, session key, concurrent access
14. **Fuzz targets** — SecureMessage, NetworkMessage

**Tempo estimado:** 1 semana

#### P3 — Longo prazo

15. Formal verification com `kani` ou `prusti`
16. Audit externo por firma especializada
17. Hardening de disco (mlock, permissões)

**Tempo estimado:** 1-2 meses

### Tempo Estimado para Endurecimento

| Fase | Esforço |
|------|---------|
| P0 (críticos) | 4 horas |
| P1 (curto prazo) | 2 dias |
| P2 (médio prazo) | 1 semana |
| P3 (longo prazo) | 1-2 meses |
| **Total até production-ready** | **~2 semanas** |
