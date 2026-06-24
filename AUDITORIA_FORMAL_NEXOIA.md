# AUDITORIA FORMAL ENTERPRISE — NEXOIA

**Data:** 2026-06-24
**Auditor:** opencode/mimo-v2-5-free (formal audit)
**Escopo:** Arquitetura, concorrência, criptografia, defesa, invariantes
**Método:** Revisão estática + análise de ownership + verificação formal leve

---

## RESUMO EXECUTIVO

| Severidade | Quantidade |
|-----------|-----------|
| **CRÍTICO** | 1 |
| **ALTO** | 3 |
| **MÉDIO** | 6 |
| **BAIXO** | 4 |
| **Total** | 14 |

**Production Ready?** **NÃO** — 1 bug crítico (anti-replay ineficaz) e 3 bugs altos impedem uso em produção.

---

## FASE 1 — BUILD SANITY

### Resultados

| Comando | Resultado |
|---------|-----------|
| `cargo check` | ✅ 0 erros, ~7 warnings (unused imports) |
| `cargo test` | ⚠️ 146 passed, **1 FAILED** |
| `cargo clippy` | ✅ 0 erros, warnings (dead_code, unused imports) |

### Teste Falho

**`session_counter_window`** — `src/network/session.rs:272`

```rust
#[test]
fn session_counter_window() {
    let mut session = SessionState::new([0u8; 32], [1u8; 32], [2u8; 32]);
    assert!(session.check_counter(100));
    assert!(session.check_counter(950));
    assert!(!session.check_counter(50));  // ← FALHA: counter 50 dentro da janela de 1024
}
```

**Causa:** Teste escrito para janela de 64 bits antiga. Implementação atual usa janela de 1024 bits. Counter 50 com diff=900 está dentro da janela → é aceito (correto).

**Severidade:** BAIXO — teste obsoleto, não bug de implementação.

**Patch:** Atualizar teste para refletir janela de 1024 bits.

---

## FASE 2 — LOCK DEPENDENCY GRAPH

### Recursos Sincronizados

| ID | Tipo | Local | Propósito |
|----|------|-------|-----------|
| L1 | `Arc<RwLock<Vec<SharedEPA>>>` | main.rs:160 | Lista de EPAs |
| L2 | `Arc<RwLock<PeerList>>` | main.rs:161 | Peers desconhecidos |
| L3 | `Arc<RwLock<ReputationStore>>` | main.rs:182 | Reputação dos nós |
| L4 | `Arc<RwLock<TrustedPeerList>>` | main.rs:188 | Peers autenticados |
| L5 | `Arc<RwLock<HashMap<SocketAddr, PeerState>>>` | main.rs:196 | Estado de heartbeat |
| L6 | `Arc<RwLock<HashMap<SocketAddr, PendingHandshake>>>` | main.rs:308 | Handshakes pendentes |
| L7 | `Arc<SessionManager>` → `RwLock<HashMap<SocketAddr, SessionState>>` | session.rs:172 | Sessões ativas |
| M1 | `Mutex<Instant>` | session.rs:33 | Última atividade da sessão |

### Tasks Tokio

| Task | Função | Locks Adquiridos |
|------|--------|------------------|
| T1 | `run_heartbeat_sender` | L4(r) → L5(w) |
| T2 | `run_heartbeat_monitor` | L7(w:cleanup) → L5(r) → L5(w)+L3(w) simultâneo → L4(r) → L4(w)+L5(w) |
| T3 | `run_udp_listener` | L6(w) variável, L5(w), L4(r/w), L3(w), L7(r/w) |
| T4 | `run_discovery` | Nenhum |
| T5 | `run_pipeline` | L1(w), L2(r), L4(r) |
| T6 | `verify_and_store_epa` (spawned) | L3(w) → L1(w) |
| T7 | HTTP API handlers | L1(r/w) |

### Grafo de Aquisição Simultânea

```
T2 (heartbeat_monitor):
  L5(write) + L3(write)  →  LINHA 1292-1299

T3 (udp_listener) - Heartbeat msg:
  L5(write)  →  L7(read)  →  L1(write)  →  L7(write)

T3 (udp_listener) - EPA msg:
  L4(read)  →  L3(w) [via spawned task]

T5 (run_pipeline):
  L1(write)  →  L2(read)  →  L4(read)
```

### Detecção de Deadlock

**Ciclos de deadlock:** ❌ Nenhum ciclo confirmado.

Todas as aquisições simultâneas seguem ordenação consistente:
- L5 antes de L3 (heartbeat_monitor)
- L3 antes de L1 (verify_and_store_epa)
- L1 antes de L2 (run_pipeline)

### Starvation / Lock Convoy

**CONC-2 (MÉDIO):** Lock convoy no heartbeat_monitor.

**Arquivo:** `src/main.rs:1292-1299`

```rust
for event in &events {
    let result = reactive_engine.evaluate(event);
    if result.matched {
        let mut peer_states_mut = peer_states.write().await;  // L5(w)
        let mut rep = reputation.write().await;                // L3(w)
        let _report = ActionExecutor::execute(
            &result.actions,
            &mut peer_states_mut,
            &mut rep,
            &peer_addrs_map,
        );
    }
}
```

**Problema:** L5(w) + L3(w) mantidos simultaneamente dentro do loop. Para cada evento que casa, ambas as locks são mantidas enquanto `ActionExecutor::execute` roda. Isso pode starvar T1 (heartbeat_sender) e T3 (udp_listener) que competem por L5.

**Impacto:** Heartbeats podem ser atrasados, causando falsos positivos de "peer inativo".

**Patch:**
```rust
// Coletar ações primeiro, depois aplicar
let mut deferred_actions = Vec::new();
for event in &events {
    let result = reactive_engine.evaluate(event);
    if result.matched {
        deferred_actions.extend(result.actions);
    }
}
if !deferred_actions.is_empty() {
    let mut peer_states_mut = peer_states.write().await;
    let mut rep = reputation.write().await;
    let _report = ActionExecutor::execute(
        &deferred_actions,
        &mut peer_states_mut,
        &mut rep,
        &peer_addrs_map,
    );
}
```

**Teste:** Monitorar latência de heartbeat com 10+ peers ativos.

---

## FASE 3 — RESOURCE OWNERSHIP VERIFICATION

### Modelo de Tokens

| Token | Criado em | Proprietário | Liberado em | Ciclo |
|-------|-----------|-------------|-------------|-------|
| `SessionToken` | main.rs:772,838 | SessionManager | session.rs:219 (cleanup) | ✅ |
| `HandshakeToken` | main.rs:514 | pending_handshakes | main.rs:779,851 | ⚠️ leak em falhas |
| `KeyToken` | crypto.rs:21 | NodeIdentity | Drop impl | ⚠️ não zeroizado |
| `PeerToken` | main.rs:770,832 | TrustedPeerList | trusted.rs:remove | ✅ |
| `EPAToken` | main.rs:425,1102 | Vec<SharedEPA> | Nunca | ❌ unbounded |
| `TaskToken` | main.rs:255,289,310,327,336 | tokio runtime | JoinHandle drop | ✅ |

### Finding: CONC-1 — Clone-Discard Bug (Anti-Replay)

**SEVERIDADE: CRÍTICO**

**Arquivo:** `src/main.rs:870-877`

```rust
// Decripta mensagem
match secure_msg.decrypt(&session.session_key) {
    Ok((counter, payload)) => {
        // Verifica anti-replay
        let mut session_mut = session.clone();  // ← CLONE descartável
        if !session_mut.check_counter(counter) { // ← modifica clone
            eprintln!(
                "  ✗ Replay detected from {} (counter={})",
                addr, counter
            );
            continue;
        }
        // session_mut é descartado aqui — mudanças NÃO persistem
```

**Prova:**
1. `SessionManager::get()` retorna `Option<SessionState>` via `.cloned()` (session.rs:191)
2. Clone cria cópia independente com bitmap duplicado
3. `check_counter()` modifica `recv_counter` e `recv_window` no clone
4. Clone sai de escopo → mudanças perdidas
5. Estado real em `SessionManager` nunca é atualizado
6. **Resultado: Anti-replay é ineficaz.** Qualquer mensagem repetida passa.

**Impacto:** Atacante pode reenviar mensagens antigas indefinidamente. Violação de integridade de mensagens.

**Patch (mínimo):**
Adicionar método `check_counter` ao `SessionManager`:

```rust
// Em session.rs, adicionar ao impl SessionManager:
pub async fn check_counter(&self, addr: &SocketAddr, counter: u64) -> bool {
    let mut sessions = self.sessions.write().await;
    if let Some(session) = sessions.get_mut(addr) {
        session.check_counter(counter)
    } else {
        false
    }
}
```

Em main.rs:870-877, substituir:
```rust
// ANTES:
let mut session_mut = session.clone();
if !session_mut.check_counter(counter) { ... }

// DEPOIS:
if !session_manager.check_counter(&addr, counter).await {
    eprintln!("  ✗ Replay detected from {} (counter={})", addr, counter);
    continue;
}
```

**Teste:** Enviar mesma mensagem duas vezes; segunda deve ser rejeitada.

### Finding: MEM-2 — PendingHandshake Leak

**SEVERIDADE: ALTO**

**Arquivo:** `src/main.rs:592-602`

```rust
if !valid {
    eprintln!("  ✗ Invalid Ed25519 signature from {}", addr);
    hs.phase = HandshakePhase::Failed("Invalid signature".to_string());
    continue;  // ← NÃO remove de pending_handshakes
}

if x25519_pubkey.len() != 32 {
    eprintln!("  ✗ Invalid x25519 pubkey length from {}", addr);
    continue;  // ← NÃO remove de pending_handshakes
}
```

**Problema:** Paths de falha em ChallengeResponse (linhas 592-602) usam `continue` sem `pending.remove(&addr)`. Handshake fica em estado `Failed` mas nunca é removido do HashMap.

**Impacto:** Atacante pode enviar múltiplos ChallengeResponse inválidos para exaurir memória.

**Patch:** Adicionar `pending.remove(&addr);` antes de cada `continue` nos paths de falha.

**Teste:** Enviar 1000 ChallengeResponse inválidos; verificar que pending_handshakes não cresce.

### Finding: Handshake Initiator Broken

**SEVERIDADE: ALTO**

**Arquivo:** `src/main.rs:226-247`

```rust
// Conecta a bootstrap peers
for peer_addr in &config.bootstrap_peers {
    let hello = NetworkMessage::Hello { ... };
    let _ = bootstrap_socket.send_to(&framed, peer_addr).await;
    // ← NÃO cria PendingHandshake local
}
```

**Problema:** Quando o node inicia handshake enviando Hello, não cria `PendingHandshake` para si mesmo. Quando o respondedor responde com Challenge, o initiator busca em `pending_handshakes` (main.rs:534-537) e não encontra → "No pending handshake".

**Impacto:** Handshake só funciona em modo respondedor. Initiação é inoperante.

**Patch:** Criar `PendingHandshake::new_initiator()` e inserir em `pending_handshakes` antes de enviar Hello.

---

## FASE 4 — DYNAMIC COLLECTION AUDIT

| Coleção | Local | Bounded? | TTL? | Eviction? | Risco |
|---------|-------|----------|------|-----------|-------|
| `Vec<SharedEPA>` | main.rs:160 | ❌ | ❌ | ❌ | MEM-1 |
| `HashMap<SocketAddr, PendingHandshake>` | main.rs:308 | ❌ | ❌ | ❌ | MEM-2 |
| `HashMap<String, NodeReputation>` | reputation.rs:69 | ❌ | ❌ | ❌ | MEM-3 |
| `HashMap<SocketAddr, TrustedPeer>` | transport.rs:158 | ✅ max_peers | ❌ | ❌ | BAIXO |
| `Vec<DateTime<Utc>>` heartbeat_window | transport.rs:74 | ✅ 5 | N/A | ✅ remove(0) | BAIXO |
| `HashMap<SocketAddr, PeerState>` | main.rs:196 | ❌ | ❌ | ❌ | MEM-4 |
| `HashMap<IpAddr, ClientRate>` | api.rs:22 | ❌ | ❌ | ❌ | BAIXO |

### Finding: MEM-1 — Vec<SharedEPA> Unbounded

**SEVERIDADE: MÉDIO**

**Arquivo:** `src/main.rs:160`, `src/main.rs:425`, `src/main.rs:1102`

```rust
let epas: Arc<RwLock<Vec<SharedEPA>>> = Arc::new(RwLock::new(persisted.epas));
// ...
epa_list.push(epa.clone());  // ← sempre adiciona, nunca remove
```

**Problema:** EPA list cresce indefinidamente. Cada EPA contém hashes, assinaturas, e opcionalmente payload encriptado (~2-5KB cada). Com 1000 EPAs = ~5MB em memória.

**Impacto:** Memory exhaustion em produção com muitos peers.

**Patch:** Adicionar max_epas (ex: 1000) com FIFO eviction:
```rust
const MAX_EPAS: usize = 1000;
// Ao adicionar:
if epa_list.len() >= MAX_EPAS {
    epa_list.remove(0);
}
epa_list.push(epa);
```

**Teste:** Criar 2000 EPAs; verificar que lista não excede 1000.

### Finding: MEM-3 — ReputationStore Unbounded

**SEVERIDADE: BAIXO**

**Arquivo:** `src/network/reputation.rs:69`

```rust
pub struct ReputationStore {
    reputations: HashMap<String, NodeReputation>,  // ← cresce ilimitadamente
```

**Problema:** Entries nunca são removidas. Nós que saíram da rede permanecem para sempre.

**Patch:** Adicionar cleanup periódico de entries com `last_seen` > 30 dias.

---

## FASE 5 — STATE MACHINE FORMAL VERIFICATION

### FSM: Handshake (5 fases)

```
INITIATOR:
  [Idle]
    ↓ Hello enviado
  [PendingChallenge] ←── cria PendingHandshake
    ↓ Challenge recebido
  [ChallengeReceived]
    ↓ ChallengeResponse enviado
  [PendingSessionKey]
    ↓ SessionKeyExchange recebido
  [KeyDerivation]
    ↓ SessionKeyConfirm enviado
  [Complete]

RESPONDER:
  [Idle]
    ↓ Hello recebido
  [ChallengeSent] ←── cria PendingHandshake
    ↓ ChallengeResponse recebido
  [ResponseReceived]
    ↓ SessionKeyExchange enviado
  [PendingConfirm]
    ↓ SessionKeyConfirm recebido
  [Complete]

falha em qualquer estado → [Failed] → remove PendingHandshake
```

### Finding: Estado Inalcançável

O estado `HandshakePhase::HelloReceived` (handshake.rs:23) é definido mas nunca verificado explicitamente — o código pula direto para `ChallengeSent` no processamento do Hello (main.rs:509). Isso é correto (o received é implícito), mas o enum sugere que `HelloReceived` deveria ser um estado transicional visível.

### Finding: Ciclo Infinito Potencial

**Handshake:** ❌ Sem ciclo infinito. Cada fase avança ou falha.

**Session:** O heartbeat monitor roda em loop infinito (main.rs:1237). Isso é intencional (daemon), mas se a task panique, a sessão nunca é limpa. Tokio silently restarta a task se o runtime não panique.

**EPA lifecycle:** EPAs são append-only. Nunca são removidos. Ciclo: Created → Active → ForeverAlive. Violação do invariant "EventuallyReleased".

---

## FASE 6 — CRYPTOGRAPHIC AUDIT

### Chaves

| Chave | Geração | Persistência | Zeroização | Risco |
|-------|---------|-------------|-----------|-------|
| Ed25519 SigningKey | OsRng (32 bytes) | JSON (plaintext ou encrypted) | ❌ | CRYPTO-1 |
| X25519 StaticSecret | OsRng (32 bytes) | JSON (plaintext ou encrypted) | ❌ | CRYPTO-1 |
| ML-KEM dk_seed | ml_kem::Generate (64 bytes) | JSON (plaintext ou encrypted) | ❌ | CRYPTO-1 |
| Session key [u8;32] | HKDF-SHA256 | Memória apenas | ❌ | CRYPTO-1 |

### Finding: CRYPTO-1 — Chaves Não Zeroizadas

**SEVERIDADE: MÉDIO**

**Arquivo:** `src/network/crypto.rs:15-16`

```rust
pub struct KeyPair {
    pub public_key: PublicKey,
    secret: StaticSecret,  // ← não implementa Zeroize
}
```

`StaticSecret` do `x25519_dalek` não implementa `Zeroize`. Quando `KeyPair` é dropado, o secret permanece na memória até ser sobrescrito por alocação futura.

Da mesma forma, `SigningKey` do `ed25519_dalek` e `MlKemKeyPair.decapsulation_key_seed: Vec<u8>` não são zeroizados.

**Impacto:** Em caso de memory dump (core dump, swap, cold boot attack), chaves privadas podem ser recuperadas.

**Patch:**
```rust
use zeroize::Zeroize;

impl Drop for KeyPair {
    fn drop(&mut self) {
        // StaticSecret não tem Zeroize, mas podemos sobrescrever via unsafe
        // ou usar a flag do x25519_dalek
    }
}
```

**Nota:** `x25519_dalek::StaticSecret` suporta `Zeroize` via feature flag `static_secrecy`. Ativar em Cargo.toml.

**Teste:** Verificar que após drop, bytes da chave são zero (dificil de testar em Rust estável).

### Finding: CRYPTO-2 — Nonce Zero em SessionKeyConfirm

**SEVERIDADE: MÉDIO**

**Arquivo:** `src/main.rs:749,815`

```rust
let confirm_nonce = Nonce::from_slice(&[0u8; 12]);  // nonce zero
```

O nonce zero é usado tanto no encrypt quanto no decrypt do "OK" de confirmação. Como é usado apenas uma vez (handshake), o risco é limitado, mas viola a best practice de nunca reutilizar nonces.

**Impacto:** Baixo — usado apenas uma vez durante handshake.

**Patch:** Gerar nonce aleatório e incluir no SessionKeyConfirm.

### Finding: CRYPTO-3 — HKDF Info Strings

**SEVERIDADE: BAIXO**

**Arquivo:** `src/network/crypto.rs:151-153`

```rust
let hk = Hkdf::<Sha256>::new(Some(b"nexoia-hybrid-session-v1"), &ikm);
hk.expand(b"session-key", &mut key)
```

**Análise:**
- `salt`: `"nexoia-hybrid-session-v1"` — bom, separa domínios
- `info`: `"session-key"` — bom, previne cross-protocol
- IKM inclui nonces como parte do input — aceitável mas não ideal (nonces deveriam ser binds, não keying material)

**Impacto:** Nenhum risco prático identificado.

### Finding: Forward Secrecy

**Verificado:** ✅

Handshake usa chaves efêmeras X25519 (`EphemeralSecret`). Após derivação da chave de sessão, o `ephemeral_secret` é consumido via `.take()` (main.rs:636,725). Se o session key for comprometido, tráfego anterior não pode ser descriptografado (assumindo que o attacker não tenha comprometido a chave estática).

**Limitação:** Se a chave estática X25519 ou ML-KEM for comprometida, todas as sessões futuras podem ser descriptografadas (não há key rotation periódico).

### Finding: Replay Protection

**Verificado:** ❌ **INEFICAZ** devido ao CONC-1 (clone-discard). Ver FASE 3.

---

## FASE 7 — DEFENSE LAYER AUDIT

### Análise de `defense.rs`

**Bem implementado.** Análise detalhada:

1. **Sharding:** 64 shards com `Mutex<Shard>` — bom para reduzir contenção
2. **SourceReservation:** RAII pattern correto — `commit()` seta flag, `Drop` decrementa se não committed
3. **Cleanup worker:** Thread separada roda a cada 60s, remove entries expiradas
4. **Input validation:** `validate_raw_input` verifica empty, max size, null bytes
5. **Max sources:** 100,000 limit com `fetch_update` atômico

### Finding: DEF-1 — Race Condition no RateLimiter

**SEVERIDADE: BAIXO**

**Arquivo:** `src/defense.rs:194-216`

```rust
// 1. Verifica limite atomicamente
let reserved = self.active_sources.fetch_update(...);

// 2. Insere no shard (pode falhar se outro thread inseriu)
let mut timestamps = VecDeque::with_capacity(...);
timestamps.push_back(now);
shard.history.insert(source_key.to_string(), timestamps);

// 3. Commit (se não commitou, Drop decrementa)
reservation.commit();
```

**Problema teórico:** Entre o `fetch_update` (step 1) e o `insert` (step 2), outro thread pode incrementar o counter para o mesmo source_key. Isso permite que um source_key tenha ligeiramente mais requests que o limite.

**Impacto:** Prático: mínimo. O `trim_expired` no loop corrige a contagem eventualmente.

**Patch:** Não necessário — aceitável para rate limiting.

### Finding: DEF-2 — RateLimiter HashMap Unbounded

**SEVERIDADE: BAIXO**

**Arquivo:** `src/defense.rs:60`

```rust
struct Shard {
    history: HashMap<String, VecDeque<Instant>>,
}
```

Entries nunca são removidas explicitamente (apenas via cleanup worker). Se 100,000 sources diferentes fizerem request, o HashMap cresce até 100,000 entries.

**Impacto:** ~100K entries × ~100 bytes = ~10MB. Aceitável.

---

## FASE 8 — GLOBAL INVARIANTS

### INV-1: Nenhuma sessão permanece órfã

**Status:** ✅ PROVADO (com ressalva)

Sessões são criadas em main.rs:772,838 e removidas por:
- `SessionManager::cleanup(300)` no heartbeat_monitor (main.rs:1241)
- `SessionManager::remove()` quando peer é removido (main.rs:1309)

**Ressalva:** Se o heartbeat_monitor task panique, sessões não são limpas. Tokio não reinicia tasks spawned.

### INV-2: Todo handshake termina

**Status:** ❌ REFUTADO

Handshakes podem ficar presos em estado `PendingHandshake` se:
1. Initiator envia Hello mas nunca recebe Challenge (timeout não implementado)
2. Responder fica em `ChallengeSent` mas initiator desaparece
3. Falha em ChallengeResponse não remove o pending (MEM-2)

**Prova:** `pending_handshakes` não tem timeout de limpeza. Entries podem existir indefinidamente.

**Patch:** Adicionar sweep periódico em `pending_handshakes` que remove entries com >5 minutos.

### INV-3: Nenhuma chave efêmera é perdida

**Status:** ✅ PROVADO

Chaves efêmeras X25519 são geradas e consumidas via `.take()` (main.rs:636,725). Após consumidas, o Option fica None. Não há leak.

### INV-4: Nenhum recurso criptográfico sobrevive além do necessário

**Status:** ❌ REFUTADO

- `session_key: [u8;32]` em SessionState não é zeroizado no Drop
- `decapsulation_key_seed` em MlKemKeyPair não é zeroizado
- `SigningKey` não é zeroizado

**Ver CRYPTO-1.**

### INV-5: Nenhuma coleção cresce infinitamente

**Status:** ❌ REFUTADO

- `Vec<SharedEPA>` — ilimitado (MEM-1)
- `pending_handshakes` — ilimitado (MEM-2)
- `ReputationStore.reputations` — ilimitado (MEM-3)
- `peer_states` — ilimitado (MEM-4)

### INV-6: Nenhum replay é aceito

**Status:** ❌ REFUTADO (CRÍTICO)

Devido ao CONC-1 (clone-discard), o anti-replay bitmap nunca é atualizado no estado real. Mensagens antigas podem ser reenviadas indefinidamente.

### INV-7: Nenhum peer removido continua ativo

**Status:** ✅ PROVADO

Quando peer é removido em main.rs:1307-1311:
```rust
peers.remove(addr);
states.remove(addr);
```

Ambos os maps são limpos. Sessão é limpa pelo cleanup periódico (INV-1).

**Ressalva:** TrustedPeerList.remove() não limpa a sessão correspondente no SessionManager. A sessão só expira via cleanup(300).

### INV-8: Todo canal é encerrado

**Status:** ⚠️ PARCIALMENTE PROVADO

UDP socket é bindado uma vez e nunca fechado explicitamente. Tokio encerra quando a task principal termina. Em crash, o OS fecha o socket.

### INV-9: Toda task termina ou permanece rastreável

**Status:** ⚠️ PARCIALMENTE PROVADO

Tasks são spawned com `tokio::spawn` sem JoinHandle armazenado. Se uma task panique, não há como detectar. Tokio não reinicia automaticamente.

**Impacto:** Se `run_udp_listener` panique, o node fica vivo mas não recebe mensagens.

### INV-10: Todo recurso possui exatamente um proprietário

**Status:** ❌ REFUTADO (CONC-1)

`SessionManager::get()` retorna `.cloned()`, criando múltiplas cópias. A anti-replay state é proprietária de cada clone. Modificações em um clone não afetam outros.

---

## FASE 9 — PROXY TYPES

### Busca por Tipos Proxy

| Padrão | Encontrado? | Detalhes |
|--------|------------|----------|
| `ManuallyDrop` | ❌ | Não usado |
| `Box::into_raw` | ❌ | Não usado |
| `*mut T` | ❌ | Não usado |
| `*const T` | ❌ | Não usado |
| Unsafe blocks | ❌ | Não usado |

**Conclusão:** ✅ Nenhum proxy type leak detectado. O código é 100% safe Rust.

---

## FASE 10 — RELATÓRIO FINAL

### Classificação por Severidade

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
| 9 | MEM-4 | peer_states unbounded | main.rs:196 |
| 10 | INV-5 | 4 coleções crescem infinitamente | multiple |

#### BAIXO (4)

| # | ID | Descrição | Arquivo:linha |
|---|-----|-----------|---------------|
| 11 | MEM-3 | ReputationStore unbounded | reputation.rs:69 |
| 12 | DEF-1 | Race condition teórica no RateLimiter | defense.rs:194 |
| 13 | DEF-2 | RateLimiter HashMap unbounded | defense.rs:60 |
| 14 | TEST-1 | Teste session_counter_window obsoleto | session.rs:272 |

### Top 10 Riscos

1. **Anti-replay ineficaz** — Mensagens podem ser replayed indefinidamente
2. **Handshake initiator broken** — Só funciona em modo respondedor
3. **Memory exhaustion via EPA** — Vec cresce sem limite
4. **PendingHandshake leak** — Atacante pode exaurir memória
5. **Sem key rotation** — Comprometimento de chave estática expõe todas as sessões
6. **Lock convoy** — Heartbeats atrasados causam falsos positivos
7. **Chaves em memória** — Não zeroizadas, vulneráveis a memory dumps
8. **Tasks não rastreáveis** — Panic em task = node zumbi
9. **Sessões não limpas** — Se heartbeat_monitor panique
10. **Nonce zero** — Viola best practices (risco prático baixo)

### Roadmap de Endurecimento

#### Prioridade 1 (Imediato — antes de produção)

1. **FIX CONC-1:** `SessionManager::check_counter()` — resolver clone-discard
2. **FIX MEM-2:** `pending.remove(&addr)` em todos os paths de falha
3. **FIX HAND-1:** Criar `PendingHandshake::new_initiator()` + inserir antes de Hello
4. **FIX TEST-1:** Atualizar `session_counter_window` para janela de 1024 bits

#### Prioridade 2 (Curto prazo — 1-2 semanas)

5. **FIX MEM-1:** Max EPAs com FIFO eviction
6. **FIX INV-2:** Timeout de 5 minutos para pending_handshakes
7. **FIX CONC-2:** Coletar ações antes de adquirir locks
8. **FIX CRYPTO-1:** Ativar feature `static_secrecy` para zeroização

#### Prioridade 3 (Médio prazo — 1 mês)

9. **FIX CRYPTO-2:** Nonce aleatório em SessionKeyConfirm
10. **FIX MEM-3:** TTL de 30 dias para ReputationStore
11. **FIX INV-9:** Armazenar JoinHandles para monitoramento de tasks
12. **Key rotation periódico** — Nova chave a cada N horas

#### Prioridade 4 (Longo prazo)

13. Formal verification com `kani` ou `prusti`
14. Fuzzing com `cargo-fuzz`
15. Audit externo por firma especializada

---

## APÊNDICE: LOCK ACQUISITION GRAPH COMPLETO

```
T1 (heartbeat_sender):
  L4(read) → drop → L5(write) → drop

T2 (heartbeat_monitor):
  L7(cleanup/write) → drop
  L5(read) → drop
  [loop events]:
    L5(write) + L3(write) simultâneo → drop
  L4(read) → drop
  L4(write) + L5(write) → drop

T3 (udp_listener):
  Hello:        L6(write) → drop
  Challenge:    L6(write) → drop
  ChallengeResp: L6(write) → [ML-KEM] → drop
  SKE:          L6(write) → drop
  SKC:          L6(write) → L4(write) + L7(write) → drop
  SecureMsg:    L7(read) → drop
  Heartbeat:    L5(write) → L7(read) → drop
  PeerExchange: L4(read) → drop
  EPA:          L4(read) → spawn T6

T5 (run_pipeline):
  L1(write) → drop → L2(read) → drop → L4(read) → drop

T6 (verify_and_store_epa):
  L3(write) → drop → L1(write) → drop
```

**Deadlock analysis:** ✅ Sem ciclos. Todas as aquisições seguem ordem consistente.
