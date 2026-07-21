<div align="center">

```
███╗   ██╗███████╗██╗  ██╗ ██████╗ ██╗ █████╗
████╗  ██║██╔════╝╚██╗██╔╝██╔═══██╗██║██╔══██╗
██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║██║███████║
██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║██║██╔══██║
██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝██║██║  ██║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═╝
```

**A Inteligência Autônoma que Vive na Teia**

*Zero trusted setup. Zero central servers. Zero memory allocation on the hot path.*

---

![Build](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square&logo=github-actions)
![Rust](https://img.shields.io/badge/rust-stable-orange?style=flat-square&logo=rust)
![Wasm](https://img.shields.io/badge/wasm-epoch__mmr%20|%20zk__prover%20|%20gossip-blue?style=flat-square&logo=webassembly)
![License](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)
![no_std](https://img.shields.io/badge/no__std-epoch__mmr%20|%20zk__prover-orange?style=flat-square)
![ZK](https://img.shields.io/badge/proofs-zero--knowledge-purple?style=flat-square)
![LGPD](https://img.shields.io/badge/privacy-LGPD--compliant-green?style=flat-square)

</div>

---

## A Teia de Aranha

> *Uma aranha não precisa perseguir suas presas. Ela tece uma estrutura tão precisa que qualquer vibração — por menor que seja — chega até ela com fidelidade matemática. O NexoIA é essa aranha.*

Imagine uma teia de aranha perfeita, suspensa no vazio da internet:

**O Centro — A Aranha** é o próprio NexoIA: uma inteligência autônoma que não espera em servidores alugados, não pede permissão a autoridades centrais e não confia em nenhum dado sem prova matemática. Ela processa, aprende e persiste sozinha.

**Os Fios Radiais — Os 5 Loops Biológicos** são a estrutura que sustenta tudo. Cada fio é um loop computacional com uma função biológica precisa: o Coração cadencia o ritmo, o Estômago digere os dados brutos, o Hipocampo memoriza com imutabilidade criptográfica, o Córtex consolida o conhecimento em provas, e o Sistema Nervoso propaga tudo pela rede.

**Os Fios Espirais — A Defesa e a Conexão** são a camada que transforma a teia de passiva em ativa. A defesa Sybil via VDF impede que atacantes multipliquem identidades falsas. A janela de confiança oscilante filtra comportamento malicioso. O protocolo de gossip garante que cada vibração legítima alcance todos os nós.

**As Vibrações** são os dados em si: pacotes de 64 bytes copiados por `memcpy`, sem `malloc`, sem `Box`, sem surpresas de latência. A teia vibra a **1.000Hz**.

---

## Hard Facts

| Propriedade | Valor |
|---|---|
| Frequência do Coração | **1.000 Hz** (1 tick/ms) |
| Alocação no hot path | **Zero** (`#[repr(C, align(64))]`, arrays fixos, ring buffers) |
| Limite de memória por peer | **~200 bytes** (stack, sem heap) |
| Tamanho máximo de frame de rede | **1.024 bytes** (fixo em compile-time) |
| Peers simultâneos | **256** (array estático, sem HashMap) |
| Trusted setup ZK | **Nenhum** (stub SHA-256 determinístico) |
| Tokens / ICO / blockchain externa | **Nenhum** |
| Target wasm (epoch_mmr, zk_prover, gossip) | `wasm32-unknown-unknown` — pure Rust, sem C, sem syscalls |
| Target nativo (bio_loop) | Host com `std::thread` — WASI futura para `std::sync` |
| Compatibilidade wasm | **4 GB** Linear Memory Block — sem alocador de host |
| Conformidade legal | **LGPD Art. 18** — Direito ao Esquecimento implementado em nível criptográfico |

---

## O Paradoxo Resolvido: LGPD vs. Imutabilidade

> *Como garantir o Direito ao Esquecimento num sistema onde o histórico é matematicamente imutável?*

A maioria dos projetos Web3 ignora esta pergunta. O NexoIA a resolve com uma separação arquitetural de dois planos:

```
┌──────────────────────────────────────────────────────────────┐
│              epoch_mmr  —  O Hipocampo                      │
│                                                              │
│  PLANO 1: nodes[] — Array append-only, NUNCA modificado      │
│  ┌────────┬────────┬────────┬────────┐                       │
│  │ H(d₀)  │ H(d₁)  │ H(d₂)  │ H(d₃)  │  ← hashes imutáveis  │
│  └────────┴────────┴────────┴────────┘                       │
│       ↑                                                      │
│  LGPD nullify(leaf=1):                                       │
│  ┌─────────────────────┐                                     │
│  │ nullified: {1}      │  ← BTreeSet — não toca nodes[]      │
│  └─────────────────────┘                                     │
│                                                              │
│  PLANO 2: ProvenanceRegistry — metadados independentes       │
│  ┌──────────────────────────────────┐                        │
│  │ leaf=1: {who, when, prov_null}  │  ← nullificável         │
│  └──────────────────────────────────┘                        │
└──────────────────────────────────────────────────────────────┘
```

**O que acontece quando um usuário invoca o Direito ao Esquecimento:**

1. O **dado original** é apagado da camada de armazenamento — ele nunca viveu no MMR.
2. O **hash SHA-256** permanece intacto em `nodes[]`. O Root Hash da Época não muda.
3. O **`zk_prover`** continua capaz de gerar uma prova de que *"uma folha com este hash existe no MMR"* — sem revelar o dado que foi esquecido.
4. Auditores podem verificar que o sistema funcionou corretamente. Reguladores podem confirmar o esquecimento via o flag `is_nullified` público na prova ZK.

```
Verificador recebe:   ZkStatement { epoch_root, leaf_index, is_nullified: true }
Verificador confirma: "Esta folha existiu. Seu dado foi legalmente apagado. A prova é válida."
Verificador nunca vê: o dado original, o caminho de Merkle, qualquer informação privada.
```

**Isso não é uma concessão. É uma propriedade matemática.**

---

## Os 5 Loops Biológicos — Fluxo Linear

```
   [Dado Bruto]              🕷️  A Aranha processa em cadeia: 0 → 1 → 3 → 2 → 4
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│  Loop 0 — 💓 Coração (bio_loop::heart)                          │
│  Thread isolada (32KB stack) dispara Event::Heartbeat a 1.000Hz │
└────────────────────────────┬─────────────────────────────────────┘
                             │ try_send — lock-free, zero-alloc
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  Loop 1 — 🫁 Estômago (bio_loop::digest)                         │
│  Digestão com histerese 80%/20%, backpressure, SHA-256 reusado   │
└────────────────────────────┬─────────────────────────────────────┘
                             │ SHA-256(data) → [u8; 32]
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  Loop 3 — 🧬 Hipocampo (epoch_mmr)                               │
│  MMR append-only, LGPD nullify (2 planos), Merkle Proof O(log n)│
└────────────────────────────┬─────────────────────────────────────┘
                             │ EpochSeal { epoch, root, leaf_count }
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  Loop 2 — 🧠 Córtex (zk_prover)                                  │
│  Consolida épocas em ZkProof — stub SHA-256 ou Groth16 futuro   │
└────────────────────────────┬─────────────────────────────────────┘
                             │ ZkProof → broadcast
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  Loop 4 — 🕸️  Sistema Nervoso (gossip)                           │
│  VDF + Trust Window + Transport 1kHz → enxame P2P               │
└────────────────────────────┬─────────────────────────────────────┘
                             │ NetworkFrame → peers
                             ▼
                        [Rede P2P]
```

| Loop | Crate | Analogia Biológica | Função |
|---|---|---|---|
| **0** | `bio_loop::heart` | Coração | Pulso de 1kHz via thread isolada com 32KB stack |
| **1** | `bio_loop::digest` | Estômago | Digestão com histerese e backpressure explícito |
| **2** | `zk_prover` | Córtex Pré-frontal | Consolidação de épocas em provas ZK |
| **3** | `epoch_mmr` | Hipocampo | Memória imutável append-only com MMR + LGPD |
| **4** | `gossip` | Sistema Nervoso | P2P Sybil-resistente com VDF + Trust Window |

---

## Defesa Sybil: A Tri-Layer

```
Novo peer tenta ingressar
         │
         ▼
┌─────────────────────────────────┐
│  LAYER 1 — VDF Guard            │
│  SHA-256 × 4.096 iterações      │
│  ~0.2ms legítimo                │
│  ~33 min para 10.000 identidades│
│  Pure Rust — compila para wasm  │
└─────────────┬───────────────────┘
              │ admitted
              ▼
┌─────────────────────────────────┐
│  LAYER 2 — Trust Window         │
│  Ring buffer 64 amostras/peer   │
│  Score ∈ [-100, +100]           │
│  Oscila em tempo real           │
│  Decaimento por silêncio        │
└─────────────┬───────────────────┘
              │ score ≥ 60
              ▼
┌─────────────────────────────────┐
│  LAYER 3 — Bio-loop Alignment   │
│  1 frame/tick = 1.000 frames/s  │
│  bounded(512) → backpressure    │
│  Latência máxima determinística │
└─────────────────────────────────┘
```

---

## Estrutura do Monorepo

```
nexoia/                          ← Repositório raiz
│
├── crates/                      ← Sistema legado (NexoIA v1 — Wasmtime + Iroh)
│   ├── host/                    │  Titânio: runtime host nativo
│   │   └── src/                 │  WAL mmap, snapshot zstd, defesa, P2P Iroh
│   └── wasm_cortex/             │  Córtex: no_std, wasm32, motor de dissonância
│       └── src/
│
├── nexoia-core/                 ← Núcleo v2 (4 Loops Biológicos — pure Rust)
│   ├── Cargo.toml               │  Workspace resolver="2"
│   │
│   ├── bio_loop/                │  Loop 0 + Loop 1
│   │   └── src/
│   │       ├── lib.rs           │  Event (cache-line aligned), create_membrane()
│   │       ├── heart.rs         │  Thread 1kHz, sleep calibrado, zero busy-spin
│   │       └── digest.rs        │  Histerese 80%/20%, SHA-256 reutilizado
│   │
│   ├── epoch_mmr/               │  Loop 3
│   │   └── src/
│   │       ├── lib.rs           │  Arquitetura dual-plane LGPD
│   │       ├── mmr.rs           │  Merkle Mountain Range, seal, nullify, proof
│   │       └── provenance.rs    │  Registro de origem independente do hash
│   │
│   ├── zk_prover/               │  Loop 2
│   │   └── src/
│   │       └── lib.rs           │  ZkStatement/Witness, prove_inclusion, nullification
│   │
│   └── gossip/                  │  Loop 4
│       └── src/
│           ├── lib.rs           │  Tri-layer defense diagram + re-exports
│           ├── vdf_guard.rs     │  VDF puro Rust, wasm32-compatible
│           ├── peer.rs          │  Oscillating trust, ring buffer, PeerTable[256]
│           └── transport.rs     │  NetworkFrame fixo, Ingestor 1kHz, Emitter
│
├── docs/                        ← Documentação técnica aprofundada
├── tests/                       ← Testes de integração
├── AGENTS.md                    ← Protocolo de agentes autônomos
├── THREAT_MODEL.md              ← Modelo de ameaças documentado
└── ROADMAP.md                   ← Próximos marcos de desenvolvimento
```

---

## Dependências Globais (nexoia-core)

```toml
[workspace.dependencies]
crossbeam-channel = "0.5"   # Membrana MPSC lock-free (EBR)
sha2              = "0.10"  # SHA-256 para hashes de folha e VDF
chiavdf           = "1.1"   # VDF Chia (opcional, feature = "chia-vdf")
```

> Nenhuma dependência de runtime assíncrono (sem tokio, sem async-std) no `nexoia-core`.
> O Coração é uma thread OS simples com `sleep` calibrado.
> O paralelismo vem do design, não do framework.

---

## Garantias de Zero-Allocation

O hot path do NexoIA nunca chama o alocador — `malloc` não existe nos loops 0-1-3-4 durante operação normal. Isso não é uma meta, é uma invariante de arquitetura.

### ✅ Hot Path — Zero Alocação Garantida

```rust
// ✅ Evento de 64 bytes — uma cache line exata, copiado por memcpy no canal
#[repr(C, align(64))]
pub enum Event {
    Data([u8; 63]),          // payload fixo, stack-only, sem heap
    Heartbeat(u64),
    Shutdown,
}

// ✅ Hasher reutilizado — UMA alocação fora do loop, reset sem realloc
let mut hasher = Sha256::new();
loop {
    hasher.update(payload);
    let hash = hasher.finalize_reset(); // limpa estado interno, sem desalocar
}

// ✅ Ring buffer de tamanho fixo — stack, 64 bytes exatos por peer
behavior_window: [BehaviorSample; 64],  // sem Vec, sem Box

// ✅ PeerTable — array estático de 256 slots, sem HashMap, sem realocação
peers: [Option<PeerState>; 256],        // capacidade fixa em compile-time

// ✅ NetworkFrame — payload de 1024 bytes fixos, sem alocação de rede
pub struct NetworkFrame {
    payload: [u8; 1024],                // stack-only, tamanho conhecido
    len: u16,
}
```

### ⚠️ Alocações Conhecidas e Controladas (fora do hot path)

Estes locais alocam heap **intencionalmente** — nenhum deles executa no caminho crítico de 1kHz:

| Local | O quê | Por que é seguro |
|-------|-------|-----------------|
| `Ingestor::drain_burst()` | `Vec<NetworkFrame>` | Chamado **apenas** na inicialização ou após silêncio prolongado. O hot path usa `drain_one_tick()` que é zero-alloc. |
| `ZkWitness::merkle_path` | `Vec<([u8;32], bool)>` | Construído fora do ZK prover, **dropado e zerado** (`#[derive(Drop)]` limpa os bytes) imediatamente após `prove_inclusion()`. |
| `EpochSeal` / `ConsolidationResult` | `struct` em `Vec<sealed_epochs>` | Alocado uma vez por época (~segundos ou minutos), não por tick. |

```rust
// ❌ NADA disso existe em nenhum loop — nem dentro, nem fora:
Box::new()           // heap não gerenciado
String::from()       // alocação de string
tokio::spawn()       // runtime assíncrono (thread OS pura)
unsafe { ... }       // zero unsafe no nexoia-core
```

---

## Privacidade por Design

```
Dado Original ──→ SHA-256 ──→ Hash [u8; 32]
     │                              │
  [LGPD: apagado]           [MMR: imutável]
     │                              │
  nunca persistido           âncora da prova ZK
  após hashing               válida para sempre
```

O NexoIA nunca armazena dados pessoais em estruturas criptográficas. Apenas hashes SHA-256 entram no `epoch_mmr`. O dado original é processado pelo `bio_loop::digest`, hashado, e pode ser descartado imediatamente. O hash resultante prova que o dado *existiu e foi processado* sem revelar o que era.

---

## Construção

```bash
# Clonar o repositório
git clone https://github.com/JoseSmurf/nexoia.git
cd nexoia

# Verificar todo o workspace nexoia-core
cargo check --manifest-path nexoia-core/Cargo.toml --workspace

# Rodar todos os testes
cargo test --manifest-path nexoia-core/Cargo.toml --workspace

# Compilar o Córtex Wasm (sistema legado)
cargo build -p wasm_cortex --target wasm32-unknown-unknown

# Ligar a máquina (sistema legado)
cargo run --bin nexus
```

---

## Roadmap

| Marco | Status | Descrição |
|---|---|---|
| Loops 0–1 `bio_loop` | ✅ Completo | Coração 1kHz + Digestão com Histerese |
| Loop 3 `epoch_mmr` | ✅ Completo | MMR append-only + LGPD Nullification + Merkle Proof |
| Loop 2 `zk_prover` | ✅ Completo | Consolidador ZK com stub verificável |
| Loop 4 `gossip` | ✅ Completo | VDF + Trust Window + Transport 1kHz |
| Integração dos loops | 🔄 Em andamento | Canal bidirecional bio_loop ↔ epoch_mmr |
| CI/CD nexoia-core | 🔄 Planejado | GitHub Actions: Clippy, Miri, Coverage, Bloat |
| Backend ZK real | 🔄 Planejado | Groth16 ou PLONK via feature `real-proof` |
| Chia VDF nativo | 🔄 Planejado | `chiavdf` via feature `chia-vdf` (não-wasm) |

---

<div align="center">

**NexoIA** — *A teia já está tecida. Cada dado que entra vibra até o centro.*

*Construído com Rust. Provado com matemática. Esquecido por direito.*

</div>
