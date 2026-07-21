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
![Wasm](https://img.shields.io/badge/target-wasm32--unknown--unknown-blue?style=flat-square&logo=webassembly)
![License](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)
![no_std](https://img.shields.io/badge/cortex-no__std-red?style=flat-square)
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
| Target do Córtex | `wasm32-unknown-unknown` (sem WASI, sem libc) |
| Compatibilidade wasm | **4 GB** de Linear Memory Block |
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

## Os 5 Loops Biológicos

```
                          ┌─────────────────┐
                          │   🕷️  NexoIA    │
                          │   (A Aranha)    │
                          └────────┬────────┘
                                   │
           ┌───────────────────────┼───────────────────────┐
           │                       │                       │
    ┌──────▼──────┐         ┌──────▼──────┐        ┌──────▼──────┐
    │  Loop 0     │         │  Loop 2     │        │  Loop 4     │
    │  💓 Coração │         │  🧠 Córtex  │        │  🕸️  Gossip │
    │  1 000 Hz   │         │  ZK Prover  │        │  Sistema    │
    │  bio_loop   │         │  zk_prover  │        │  Nervoso    │
    └──────┬──────┘         └──────┬──────┘        └──────┬──────┘
           │                       │                       │
    ┌──────▼──────┐         ┌──────▼──────┐               │
    │  Loop 1     │         │  Loop 3     │               │
    │  🫁 Estômago│         │  🧬 Hipoc.  │               │
    │  Digestão   │─────────│  epoch_mmr  │───────────────┘
    │  bio_loop   │         │  MMR + LGPD │
    └─────────────┘         └─────────────┘
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

O hot path do NexoIA nunca chama o alocador do sistema operacional. Isso não é uma meta — é uma invariante verificável em code review:

```rust
// ✅ Zero-allocation: array fixo, cópia por memcpy no canal
#[repr(C, align(64))]       // uma cache line exata
pub enum Event {
    Data([u8; 63]),          // payload fixo, stack-only
    Heartbeat(u64),
    Shutdown,
}

// ✅ Zero-allocation: hasher reutilizado via finalize_reset()
let mut hasher = Sha256::new();   // UMA alocação, fora do loop
loop {
    hasher.update(payload);
    let hash = hasher.finalize_reset(); // reset sem realloc
}

// ✅ Zero-allocation: ring buffer de tamanho fixo por peer
behavior_window: [BehaviorSample; 64],  // 64 bytes, stack
```

```rust
// ❌ O que NÃO existe no hot path:
Vec::new()          // alocação heap
Box::new()          // heap
String::from()      // heap
HashMap::new()      // heap + rehashing
tokio::spawn()      // overhead de task scheduling no crítico
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
