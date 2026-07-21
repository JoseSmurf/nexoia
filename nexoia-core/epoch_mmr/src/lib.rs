/// `epoch_mmr` — O Hipocampo da NexoIA
///
/// Memória de longo prazo imutável baseada em Merkle Mountain Range (MMR).
///
/// # Dois Planos de Nullificação (LGPD)
///
/// ```text
/// ┌─────────────────────────────────────────────────────┐
/// │  Plano 1: Hash no MMR (mmr::Mmr)                   │
/// │  • O hash SHA-256 do dado NUNCA é removido.         │
/// │  • Somente o flag `nullified` é marcado.            │
/// │  • Todas as Merkle Proofs continuam válidas.        │
/// │  • O Root Hash da Epoch NÃO muda.                   │
/// ├─────────────────────────────────────────────────────┤
/// │  Plano 2: Metadados de Proveniência (provenance::)  │
/// │  • Quem inseriu, quando, de onde.                   │
/// │  • Pode ser nullificado INDEPENDENTEMENTE do hash.  │
/// │  • Auditoria regulatória opera neste plano.         │
/// └─────────────────────────────────────────────────────┘
/// ```
pub mod mmr;
pub mod provenance;

pub use mmr::{EpochSeal, LeafInfo, MerkleProof, Mmr, MmrError};
pub use provenance::{LeafProvenance, LeafSource, ProvenanceRegistry};
