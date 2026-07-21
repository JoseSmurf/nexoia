use sha2::{Digest, Sha256};

// ─── Constantes ───────────────────────────────────────────────────────────────

/// Dificuldade padrão: 400.000 iterações sequenciais de SHA-256.
///
/// Custo esperado por prova (uma vez por conexão de peer):
///   SHA-NI (x86_64): ~20ms   → 10.000 identidades ≈ 3 min (paralelo 16×)
///   Pure Rust (ARM):  ~200ms → 10.000 identidades ≈ 33 min (single-thread)
///
/// O Sybil é combatido pela COMBINAÇÃO de VDF + Trust Window + bio_loop cadence:
/// mesmo que um atacante paralelize 10.000 provas em 16 núcleos (~3 min SHA-NI),
/// cada identidade ainda precisa de ~1s de confiança positiva no ring buffer
/// antes de ser admitida como peer ativo (Layer 2). Isso torna o custo total
/// de 10.000 identidades Sybil proibitivo mesmo com paralelismo agressivo.
pub const DEFAULT_DIFFICULTY: u32 = 400_000;

/// Dificuldade máxima permitida (evita DoS por desafios impossíveis).
/// 40M iterações ≈ 20s no pior caso — ceiling seguro sem engasgar o verificador.
pub const MAX_DIFFICULTY: u32 = 40_000_000;

// ─── Por que SHA-256 iterado é um VDF válido neste contexto ──────────────────
//
// Um VDF ideal tem verificação mais barata que a prova (ex: Wesolowski O(1)).
// SHA-256 iterado tem O(n) para ambos — mas isso é aceitável porque
// a verificação acontece UMA VEZ por peer, não por mensagem.
//
// Para o nosso modelo de ameaça (Sybil em gossip P2P):
// 1. Custo de 1 identidade = difficulty × T_sha256 ≈ 20-200ms
// 2. Sybil de 10.000 identidades: ~33 min (single-thread Pure Rust) a ~3 min (16× SHA-NI)
// 3. Paralelismo entre identidades é possível, mas cada PROVA individual
//    é estritamente sequencial — sem speedup por ASIC paralelo dentro de uma prova.
// 4. Combinado com a Trust Window (Layer 2), o custo total de ataque domina
//    qualquer ganho marginal de paralelismo.
//
// Compatibilidade: pure Rust, sem C, sem unsafe, compila para wasm32.

// ─── Challenge ────────────────────────────────────────────────────────────────

/// Desafio emitido pelo nó receptor para um novo peer.
/// Contém o seed (aleatório ou derivado do IP+timestamp) e a dificuldade.
#[derive(Debug, Clone, Copy)]
pub struct VdfChallenge {
    /// Seed aleatório — previne pré-computação de provas
    pub seed: [u8; 32],
    /// Número de iterações SHA-256 exigidas
    pub difficulty: u32,
}

impl VdfChallenge {
    /// Cria um novo desafio com semente derivada de dados do peer.
    /// Em produção: seed = SHA256(peer_ip || timestamp || local_nonce)
    pub fn new(seed: [u8; 32], difficulty: u32) -> Self {
        let difficulty = difficulty.min(MAX_DIFFICULTY);
        Self { seed, difficulty }
    }

    /// Cria um desafio padrão para testes.
    pub fn default_difficulty(seed: [u8; 32]) -> Self {
        Self::new(seed, DEFAULT_DIFFICULTY)
    }
}

// ─── Proof ────────────────────────────────────────────────────────────────────

/// Prova VDF gerada pelo peer que quer ingressar na rede.
#[derive(Debug, Clone, Copy)]
pub struct VdfProof {
    /// Seed do desafio original (para correlacionar)
    pub seed: [u8; 32],
    /// Resultado após `difficulty` iterações sequenciais
    pub output: [u8; 32],
    /// Número de iterações realizadas (deve corresponder ao desafio)
    pub difficulty: u32,
}

// ─── Computação e Verificação ────────────────────────────────────────────────

/// Computa o VDF sequencialmente. Executado pelo peer que quer ingressar.
///
/// Hot path: zero-allocation. O `hasher` é reutilizado via `finalize_reset()`.
/// Tempo: O(difficulty) × T_sha256 ≈ difficulty × 50ns.
pub fn compute_vdf(challenge: &VdfChallenge) -> VdfProof {
    let mut current = challenge.seed;
    let mut hasher = Sha256::new();

    for _ in 0..challenge.difficulty {
        hasher.update(current);
        let result = hasher.finalize_reset();
        current.copy_from_slice(result.as_slice());
    }

    VdfProof {
        seed: challenge.seed,
        output: current,
        difficulty: challenge.difficulty,
    }
}

/// Verifica uma prova VDF. Executado pelo nó receptor.
///
/// Custo idêntico ao da prova — O(difficulty). Isso é aceitável porque
/// a verificação acontece UMA VEZ por par de conexão, não em loop.
#[must_use]
pub fn verify_vdf(challenge: &VdfChallenge, proof: &VdfProof) -> VdfVerdict {
    // Sanity checks antes de gastar CPU
    if proof.seed != challenge.seed {
        return VdfVerdict::SeedMismatch;
    }
    if proof.difficulty != challenge.difficulty {
        return VdfVerdict::DifficultyMismatch;
    }
    if challenge.difficulty > MAX_DIFFICULTY {
        return VdfVerdict::DifficultyExceeded;
    }

    // Re-executa a sequência e compara o output
    let expected = compute_vdf(challenge);
    if expected.output == proof.output {
        VdfVerdict::Valid
    } else {
        VdfVerdict::Invalid
    }
}

/// Resultado da verificação VDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VdfVerdict {
    Valid,
    Invalid,
    SeedMismatch,
    DifficultyMismatch,
    DifficultyExceeded,
}

impl VdfVerdict {
    pub fn is_valid(self) -> bool {
        self == VdfVerdict::Valid
    }
}

// ─── Handshake State Machine ──────────────────────────────────────────────────

/// Máquina de estados do handshake VDF para um peer ingressante.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Desafio emitido, aguardando prova
    ChallengeIssued,
    /// Prova verificada com sucesso — peer pode ingressar
    Admitted,
    /// Prova inválida — peer rejeitado
    Rejected(VdfVerdict),
}

/// Contexto de handshake para um peer.
pub struct PeerHandshake {
    pub peer_id: [u8; 32],
    pub challenge: VdfChallenge,
    pub state: HandshakeState,
}

impl PeerHandshake {
    pub fn new(peer_id: [u8; 32], seed: [u8; 32]) -> Self {
        Self {
            peer_id,
            challenge: VdfChallenge::default_difficulty(seed),
            state: HandshakeState::ChallengeIssued,
        }
    }

    /// Submete a prova e transiciona o estado.
    pub fn submit_proof(&mut self, proof: &VdfProof) {
        let verdict = verify_vdf(&self.challenge, proof);
        self.state = if verdict.is_valid() {
            HandshakeState::Admitted
        } else {
            HandshakeState::Rejected(verdict)
        };
    }

    pub fn is_admitted(&self) -> bool {
        self.state == HandshakeState::Admitted
    }
}

// ─── Testes ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = byte;
        s
    }

    #[test]
    fn valid_proof_passes_verification() {
        let challenge = VdfChallenge::new(seed(0xAB), 64); // baixa dificuldade p/ teste
        let proof = compute_vdf(&challenge);
        assert!(verify_vdf(&challenge, &proof).is_valid());
    }

    #[test]
    fn tampered_output_fails() {
        let challenge = VdfChallenge::new(seed(0xCD), 64);
        let mut proof = compute_vdf(&challenge);
        proof.output[0] ^= 0xFF; // corrompe o output
        assert_eq!(verify_vdf(&challenge, &proof), VdfVerdict::Invalid);
    }

    #[test]
    fn wrong_seed_fails() {
        let challenge = VdfChallenge::new(seed(0x01), 64);
        let proof = VdfProof {
            seed: seed(0x02), // seed errado
            output: [0u8; 32],
            difficulty: 64,
        };
        assert_eq!(verify_vdf(&challenge, &proof), VdfVerdict::SeedMismatch);
    }

    #[test]
    fn handshake_state_machine_full_cycle() {
        let peer_id = seed(0x42);
        let mut hs = PeerHandshake::new(peer_id, seed(0xFF));
        assert_eq!(hs.state, HandshakeState::ChallengeIssued);

        let proof = compute_vdf(&hs.challenge);
        hs.submit_proof(&proof);
        assert!(hs.is_admitted());
    }

    #[test]
    fn vdf_is_deterministic() {
        let challenge = VdfChallenge::new(seed(0x77), 128);
        let p1 = compute_vdf(&challenge);
        let p2 = compute_vdf(&challenge);
        assert_eq!(p1.output, p2.output, "VDF deve ser determinístico");
    }
}
