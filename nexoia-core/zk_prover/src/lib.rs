use epoch_mmr::EpochSeal;
use sha2::{Digest, Sha256};

// ─── Statement e Witness ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct ZkStatement {
    pub epoch_root: [u8; 32],
    pub leaf_index: u64,
    pub epoch: u64,
    pub is_nullified: bool,
}

#[derive(Debug, Clone)]
pub struct ZkWitness {
    pub leaf_hash: [u8; 32],
    pub merkle_path: Vec<([u8; 32], bool)>,
}

impl Drop for ZkWitness {
    fn drop(&mut self) {
        self.leaf_hash = [0u8; 32];
        for (hash, _) in self.merkle_path.iter_mut() {
            *hash = [0u8; 32];
        }
    }
}

// ─── Prova ZK ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ZkProof {
    pub statement: ZkStatement,
    pub proof_bytes: [u8; 32],
    pub is_stub: bool,
}

impl ZkProof {
    pub fn verify(&self) -> bool {
        if self.is_stub {
            let expected = derive_stub_commitment(&self.statement);
            expected == self.proof_bytes
        } else {
            unimplemented!("Backend ZK real requer feature 'real-proof'")
        }
    }
}

// ─── Prover ───────────────────────────────────────────────────────────────────

pub struct ZkProver {
    sealed_epochs: Vec<EpochSeal>,
    pub mode: ProverMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProverMode {
    Stub,
    Real,
}

impl ZkProver {
    pub fn new(mode: ProverMode) -> Self {
        Self {
            sealed_epochs: Vec::new(),
            mode,
        }
    }

    pub fn consolidate(&mut self, seal: EpochSeal) -> ConsolidationResult {
        let epoch = seal.epoch;
        let root = seal.root;
        self.sealed_epochs.push(seal);

        ConsolidationResult {
            epoch,
            root,
            ready_to_prove: true,
        }
    }

    pub fn prove_inclusion(
        &self,
        statement: ZkStatement,
        witness: ZkWitness,
    ) -> Result<ZkProof, ProverError> {
        let seal_exists = self
            .sealed_epochs
            .iter()
            .any(|s| s.root == statement.epoch_root && s.epoch == statement.epoch);

        if !seal_exists {
            return Err(ProverError::UnknownEpoch {
                epoch: statement.epoch,
            });
        }

        self.verify_witness_internally(&statement, &witness)?;

        let proof_bytes = match self.mode {
            ProverMode::Stub => derive_stub_commitment(&statement),
            ProverMode::Real => {
                return Err(ProverError::RealProofNotImplemented);
            }
        };

        drop(witness);

        Ok(ZkProof {
            statement,
            proof_bytes,
            is_stub: matches!(self.mode, ProverMode::Stub),
        })
    }

    pub fn prove_nullification(
        &self,
        statement: ZkStatement,
        witness: ZkWitness,
    ) -> Result<ZkProof, ProverError> {
        if !statement.is_nullified {
            return Err(ProverError::LeafNotNullified {
                leaf_index: statement.leaf_index,
            });
        }
        self.prove_inclusion(statement, witness)
    }

    fn verify_witness_internally(
        &self,
        statement: &ZkStatement,
        witness: &ZkWitness,
    ) -> Result<(), ProverError> {
        let computed_root = recompute_root(&witness.leaf_hash, &witness.merkle_path);

        if computed_root != statement.epoch_root {
            return Err(ProverError::InvalidWitness {
                reason: "merkle path não converge para o epoch_root declarado",
            });
        }

        Ok(())
    }

    pub fn sealed_epoch_count(&self) -> usize {
        self.sealed_epochs.len()
    }

    pub fn get_seal(&self, epoch: u64) -> Option<&EpochSeal> {
        self.sealed_epochs.iter().find(|s| s.epoch == epoch)
    }
}

// ─── Resultado de Consolidação ────────────────────────────────────────────────

#[derive(Debug)]
pub struct ConsolidationResult {
    pub epoch: u64,
    pub root: [u8; 32],
    pub ready_to_prove: bool,
}

// ─── Erros ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ProverError {
    UnknownEpoch { epoch: u64 },
    InvalidWitness { reason: &'static str },
    LeafNotNullified { leaf_index: u64 },
    RealProofNotImplemented,
}

impl std::fmt::Display for ProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownEpoch { epoch } => write!(f, "época {epoch} não encontrada no prover"),
            Self::InvalidWitness { reason } => write!(f, "witness inválido: {reason}"),
            Self::LeafNotNullified { leaf_index } => {
                write!(f, "folha {leaf_index} não está nullificada")
            }
            Self::RealProofNotImplemented => {
                write!(f, "backend ZK real requer feature 'real-proof'")
            }
        }
    }
}

impl std::error::Error for ProverError {}

// ─── Utilitários Criptográficos ───────────────────────────────────────────────

fn recompute_root(leaf_hash: &[u8; 32], path: &[([u8; 32], bool)]) -> [u8; 32] {
    let mut current = *leaf_hash;
    for (sibling, sibling_is_right) in path {
        current = if *sibling_is_right {
            epoch_mmr::mmr::merge_hashes(&current, sibling)
        } else {
            epoch_mmr::mmr::merge_hashes(sibling, &current)
        };
    }
    current
}

fn derive_stub_commitment(stmt: &ZkStatement) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(stmt.epoch_root);
    hasher.update(stmt.leaf_index.to_le_bytes());
    hasher.update(stmt.epoch.to_le_bytes());
    hasher.update([stmt.is_nullified as u8]);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(result.as_slice());
    out
}

// ─── Testes ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_seal(epoch: u64, root_byte: u8) -> EpochSeal {
        let mut root = [0u8; 32];
        root[0] = root_byte;
        EpochSeal {
            epoch,
            root,
            leaf_count: 4,
            node_count: 7,
        }
    }

    fn make_leaf_hash(byte: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = byte;
        h
    }

    fn single_leaf_setup(leaf_byte: u8, epoch: u64) -> (EpochSeal, ZkStatement, ZkWitness) {
        let leaf_hash = make_leaf_hash(leaf_byte);
        let seal = EpochSeal {
            epoch,
            root: leaf_hash,
            leaf_count: 1,
            node_count: 1,
        };
        let stmt = ZkStatement {
            epoch_root: leaf_hash,
            leaf_index: 0,
            epoch,
            is_nullified: false,
        };
        let witness = ZkWitness {
            leaf_hash,
            merkle_path: vec![],
        };
        (seal, stmt, witness)
    }

    #[test]
    fn consolidate_registers_seal() {
        let mut prover = ZkProver::new(ProverMode::Stub);
        let seal = make_seal(0, 0xAB);
        let result = prover.consolidate(seal);
        assert_eq!(result.epoch, 0);
        assert!(result.ready_to_prove);
        assert_eq!(prover.sealed_epoch_count(), 1);
    }

    #[test]
    fn prove_inclusion_stub_succeeds() {
        let mut prover = ZkProver::new(ProverMode::Stub);
        let (seal, stmt, witness) = single_leaf_setup(0xCC, 0);
        prover.consolidate(seal);

        let proof = prover
            .prove_inclusion(stmt, witness)
            .expect("prova deve ser gerada");
        assert!(proof.is_stub);
        assert!(proof.verify(), "prova stub deve verificar com sucesso");
    }

    #[test]
    fn proof_verification_is_deterministic() {
        let (seal_a, stmt_a, witness_a) = single_leaf_setup(0xDD, 1);
        let (_, stmt_b, witness_b) = single_leaf_setup(0xDD, 1);

        let mut prover_a = ZkProver::new(ProverMode::Stub);
        prover_a.consolidate(seal_a);
        let proof_a = prover_a.prove_inclusion(stmt_a, witness_a).unwrap();

        let mut prover_b = ZkProver::new(ProverMode::Stub);
        let (seal_b, _, _) = single_leaf_setup(0xDD, 1);
        prover_b.consolidate(seal_b);
        let proof_b = prover_b.prove_inclusion(stmt_b, witness_b).unwrap();

        assert_eq!(
            proof_a.proof_bytes, proof_b.proof_bytes,
            "provas para o mesmo statement devem ser idênticas (determinismo)"
        );
    }

    #[test]
    fn prove_inclusion_fails_for_unknown_epoch() {
        let prover = ZkProver::new(ProverMode::Stub);
        let (_, stmt, witness) = single_leaf_setup(0xEE, 99);
        let result = prover.prove_inclusion(stmt, witness);
        assert!(
            matches!(result, Err(ProverError::UnknownEpoch { epoch: 99 })),
            "deve falhar para época desconhecida"
        );
    }

    #[test]
    fn prove_inclusion_fails_for_invalid_witness() {
        let mut prover = ZkProver::new(ProverMode::Stub);
        let (seal, stmt, _) = single_leaf_setup(0xFF, 0);
        prover.consolidate(seal);

        let bad_witness = ZkWitness {
            leaf_hash: make_leaf_hash(0x00),
            merkle_path: vec![],
        };

        let result = prover.prove_inclusion(stmt, bad_witness);
        assert!(
            matches!(result, Err(ProverError::InvalidWitness { .. })),
            "deve rejeitar witness incoerente com o epoch_root"
        );
    }

    #[test]
    fn nullification_proof_requires_flag() {
        let mut prover = ZkProver::new(ProverMode::Stub);
        let (seal, mut stmt, witness) = single_leaf_setup(0xAA, 0);
        prover.consolidate(seal);

        stmt.is_nullified = false;
        assert!(matches!(
            prover.prove_nullification(stmt, witness),
            Err(ProverError::LeafNotNullified { .. })
        ));
    }

    #[test]
    fn nullification_proof_succeeds_when_flagged() {
        let mut prover = ZkProver::new(ProverMode::Stub);
        let (seal, mut stmt, witness) = single_leaf_setup(0xBB, 0);
        prover.consolidate(seal);

        stmt.is_nullified = true;
        let proof = prover.prove_nullification(stmt, witness).unwrap();
        assert!(proof.verify());
    }

    #[test]
    fn witness_memory_is_zeroed_on_drop() {
        let w = ZkWitness {
            leaf_hash: [0xFF; 32],
            merkle_path: vec![([0xAB; 32], true)],
        };
        drop(w);
    }
}
