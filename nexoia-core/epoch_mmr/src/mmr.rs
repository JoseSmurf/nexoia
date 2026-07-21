use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

// ─── Tipos Públicos ───────────────────────────────────────────────────────────

/// Resultado do fechamento de uma época.
/// Enviado ao `zk_prover` como o "statement" a ser provado.
#[derive(Debug, Clone, Copy)]
pub struct EpochSeal {
    /// Número da época (monotônico)
    pub epoch: u64,
    /// Root hash resultante do "bag" de todos os peaks
    pub root: [u8; 32],
    /// Quantidade de folhas nesta época (para o ZK circuit saber o tamanho)
    pub leaf_count: u64,
    /// Total de nós na árvore (folhas + internos)
    pub node_count: usize,
}

/// Resultado de uma consulta de folha.
#[derive(Debug, Clone, Copy)]
pub struct LeafInfo {
    /// Hash SHA-256 do dado original.
    /// IMUTÁVEL — presente mesmo após nullificação (LGPD).
    pub hash: [u8; 32],
    /// True se o dado original foi apagado (LGPD Redação).
    /// O hash permanece; o conteúdo, não.
    pub nullified: bool,
    /// Índice da folha (ordem de inserção, base-0)
    pub leaf_index: u64,
}

/// Prova de inclusão de uma folha no MMR (Merkle Path).
/// Permanece válida mesmo após nullificação da folha.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf_index: u64,
    pub leaf_hash: [u8; 32],
    /// Irmãos no caminho da folha até a peak.
    /// Cada entrada: (hash_do_irmão, irmão_está_à_direita)
    pub siblings: Vec<([u8; 32], bool)>,
    /// Root hash da época em que esta prova foi gerada
    pub epoch_root: [u8; 32],
}

impl MerkleProof {
    /// Verifica se esta prova é consistente com o root fornecido.
    /// Funciona independentemente de a folha estar nullificada ou não —
    /// o hash da folha na árvore nunca muda.
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        let mut current = self.leaf_hash;
        for (sibling, sibling_is_right) in &self.siblings {
            current = if *sibling_is_right {
                merge_hashes(&current, sibling)
            } else {
                merge_hashes(sibling, &current)
            };
        }
        &current == expected_root
    }
}

// ─── Erros ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum MmrError {
    LeafOutOfBounds { leaf_index: u64, leaf_count: u64 },
    EmptyMmr,
}

impl std::fmt::Display for MmrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LeafOutOfBounds {
                leaf_index,
                leaf_count,
            } => write!(
                f,
                "folha {leaf_index} fora dos limites (total: {leaf_count})"
            ),
            Self::EmptyMmr => write!(f, "MMR vazio — nenhuma folha inserida"),
        }
    }
}

impl std::error::Error for MmrError {}

// ─── Nó Interno ──────────────────────────────────────────────────────────────

/// Um nó no MMR (pode ser folha ou nó interno).
/// Armazenado no array plano e append-only.
#[derive(Clone, Copy)]
struct MmrNode {
    hash: [u8; 32],
    height: u32,
}

// ─── MMR (Merkle Mountain Range) ─────────────────────────────────────────────

/// Estrutura de dados de proveniência append-only baseada em MMR.
///
/// # Por que MMR e não uma Merkle Tree simples?
///
/// Uma Merkle Tree convencional exige que todas as folhas sejam conhecidas
/// ANTES de construir a raiz. No nosso sistema, as folhas chegam em stream
/// contínuo do `bio_loop`. O MMR permite inserção O(log n) incremental sem
/// recalcular a árvore inteira.
///
/// # Invariante de Nullificação
///
/// O array `nodes` é SOMENTE-APPEND: uma vez escrito, nenhum slot é modificado.
/// A nullificação opera exclusivamente no `BTreeSet<nullified>`. O hash da folha
/// permanece na posição original, preservando todos os caminhos de Merkle.
pub struct Mmr {
    /// Array plano de todos os nós (folhas + internos). IMUTÁVEL após escrita.
    nodes: Vec<MmrNode>,

    /// Índices no array `nodes` dos peaks atuais (montanhas não pareadas).
    /// Muda a cada append, mas os nós referenciados são imutáveis.
    peaks: Vec<usize>,

    /// Número de folhas inseridas (nós com height == 0).
    pub leaf_count: u64,

    /// Número da época atual (incrementado a cada `seal_epoch`).
    pub epoch: u64,

    /// Conjunto de índices de folhas (base-0) que foram LGPD-nullificadas.
    /// INVARIANTE: o hash na posição correspondente em `nodes` nunca é alterado.
    nullified: BTreeSet<u64>,
}

impl Default for Mmr {
    fn default() -> Self {
        Self::new()
    }
}

impl Mmr {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            peaks: Vec::new(),
            leaf_count: 0,
            epoch: 0,
            nullified: BTreeSet::new(),
        }
    }

    // ── Inserção ─────────────────────────────────────────────────────────────

    /// Insere uma nova folha no MMR. Retorna o índice da folha (base-0).
    ///
    /// Complexidade: O(log n) amortizado.
    /// Alocações: apenas `Vec::push` no `nodes` e `peaks` — sem heap extra.
    pub fn append(&mut self, hash: [u8; 32]) -> u64 {
        let leaf_index = self.leaf_count;

        // Adiciona a folha como um nó de altura 0
        let leaf_pos = self.nodes.len();
        self.nodes.push(MmrNode { hash, height: 0 });
        self.peaks.push(leaf_pos);

        // Mescla peaks de mesma altura (o coração do algoritmo MMR)
        // Enquanto os dois últimos peaks tiverem a mesma altura, cria o pai
        loop {
            let n = self.peaks.len();
            if n < 2 {
                break;
            }
            let left_idx = self.peaks[n - 2];
            let right_idx = self.peaks[n - 1];

            if self.nodes[left_idx].height != self.nodes[right_idx].height {
                break;
            }

            // Cria o nó pai: SHA256(left_hash || right_hash)
            let parent_hash = merge_hashes(&self.nodes[left_idx].hash, &self.nodes[right_idx].hash);
            let parent_height = self.nodes[left_idx].height + 1;
            let parent_pos = self.nodes.len();

            self.nodes.push(MmrNode {
                hash: parent_hash,
                height: parent_height,
            });

            // Substitui os dois peaks mesclados pelo pai
            self.peaks.pop();
            self.peaks.pop();
            self.peaks.push(parent_pos);
        }

        self.leaf_count += 1;
        leaf_index
    }

    // ── Selagem de Época ──────────────────────────────────────────────────────

    /// Fecha a época atual e retorna seu `EpochSeal` (root hash + metadados).
    ///
    /// O "bagging" combina todos os peaks da esquerda para a direita:
    ///   root = SHA256(SHA256(peak0 || peak1) || peak2) || ...
    ///
    /// Isso produz um único hash determinístico que representa TODO o estado
    /// do MMR neste momento — é o "statement" enviado ao `zk_prover`.
    pub fn seal_epoch(&mut self) -> Result<EpochSeal, MmrError> {
        if self.leaf_count == 0 {
            return Err(MmrError::EmptyMmr);
        }

        let root = self.bag_peaks();
        let seal = EpochSeal {
            epoch: self.epoch,
            root,
            leaf_count: self.leaf_count,
            node_count: self.nodes.len(),
        };

        self.epoch += 1;
        Ok(seal)
    }

    /// Computa o root atual sem selar (para consulta sem avançar época).
    pub fn current_root(&self) -> Option<[u8; 32]> {
        if self.peaks.is_empty() {
            None
        } else {
            Some(self.bag_peaks())
        }
    }

    fn bag_peaks(&self) -> [u8; 32] {
        debug_assert!(!self.peaks.is_empty());
        let mut acc = self.nodes[self.peaks[0]].hash;
        for &peak_idx in &self.peaks[1..] {
            acc = merge_hashes(&acc, &self.nodes[peak_idx].hash);
        }
        acc
    }

    // ── Consulta de Folhas ────────────────────────────────────────────────────

    /// Consulta uma folha pelo seu índice.
    pub fn get_leaf(&self, leaf_index: u64) -> Option<LeafInfo> {
        if leaf_index >= self.leaf_count {
            return None;
        }
        let node_pos = self.leaf_node_pos(leaf_index)?;
        Some(LeafInfo {
            hash: self.nodes[node_pos].hash,
            nullified: self.nullified.contains(&leaf_index),
            leaf_index,
        })
    }

    // ── Nullificação LGPD ─────────────────────────────────────────────────────

    /// Marca uma folha como nullificada (LGPD — Direito ao Esquecimento).
    ///
    /// # O que acontece
    /// - O índice da folha é adicionado ao `BTreeSet<nullified>`.
    /// - O array `nodes` NÃO é tocado — o hash permanece inalterado.
    /// - Todas as provas de Merkle existentes para esta folha continuam válidas.
    /// - O root hash da época NÃO muda.
    ///
    /// # Consequências para o ZK Prover
    /// O `zk_prover` pode gerar uma prova de que "uma folha com este hash
    /// existe no MMR" sem revelar o dado original — que foi apagado.
    /// Isso permite conformidade LGPD SEM invalidar a prova criptográfica.
    pub fn nullify(&mut self, leaf_index: u64) -> Result<(), MmrError> {
        if leaf_index >= self.leaf_count {
            return Err(MmrError::LeafOutOfBounds {
                leaf_index,
                leaf_count: self.leaf_count,
            });
        }
        self.nullified.insert(leaf_index);
        Ok(())
    }

    /// Retorna true se a folha foi nullificada.
    pub fn is_nullified(&self, leaf_index: u64) -> bool {
        self.nullified.contains(&leaf_index)
    }

    /// Retorna a quantidade de folhas nullificadas.
    pub fn nullified_count(&self) -> usize {
        self.nullified.len()
    }

    // ── Merkle Proof ──────────────────────────────────────────────────────────

    /// Gera a prova de inclusão de uma folha.
    ///
    /// A prova é válida independentemente de a folha estar nullificada ou não
    /// — o hash da folha no array `nodes` nunca muda.
    pub fn generate_proof(&self, leaf_index: u64) -> Result<MerkleProof, MmrError> {
        if leaf_index >= self.leaf_count {
            return Err(MmrError::LeafOutOfBounds {
                leaf_index,
                leaf_count: self.leaf_count,
            });
        }

        let node_pos = self
            .leaf_node_pos(leaf_index)
            .ok_or(MmrError::LeafOutOfBounds {
                leaf_index,
                leaf_count: self.leaf_count,
            })?;

        let leaf_hash = self.nodes[node_pos].hash;
        let siblings = self.collect_siblings(node_pos);
        let epoch_root = self.current_root().unwrap_or([0u8; 32]);

        Ok(MerkleProof {
            leaf_index,
            leaf_hash,
            siblings,
            epoch_root,
        })
    }

    /// Coleta os irmãos no caminho de um nó até o seu peak.
    fn collect_siblings(&self, start_pos: usize) -> Vec<([u8; 32], bool)> {
        let mut siblings = Vec::new();
        let current_pos = start_pos;
        let current_height = self.nodes[current_pos].height;

        // Subimos pela árvore coletando irmãos
        // Para cada nível h, o irmão de um nó à posição p está adjacente
        // (à esquerda ou à direita dependendo do índice da folha)
        let mut h = current_height;
        let mut pos = current_pos;

        // Encontramos o peak ao qual este nó pertence
        // e coletamos os irmãos no caminho
        loop {
            // Encontra o irmão deste nó no array
            if let Some(sibling_pos) = self.find_sibling(pos, h) {
                let sibling_is_right = sibling_pos > pos;
                siblings.push((self.nodes[sibling_pos].hash, sibling_is_right));

                // Move para o pai
                if let Some(parent_pos) = self.find_parent(pos, sibling_pos) {
                    pos = parent_pos;
                    h += 1;
                } else {
                    break;
                }
            } else {
                break; // chegamos a um peak (sem irmão)
            }
        }

        siblings
    }

    /// Encontra o irmão de um nó de altura `h` na posição `pos`.
    fn find_sibling(&self, pos: usize, height: u32) -> Option<usize> {
        // Em um MMR, o irmão de um nó de altura h está a 2^(h+1)-1 posições de distância
        // no array de nós. Verificamos ambos os lados.
        let step = ((1usize << (height + 1)) - 1).min(self.nodes.len());

        // Irmão à direita?
        let right = pos + step;
        if right < self.nodes.len() && self.nodes[right].height == height {
            return Some(right);
        }

        // Irmão à esquerda?
        if pos >= step {
            let left = pos - step;
            if self.nodes[left].height == height {
                return Some(left);
            }
        }

        None
    }

    /// Encontra o nó pai dado dois irmãos.
    fn find_parent(&self, pos_a: usize, pos_b: usize) -> Option<usize> {
        let parent_pos = pos_a.max(pos_b) + 1;
        if parent_pos < self.nodes.len()
            && self.nodes[parent_pos].height == self.nodes[pos_a].height + 1
        {
            Some(parent_pos)
        } else {
            None
        }
    }

    // ── Utilitários ──────────────────────────────────────────────────────────

    /// Encontra a posição no array `nodes` da k-ésima folha (k = leaf_index).
    fn leaf_node_pos(&self, leaf_index: u64) -> Option<usize> {
        let mut count = 0u64;
        for (pos, node) in self.nodes.iter().enumerate() {
            if node.height == 0 {
                if count == leaf_index {
                    return Some(pos);
                }
                count += 1;
            }
        }
        None
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

// ─── Primitiva de Hash ────────────────────────────────────────────────────────

/// Mescla dois hashes no padrão Merkle: SHA256(left || right).
/// Inline — zero overhead no hot path.
#[inline(always)]
pub fn merge_hashes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left.as_slice());
    hasher.update(right.as_slice());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(result.as_slice());
    out
}

// ─── Testes ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(byte: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = byte;
        h
    }

    #[test]
    fn append_and_root_changes() {
        let mut mmr = Mmr::new();
        let root_before = mmr.current_root();
        assert!(root_before.is_none(), "MMR vazio não tem root");

        mmr.append(leaf(0xAA));
        let root1 = mmr.current_root().unwrap();

        mmr.append(leaf(0xBB));
        let root2 = mmr.current_root().unwrap();

        assert_ne!(root1, root2, "root muda ao adicionar folha");
    }

    #[test]
    fn nullification_does_not_change_root() {
        let mut mmr = Mmr::new();
        mmr.append(leaf(0x01));
        mmr.append(leaf(0x02));
        mmr.append(leaf(0x03));

        let root_before = mmr.current_root().unwrap();

        // Nullifica a folha 1
        mmr.nullify(1)
            .expect("nullify deve funcionar para folha válida");

        let root_after = mmr.current_root().unwrap();

        assert_eq!(
            root_before, root_after,
            "ROOT NÃO DEVE MUDAR após nullificação — hash preservado na árvore"
        );
    }

    #[test]
    fn nullified_leaf_still_queryable_with_hash() {
        let mut mmr = Mmr::new();
        let hash = leaf(0xDE);
        mmr.append(hash);

        mmr.nullify(0).unwrap();

        let info = mmr
            .get_leaf(0)
            .expect("folha nullificada ainda deve ser consultável");
        assert_eq!(info.hash, hash, "hash permanece após nullificação");
        assert!(info.nullified, "flag nullified deve estar ativo");
    }

    #[test]
    fn merkle_proof_valid_after_nullification() {
        let mut mmr = Mmr::new();
        mmr.append(leaf(0x01));
        mmr.append(leaf(0x02));
        mmr.append(leaf(0x03));
        mmr.append(leaf(0x04));

        // Gera prova ANTES de nullificar
        let proof = mmr.generate_proof(1).unwrap();
        let root = mmr.current_root().unwrap();

        // Nullifica a folha
        mmr.nullify(1).unwrap();

        // A prova ainda deve ser válida — root não mudou
        assert!(
            proof.verify(&root),
            "Merkle proof deve permanecer válida após nullificação"
        );
    }

    #[test]
    fn seal_epoch_returns_deterministic_root() {
        let mut mmr1 = Mmr::new();
        mmr1.append(leaf(0xAA));
        mmr1.append(leaf(0xBB));
        let seal1 = mmr1.seal_epoch().unwrap();

        let mut mmr2 = Mmr::new();
        mmr2.append(leaf(0xAA));
        mmr2.append(leaf(0xBB));
        let seal2 = mmr2.seal_epoch().unwrap();

        assert_eq!(
            seal1.root, seal2.root,
            "MMRs idênticos devem produzir root idêntico"
        );
    }

    #[test]
    fn epoch_increments_on_seal() {
        let mut mmr = Mmr::new();
        mmr.append(leaf(0x01));
        let s1 = mmr.seal_epoch().unwrap();
        mmr.append(leaf(0x02));
        let s2 = mmr.seal_epoch().unwrap();
        assert_eq!(s1.epoch, 0);
        assert_eq!(s2.epoch, 1);
    }

    #[test]
    fn nullify_out_of_bounds_returns_error() {
        let mut mmr = Mmr::new();
        mmr.append(leaf(0x01));
        assert!(mmr.nullify(99).is_err());
    }
}
