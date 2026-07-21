use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Fonte da Folha ───────────────────────────────────────────────────────────

/// Origem de um dado registrado como folha no MMR.
/// Armazenado na proveniência para auditoria e conformidade LGPD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LeafSource {
    /// Dado validado pelo `bio_loop::digest` (fonte local)
    BioLoopDigest = 0,
    /// Dado recebido de um peer via `gossip`
    GossipPeer = 1,
    /// Input manual do operador via CLI
    CliInput = 2,
    /// Prova ZK verificada e absorvida como fato
    ZkProof = 3,
}

impl LeafSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BioLoopDigest => "bio_loop::digest",
            Self::GossipPeer => "gossip::peer",
            Self::CliInput => "cli::input",
            Self::ZkProof => "zk_prover::verified",
        }
    }
}

// ─── Registro de Proveniência ─────────────────────────────────────────────────

/// Metadados de proveniência para uma folha do MMR.
///
/// LGPD: Este registro é SEPARADO do hash da folha. Isso significa que:
/// - Quando a folha é nullificada no MMR, o DADO é apagado.
/// - Este registro de proveniência pode ser retido para fins de auditoria
///   regulatória (quem inseriu, quando, de onde) sem revelar o dado.
/// - Ou este registro também pode ser apagado — são camadas independentes.
#[derive(Debug, Clone)]
pub struct LeafProvenance {
    /// Índice da folha no MMR (base-0)
    pub leaf_index: u64,
    /// Timestamp UNIX (segundos) no momento da inserção
    pub inserted_at: u64,
    /// Época em que esta folha foi inserida
    pub epoch: u64,
    /// Origem do dado
    pub source: LeafSource,
    /// ID do peer que originou o dado (primeiros 8 bytes do peer hash).
    /// None para fontes locais.
    pub peer_id: Option<u64>,
    /// True se este registro de proveniência foi LGPD-nullificado
    /// (independente do hash da folha no MMR).
    pub prov_nullified: bool,
}

impl LeafProvenance {
    /// Cria um registro de proveniência para uma folha recém-inserida.
    pub fn new(leaf_index: u64, source: LeafSource, epoch: u64) -> Self {
        let inserted_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            leaf_index,
            inserted_at,
            epoch,
            source,
            peer_id: None,
            prov_nullified: false,
        }
    }

    /// Associa um peer ID (para fontes `GossipPeer`).
    pub fn with_peer(mut self, peer_id: u64) -> Self {
        self.peer_id = Some(peer_id);
        self
    }
}

// ─── Registro de Proveniência ─────────────────────────────────────────────────

/// Repositório append-only de registros de proveniência.
///
/// Indexado por `leaf_index` via BTreeMap para consulta O(log n).
/// Nunca remove registros — mesmo que a folha no MMR seja nullificada,
/// o registro de proveniência pode ser mantido para auditoria
/// (ou individualmente nullificado via `nullify_prov`).
pub struct ProvenanceRegistry {
    /// Mapeamento leaf_index → LeafProvenance. O(log n) para consulta e nullificação.
    records: BTreeMap<u64, LeafProvenance>,
}

impl Default for ProvenanceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvenanceRegistry {
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    /// Registra a proveniência de uma nova folha.
    /// Se a leaf_index já existir (consistência contra reorg), sobrescreve.
    pub fn record(&mut self, prov: LeafProvenance) {
        self.records.insert(prov.leaf_index, prov);
    }

    /// Consulta o registro de proveniência de uma folha — O(log n).
    pub fn get(&self, leaf_index: u64) -> Option<&LeafProvenance> {
        self.records.get(&leaf_index)
    }

    /// Nullifica o REGISTRO DE PROVENIÊNCIA de uma folha (LGPD — camada 2).
    /// Independente da nullificação do hash no MMR. Retorna true se o registro existia.
    pub fn nullify_prov(&mut self, leaf_index: u64) -> bool {
        self.records
            .get_mut(&leaf_index)
            .map(|rec| {
                rec.prov_nullified = true;
                true
            })
            .unwrap_or(false)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

// ─── Testes ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_query() {
        let mut reg = ProvenanceRegistry::new();
        reg.record(LeafProvenance::new(0, LeafSource::BioLoopDigest, 0));
        reg.record(LeafProvenance::new(1, LeafSource::GossipPeer, 0).with_peer(0xDEAD));

        let p0 = reg.get(0).unwrap();
        assert_eq!(p0.source, LeafSource::BioLoopDigest);
        assert!(p0.peer_id.is_none());

        let p1 = reg.get(1).unwrap();
        assert_eq!(p1.source, LeafSource::GossipPeer);
        assert_eq!(p1.peer_id, Some(0xDEAD));
    }

    #[test]
    fn prov_nullification_is_independent_of_mmr() {
        let mut reg = ProvenanceRegistry::new();
        reg.record(LeafProvenance::new(42, LeafSource::CliInput, 3));

        assert!(!reg.get(42).unwrap().prov_nullified);
        reg.nullify_prov(42);
        assert!(reg.get(42).unwrap().prov_nullified);
        // O registro ainda existe — apenas marcado como nullificado
        assert!(reg.get(42).is_some());
    }
}
