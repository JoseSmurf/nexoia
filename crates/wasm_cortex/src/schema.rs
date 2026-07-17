use crate::provenance::Provenance;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct NexoPacket {
    pub fragment_id: u64,
    pub payload: [u8; 32], // Array fixo (32 bytes suportado nativamente pelo Serde sem crates extras)
    pub provenance: Provenance,
}
