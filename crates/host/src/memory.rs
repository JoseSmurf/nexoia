use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Serialize, Deserialize)]
pub struct FragmentMeta {
    pub offset: usize,
    pub len: usize,
}
#[derive(Serialize, Deserialize)]
pub struct SemanticMemoryStore {
    // Futuramente usaremos memmap2::MmapMut aqui. Por enquanto, preparamos o terreno.
    pub index: HashMap<u64, FragmentMeta>,
    pub tombstones: HashSet<u64>,
    pub live_fragments: HashSet<u64>,
}

impl SemanticMemoryStore {
    pub fn new() -> Self {
        Self {
            index: HashMap::new(),
            tombstones: HashSet::new(),
            live_fragments: HashSet::new(),
        }
    }

    pub fn mark_for_deletion(&mut self, ids: &[u64]) {
        for id in ids {
            self.tombstones.insert(*id);
            self.live_fragments.remove(id);
        }
    }
}

impl Default for SemanticMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}
