use serde::{Deserialize, Serialize};

pub const MAX_PROVENANCE: usize = 12;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Provenance {
    pub fragments: [u64; MAX_PROVENANCE],
    pub influence: [u8; MAX_PROVENANCE],
    pub count: u8,
}

impl Default for Provenance {
    fn default() -> Self {
        Self {
            fragments: [0; MAX_PROVENANCE],
            influence: [0; MAX_PROVENANCE],
            count: 0,
        }
    }
}

impl Provenance {
    pub fn add_fragment(&mut self, fragment_id: u64, weight: u8) {
        for i in 0..self.count as usize {
            if self.fragments[i] == fragment_id {
                self.influence[i] = self.influence[i].saturating_add(weight);
                return;
            }
        }
        if (self.count as usize) < MAX_PROVENANCE {
            let idx = self.count as usize;
            self.fragments[idx] = fragment_id;
            self.influence[idx] = weight;
            self.count += 1;
        } else {
            let mut min_idx = 0;
            let mut min_val = self.influence[0];
            for i in 1..MAX_PROVENANCE {
                if self.influence[i] < min_val {
                    min_val = self.influence[i];
                    min_idx = i;
                }
            }
            self.fragments[min_idx] = fragment_id;
            self.influence[min_idx] = weight;
        }
    }
}
