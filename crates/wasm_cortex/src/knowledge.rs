//! ────────────────────────────────────────────────────────────
//! knowledge.rs — Tabela de Conhecimento do Córtex (Sono REM)
//! ────────────────────────────────────────────────────────────
//!
//! Gerencia o ciclo ativo de esquecimento (REM) no Wasm Cortex:
//!
//! 1. **Inserção/Atualização**: cada fragmento visto é registrado
//!    com sua força, recência e frequência de acesso.
//! 2. **Decaimento**: a cada ciclo REM, strength de todos os
//!    fragmentos é reduzida à metade (divisão inteira).
//! 3. **Critério Composto**: Força (50%) + Ressonância (30%) +
//!    Recência (20%) — calculado como score inteiro 0-255.
//! 4. **Esquecimento**: fragmentos com score abaixo de
//!    `DECAY_THRESHOLD` são marcados como `dirty` e enviados
//!    ao Host via `batch_forget`.
//!
//! O Host nunca deleta EPAs — apenas marca tombstones no índice
//! ativo. O conhecimento esquecido pode ser re-aprendido.
//!
//! # Alinhamento com a Visão
//!
//! - O Córtex decide **autonomamente** o que esquecer.
//! - O Host é executor, não juiz.
//! - O critério é **matemático, determinístico e auditável**.
//! - Nenhum conhecimento é destruído — apenas despriorizado.

/// Número máximo de fragmentos monitorados simultaneamente.
pub const KNOWLEDGE_TABLE_SIZE: usize = 64;

/// Intervalo de ingestões entre ciclos REM.
pub const REM_INTERVAL: u32 = 10;

/// Score mínimo para um fragmento permanecer vivo (0-255).
/// Abaixo disso, o fragmento é marcado para esquecimento.
///
/// Calibração:
/// - strength 32 + hit 0 + recência máxima  → score 67  → vivo
/// - strength 16 + hit 0 + recência máxima  → score 59  → vivo
/// - strength 8  + hit 0 + recência máxima  → score 55  → vivo
/// - strength 0  + hit 0 + recência máxima  → score 51  → vivo
/// - strength 0  + hit 0 + idade 200 ciclos → score 11  → esquecido
pub const DECAY_THRESHOLD: u8 = 32;

/// Número de ciclos sem reforço após o qual um fragmento
/// é considerado obsoleto (usado no cálculo de recência).
pub const MAX_AGE: u32 = 100;

/// Um slot individual na tabela de conhecimento.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct KnowledgeEntry {
    /// ID do fragmento (0 = slot vazio).
    pub fragment_id: u64,
    /// INGEST_COUNT no último acesso.
    pub last_seen: u32,
    /// Quantas vezes o fragmento foi re-referenciado.
    pub hit_count: u16,
    /// Força do fragmento (0-255). Decai por /2 a cada REM.
    pub strength: u8,
    /// true se o fragmento deve ser esquecido no próximo ciclo.
    pub dirty: bool,
}

/// Tabela de conhecimento do Córtex.
///
/// Array fixo de 64 slots × 16 bytes = 1024 bytes.
/// Zero alocação dinâmica, zero syscalls.
pub struct KnowledgeTable {
    pub slots: [KnowledgeEntry; KNOWLEDGE_TABLE_SIZE],
    /// Quantos slots estão ocupados (fragment_id != 0).
    pub count: u16,
}

impl Default for KnowledgeTable {
    fn default() -> Self {
        Self::new()
    }
}

impl KnowledgeTable {
    /// Cria uma tabela vazia (todos os slots zerados).
    pub const fn new() -> Self {
        const EMPTY: KnowledgeEntry = KnowledgeEntry {
            fragment_id: 0,
            last_seen: 0,
            hit_count: 0,
            strength: 0,
            dirty: false,
        };
        KnowledgeTable {
            slots: [EMPTY; KNOWLEDGE_TABLE_SIZE],
            count: 0,
        }
    }

    /// Encontra o índice de um fragmento, ou `None` se não existir.
    fn find_index(&self, fragment_id: u64) -> Option<usize> {
        self.slots.iter().position(|e| e.fragment_id == fragment_id)
    }

    /// Encontra o índice do primeiro slot vazio.
    fn find_empty(&self) -> Option<usize> {
        self.slots.iter().position(|e| e.fragment_id == 0)
    }

    /// Insere ou atualiza um fragmento na tabela.
    ///
    /// - Se já existe: renova `last_seen`, incrementa `hit_count`,
    ///   atualiza `strength` para o valor máximo entre o atual e o novo.
    /// - Se não existe e há vaga: adiciona.
    /// - Se não existe e tabela cheia: substitui o slot de menor score.
    pub fn insert_or_update(&mut self, fragment_id: u64, strength: u8, now: u32) {
        if fragment_id == 0 {
            return; // IDs zero são reservados para slots vazios
        }

        // Tenta atualizar existente
        if let Some(idx) = self.find_index(fragment_id) {
            let entry = &mut self.slots[idx];
            entry.last_seen = now;
            entry.hit_count = entry.hit_count.saturating_add(1);
            entry.strength = entry.strength.max(strength);
            entry.dirty = false; // re-armado, não será esquecido
            return;
        }

        // Tenta slot vazio
        if let Some(idx) = self.find_empty() {
            self.slots[idx] = KnowledgeEntry {
                fragment_id,
                last_seen: now,
                hit_count: 0,
                strength,
                dirty: false,
            };
            self.count += 1;
            return;
        }

        // Tabela cheia: substitui o de menor score (não-dirty primeiro,
        // depois dirty como fallback)
        let now_local = now;
        let replace_idx = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.dirty)
            .min_by_key(|(_, e)| Self::entry_score_inner(e, now_local))
            .map(|(i, _)| i)
            .or_else(|| {
                self.slots
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, e)| Self::entry_score_inner(e, now_local))
                    .map(|(i, _)| i)
            });

        if let Some(idx) = replace_idx {
            self.slots[idx] = KnowledgeEntry {
                fragment_id,
                last_seen: now,
                hit_count: 0,
                strength,
                dirty: false,
            };
        }
    }

    /// Calcula o score composto do fragmento.
    ///
    /// # Fórmula (inteira, sem ponto flutuante)
    ///
    /// ```text
    /// score = (strength × 5 + hit_clamped × 3 + recency × 2) / 10
    /// ```
    ///
    /// | Componente   | Peso | Fonte                     |
    /// |-------------|------|---------------------------|
    /// | Força       | 50%  | strength (0-255)           |
    /// | Ressonância | 30%  | hit_count (cap 255)        |
    /// | Recência    | 20%  | 255 - idade (cap 255)      |
    ///
    /// Score resultante: 0-255. Abaixo de `DECAY_THRESHOLD` → esquecido.
    fn entry_score_inner(entry: &KnowledgeEntry, now: u32) -> u16 {
        // ─── Força (50%) ───
        // strength começa alto e decai progressivamente.
        // Fragmentos fortes resistem ao esquecimento.
        let strength_weight = (entry.strength as u16) * 5;

        // ─── Ressonância (30%) ───
        // hit_count mede quantas vezes o fragmento foi re-acessado.
        // Quanto mais acessado, mais relevante para o Córtex.
        let hit = entry.hit_count.min(255);
        let resonance_weight = hit * 3;

        // ─── Recência (20%) ───
        // idade = ciclos desde o último acesso.
        // Fragmentos vistos recentemente têm prioridade sobre os antigos.
        let age = now.wrapping_sub(entry.last_seen);
        let recency_raw = if age > 255 { 0u8 } else { 255u8 - age as u8 };
        let recency_weight = (recency_raw as u16) * 2;

        strength_weight + resonance_weight + recency_weight
    }

    /// Versão pública do score (retorna u8 para facilitar debug).
    pub fn entry_score(&self, fragment_id: u64, now: u32) -> u8 {
        if let Some(idx) = self.find_index(fragment_id) {
            let score = Self::entry_score_inner(&self.slots[idx], now);
            (score / 10) as u8
        } else {
            0
        }
    }

    /// Aplica decaimento a todos os slots e marca dirty os abaixo do threshold.
    ///
    /// Para cada fragmento vivo:
    /// 1. `strength = strength / 2` (divisão inteira para baixo)
    /// 2. Calcula score composto
    /// 3. Se score < DECAY_THRESHOLD: marca `dirty = true`
    pub fn decay(&mut self, now: u32) {
        for entry in self.slots.iter_mut() {
            if entry.fragment_id == 0 {
                continue;
            }

            // Fragmentos inseridos neste ciclo não sofrem decay nem
            // correm risco de serem marcados como dirty.
            if entry.last_seen == now {
                continue;
            }

            // Decaimento logarítmico: força reduzida à metade
            entry.strength /= 2;

            let score = Self::entry_score_inner(entry, now) / 10;
            if score < DECAY_THRESHOLD as u16 {
                entry.dirty = true;
            }
        }
    }

    /// Coleta IDs dos fragmentos marcados como dirty no buffer.
    /// Retorna o número de IDs escritos (nunca excede o tamanho do buffer).
    pub fn collect_dirty(&self, buf: &mut [u64]) -> u32 {
        let mut written = 0u32;
        for entry in self.slots.iter() {
            if entry.dirty && entry.fragment_id != 0 {
                if let Some(slot) = buf.get_mut(written as usize) {
                    *slot = entry.fragment_id;
                    written += 1;
                } else {
                    break;
                }
            }
        }
        written
    }

    /// Limpa a flag dirty dos fragmentos processados pelo Host.
    /// Remove fragmentos com dirty=false da tabela (libera slot).
    pub fn clear_dirty(&mut self, ids: &[u64]) {
        for id in ids {
            if let Some(idx) = self.find_index(*id) {
                self.slots[idx].dirty = false;
                // Libera o slot: se strength zerou, remove da tabela
                if self.slots[idx].strength == 0 {
                    self.slots[idx].fragment_id = 0;
                    self.slots[idx].hit_count = 0;
                    self.slots[idx].last_seen = 0;
                    self.count = self.count.saturating_sub(1);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_table_is_empty() {
        let table = KnowledgeTable::new();
        assert_eq!(table.count, 0);
        assert!(table.slots.iter().all(|e| e.fragment_id == 0));
    }

    #[test]
    fn test_insert_and_find() {
        let mut table = KnowledgeTable::new();
        table.insert_or_update(42, 128, 1);
        assert_eq!(table.count, 1);
        assert!(table.find_index(42).is_some());
    }

    #[test]
    fn test_update_existing() {
        let mut table = KnowledgeTable::new();
        table.insert_or_update(42, 100, 1);
        table.insert_or_update(42, 200, 5);
        let idx = table.find_index(42).unwrap();
        assert_eq!(table.slots[idx].last_seen, 5);
        assert_eq!(table.slots[idx].hit_count, 1); // incrementado
        assert_eq!(table.slots[idx].strength, 200); // max(100, 200)
    }

    #[test]
    fn test_decay_reduces_strength() {
        let mut table = KnowledgeTable::new();
        table.insert_or_update(42, 128, 1);
        table.decay(10);
        let idx = table.find_index(42).unwrap();
        assert_eq!(table.slots[idx].strength, 64); // 128 / 2
        table.decay(20);
        assert_eq!(table.slots[idx].strength, 32); // 64 / 2
    }

    #[test]
    fn test_decay_marks_dirty() {
        let mut table = KnowledgeTable::new();
        table.insert_or_update(42, 10, 1); // strength baixa
        table.decay(200); // age alto = recency baixa, score < threshold
        let idx = table.find_index(42).unwrap();
        assert!(table.slots[idx].dirty);
    }

    #[test]
    fn test_collect_dirty() {
        let mut table = KnowledgeTable::new();
        table.insert_or_update(1, 10, 1); // será esquecido
        table.insert_or_update(2, 200, 1); // forte, permanece
        table.decay(200);
        let mut buf = [0u64; 64];
        let count = table.collect_dirty(&mut buf);
        assert_eq!(count, 1);
        assert!(buf[..count as usize].contains(&1));
    }

    #[test]
    fn test_clear_dirty_frees_slot() {
        let mut table = KnowledgeTable::new();
        table.insert_or_update(42, 1, 1);
        table.decay(100);
        assert!(table.slots[table.find_index(42).unwrap()].dirty);
        table.clear_dirty(&[42]);
        // strength era 0 após decay (1/2=0), então slot foi liberado
        assert!(table.find_index(42).is_none());
    }

    #[test]
    fn test_recent_fragment_not_dirty() {
        let mut table = KnowledgeTable::new();
        table.insert_or_update(42, 5, 199); // strength baixa, mas visto recentemente
        table.decay(200); // strength=2, age=1, recency=254 → score alto
        let idx = table.find_index(42).unwrap();
        assert!(!table.slots[idx].dirty);
    }

    #[test]
    fn test_table_full_eviction() {
        let mut table = KnowledgeTable::new();
        // Preenche todos os 64 slots
        for i in 1..=KNOWLEDGE_TABLE_SIZE as u64 {
            table.insert_or_update(i, 200, 1);
        }
        assert_eq!(table.count as usize, KNOWLEDGE_TABLE_SIZE);

        // Insere um novo — deve substituir o de menor score
        table.insert_or_update(999, 255, 10);
        assert_eq!(table.count as usize, KNOWLEDGE_TABLE_SIZE);
        assert!(table.find_index(999).is_some());
    }
}
