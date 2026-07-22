//! membrane.rs — A Garra Física (Membrane Enforcement)
//!
//! Uma parede lock-free no nível de socket que atua interceptando pacotes em O(1)
//! antes de qualquer alocação ou desserialização.
//! Otimizada para L1 cache e sem garbage collection (Zero-Allocation).

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

const BLOOM_FILTER_WORDS: usize = 512;
const BLOOM_FILTER_BITS: usize = BLOOM_FILTER_WORDS * 64; // 32768 bits (4KB)

/// Otimização agressiva L1 Cache: Alinhamento de struct em 64-bytes (tamanho exato da cache line em x86_64).
/// Em ataques DDoS, o iterador de um array mata a CPU. O Bloom Filter Atômico não itera. Ele apenas
/// lê ponteiros estáticos diretamente da cache L1 da CPU em complexidade de tempo puramente $O(1)$.
#[repr(C)]
#[repr(align(64))]
pub struct LockFreeBlacklist {
    // Array estático. Usa Mutabilidade Interior (Interior Mutability) sem locks graças aos Atomics.
    bitset: [AtomicU64; BLOOM_FILTER_WORDS],
}

impl Default for LockFreeBlacklist {
    fn default() -> Self {
        Self::new()
    }
}

impl LockFreeBlacklist {
    /// Cria uma nova membrana zerada
    pub fn new() -> Self {
        #[allow(clippy::declare_interior_mutable_const)]
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            bitset: [ZERO; BLOOM_FILTER_WORDS],
        }
    }

    /// Retorna k=3 índices baseados no hash canônico (BLAKE3) do IP
    #[inline(always)]
    fn get_indices(ip: &IpAddr) -> (usize, usize, usize) {
        let mut hasher = blake3::Hasher::new();
        match ip {
            IpAddr::V4(v4) => hasher.update(&v4.octets()),
            IpAddr::V6(v6) => hasher.update(&v6.octets()),
        };
        let hash = hasher.finalize();
        let bytes = hash.as_bytes();

        // Extrai 3 blocos pseudo-aleatórios de 16 bits
        let h1 = u16::from_le_bytes([bytes[0], bytes[1]]) as usize % BLOOM_FILTER_BITS;
        let h2 = u16::from_le_bytes([bytes[2], bytes[3]]) as usize % BLOOM_FILTER_BITS;
        let h3 = u16::from_le_bytes([bytes[4], bytes[5]]) as usize % BLOOM_FILTER_BITS;

        (h1, h2, h3)
    }

    /// Bane um IP no filtro de forma atômica (Sem locks)
    pub fn ban_ip(&self, ip: &IpAddr) {
        let (h1, h2, h3) = Self::get_indices(ip);
        self.set_bit(h1);
        self.set_bit(h2);
        self.set_bit(h3);
    }

    /// Libera um IP do filtro.
    /// Nota: Em Bloom Filters tradicionais, remoção não é possível sem corromper outros registros.
    /// Esta função está aqui caso adotemos um Counting Bloom Filter, mas no atual modelo
    /// a blacklist é final até o reboot do nó (Filosofia "Shoot on sight" para o Behavior Engine).
    #[allow(dead_code)]
    pub fn clear(&self) {
        for word in self.bitset.iter() {
            word.store(0, Ordering::Relaxed);
        }
    }

    /// Checagem puramente O(1).
    /// Dropa atacantes sem envolver o agendador do SO ou filas async pesadas.
    #[inline(always)]
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        let (h1, h2, h3) = Self::get_indices(ip);
        self.test_bit(h1) && self.test_bit(h2) && self.test_bit(h3)
    }

    #[inline(always)]
    fn set_bit(&self, bit_index: usize) {
        let word_idx = bit_index / 64;
        let bit_offset = bit_index % 64;

        // Ordering::Relaxed garante a maior velocidade possível.
        // Não nos importamos com a exata ordem entre threads aqui,
        // apenas com a eventual consistência da marcação.
        self.bitset[word_idx].fetch_or(1 << bit_offset, Ordering::Relaxed);
    }

    #[inline(always)]
    fn test_bit(&self, bit_index: usize) -> bool {
        let word_idx = bit_index / 64;
        let bit_offset = bit_index % 64;
        let word = self.bitset[word_idx].load(Ordering::Relaxed);
        (word & (1 << bit_offset)) != 0
    }
}
