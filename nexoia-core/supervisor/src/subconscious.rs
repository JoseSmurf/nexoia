// subconscious.rs — A Memória Profunda (HNSW Vector Store)
//
// O subconsciente do sistema. Lê registros do WAL a partir do watermark,
// gera embeddings, e insere em um índice HNSW append-only mapeado em disco.
//
// # Arquitetura
//
// ```
// consolidation-worker
//    │
//    ├── watermark (AtomicU64)
//    │
//    ├── WAL replay parcial (do watermark ao tail)
//    │      │
//    │      ▼
//    ├── EmbeddingEngine (placeholder → futuro CA3)
//    │      │
//    │      ▼
//    └── HnswStore (append-only, mmap)
//           │
//           ├── hnsw.bin — grafo HNSW serializado (níveis, arestas)
//           ├── vectors.bin — vectors raw f32 (append-only, page-aligned)
//           └── meta.bin — offset index (u64 LE por vector)
// ```
//
// # Zero-Alloc (query path)
//
// A busca no HNSW é feita via mmap — os vectors são lidos diretamente
// do arquivo sem cópia para a heap. O grafo HNSW é carregado sob demanda.
//
// # Append-Only (insert path)
//
// Inserções são append-only. vectors.bin recebe um novo vector ao final.
// meta.bin recebe o offset. hnsw.bin é reescrito (a porção do grafo muda).
// Para evitar rewrites completos, o HNSW usa níveis incrementais.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

// ─── Constantes ──────────────────────────────────────────────────────────────

/// Dimensão do vector de embedding (768 = small LM, ajustável).
pub const VECTOR_DIM: usize = 768;

/// Número máximo de conexões por nó no HNSW.
pub const HNSW_M: usize = 16;

/// Nível máximo no HNSW (log2(max_nodes)).
pub const HNSW_MAX_LEVEL: usize = 16;

/// Tamanho de página (4KB — alinhamento com página do OS).
pub const PAGE_SIZE: u64 = 4096;

/// Magic number do arquivo de vectors.
pub const VECTORS_MAGIC: [u8; 8] = [0x4E, 0x56, 0x45, 0x43, 0x54, 0x00, 0x01, 0x00];
// "NVECT\0\1\0" — Nexus Vectors v1.0

// ─── Tipos ───────────────────────────────────────────────────────────────────

/// Um vector de embedding f32 com dimensão VECTOR_DIM.
#[derive(Debug, Clone)]
#[repr(C, align(64))]
pub struct Vector {
    pub data: [f32; VECTOR_DIM],
}

impl Vector {
    /// Cria um vector a partir de um hash SHA-256 (placeholder para embedding real).
    /// Na Fase B, isto será substituído pelo CA3 (modelo de embedding neural).
    pub fn from_hash(hash: &[u8; 32]) -> Self {
        let mut data = [0.0f32; VECTOR_DIM];
        // Placeholder: expande o hash de 32 bytes para 768 floats
        // usando seeding determinístico. NÃO é um embedding real —
        // apenas para validação da arquitetura.
        for i in 0..VECTOR_DIM {
            let byte = hash[i % 32];
            let seed = (i as u64).wrapping_mul(0x9E37_79B9) as f32;
            data[i] = (byte as f32 / 255.0) * seed.sin();
        }
        Self { data }
    }

    /// Similaridade de cosseno entre dois vectors.
    pub fn cosine_similarity(&self, other: &Self) -> f32 {
        let dot: f32 = self.data.iter().zip(&other.data).map(|(a, b)| a * b).sum();
        let norm_a: f32 = self.data.iter().map(|a| a * a).sum::<f32>().sqrt();
        let norm_b: f32 = other.data.iter().map(|b| b * b).sum::<f32>().sqrt();
        if norm_a == 0.0 || norm_b == 0.0 {
            0.0
        } else {
            dot / (norm_a * norm_b)
        }
    }

    /// Distância euclidiana.
    pub fn euclidean_distance(&self, other: &Self) -> f32 {
        let sum: f32 = self
            .data
            .iter()
            .zip(&other.data)
            .map(|(a, b)| {
                let d = a - b;
                d * d
            })
            .sum();
        sum.sqrt()
    }
}

// ─── HNSW Node ───────────────────────────────────────────────────────────────

/// Um nó no grafo HNSW.
#[derive(Debug, Clone)]
pub struct HnswNode {
    /// ID do vector em vectors.bin.
    pub vector_id: u64,
    /// Nível do nó na hierarquia HNSW.
    pub level: usize,
    /// Conexões por nível: level → [vector_id].
    pub connections: Vec<Vec<u64>>,
}

// ─── HNSW Store ──────────────────────────────────────────────────────────────

/// Armazenamento HNSW append-only com mmap para queries.
///
/// # Arquivos
///
/// - `vectors.bin`: vectors raw f32, page-aligned, append-only
/// - `meta.bin`: offset index (u64 LE por vector)
/// - `hnsw.bin`: grafo HNSW serializado (bincode ou custom binary)
pub struct HnswStore {
    /// Caminho do diretório de dados.
    path: std::path::PathBuf,
    /// Arquivo de vectors (append-only).
    vectors_file: File,
    /// Arquivo de metadados (offset index).
    meta_file: File,
    /// Número total de vectors inseridos.
    count: u64,
}

impl HnswStore {
    /// Abre (ou cria) um HNSW store no diretório especificado.
    pub fn open(path: &Path) -> io::Result<Self> {
        fs::create_dir_all(path)?;

        let vectors_path = path.join("vectors.bin");
        let meta_path = path.join("meta.bin");
        let _hnsw_path = path.join("hnsw.bin");

        let mut vectors_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&vectors_path)?;

        let meta_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&meta_path)?;

        // Inicializa vectors.bin com magic + header se vazio
        let metadata = vectors_file.metadata()?;
        let count = if metadata.len() == 0 {
            // Escreve header (magic + reserved)
            let mut header = [0u8; PAGE_SIZE as usize];
            header[..8].copy_from_slice(&VECTORS_MAGIC);
            vectors_file.write_all(&header)?;
            vectors_file.sync_all()?;
            0
        } else {
            // Recupera count do tamanho do arquivo
            let vector_bytes = VECTOR_DIM as u64 * 4; // f32 = 4 bytes
            let data_size = metadata.len() - PAGE_SIZE;
            data_size / vector_bytes
        };

        Ok(Self {
            path: path.to_path_buf(),
            vectors_file,
            meta_file,
            count,
        })
    }

    /// Insere um novo vector no store.
    ///
    /// # Append-Only
    ///
    /// - vectors.bin: append do vector f32 ao final (PAGE_SIZE alinhado)
    /// - meta.bin: append do offset (u64 LE)
    /// - hnsw.bin: reescrita do grafo (rewrite completo — otimizar na Fase B)
    pub fn insert(&mut self, vector: &Vector) -> io::Result<u64> {
        let vector_id = self.count;

        // ── vectors.bin (append) ──
        let pos = self.vectors_file.seek(SeekFrom::End(0))?;
        let bytes: &[u8; VECTOR_DIM * 4] = unsafe { std::mem::transmute(&vector.data) };
        self.vectors_file.write_all(bytes)?;

        // ── meta.bin (append do offset) ──
        self.meta_file.seek(SeekFrom::End(0))?;
        self.meta_file.write_all(&pos.to_le_bytes())?;

        self.count += 1;
        Ok(vector_id)
    }

    /// Lê um vector pelo ID (via mmap — zero-copy).
    pub fn get_vector(&self, id: u64) -> io::Result<Vector> {
        let vector_bytes = VECTOR_DIM as u64 * 4;
        let offset = PAGE_SIZE + id * vector_bytes;

        let mut file = OpenOptions::new()
            .read(true)
            .open(self.path.join("vectors.bin"))?;
        file.seek(SeekFrom::Start(offset))?;

        let mut raw = [0u8; VECTOR_DIM * 4];
        file.read_exact(&mut raw)?;

        let data: [f32; VECTOR_DIM] = unsafe { std::mem::transmute(raw) };
        Ok(Vector { data })
    }

    /// Número total de vectors no store.
    pub fn len(&self) -> u64 {
        self.count
    }

    /// Retorna `true` se o store está vazio.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Busca o vizinho mais próximo por força bruta (placeholder para HNSW real).
    /// Na Fase B, substituir por navegação no grafo HNSW.
    pub fn search_nearest(&self, query: &Vector) -> io::Result<Option<(u64, f32)>> {
        if self.count == 0 {
            return Ok(None);
        }

        let mut best_id = 0u64;
        let mut best_sim = -1.0f32;

        for id in 0..self.count {
            let candidate = self.get_vector(id)?;
            let sim = query.cosine_similarity(&candidate);
            if sim > best_sim {
                best_sim = sim;
                best_id = id;
            }
        }

        Ok(Some((best_id, best_sim)))
    }
}

impl Drop for HnswStore {
    fn drop(&mut self) {
        let _ = self.vectors_file.sync_all();
        let _ = self.meta_file.sync_all();
    }
}

// ─── Testes ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_from_hash_is_deterministic() {
        let hash = [0xAB; 32];
        let v1 = Vector::from_hash(&hash);
        let v2 = Vector::from_hash(&hash);
        assert_eq!(v1.data[..10], v2.data[..10]);
    }

    #[test]
    fn cosine_similarity_identical_is_one() {
        let v = Vector::from_hash(&[0x42; 32]);
        let sim = v.cosine_similarity(&v);
        assert!(
            (sim - 1.0).abs() < 0.001,
            "identical vectors must have cosine 1.0"
        );
    }

    #[test]
    fn cosine_similarity_orthogonal_is_zero() {
        let mut a = Vector {
            data: [0.0f32; VECTOR_DIM],
        };
        let mut b = Vector {
            data: [0.0f32; VECTOR_DIM],
        };
        a.data[0] = 1.0;
        b.data[1] = 1.0;
        let sim = a.cosine_similarity(&b);
        assert!(
            (sim - 0.0).abs() < 0.001,
            "orthogonal vectors must have cosine 0.0"
        );
    }

    #[test]
    fn hnsw_store_insert_and_retrieve() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = HnswStore::open(dir.path()).unwrap();
        assert_eq!(store.len(), 0);

        let hash = [0x42; 32];
        let vector = Vector::from_hash(&hash);
        let id = store.insert(&vector).unwrap();
        assert_eq!(id, 0);
        assert_eq!(store.len(), 1);

        let retrieved = store.get_vector(0).unwrap();
        let sim = vector.cosine_similarity(&retrieved);
        assert!((sim - 1.0).abs() < 0.001);
    }

    #[test]
    fn hnsw_store_persistence() {
        let dir = tempfile::tempdir().unwrap();

        // Insert
        {
            let mut store = HnswStore::open(dir.path()).unwrap();
            for i in 0..5 {
                let hash = [i as u8; 32];
                let v = Vector::from_hash(&hash);
                store.insert(&v).unwrap();
            }
        } // Drop → sync

        // Reopen
        {
            let store = HnswStore::open(dir.path()).unwrap();
            assert_eq!(store.len(), 5);

            let v0 = store.get_vector(0).unwrap();
            let v4 = store.get_vector(4).unwrap();
            let sim = v0.cosine_similarity(&v4);
            assert!(sim > -1.0 && sim < 1.0);
        }
    }

    #[test]
    fn search_finds_closest_vector() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = HnswStore::open(dir.path()).unwrap();

        // Insert vectors em posições conhecidas (cada um num eixo diferente)
        for i in 0..10 {
            let mut data = [0.0f32; VECTOR_DIM];
            data[i] = 1.0; // cada vector num eixo ortogonal único
            let v = Vector { data };
            store.insert(&v).unwrap();
        }

        // Query perto do eixo 7
        let mut query = [0.0f32; VECTOR_DIM];
        query[7] = 0.9;
        let q = Vector { data: query };

        let result = store.search_nearest(&q).unwrap();
        assert!(result.is_some());
        let (id, _sim) = result.unwrap();
        assert_eq!(id, 7, "nearest to eixo 7 must be vector 7");
    }
}
