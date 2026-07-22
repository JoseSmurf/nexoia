// wal.rs — Write-Ahead Log do Hipocampo
//
// # Arquitetura
//
// O WAL é a fonte de verdade (source of truth). O MMR é um cache volátil
// reconstruído a partir do WAL no startup. Na hot path:
//
//   Event::Data → SHA-256 → WAL.append() (fsync em selagem de época)
//                               ↓
//                          MMR.append() (cache volátil)
//                               ↓
//                          seal_epoch() → EpochSeal persistido no EPA
//
// # Formato do arquivo
//
// [HEADER: 256 bytes]
//   [0-7]    magic:     "NEXO_WAL" (0x4E45584F5F57414C)
//   [8-15]   version:   u64 = 1 (little-endian)
//   [16-23]  min_ts:    u64 (primeiro timestamp monotônico)
//   [24-31]  max_ts:    u64 (último timestamp escrito)
//   [32-255] reserved:  zeros
//
// [RECORD: 64 bytes cada]
//   [0]     type:       u8 (0x01=Leaf, 0x02=Heartbeat, 0x03=EpochSeal)
//   [1-7]   reserved:   zeros (alinhamento)
//   [8-15]  leaf_index: u64 LE
//   [16-47] hash:       [u8; 32] (SHA-256 do payload)
//   [48-55] timestamp:  u64 LE (monotônico, NON-wall-clock)
//   [56-63] content_id: u64 LE (ponteiro para ContentStore)
//
// # Garantias
//
// - Hot path: `append()` escreve 64 bytes com `write_all()` — 1 syscall,
//   zero heap, zero alocação. ~50ns em NVMe com page cache quente.
// - Thread safety: `Mutex<File>` de curta duração (< 100ns).
// - Crash recovery: `replay()` lê todo o WAL, reconstrói o MMR.
// - WAL é o source of truth; se o MMR corromper, apague o MMR e replay.

use crate::Mmr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

// ─── Constantes ───────────────────────────────────────────────────────────────

/// Magic number: "NEXO_WAL" em ASCII.
const MAGIC: [u8; 8] = [0x4E, 0x45, 0x58, 0x4F, 0x5F, 0x57, 0x41, 0x4C];

/// Versão do formato WAL.
const VERSION: u64 = 1;

/// Tamanho do header do WAL (256 bytes).
const HEADER_SIZE: usize = 256;

/// Tamanho de cada registro (64 bytes — uma cache line).
const RECORD_SIZE: usize = 64;

// ─── Tipos de Registro ────────────────────────────────────────────────────────

/// Tipo de registro no WAL.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    /// Folha do MMR: hash SHA-256 de um Event::Data.
    Leaf = 0x01,
    /// Heartbeat: pulso do coração (sem hash, apenas timestamp).
    Heartbeat = 0x02,
    /// Selagem de época: marco de checkpoint do MMR.
    EpochSeal = 0x03,
}

impl RecordType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Leaf),
            0x02 => Some(Self::Heartbeat),
            0x03 => Some(Self::EpochSeal),
            _ => None,
        }
    }
}

// ─── WAL Record (64 bytes, stack-only) ─────────────────────────────────────────

/// Um registro no WAL. Cabe exatamente em 64 bytes (uma cache line).
/// Construído na stack, escrito com `write_all` — sem heap.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(64))]
pub struct WalRecord {
    pub record_type: RecordType,
    /// Índice da folha no MMR (válido apenas para Leaf).
    pub leaf_index: u64,
    /// Hash SHA-256 (válido apenas para Leaf e EpochSeal).
    pub hash: [u8; 32],
    /// Timestamp monotônico (NON-wall-clock).
    pub timestamp: u64,
    /// Ponteiro para ContentStore (ponte semântica para Fase B).
    pub content_id: u64,
}

impl WalRecord {
    fn encode(&self) -> [u8; RECORD_SIZE] {
        let mut buf = [0u8; RECORD_SIZE];
        buf[0] = self.record_type as u8;
        buf[8..16].copy_from_slice(&self.leaf_index.to_le_bytes());
        buf[16..48].copy_from_slice(&self.hash);
        buf[48..56].copy_from_slice(&self.timestamp.to_le_bytes());
        buf[56..64].copy_from_slice(&self.content_id.to_le_bytes());
        buf
    }

    fn decode(buf: &[u8; RECORD_SIZE]) -> Option<Self> {
        let rt = RecordType::from_u8(buf[0])?;
        let leaf_index = u64::from_le_bytes(buf[8..16].try_into().ok()?);
        let hash: [u8; 32] = buf[16..48].try_into().ok()?;
        let timestamp = u64::from_le_bytes(buf[48..56].try_into().ok()?);
        let content_id = u64::from_le_bytes(buf[56..64].try_into().ok()?);
        Some(Self {
            record_type: rt,
            leaf_index,
            hash,
            timestamp,
            content_id,
        })
    }
}

// ─── WAL Store ────────────────────────────────────────────────────────────────

/// Write-Ahead Log append-only para o MMR.
///
/// # Thread Safety
///
/// Internamente usa `Mutex<File>` para escrita serializada. A contenção
/// é mínima (< 50ns) porque o hot path adquire o lock por apenas 64 bytes
/// de `write_all`. O lock nunca é segurado através de uma operação bloqueante
/// como fsync — a menos que explicitamente chamado via `sync()`.
pub struct WalStore {
    file: Mutex<File>,
    /// Timestamp monotônico (contador atômico, não wall-clock).
    /// Cada `append()` incrementa e usa o valor anterior como timestamp.
    monotonic: AtomicU64,
    /// Caminho do arquivo WAL (para replay e debug).
    path: std::path::PathBuf,
}

impl WalStore {
    /// Abre (ou cria) o WAL no caminho especificado.
    ///
    /// Se o arquivo já existir, abre para append. O último registro é
    /// lido para recuperar o contador monotônico (timestamp + 1).
    /// Se o WAL estiver vazio (só header), o contador começa em 1.
    pub fn open(path: &Path) -> io::Result<Self> {
        if path.exists() {
            let mut file = OpenOptions::new().read(true).append(true).open(path)?;

            let len = file.metadata()?.len();

            // Lê o último registro (se houver) para recuperar o contador
            let monotonic = if len >= (HEADER_SIZE as u64 + RECORD_SIZE as u64) {
                file.seek(SeekFrom::End(-(RECORD_SIZE as i64)))?;
                let mut last = [0u8; RECORD_SIZE];
                file.read_exact(&mut last)?;
                if let Some(record) = WalRecord::decode(&last) {
                    AtomicU64::new(record.timestamp + 1)
                } else {
                    AtomicU64::new(1)
                }
            } else {
                AtomicU64::new(1)
            };

            Ok(Self {
                file: Mutex::new(file),
                monotonic,
                path: path.to_path_buf(),
            })
        } else {
            Self::create(path)
        }
    }

    /// Cria um novo WAL (ou sobrescreve um existente).
    fn create(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        // Escreve o header
        let mut header = [0u8; HEADER_SIZE];
        header[0..8].copy_from_slice(&MAGIC);
        header[8..16].copy_from_slice(&VERSION.to_le_bytes());
        file.write_all(&header)?;
        file.sync_all()?;

        Ok(Self {
            file: Mutex::new(file),
            monotonic: AtomicU64::new(1),
            path: path.to_path_buf(),
        })
    }

    /// Append de um registro no WAL.
    ///
    /// # Zero-Allocation Guarantee
    ///
    /// - O buffer de 64 bytes é alocado na stack.
    /// - `write_all` faz 1 syscall (page cache).
    /// - O Mutex é uncontended no caso comum.
    /// - Sem heap, sem alocações dinâmicas.
    pub fn append(
        &self,
        record_type: RecordType,
        leaf_index: u64,
        hash: &[u8; 32],
        content_id: u64,
    ) -> io::Result<u64> {
        let ts = self.monotonic.fetch_add(1, Ordering::Relaxed);
        let record = WalRecord {
            record_type,
            leaf_index,
            hash: *hash,
            timestamp: ts,
            content_id,
        };
        let buf = record.encode();

        let mut file = self.file.lock().expect("wal lock");
        file.write_all(&buf)?;
        Ok(ts)
    }

    /// Atalho para append de Leaf (uso no hot path).
    #[inline(always)]
    pub fn append_leaf(&self, leaf_index: u64, hash: &[u8; 32]) -> io::Result<u64> {
        self.append(RecordType::Leaf, leaf_index, hash, 0)
    }

    /// Atalho para append de EpochSeal (chamado pelo pipeline).
    pub fn append_seal(&self, epoch: u64, root: &[u8; 32]) -> io::Result<u64> {
        self.append(RecordType::EpochSeal, epoch, root, 0)
    }

    /// Força o fsync do WAL para o disco.
    /// Antes do fsync, atualiza o campo `max_ts` no header
    /// para que o próximo `open()` recupere o contador correto.
    /// Chamado após cada selagem de época.
    pub fn sync(&self) -> io::Result<()> {
        let max_ts = self.monotonic.load(Ordering::Relaxed);
        let mut file = self.file.lock().expect("wal lock");
        // Atualiza max_ts no header (offset 24, 8 bytes)
        file.seek(SeekFrom::Start(24))?;
        file.write_all(&max_ts.to_le_bytes())?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    }

    /// Replay: reconstrói o MMR a partir do WAL.
    ///
    /// Lê TODO o arquivo WAL em memória (alocação única, fora do hot path)
    /// e alimenta cada registro Leaf para `mmr.append()`.
    ///
    /// Retorna a quantidade de registros Leaf recuperados.
    pub fn replay(&self, mmr: &Mutex<Mmr>) -> io::Result<u64> {
        let mut file = OpenOptions::new().read(true).open(&self.path)?;
        let len = file.metadata()?.len();
        if len < HEADER_SIZE as u64 {
            return Ok(0);
        }

        let mut data = Vec::with_capacity((len - HEADER_SIZE as u64) as usize);
        file.read_to_end(&mut data)?;

        let mut count = 0u64;
        for chunk in data.chunks_exact(RECORD_SIZE) {
            let buf: &[u8; RECORD_SIZE] = chunk.try_into().unwrap();
            if let Some(record) = WalRecord::decode(buf) {
                match record.record_type {
                    RecordType::Leaf => {
                        let mut guard = mmr.lock().expect("mmr lock");
                        guard.append(record.hash);
                        count += 1;
                    }
                    RecordType::EpochSeal => {
                        // Registro de selagem: o MMR já reconstruiu
                        // automaticamente via os Leaf records anteriores.
                        // O EpochSeal é útil para auditoria futura e
                        // snapshot de checkpoint.
                    }
                    RecordType::Heartbeat => {
                        // Heartbeats não produzem hash — apenas marcam
                        // que o sistema estava vivo.
                    }
                }
            }
        }

        // Atualiza o contador monotônico baseado no último registro
        if let Some(last_chunk) = data.chunks_exact(RECORD_SIZE).next_back() {
            let buf: &[u8; RECORD_SIZE] = last_chunk.try_into().unwrap();
            if let Some(record) = WalRecord::decode(buf) {
                self.monotonic
                    .store(record.timestamp + 1, Ordering::Relaxed);
            }
        }

        Ok(count)
    }

    /// Número total de registros no WAL (estimativa baseada no tamanho do arquivo).
    pub fn record_count(&self) -> io::Result<u64> {
        let file = self.file.lock().expect("wal lock");
        let len = file.metadata()?.len();
        if len < HEADER_SIZE as u64 {
            Ok(0)
        } else {
            Ok((len - HEADER_SIZE as u64) / RECORD_SIZE as u64)
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ─── Testes ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mmr;
    use std::sync::Mutex;
    use tempfile::tempdir;

    fn test_hash(byte: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = byte;
        h
    }

    #[test]
    fn create_and_append() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.wal");

        let wal = WalStore::open(&path).unwrap();
        assert!(path.exists(), "WAL file must exist after creation");

        wal.append_leaf(0, &test_hash(0xAA)).unwrap();
        wal.append_leaf(1, &test_hash(0xBB)).unwrap();
        wal.append_seal(0, &test_hash(0xFF)).unwrap();
        wal.sync().unwrap();

        let count = wal.record_count().unwrap();
        assert_eq!(count, 3, "must have 3 records");
    }

    #[test]
    fn replay_rebuilds_mmr() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("replay.wal");

        // ── Escrita ──
        {
            let wal = WalStore::open(&path).unwrap();
            wal.append_leaf(0, &test_hash(0x01)).unwrap();
            wal.append_leaf(1, &test_hash(0x02)).unwrap();
            wal.append_leaf(2, &test_hash(0x03)).unwrap();
            wal.sync().unwrap();
        }

        // ── Replay em MMR novo ──
        let mmr = Mutex::new(Mmr::new());
        {
            let wal = WalStore::open(&path).unwrap();
            let recovered = wal.replay(&mmr).unwrap();
            assert_eq!(recovered, 3, "must recover 3 leaves");

            // Apos replay, o epoch seal deve funcionar
            let seal = mmr.lock().unwrap().seal_epoch().unwrap();
            assert_eq!(seal.leaf_count, 3, "MMR must have 3 leaves after replay");
        }
    }

    #[test]
    fn replay_empty_wal() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.wal");

        let mmr = Mutex::new(Mmr::new());
        let wal = WalStore::open(&path).unwrap();
        let recovered = wal.replay(&mmr).unwrap();
        assert_eq!(recovered, 0, "empty WAL must recover 0");
    }

    #[test]
    fn monotonic_timestamp_increases() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mono.wal");

        let wal = WalStore::open(&path).unwrap();

        // Append 5 records, each gets a unique timestamp
        let mut ts1 = 0u64;
        for i in 0..5 {
            ts1 = wal.append_leaf(i, &test_hash(i as u8)).unwrap();
        }

        // Reopen and replay — timestamp must continue
        let wal2 = WalStore::open(&path).unwrap();
        let ts2 = wal2.append_leaf(5, &test_hash(0xFF)).unwrap();

        assert!(ts2 > ts1, "timestamp must be monotonic across reopen");
    }

    #[test]
    fn record_size_is_64_bytes() {
        assert_eq!(std::mem::size_of::<WalRecord>(), 64);
        assert_eq!(std::mem::align_of::<WalRecord>(), 64);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let record = WalRecord {
            record_type: RecordType::Leaf,
            leaf_index: 42,
            hash: [0xAB; 32],
            timestamp: 12345,
            content_id: 6789,
        };
        let buf = record.encode();
        let decoded = WalRecord::decode(&buf).unwrap();
        assert_eq!(decoded.record_type, RecordType::Leaf);
        assert_eq!(decoded.leaf_index, 42);
        assert_eq!(decoded.hash, [0xAB; 32]);
        assert_eq!(decoded.timestamp, 12345);
        assert_eq!(decoded.content_id, 6789);
    }
}
