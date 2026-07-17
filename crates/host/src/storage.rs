use memmap2::MmapMut;
use std::fs::OpenOptions;
use std::io::{self, Error, ErrorKind};
use std::path::Path;

const WAL_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

pub struct WalBuffer {
    mmap: MmapMut,
    cursor: usize,
}

impl WalBuffer {
    /// Inicializa a Medula. Abre o arquivo, garante os 10MB e recupera o estado (cursor).
    pub fn new<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let meta = file.metadata()?;
        if meta.len() != WAL_SIZE {
            file.set_len(WAL_SIZE)?;
        }

        // O MmapMut é intrinsecamente unsafe. Em produção, você usaria lock de arquivo (ex: fs2).
        let mut mmap = unsafe { MmapMut::map_mut(&file)? };

        // Realiza o "Recovery" para achar o cursor real
        let cursor = Self::recover_cursor(&mut mmap);

        println!(
            "💾 [WAL] Recuperação finalizada. Cursor no byte: {} / {}",
            cursor, WAL_SIZE
        );

        Ok(Self { mmap, cursor })
    }

    /// Varre a memória lendo `[Tamanho(4) | Dados | Hash(32)]` para encontrar onde as gravações pararam.
    fn recover_cursor(mmap: &mut MmapMut) -> usize {
        let mut cursor = 0;
        let len = mmap.len();

        while cursor + 4 <= len {
            // 1. Lê o tamanho do próximo pacote
            let mut size_bytes = [0u8; 4];
            size_bytes.copy_from_slice(&mmap[cursor..cursor + 4]);
            let packet_size = u32::from_le_bytes(size_bytes) as usize;

            // Se for 0, chegamos na área virgem (não escrita)
            if packet_size == 0 || cursor + 4 + packet_size + 32 > len {
                break;
            }

            // 2. Extrai os dados e o Hash
            let data_start = cursor + 4;
            let data_end = data_start + packet_size;
            let hash_start = data_end;
            let hash_end = hash_start + 32;

            let payload = &mmap[data_start..data_end];
            let stored_hash = &mmap[hash_start..hash_end];

            // 3. Verifica a integridade com Blake3
            let calculated_hash = blake3::hash(payload);

            if calculated_hash.as_bytes() != stored_hash {
                println!(
                    "⚠️ [WAL] Corrupção detectada no byte {}. Assumindo Torn Write.",
                    cursor
                );
                break; // Hash falhou. Foi aqui que a energia caiu no passado.
            }

            // Pacote íntegro! Avança o cursor.
            cursor = hash_end;
        }

        cursor
    }

    /// Injeta deltas na RAM encapsulados com Blake3 para tolerância a falhas.
    pub fn append_delta(&mut self, payload: &[u8]) -> io::Result<()> {
        let payload_len = payload.len();
        let total_frame_size = 4 + payload_len + 32; // Tamanho(u32) + Dados + Blake3(32)

        if self.cursor + total_frame_size > self.mmap.len() {
            return Err(Error::new(
                ErrorKind::OutOfMemory,
                "WAL Overflow. Necessário Snapshot Zstd.",
            ));
        }

        // 1. Escreve Tamanho (4 bytes)
        let size_bytes = (payload_len as u32).to_le_bytes();
        self.mmap[self.cursor..self.cursor + 4].copy_from_slice(&size_bytes);

        // 2. Escreve Payload
        let data_start = self.cursor + 4;
        self.mmap[data_start..data_start + payload_len].copy_from_slice(payload);

        // 3. Escreve Hash Blake3 (32 bytes)
        let hash = blake3::hash(payload);
        let hash_start = data_start + payload_len;
        self.mmap[hash_start..hash_start + 32].copy_from_slice(hash.as_bytes());

        // Atualiza o cursor da sessão
        self.cursor += total_frame_size;

        Ok(())
    }

    /// Força o flush da memória para o disco
    pub fn flush(&self) -> io::Result<()> {
        self.mmap.flush()
    }
}
