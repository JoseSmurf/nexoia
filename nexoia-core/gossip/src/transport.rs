use crossbeam_channel::{Receiver, Sender, TrySendError};

// ─── Constantes de Transporte ────────────────────────────────────────────────

/// Tamanho máximo de um frame de rede.
/// Fixo — garante que NetworkFrame tem tamanho conhecido em compile-time.
/// 1024 bytes: suficiente para um NexoPacket completo + cabeçalho.
pub const MAX_FRAME_SIZE: usize = 1_024;

/// Profundidade da fila de ingestão de rede.
/// Bounded para backpressure — o ritmo de drenagem é o bio_loop @ 1kHz.
pub const INGESTION_QUEUE_DEPTH: usize = 512;

// ─── Frame de Rede ────────────────────────────────────────────────────────────

/// Um frame de mensagem P2P. Tamanho fixo em stack — zero-allocation.
///
/// Invariante de Zero-Allocation:
/// - `payload` é um array fixo — sem Vec, sem Box.
/// - Transferido por cópia via crossbeam bounded channel (memcpy do slot).
/// - `len` indica o tamanho real do payload (≤ MAX_FRAME_SIZE).
#[derive(Clone, Copy)]
pub struct NetworkFrame {
    /// Peer de origem (32 bytes = hash da chave pública ou peer_id)
    pub peer_id: [u8; 32],
    /// Payload raw do frame (bytes da rede)
    pub payload: [u8; MAX_FRAME_SIZE],
    /// Tamanho real do payload em bytes
    pub len: u16,
    /// Tipo do frame
    pub kind: FrameKind,
}

/// Tipo do frame — 1 byte, sem alocação.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum FrameKind {
    /// Handshake VDF — novo peer apresentando prova
    VdfHandshake = 0x01,
    /// Mensagem de gossip — dado para replicar na rede
    GossipData = 0x02,
    /// Heartbeat de peer — keepalive com tick do bio_loop
    PeerHeartbeat = 0x03,
    /// Prova ZK recebida via gossip
    ZkProof = 0x04,
    /// Epoch seal propagado — sincronização de estado
    EpochSeal = 0x05,
    /// Frame desconhecido ou corrompido
    Unknown = 0xFF,
}

impl NetworkFrame {
    /// Cria um frame zerado. Usado para pre-alocar buffers de recepção.
    pub const fn empty() -> Self {
        Self {
            peer_id: [0u8; 32],
            payload: [0u8; MAX_FRAME_SIZE],
            len: 0,
            kind: FrameKind::Unknown,
        }
    }

    /// Retorna o slice válido do payload (sem bytes de padding).
    #[inline]
    pub fn payload_slice(&self) -> &[u8] {
        &self.payload[..self.len as usize]
    }

    /// Constrói um frame a partir de bytes raw. Retorna None se exceder o tamanho.
    pub fn from_bytes(peer_id: [u8; 32], kind: FrameKind, data: &[u8]) -> Option<Self> {
        if data.len() > MAX_FRAME_SIZE {
            return None;
        }
        let mut frame = Self::empty();
        frame.peer_id = peer_id;
        frame.kind = kind;
        frame.payload[..data.len()].copy_from_slice(data);
        frame.len = data.len() as u16;
        Some(frame)
    }
}

// ─── Canal de Ingestão ────────────────────────────────────────────────────────

/// Cria o canal de ingestão de rede.
/// Bounded(INGESTION_QUEUE_DEPTH) — backpressure automático.
/// A drenagem é feita pelo bio_loop @ 1kHz (um frame por tick do Coração).
pub fn create_ingestion_channel() -> (Sender<NetworkFrame>, Receiver<NetworkFrame>) {
    crossbeam_channel::bounded(INGESTION_QUEUE_DEPTH)
}

// ─── Ingestor ─────────────────────────────────────────────────────────────────

/// Ingestor de frames de rede alinhado ao ritmo do bio_loop.
///
/// # Alinhamento com bio_loop @ 1kHz
///
/// O Coração emite um `Tick` a cada 1ms via `Event::Heartbeat(tick)`.
/// O `Ingestor::drain_one_tick()` deve ser chamado exatamente uma vez por tick.
/// Isso cria um ritmo de drenagem de 1 frame/ms = 1.000 frames/s máximo.
///
/// Se a rede enviar mais rápido, o canal enche e `try_send` retorna `Full`
/// — backpressure natural sem alocação.
pub struct Ingestor {
    rx: Receiver<NetworkFrame>,
    /// Contador de frames processados (para diagnóstico)
    pub frames_processed: u64,
    /// Contador de frames descartados por backpressure no receptor
    pub frames_dropped: u64,
}

impl Ingestor {
    pub fn new(rx: Receiver<NetworkFrame>) -> Self {
        Self {
            rx,
            frames_processed: 0,
            frames_dropped: 0,
        }
    }

    /// Drena UM frame da fila, para ser chamado sincronicamente no tick do Coração.
    ///
    /// # Por que um frame por tick?
    ///
    /// Garante latência máxima previsível: qualquer frame espera no máximo
    /// `INGESTION_QUEUE_DEPTH / 1000` segundos = 512ms com a fila cheia.
    /// Isso é um bound determinístico — sem latências imprevisíveis de polling.
    #[inline]
    pub fn drain_one_tick(&mut self) -> Option<NetworkFrame> {
        match self.rx.try_recv() {
            Ok(frame) => {
                self.frames_processed += 1;
                Some(frame)
            }
            Err(_) => None, // fila vazia — ok, próximo tick
        }
    }

    /// Drena todos os frames disponíveis no momento (modo burst).
    /// Usado durante a inicialização ou após período de silêncio.
    pub fn drain_burst(&mut self, max_frames: usize) -> Vec<NetworkFrame> {
        // NOTA: esta função aloca um Vec — usada apenas fora do hot path (init/burst)
        let mut out = Vec::with_capacity(max_frames.min(64));
        for _ in 0..max_frames {
            match self.rx.try_recv() {
                Ok(frame) => {
                    self.frames_processed += 1;
                    out.push(frame);
                }
                Err(_) => break,
            }
        }
        out
    }

    pub fn queue_len(&self) -> usize {
        self.rx.len()
    }
}

// ─── Emissor ──────────────────────────────────────────────────────────────────

/// Emissor de frames para a rede.
/// Wraps o `Sender<NetworkFrame>` com métricas e backpressure explícito.
pub struct Emitter {
    tx: Sender<NetworkFrame>,
    pub frames_sent: u64,
    pub frames_rejected: u64,
}

impl Emitter {
    pub fn new(tx: Sender<NetworkFrame>) -> Self {
        Self {
            tx,
            frames_sent: 0,
            frames_rejected: 0,
        }
    }

    /// Tenta emitir um frame. Retorna Err se a fila de saída estiver cheia.
    /// NUNCA bloqueia — garante que o loop do bio_loop não seja atrasado.
    // O `Err` carrega o frame de volta sem heap — intencional (hot path, zero alloc).
    #[allow(clippy::result_large_err)]
    pub fn try_emit(&mut self, frame: NetworkFrame) -> Result<(), NetworkFrame> {
        match self.tx.try_send(frame) {
            Ok(()) => {
                self.frames_sent += 1;
                Ok(())
            }
            Err(TrySendError::Full(f)) => {
                self.frames_rejected += 1;
                Err(f)
            }
            Err(TrySendError::Disconnected(f)) => Err(f),
        }
    }
}

// ─── Validador de Frame ───────────────────────────────────────────────────────

/// Valida um frame recebido antes de encaminhá-lo ao Ingestor.
/// Zero-allocation: opera apenas sobre referências ao frame.
#[must_use]
pub fn validate_frame(frame: &NetworkFrame) -> FrameValidation {
    if frame.len == 0 {
        return FrameValidation::Empty;
    }
    if frame.len as usize > MAX_FRAME_SIZE {
        return FrameValidation::Oversized;
    }
    if frame.peer_id == [0u8; 32] {
        return FrameValidation::AnonymousPeer;
    }
    if frame.kind == FrameKind::Unknown {
        return FrameValidation::UnknownKind;
    }
    FrameValidation::Valid
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameValidation {
    Valid,
    Empty,
    Oversized,
    AnonymousPeer,
    UnknownKind,
}

// ─── Testes ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer_id(byte: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    #[test]
    fn frame_from_bytes_roundtrip() {
        let data = [0xAB, 0xCD, 0xEF];
        let frame = NetworkFrame::from_bytes(make_peer_id(0x01), FrameKind::GossipData, &data)
            .expect("frame válido deve ser criado");

        assert_eq!(frame.payload_slice(), &data);
        assert_eq!(frame.len, 3);
        assert_eq!(frame.kind, FrameKind::GossipData);
    }

    #[test]
    fn frame_from_bytes_rejects_oversized() {
        let big = vec![0u8; MAX_FRAME_SIZE + 1];
        let result = NetworkFrame::from_bytes(make_peer_id(0x02), FrameKind::GossipData, &big);
        assert!(result.is_none(), "frame oversized deve ser rejeitado");
    }

    #[test]
    fn ingestor_drain_one_per_tick() {
        let (tx, rx) = create_ingestion_channel();
        let mut ingestor = Ingestor::new(rx);

        // Injeta 3 frames
        for i in 0..3u8 {
            let frame =
                NetworkFrame::from_bytes(make_peer_id(i + 1), FrameKind::PeerHeartbeat, &[i])
                    .unwrap();
            tx.try_send(frame).unwrap();
        }

        // Drena um por tick
        assert!(ingestor.drain_one_tick().is_some());
        assert!(ingestor.drain_one_tick().is_some());
        assert!(ingestor.drain_one_tick().is_some());
        assert!(ingestor.drain_one_tick().is_none(), "fila deve estar vazia");
        assert_eq!(ingestor.frames_processed, 3);
    }

    #[test]
    fn backpressure_when_queue_full() {
        let (tx, _rx) = crossbeam_channel::bounded::<NetworkFrame>(2);
        let mut emitter = Emitter::new(tx);

        let f = NetworkFrame::from_bytes(make_peer_id(0x01), FrameKind::GossipData, &[1]).unwrap();
        assert!(emitter.try_emit(f).is_ok());
        assert!(emitter.try_emit(f).is_ok());
        // Terceiro deve falhar (canal cheio)
        assert!(emitter.try_emit(f).is_err());
        assert_eq!(emitter.frames_rejected, 1);
    }

    #[test]
    fn validate_frame_catches_issues() {
        let valid = NetworkFrame::from_bytes(make_peer_id(0x01), FrameKind::GossipData, &[1, 2, 3])
            .unwrap();
        assert_eq!(validate_frame(&valid), FrameValidation::Valid);

        let anonymous = NetworkFrame::from_bytes([0u8; 32], FrameKind::GossipData, &[1]).unwrap();
        assert_eq!(validate_frame(&anonymous), FrameValidation::AnonymousPeer);

        let empty = NetworkFrame::empty();
        assert_eq!(validate_frame(&empty), FrameValidation::Empty);
    }
}
