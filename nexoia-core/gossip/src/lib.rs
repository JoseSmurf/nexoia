/// `gossip` — Teia P2P Sybil-Resistente com Defesa Tri-Layer
///
/// # Arquitetura de Defesa (3 Camadas)
///
/// ```text
/// ┌──────────────────────────────────────────────────────────────────┐
/// │  CAMADA 1 — VDF Guard (vdf_guard)                               │
/// │  Custo computacional sequencial na entrada de novos peers.      │
/// │  Resistência Sybil: O(n) identidades = O(n × VDF_cost) CPU.    │
/// │  Wasm-compatível: pure Rust, SHA-256 iterado.                   │
/// ├──────────────────────────────────────────────────────────────────┤
/// │  CAMADA 2 — Oscillating Trust Window (peer)                     │
/// │  Ring buffer de 64 amostras de comportamento por peer.          │
/// │  Score oscila em tempo real: comportamento bom recupera trust,  │
/// │  mau comportamento degrada. Silêncio aplica decaimento gradual. │
/// ├──────────────────────────────────────────────────────────────────┤
/// │  CAMADA 3 — Alinhamento bio_loop @ 1kHz (transport)            │
/// │  Ingestão limitada a 1 frame/tick = máx 1.000 frames/s.        │
/// │  Bounded channel → backpressure natural sem alocação.           │
/// │  Latência máxima determinística: queue_depth / 1000 segundos.  │
/// └──────────────────────────────────────────────────────────────────┘
/// ```
///
/// # Fluxo de Dados
///
/// ```text
/// Rede externa
///     │
///     ▼ NetworkFrame (stack, zero-alloc)
/// transport::validate_frame()
///     │ inválido → descarta
///     │ válido ↓
/// vdf_guard::PeerHandshake          ← novo peer?
///     │ admitted ↓
/// peer::PeerState::record()         ← atualiza trust window
///     │ banned → evict
///     │ active ↓
/// crossbeam_channel::try_send()     ← enfileira para bio_loop
///     │ Full → backpressure (drop)
///     │ Ok ↓
/// bio_loop::digest (1 frame/tick)   ← Coração cadencia a drenagem
/// ```
pub mod peer;
pub mod transport;
pub mod vdf_guard;

pub use peer::{
    BehaviorSample, ConnectionState, PeerState, PeerTable, TRUST_THRESHOLD_BAN,
    TRUST_THRESHOLD_HIGH, TRUST_WINDOW_SIZE,
};
pub use transport::{
    create_ingestion_channel, validate_frame, Emitter, FrameKind, FrameValidation, Ingestor,
    NetworkFrame, INGESTION_QUEUE_DEPTH, MAX_FRAME_SIZE,
};
pub use vdf_guard::{
    compute_vdf, verify_vdf, HandshakeState, PeerHandshake, VdfChallenge, VdfProof, VdfVerdict,
    DEFAULT_DIFFICULTY,
};
