// ─── Constantes da Janela de Confiança ───────────────────────────────────────

/// Tamanho da janela deslizante de comportamento — fixo, zero-allocation.
/// 64 amostras × 1 byte/amostra = 64 bytes por peer (cabe numa cache line).
pub const TRUST_WINDOW_SIZE: usize = 64;

/// Pontuação máxima possível (peer perfeito, histórico limpo)
pub const TRUST_MAX: i16 = 100;

/// Pontuação mínima possível (peer malicioso confirmado)
pub const TRUST_MIN: i16 = -100;

/// Threshold para admitir mensagens sem verificação extra
pub const TRUST_THRESHOLD_HIGH: i16 = 60;

/// Threshold de banimento — peer abaixo disto é desconectado
pub const TRUST_THRESHOLD_BAN: i16 = -50;

/// Decaimento por ausência: a cada `SILENCE_DECAY_TICKS` ticks sem atividade,
/// a pontuação cai 1 ponto (evita peers "fantasmas" com score alto travado).
pub const SILENCE_DECAY_TICKS: u32 = 1_000; // 1 segundo @ 1kHz

// ─── Amostra de Comportamento ────────────────────────────────────────────────

/// Uma amostra de comportamento registrada na janela deslizante.
/// 1 byte — cabe numa cache line inteira (64 amostras = 64 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BehaviorSample {
    /// Mensagem válida recebida e processada
    Good = 1,
    /// Mensagem inválida, fora de protocolo ou mal-formada
    Bad = 0,
    /// Slot vazio (ainda não preenchido no início da janela)
    Empty = 2,
}

// ─── Estado do Peer ───────────────────────────────────────────────────────────

/// Estado completo de um peer na Teia P2P.
/// Tamanho fixo em stack: ~200 bytes por peer.
/// Para 1000 peers: ~200KB de memória total — sem heap.
#[derive(Clone)]
pub struct PeerState {
    /// Identificador criptográfico do peer (hash da chave pública ou peer_id)
    pub id: [u8; 32],

    /// Pontuação de confiança atual (-100 a +100)
    pub trust_score: i16,

    /// Ring buffer de amostras de comportamento recentes.
    /// INVARIANTE: tamanho fixo TRUST_WINDOW_SIZE, sem Vec.
    behavior_window: [BehaviorSample; TRUST_WINDOW_SIZE],

    /// Ponteiro de escrita no ring buffer (wraps around)
    window_head: usize,

    /// Total de amostras gravadas (satura em TRUST_WINDOW_SIZE)
    window_fill: usize,

    /// Tick do último evento recebido (para detecção de silêncio)
    pub last_active_tick: u64,

    /// True se o handshake VDF foi concluído com sucesso
    pub vdf_verified: bool,

    /// Contador de violações de protocolo (resets ao atingir threshold de ban)
    pub strike_count: u8,

    /// Estado de conexão
    pub connection: ConnectionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Handshake VDF em andamento
    Handshaking,
    /// Peer ativo e confiável
    Active,
    /// Peer suspenso temporariamente (score baixo, mas não banido)
    Suspended,
    /// Peer banido permanentemente nesta sessão
    Banned,
}

impl PeerState {
    /// Cria um novo peer no estado de handshake.
    pub fn new(id: [u8; 32]) -> Self {
        Self {
            id,
            trust_score: 0, // começa neutro — sem crédito e sem débito
            behavior_window: [BehaviorSample::Empty; TRUST_WINDOW_SIZE],
            window_head: 0,
            window_fill: 0,
            last_active_tick: 0,
            vdf_verified: false,
            strike_count: 0,
            connection: ConnectionState::Handshaking,
        }
    }

    // ── Registro de Comportamento ─────────────────────────────────────────────

    /// Registra uma amostra de comportamento e recalcula o score.
    /// O(1) — ring buffer de tamanho fixo, sem alocação.
    pub fn record(&mut self, sample: BehaviorSample, current_tick: u64) {
        self.behavior_window[self.window_head] = sample;
        self.window_head = (self.window_head + 1) % TRUST_WINDOW_SIZE;
        if self.window_fill < TRUST_WINDOW_SIZE {
            self.window_fill += 1;
        }
        self.last_active_tick = current_tick;

        if sample == BehaviorSample::Bad {
            self.strike_count = self.strike_count.saturating_add(1);
        }

        self.recalculate_score();
        self.update_connection_state();
    }

    /// Aplica decaimento por silêncio baseado nos ticks passados.
    /// Chamado pelo Heart Loop a cada N ticks.
    pub fn apply_silence_decay(&mut self, current_tick: u64) {
        let silent_ticks = current_tick.saturating_sub(self.last_active_tick);
        let decay = (silent_ticks / SILENCE_DECAY_TICKS as u64) as i16;
        if decay > 0 {
            self.trust_score = (self.trust_score - decay).max(TRUST_MIN);
            self.update_connection_state();
        }
    }

    // ── Cálculo de Score — A Janela Oscilante ─────────────────────────────────

    /// Recalcula o trust score baseado na janela de comportamento atual.
    ///
    /// Fórmula: score = (good - bad) / fill × 100, saturado em [-100, +100].
    ///
    /// A "oscilação" vem do ring buffer: amostras antigas saem automaticamente
    /// quando a janela enche. Um peer que se comportou mal no passado mas
    /// se recuperou verá seu score subir gradualmente — e vice-versa.
    fn recalculate_score(&mut self) {
        if self.window_fill == 0 {
            self.trust_score = 0;
            return;
        }

        let mut good: i32 = 0;
        let mut bad: i32 = 0;

        // Itera apenas os slots preenchidos
        for i in 0..self.window_fill {
            match self.behavior_window[i] {
                BehaviorSample::Good => good += 1,
                BehaviorSample::Bad => bad += 1,
                BehaviorSample::Empty => {}
            }
        }

        // Score normalizado em [-100, +100]
        let raw = (good - bad) * 100 / self.window_fill as i32;
        self.trust_score = raw.clamp(TRUST_MIN as i32, TRUST_MAX as i32) as i16;
    }

    fn update_connection_state(&mut self) {
        self.connection = match self.trust_score {
            s if s <= TRUST_THRESHOLD_BAN => ConnectionState::Banned,
            s if s < 0 => ConnectionState::Suspended,
            _ if self.vdf_verified => ConnectionState::Active,
            _ => ConnectionState::Handshaking,
        };
    }

    // ── Consultas ─────────────────────────────────────────────────────────────

    pub fn is_trusted(&self) -> bool {
        self.trust_score >= TRUST_THRESHOLD_HIGH && self.vdf_verified
    }

    pub fn is_banned(&self) -> bool {
        self.connection == ConnectionState::Banned
    }

    pub fn admit_after_vdf(&mut self, current_tick: u64) {
        self.vdf_verified = true;
        self.last_active_tick = current_tick;
        self.connection = ConnectionState::Active;
        // Bônus inicial pelo custo VDF pago
        self.trust_score = 10;
    }
}

// ─── Tabela de Peers ──────────────────────────────────────────────────────────

/// Tabela de peers com capacidade máxima fixa.
/// Sem HashMap — busca linear O(n) mas n é pequeno (≤256) e cache-friendly.
pub const MAX_PEERS: usize = 256;

pub struct PeerTable {
    peers: [Option<PeerState>; MAX_PEERS],
    count: usize,
}

impl PeerTable {
    pub fn new() -> Self {
        // `Option<PeerState>` não implementa Copy, então inicializamos manualmente
        Self {
            peers: std::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// Insere ou atualiza um peer. Retorna Err se a tabela estiver cheia.
    pub fn upsert(&mut self, state: PeerState) -> Result<(), &'static str> {
        // Tenta atualizar peer existente
        for slot in self.peers.iter_mut().flatten() {
            if slot.id == state.id {
                *slot = state;
                return Ok(());
            }
        }
        // Insere em slot livre
        for slot in self.peers.iter_mut() {
            if slot.is_none() {
                *slot = Some(state);
                self.count += 1;
                return Ok(());
            }
        }
        Err("tabela de peers cheia")
    }

    pub fn get_mut(&mut self, id: &[u8; 32]) -> Option<&mut PeerState> {
        self.peers
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|p| &p.id == id)
    }

    pub fn get(&self, id: &[u8; 32]) -> Option<&PeerState> {
        self.peers
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|p| &p.id == id)
    }

    /// Remove peers banidos, liberando slots.
    pub fn evict_banned(&mut self) {
        for slot in self.peers.iter_mut() {
            if slot.as_ref().map(|p| p.is_banned()).unwrap_or(false) {
                *slot = None;
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    /// Aplica decaimento de silêncio a todos os peers ativos.
    pub fn tick_all(&mut self, current_tick: u64) {
        for peer in self.peers.iter_mut().flatten() {
            peer.apply_silence_decay(current_tick);
        }
    }

    pub fn active_count(&self) -> usize {
        self.peers
            .iter()
            .filter(|s| {
                s.as_ref()
                    .map(|p| p.connection == ConnectionState::Active)
                    .unwrap_or(false)
            })
            .count()
    }

    pub fn total_count(&self) -> usize {
        self.count
    }
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Testes ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_id(byte: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    #[test]
    fn score_increases_with_good_behavior() {
        let mut peer = PeerState::new(peer_id(0x01));
        for _ in 0..TRUST_WINDOW_SIZE {
            peer.record(BehaviorSample::Good, 0);
        }
        assert_eq!(peer.trust_score, TRUST_MAX);
    }

    #[test]
    fn score_decreases_with_bad_behavior() {
        let mut peer = PeerState::new(peer_id(0x02));
        for _ in 0..TRUST_WINDOW_SIZE {
            peer.record(BehaviorSample::Bad, 0);
        }
        assert_eq!(peer.trust_score, TRUST_MIN);
        assert!(peer.is_banned());
    }

    #[test]
    fn oscillation_recovers_after_bad_patch() {
        let mut peer = PeerState::new(peer_id(0x03));
        peer.vdf_verified = true;

        // 32 bad samples
        for _ in 0..32 {
            peer.record(BehaviorSample::Bad, 0);
        }
        let score_after_bad = peer.trust_score;

        // 64 good samples — janela deslizante apaga os bad
        for _ in 0..TRUST_WINDOW_SIZE {
            peer.record(BehaviorSample::Good, 1);
        }

        assert!(
            peer.trust_score > score_after_bad,
            "score deve recuperar após bom comportamento contínuo"
        );
    }

    #[test]
    fn silence_decay_reduces_score() {
        let mut peer = PeerState::new(peer_id(0x04));
        peer.vdf_verified = true;
        peer.last_active_tick = 0;
        peer.trust_score = 50;

        // Simula 2000 ticks de silêncio (2 decaimentos)
        peer.apply_silence_decay(2 * SILENCE_DECAY_TICKS as u64);
        assert!(peer.trust_score < 50, "score deve cair após silêncio");
    }

    #[test]
    fn peer_table_evicts_banned() {
        let mut table = PeerTable::new();
        let mut banned = PeerState::new(peer_id(0xBA));
        for _ in 0..TRUST_WINDOW_SIZE {
            banned.record(BehaviorSample::Bad, 0);
        }
        table.upsert(banned).unwrap();
        assert_eq!(table.total_count(), 1);

        table.evict_banned();
        assert_eq!(table.total_count(), 0);
    }
}
