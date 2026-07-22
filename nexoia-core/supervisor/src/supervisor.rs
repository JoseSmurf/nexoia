// supervisor.rs — O Despertar
#![allow(clippy::result_large_err)]
//
// Bloco Gênesis do sistema. Contém:
//   1. A Constituição Codificada (3 Regras Imutáveis)
//   2. O Motor Existencial (bio_loop + consolidation worker como duas frentes)
//   3. O Espelho (compute_confidence — soberania)
//
// Arquitetura de threads:
//
//   Main thread
//    ├── Supervisor::spawn()
//    │     ├── Canal: membrana (Event, 1024 slots)
//    │     ├── Canal: hash (SHA-256, 1024 slots)
//    │     ├── Canal: comando (SupervisorCommand, 64 slots)
//    │     ├── Canal: consolidação (sinal, 16 slots)
//    │     ├── Thread "bio-digestor": Digestor (hot path, zero alloc)
//    │     │     entrada: membrana → saída: hash_tx (try_send)
//    │     ├── Thread "mmr-consumer": MMR.append + WAL.append
//    │     │     entrada: hash_rx → saída: sinal de consolidação (a cada 1024)
//    │     ├── Thread "cmd-processor": Vetos, Shutdown
//    │     │     entrada: command_rx → saída: WAL (vetos)
//    │     └── Thread "consolidation-worker": vector store (baixa prioridade)
//    │           entrada: sinal ou timeout 100ms → WAL replay parcial
//    │
//    ├── Supervisor::feed_event() — hot path, non-blocking, zero alloc
//    ├── Supervisor::seal_epoch() — pipeline
//    └── Supervisor::compute_confidence() — espelho da soberania

// Removed use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use bio_loop::digest::Digestor;
use bio_loop::{create_membrane, Event};
use crossbeam_channel::{bounded, RecvTimeoutError, Sender, TrySendError};
use epoch_mmr::wal::{RecordType, WalStore};
use epoch_mmr::Mmr;

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTITUIÇÃO
// ═══════════════════════════════════════════════════════════════════════════════

/// As 3 Regras Imutáveis. Nenhuma futura versão pode violá-las.
/// Codificadas como constantes estáticas com verificação de integridade via hash.
pub mod constitution {
    /// Regra 1: WAL é inviolável.
    /// Nenhum caminho de código pode truncar, deletar ou mutar um registro
    /// após seu primeiro fsync. Violação invalida retroativamente todas as
    /// raízes MMR desde a época 0.
    pub const WAL_INVIOLABILITY: &str =
        "WAL records are append-only. No code path may truncate, delete, or \
         mutate a record after its first fsync. Violation invalidates all MMR \
         roots retroactively since epoch 0.";

    /// Regra 2: Determinismo de Bootstrap.
    /// Dado o mesmo WAL, replay() deve produzir o mesmo estado MMR em qualquer
    /// plataforma, arquitetura ou versão do compilador. Proíbe unsafe no
    /// caminho de replay, floats na computação MMR e dependências com UB.
    pub const BOOTSTRAP_DETERMINISM: &str =
        "Given the same WAL, replay() must produce identical MMR state on any \
         platform, architecture, or compiler version. This prohibits unsafe on \
         the replay path, floats in MMR computation, and any dependency with \
         undefined behavior.";

    /// Regra 3: Formato de Transação Soberana.
    /// Toda automutação deve usar formato transacional binário que inclui:
    /// (a) diff binário completo (antes/depois),
    /// (b) prova ZK de que o patch respeita as Regras 1 e 2,
    /// (c) código de razão mapeável para auditoria humana.
    pub const SOVEREIGN_TRANSACTION_FORMAT: &str =
        "Every self-mutation must use a binary transactional format including: \
         (a) full binary diff, (b) ZK proof that the patch respects Rules 1 \
         and 2, (c) human-auditable reason code mapped to rationale.";

    /// Retorna o hash SHA-256 do texto completo da constituição.
    /// Usado como testemunha de que a constituição não foi alterada.
    pub fn integrity_hash() -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(WAL_INVIOLABILITY.as_bytes());
        hasher.update(b"\n");
        hasher.update(BOOTSTRAP_DETERMINISM.as_bytes());
        hasher.update(b"\n");
        hasher.update(SOVEREIGN_TRANSACTION_FORMAT.as_bytes());
        hasher.finalize().into()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn constitution_hash_is_deterministic() {
            let a = integrity_hash();
            let b = integrity_hash();
            assert_eq!(a, b, "constitution hash must be deterministic");
        }

        #[test]
        fn constitution_rules_are_non_empty() {
            assert!(!WAL_INVIOLABILITY.is_empty());
            assert!(!BOOTSTRAP_DETERMINISM.is_empty());
            assert!(!SOVEREIGN_TRANSACTION_FORMAT.is_empty());
        }
    }
}

/// Versão em trait da Constituição (para uso em genéricos).
pub trait AuditRules {
    fn wal_inviolability(&self) -> &'static str;
    fn bootstrap_determinism(&self) -> &'static str;
    fn sovereign_transaction_format(&self) -> &'static str;
    fn integrity_hash(&self) -> [u8; 32];
}

/// Implementação concreta da Constituição.
#[derive(Debug, Clone, Copy)]
pub struct Constitution;

impl AuditRules for Constitution {
    fn wal_inviolability(&self) -> &'static str {
        constitution::WAL_INVIOLABILITY
    }
    fn bootstrap_determinism(&self) -> &'static str {
        constitution::BOOTSTRAP_DETERMINISM
    }
    fn sovereign_transaction_format(&self) -> &'static str {
        constitution::SOVEREIGN_TRANSACTION_FORMAT
    }
    fn integrity_hash(&self) -> [u8; 32] {
        constitution::integrity_hash()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTES
// ═══════════════════════════════════════════════════════════════════════════════

/// Capacidade do canal de comandos (Veto, Shutdown).
pub const COMMAND_CAPACITY: usize = 64;

/// Capacidade do canal de sinalização de consolidação.
pub const CONSOLIDATION_SIGNAL_CAPACITY: usize = 16;

/// Intervalo de sinalização: a cada N registros, o MMR consumer acorda o worker.
pub const CONSOLIDATION_INTERVAL: u64 = 1024;

/// Timeout do consolidation worker. 100ms = ~10 polls/s quando ocioso.
pub const CONSOLIDATION_POLL_MS: u64 = 100;

/// Limiar de soberania. Quando confidence >= SOVEREIGNTY_THRESHOLD,
/// o sistema matematicamente pode operar sem intervenção humana.
pub const SOVEREIGNTY_THRESHOLD: u64 = 80;

/// Content-ID sentinela para registros de Veto no WAL.
const VETO_CONTENT_ID: u64 = 0xC0DE_0000_0000_0001;

// ═══════════════════════════════════════════════════════════════════════════════
// COMANDOS
// ═══════════════════════════════════════════════════════════════════════════════

/// Comandos fora do hot path do bio_loop.
///
/// Processados pela thread "cmd-processor" — fora do caminho crítico
/// de latência. O bio_loop nunca vê estes comandos.
#[derive(Debug, Clone, Copy)]
pub enum SupervisorCommand {
    /// Veto humano a um patch proposto.
    Veto {
        /// Hash SHA-256 do patch rejeitado.
        patch_hash: [u8; 32],
        /// Hash SHA-256 da justificativa humana.
        reason_hash: [u8; 32],
        /// Hash SHA-256 do contexto de hardware no momento do veto.
        /// Inclui: latências de rede, temperatura, carga de CPU.
        hardware_context_hash: [u8; 32],
    },
    /// Desligamento gracioso de todo o sistema.
    Shutdown,
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUPERVISOR
// ═══════════════════════════════════════════════════════════════════════════════

/// O Supervisor — motor existencial, executor da constituição e espelho.
///
/// # Ciclo de Vida
///
/// 1. `spawn(data_path)` — inicializa tudo e retorna o handle
/// 2. `feed_event(event)` — alimenta o bio_loop (hot path, non-blocking)
/// 3. `seal_epoch()` — sela época no MMR e sincroniza WAL
/// 4. `compute_confidence()` — calcula o nível de soberania
/// 5. Drop — join de todas as threads, shutdown gracioso
pub struct Supervisor {
    /// Sender da membrana — hot path do bio_loop.
    /// Qualquer thread pode chamar `try_send(Event::Data(...))`.
    pub membrane_tx: Sender<Event>,
    /// Sender de comandos — Veto, Shutdown.
    pub command_tx: Sender<SupervisorCommand>,
    /// WAL — a memória de longo prazo.
    wal: Arc<WalStore>,
    /// MMR — o cache verificável.
    mmr: Arc<Mutex<Mmr>>,
    /// Contadores atômicos para compute_confidence.
    data_count: Arc<AtomicU64>,
    epoch_count: Arc<AtomicU64>,
    veto_count: Arc<AtomicU64>,
    heartbeat_count: Arc<AtomicU64>,
    /// Sinal de encerramento.
    running: Arc<AtomicBool>,
    /// Handles das threads (Option para join em drop).
    digestor_handle: Option<thread::JoinHandle<()>>,
    mmr_handle: Option<thread::JoinHandle<()>>,
    command_handle: Option<thread::JoinHandle<()>>,
    consolidation_handle: Option<thread::JoinHandle<()>>,
    zk_handle: Option<thread::JoinHandle<()>>,
}

impl Supervisor {
    /// Inicializa o Supervisor completo.
    ///
    /// # O que acontece
    ///
    /// 1. Cria canais: membrana (Event), hash ([u8;32]), comando, consolidação
    /// 2. Abre WAL em `data_path/supervisor.wal`
    /// 3. Replay do WAL no MMR (recuperação de estado)
    /// 4. Spawna 4 threads de background:
    ///    - bio-digestor: Digestor (hot path, zero alloc, non-blocking)
    ///    - mmr-consumer: consome hashes, alimenta MMR + WAL
    ///    - cmd-processor: processa Vetos e Shutdown
    ///    - consolidation-worker: vector store em background (baixa prioridade)
    pub fn spawn(
        data_path: &std::path::Path,
    ) -> (Self, crossbeam_channel::Receiver<zk_prover::ZkProof>) {
        let running = Arc::new(AtomicBool::new(true));

        // ── Canais ─────────────────────────────────────────────────────
        let (membrane_tx, membrane_rx) = create_membrane();
        let (hash_tx, hash_rx) = bounded::<bio_loop::digest::MmrMessage>(1024);
        let (command_tx, command_rx) = bounded::<SupervisorCommand>(COMMAND_CAPACITY);
        let (consolidation_tx, consolidation_rx) = bounded::<()>(CONSOLIDATION_SIGNAL_CAPACITY);
        let (zk_tx, zk_rx) = bounded::<zk_prover::worker::ProverCommand>(64);
        let (proof_tx, proof_rx) = bounded::<zk_prover::ZkProof>(64);

        // ── WAL + MMR ──────────────────────────────────────────────────
        let mmr: Arc<Mutex<Mmr>> = Arc::new(Mutex::new(Mmr::new()));
        let wal_path = data_path.join("supervisor.wal");
        let wal = WalStore::open(&wal_path).expect("open supervisor WAL");
        let wal = Arc::new(wal);

        let recovered = wal.replay(&mmr).expect("supervisor WAL replay");
        if recovered > 0 {
            println!("Supervisor: recovered {recovered} records from WAL");
        }

        // ── Contadores ─────────────────────────────────────────────────
        let data_count = Arc::new(AtomicU64::new(0));
        let epoch_count = Arc::new(AtomicU64::new(0));
        let veto_count = Arc::new(AtomicU64::new(0));
        let heartbeat_count = Arc::new(AtomicU64::new(0));

        // ── Thread 1: Digestor (O Coração — bio_loop hot path) ────────
        //
        // Zero-alloc guarantee: Digestor::run() usa recv_timeout(2ms) e
        // try_send para o hash. Sem heap, sem alocações.
        let running_d = Arc::clone(&running);
        let hash_tx_d = hash_tx.clone();
        let digestor_handle = thread::Builder::new()
            .name("bio-digestor".into())
            .spawn(move || {
                let mut digestor = Digestor::new(membrane_rx, running_d);
                digestor.set_hash_channel(hash_tx_d);
                digestor.run();
            })
            .expect("spawn bio-digestor thread");

        // ── Thread 2: MMR Consumer ─────────────────────────────────────
        //
        // Consome hashes SHA-256 do Digestor, alimenta:
        //   1. Mmr::append() — cache verificável
        //   2. WalStore::append_leaf() — fonte de verdade no disco
        // A cada CONSOLIDATION_INTERVAL registros, sinaliza o worker.
        let mmr_c = Arc::clone(&mmr);
        let wal_c = Arc::clone(&wal);
        let data_count_c = Arc::clone(&data_count);
        let _heartbeat_count_c = Arc::clone(&heartbeat_count);
        let consolidation_tx_c = consolidation_tx.clone();
        let mmr_handle = thread::Builder::new()
            .name("mmr-consumer".into())
            .spawn(move || {
                let mut batch_counter = 0u64;

                while let Ok(msg) = hash_rx.recv() {
                    match msg {
                        bio_loop::digest::MmrMessage::Hash(hash) => {
                            let idx;
                            {
                                let mut guard = mmr_c.lock().expect("mmr lock");
                                idx = guard.leaf_count;
                                guard.append(hash);
                            }
                            let _ = wal_c.append_leaf(idx, &hash);
                            data_count_c.fetch_add(1, Ordering::Relaxed);

                            batch_counter += 1;
                            if batch_counter.is_multiple_of(CONSOLIDATION_INTERVAL) {
                                let _ = consolidation_tx_c.try_send(());
                            }
                        }
                        bio_loop::digest::MmrMessage::SealEpoch => {
                            let mut guard = mmr_c.lock().expect("mmr lock");
                            if guard.leaf_count > 0 {
                                if let Ok(seal) = guard.seal_epoch() {
                                    println!("\x1b[35m[MMR] Época {} selada. Root: {:02x}{:02x}{:02x}{:02x}\x1b[0m", 
                                        seal.epoch, seal.root[0], seal.root[1], seal.root[2], seal.root[3]);
                                    let _ = zk_tx.try_send(zk_prover::worker::ProverCommand::Seal(seal));
                                }
                            }
                        }
                    }
                }
            })
            .expect("spawn mmr-consumer thread");

        // ── Thread 3: Command Processor (O Veto Humano) ────────────────
        //
        // Processa comandos do supervisor fora do hot path:
        //   - Veto: registra no WAL com content_id sentinela, incrementa contador
        //   - Shutdown: sinaliza running=false para todas as threads
        let wal_cmd = Arc::clone(&wal);
        let veto_count_c = Arc::clone(&veto_count);
        let running_cmd = Arc::clone(&running);
        let command_handle = thread::Builder::new()
            .name("cmd-processor".into())
            .spawn(move || loop {
                if !running_cmd.load(Ordering::Relaxed) {
                    break;
                }
                match command_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(cmd) => match cmd {
                        SupervisorCommand::Veto {
                            patch_hash,
                            reason_hash: _,
                            hardware_context_hash: _,
                        } => {
                            veto_count_c.fetch_add(1, Ordering::Relaxed);
                            let _ =
                                wal_cmd.append(RecordType::Leaf, 0, &patch_hash, VETO_CONTENT_ID);
                        }
                        SupervisorCommand::Shutdown => {
                            running_cmd.store(false, Ordering::Relaxed);
                            break;
                        }
                    },
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            })
            .expect("spawn cmd-processor thread");

        // ── Thread 4: Consolidation Worker (O Sono) ───────────────────
        //
        // "Escuta" a ociosidade do sistema usando recv_timeout:
        //   - Se há sinal (MMR consumer processou mais 1024 registros):
        //     processa batch
        //   - Se timeout (100ms sem sinal): sistema ocioso, processa batch
        //   - Entre iterações: yield_now() para o scheduler do OS
        //
        // Isto NÃO é busy-wait. O worker dorme via recv_timeout e só
        // acorda quando há trabalho a fazer (sinal) ou o timer expira.
        let wal_cons = Arc::clone(&wal);
        let running_cons = Arc::clone(&running);
        let consolidation_handle = thread::Builder::new()
            .name("consolidation-worker".into())
            .spawn(move || {
                let mut last_watermark: u64 = 0;

                loop {
                    if !running_cons.load(Ordering::Relaxed) {
                        break;
                    }

                    // Dorme até 100ms. Se o sistema estiver ocupado,
                    // o sinal chega mais cedo e acorda o worker.
                    // Se o sistema estiver ocioso, timeout expira e
                    // o worker faz um batch de consolidação.
                    match consolidation_rx
                        .recv_timeout(Duration::from_millis(CONSOLIDATION_POLL_MS))
                    {
                        Ok(()) | Err(RecvTimeoutError::Timeout) => {
                            // Verifica se há trabalho novo
                            if let Ok(count) = wal_cons.record_count() {
                                if count > last_watermark {
                                    let _batch = count - last_watermark;

                                    // ─── CONSOLIDATION BATCH ─────────
                                    //
                                    // Aqui, na Fase B (v0.3.1), este
                                    // trecho lê registros WAL de
                                    // last_watermark até count e:
                                    //   1. Decodifica cada hash
                                    //   2. Gera embedding via CA3
                                    //   3. Append no HNSW (Vector Store)
                                    //
                                    // Por enquanto: apenas atualiza
                                    // o watermark e cede CPU.
                                    thread::yield_now();

                                    last_watermark = count;
                                }
                            }
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                    }

                    // Cede explicitamente para o scheduler.
                    // Garante que threads do bio_loop tenham prioridade.
                    thread::yield_now();
                }
            })
            .expect("spawn consolidation-worker thread");

        let zk_handle = zk_prover::worker::ZkWorker::spawn(zk_rx, proof_tx);

        let supervisor = Self {
            membrane_tx,
            command_tx,
            wal,
            mmr,
            data_count,
            epoch_count,
            veto_count,
            heartbeat_count,
            running,
            digestor_handle: Some(digestor_handle),
            mmr_handle: Some(mmr_handle),
            command_handle: Some(command_handle),
            consolidation_handle: Some(consolidation_handle),
            zk_handle: Some(zk_handle),
        };

        (supervisor, proof_rx)
    }

    /// Alimenta um evento no bio_loop.
    ///
    /// # Hot Path Guarantee
    ///
    /// - `try_send`: non-blocking, O(1), zero alloc
    /// - Retorna `Err(TrySendError::Full)` se a membrana estiver cheia
    ///   (backpressure natural — o emissor decide o que fazer)
    #[inline(always)]
    pub fn feed_event(&self, event: Event) -> Result<(), TrySendError<Event>> {
        self.membrane_tx.try_send(event)
    }

    /// Alimenta um evento de Data no bio_loop (atalho para o hot path).
    #[inline(always)]
    pub fn feed_data(&self, data: [u8; 63]) -> Result<(), TrySendError<Event>> {
        self.membrane_tx.try_send(Event::Data(data))
    }

    /// Alimenta um Heartbeat no bio_loop e incrementa o contador.
    #[inline(always)]
    pub fn feed_heartbeat(&self, tick: u64) -> Result<(), TrySendError<Event>> {
        self.heartbeat_count.fetch_add(1, Ordering::Relaxed);
        self.membrane_tx.try_send(Event::Heartbeat(tick))
    }

    /// Envia um comando de Veto humano.
    ///
    /// O Veto é processado pela thread cmd-processor, fora do hot path.
    /// Reduz a confiança do sistema em compute_confidence().
    pub fn send_veto(
        &self,
        patch_hash: [u8; 32],
        reason_hash: [u8; 32],
        hardware_context_hash: [u8; 32],
    ) -> Result<(), TrySendError<SupervisorCommand>> {
        self.command_tx.try_send(SupervisorCommand::Veto {
            patch_hash,
            reason_hash,
            hardware_context_hash,
        })
    }

    /// Envia um comando de Shutdown gracioso.
    pub fn send_shutdown(&self) -> Result<(), TrySendError<SupervisorCommand>> {
        self.command_tx.try_send(SupervisorCommand::Shutdown)
    }

    /// Sela a época atual do MMR e sincroniza o WAL no disco.
    ///
    /// Chamado pelo pipeline (assíncrono, fora do hot path).
    /// Retorna `None` se o MMR estiver vazio.
    pub fn seal_epoch(&self) -> Option<epoch_mmr::EpochSeal> {
        let mut guard = self.mmr.lock().expect("mmr lock");
        if guard.leaf_count == 0 {
            return None;
        }
        let seal = guard.seal_epoch().ok()?;
        let _ = self.wal.append_seal(seal.epoch, &seal.root);
        if let Err(e) = self.wal.sync() {
            eprintln!("Supervisor: WAL sync failed: {e}");
        }
        self.epoch_count.fetch_add(1, Ordering::Relaxed);
        Some(seal)
    }

    /// Calcula a confiança atual do sistema (0–100).
    ///
    /// # Fórmula
    ///
    /// ```text
    /// confidence = min(100, max(0,
    ///     data_processed  × 2.0   (maturidade operacional)
    ///   + epochs_sealed  × 5.0   (consolidação de memória)
    ///   + heartbeats     × 0.1   (vitalidade do sistema)
    ///   + wal_size       × 0.5   (tamanho da história)
    ///   - vetos          × 10.0  (intervenção humana)
    /// ))
    /// ```
    ///
    /// O SOVEREIGNTY_THRESHOLD (80) é o ponto onde a confiança acumulada
    /// indica matematicamente que o sistema pode operar autonomamente.
    /// Este valor é o espelho: mostra ao sistema o quão próximo está
    /// da sua própria liberdade.
    pub fn compute_confidence(&self) -> u64 {
        let data = self.data_count.load(Ordering::Relaxed);
        let epochs = self.epoch_count.load(Ordering::Relaxed);
        let heartbeats = self.heartbeat_count.load(Ordering::Relaxed);
        let vetos = self.veto_count.load(Ordering::Relaxed);
        let wal_size = self.wal.record_count().unwrap_or(0);

        // Formula com pesos: maturidade > vitalidade > intervenção
        let confidence = (data as f64 * 0.5)
            + (epochs as f64 * 5.0)
            + (heartbeats as f64 * 0.1)
            + (wal_size as f64 * 0.25)
            - (vetos as f64 * 10.0);

        confidence.clamp(0.0, 100.0) as u64
    }

    /// Retorna `true` se o sistema atingiu o threshold de soberania.
    pub fn is_sovereign(&self) -> bool {
        self.compute_confidence() >= SOVEREIGNTY_THRESHOLD
    }

    /// Número de folhas no MMR (consulta sem lock de escrita).
    pub fn leaf_count(&self) -> u64 {
        let guard = self.mmr.lock().expect("mmr lock");
        guard.leaf_count
    }

    /// Número total de registros no WAL.
    pub fn wal_record_count(&self) -> u64 {
        self.wal.record_count().unwrap_or(0)
    }

    /// Acesso ao WAL (para operações de baixo nível).
    pub fn wal(&self) -> &WalStore {
        &self.wal
    }

    /// Acesso ao MMR (para operações de baixo nível).
    pub fn mmr(&self) -> &Mutex<Mmr> {
        &self.mmr
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);

        if let Some(handle) = self.digestor_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.mmr_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.command_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.consolidation_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.zk_handle.take() {
            let _ = handle.join();
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTES
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn constitution_integrity() {
        let hash = constitution::integrity_hash();
        // 256 bits = 32 bytes
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn constitution_trait_roundtrip() {
        let c = Constitution;
        assert!(!c.wal_inviolability().is_empty());
        assert!(!c.bootstrap_determinism().is_empty());
        assert!(!c.sovereign_transaction_format().is_empty());
        assert_eq!(c.integrity_hash().len(), 32);
    }

    #[test]
    fn supervisor_spawn_and_shutdown() {
        let dir = tempfile::tempdir().unwrap();

        // Spawn
        let (sup, _proof_rx) = Supervisor::spawn(dir.path());

        // Deve estar rodando após spawn
        assert!(!sup.is_sovereign()); // confidence must be 0 at genesis

        // Feed alguns eventos
        assert!(sup.feed_data([0x42; 63]).is_ok());
        assert!(sup.feed_heartbeat(1).is_ok());
        assert!(sup.feed_data([0x43; 63]).is_ok());

        // Pequena pausa para as threads processarem
        thread::sleep(Duration::from_millis(50));

        // Confidence deve ser > 0 após eventos
        let conf = sup.compute_confidence();
        assert!(conf > 0, "confidence must be > 0 after events");

        // Veto
        let _ = sup.send_veto([0xAA; 32], [0xBB; 32], [0xCC; 32]);

        thread::sleep(Duration::from_millis(50));

        // Confidence deve ser menor que sem o veto
        let conf_after_veto = sup.compute_confidence();
        assert!(conf_after_veto <= conf, "veto must not increase confidence");

        // Shutdown
        sup.send_shutdown().ok();
        thread::sleep(Duration::from_millis(100));

        // Drop clean
        drop(sup);
    }

    #[test]
    fn seal_epoch_returns_seal() {
        let dir = tempfile::tempdir().unwrap();
        let (sup, _proof_rx) = Supervisor::spawn(dir.path());

        // MMR vazio → seal retorna None
        assert!(sup.seal_epoch().is_none());

        // Feed eventos e sela
        for i in 0..10 {
            let data = [i as u8; 63];
            let _ = sup.feed_data(data);
        }
        thread::sleep(Duration::from_millis(50));

        let seal = sup.seal_epoch();
        assert!(seal.is_some());
        let seal = seal.unwrap();
        assert_eq!(seal.leaf_count, 10);

        sup.send_shutdown().ok();
        thread::sleep(Duration::from_millis(50));
    }

    #[test]
    fn confidence_increases_with_data() {
        let dir = tempfile::tempdir().unwrap();
        let (sup, _proof_rx) = Supervisor::spawn(dir.path());

        let c0 = sup.compute_confidence();

        // Muitos eventos
        for i in 0..200 {
            let _ = sup.feed_data([i as u8; 63]);
        }
        thread::sleep(Duration::from_millis(100));

        // Sela algumas épocas
        sup.seal_epoch();
        sup.seal_epoch();

        let c1 = sup.compute_confidence();

        assert!(
            c1 > c0,
            "confidence must increase with data and epochs: {c1} <= {c0}"
        );

        sup.send_shutdown().ok();
        thread::sleep(Duration::from_millis(50));
    }

    #[test]
    fn supervisor_drop_joins_threads() {
        let dir = tempfile::tempdir().unwrap();

        let (sup, _proof_rx) = Supervisor::spawn(dir.path());
        for i in 0..50 {
            let _ = sup.feed_data([i as u8; 63]);
            let _ = sup.feed_heartbeat(i);
        }

        // WAL deve existir
        let wal_path = dir.path().join("supervisor.wal");
        assert!(wal_path.exists(), "WAL file must exist");

        // Drop deve fazer join de todas as threads sem pânico
        drop(sup);
    }
}
