// provenance_bridge.rs — Ponte entre o motor de proveniência e o pipeline legado
//
// # Arquitetura
//
// ```
//                  ┌──────────────────┐
//                  │  Membrane tx     │──── Event::Data([u8;63]) ──→  Digestor (std::thread)
//                  │  (crossbeam tx)  │                                    │
//                  └──────────────────┘                                    │ SHA-256
//                                                                          ▼
//                  ┌──────────────────┐                              [u8; 32]
//                  │  hash_tx         │──── try_send ──────────────→  Mmr::append()
//                  │  (crossbeam tx)  │                                    │
//                  └──────────────────┘                                    │ periodic seal
//                                                                          ▼
//                                                                   EpochSeal { root }
//                                                                          │
//                  ┌──────────────────────────────────────────────────────┘
//                  ▼
//          pipeline::run_pipeline(state, &bridge)
//                  │
//                  ▼
//          Manifest { epoch_root, ... }
//                  │
//                  ▼
//          SharedEPA::create(...)
// ```
//
// # Garantias
// - Zero-alocação no hot path: o hash cruza o canal como `[u8; 32]` (memcpy).
// - `try_send` é non-blocking: se o canal encher, o hash é dropped (backpressure).
// - O Digestor bloqueia sua thread (`recv_timeout`); o MMR consumer também
//   (`hash_rx.recv()`). Nenhum interfere com o tokio runtime do pipeline.

use bio_loop::digest::Digestor;
use bio_loop::{create_membrane, Event};
use crossbeam_channel::{bounded, Sender};
use epoch_mmr::Mmr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// Resultado de uma selagem de época.
#[derive(Debug, Clone, Copy)]
pub struct EpochSeal {
    pub epoch: u64,
    pub root: [u8; 32],
    pub leaf_count: u64,
}

/// Ponte entre bio_loop + epoch_mmr e o pipeline legado.
pub struct ProvenanceBridge {
    /// Sender da Membrana — qualquer thread pode injetar `Event::Data`
    /// para ser digerido e hasheado.
    #[allow(dead_code)]
    pub membrane_tx: Sender<Event>,
    /// Handle da thread do Digestor (join em shutdown).
    digestor_handle: Option<thread::JoinHandle<()>>,
    /// Handle da thread consumidora do MMR (join em shutdown).
    mmr_handle: Option<thread::JoinHandle<()>>,
    /// Sinalizador de execução — setar `false` encerra o Digestor.
    running: Arc<AtomicBool>,
    /// MMR compartilhado entre a thread consumidora e o pipeline.
    mmr: Arc<Mutex<Mmr>>,
}

impl ProvenanceBridge {
    /// Inicializa a ponte completa:
    /// 1. Cria a Membrana (canal bounded de eventos, capacidade 1024)
    /// 2. Cria o canal de saída de hashes (capacidade 1024)
    /// 3. Spawna o Digestor em background (bloqueante, síncrono)
    /// 4. Spawna o consumidor de hashes → `Mmr::append()` em background
    pub fn spawn() -> Self {
        let running = Arc::new(AtomicBool::new(true));

        // ── Membrana (entrada de eventos) ──
        let (membrane_tx, membrane_rx) = create_membrane();

        // ── Canal de hashes (saída do digestor → MMR) ──
        let (hash_tx, hash_rx) = bounded::<[u8; 32]>(1024);

        // ── MMR compartilhado ──
        let mmr: Arc<Mutex<Mmr>> = Arc::new(Mutex::new(Mmr::new()));

        // ── Thread do Digestor ──
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

        // ── Thread consumidora do MMR ──
        let mmr_c = Arc::clone(&mmr);
        let mmr_handle = thread::Builder::new()
            .name("mmr-consumer".into())
            .spawn(move || {
                // `recv()` bloqueia até chegar hash ou o canal ser desconectado
                // (o que ocorre quando o Digestor é dropado e hash_tx é dropped).
                while let Ok(hash) = hash_rx.recv() {
                    let mut guard = mmr_c.lock().expect("mmr lock");
                    guard.append(hash);
                }
            })
            .expect("spawn mmr-consumer thread");

        Self {
            membrane_tx,
            digestor_handle: Some(digestor_handle),
            mmr_handle: Some(mmr_handle),
            running,
            mmr,
        }
    }

    /// Sela a época atual do MMR e retorna o `EpochSeal`.
    ///
    /// Chamado pelo pipeline antes de criar o EPA para obter a raiz
    /// criptográfica de toda a proveniência desde a última selagem.
    ///
    /// Retorna `None` se o MMR estiver vazio (sem folhas inseridas).
    pub fn seal_current_epoch(&self) -> Option<EpochSeal> {
        let mut guard = self.mmr.lock().expect("mmr lock");
        if guard.leaf_count == 0 {
            return None;
        }
        let seal = guard.seal_epoch().ok()?;
        Some(EpochSeal {
            epoch: seal.epoch,
            root: seal.root,
            leaf_count: seal.leaf_count,
        })
    }

    /// Número de folhas no MMR (consulta sem lock de escrita).
    #[allow(dead_code)]
    pub fn leaf_count(&self) -> u64 {
        let guard = self.mmr.lock().expect("mmr lock");
        guard.leaf_count
    }
}

impl Drop for ProvenanceBridge {
    fn drop(&mut self) {
        // Sinaliza encerramento para o Digestor
        self.running.store(false, Ordering::Relaxed);

        // Ao cair deste escopo, os fields `digestor_handle` e `mmr_handle`
        // são dropped. O Digestor já parou (running = false), e o canal
        // hash_tx foi desconectado (drop do Digestor), então o MMR consumer
        // também encerrou. Os joins apenas esperam a confirmação.
        if let Some(handle) = self.digestor_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.mmr_handle.take() {
            let _ = handle.join();
        }
    }
}
