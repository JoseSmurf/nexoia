use crossbeam_channel::{Receiver, RecvTimeoutError};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::Event;

// ─── Constantes da Membrana ───────────────────────────────────────────────────

/// Capacidade máxima do canal bounded (Membrana).
/// 1024 slots × 64 bytes/evento = 64 KB de buffer máximo — cabe no L2 cache.
pub const MEMBRANE_CAPACITY: usize = 1_024;

/// Limiar alto: ao atingir 80% de ocupação, entra em modo de supressão.
/// Escolhido para dar margem de reação antes de transbordar.
pub const HYSTERESIS_HIGH: usize = (MEMBRANE_CAPACITY * 80) / 100; // 819

/// Limiar baixo: só sai de supressão quando cai para 20%.
/// A assimetria HIGH/LOW é a histerese em si: evita o "flapping"
/// (entrar/sair de supressão a cada evento) que desperdiçaria ciclos.
pub const HYSTERESIS_LOW: usize = (MEMBRANE_CAPACITY * 20) / 100; // 204

/// Timeout de espera por evento quando o canal está vazio.
/// Mantém o Digestor responsivo a `running = false` sem busy-spin.
const RECV_TIMEOUT: Duration = Duration::from_millis(2);

// ─── Métricas ─────────────────────────────────────────────────────────────────

/// Métricas do Digestor expostas atomicamente para monitoramento externo
/// (sem lock, sem alocação de heap para a leitura).
pub struct DigestorMetrics {
    /// Total de eventos processados com sucesso
    pub processed: Arc<AtomicU64>,
    /// Total de eventos descartados por backpressure (supressão ativa)
    pub dropped: Arc<AtomicU64>,
    /// Quantidade de vezes que o sistema entrou em modo de supressão
    pub suppressions: Arc<AtomicU64>,
}

impl DigestorMetrics {
    fn new() -> Self {
        Self {
            processed: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
            suppressions: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Snapshot instantâneo das métricas (sem bloqueio).
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.processed.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
            self.suppressions.load(Ordering::Relaxed),
        )
    }
}

// ─── Digestor ─────────────────────────────────────────────────────────────────

/// Loop de digestão com histerese e backpressure explícito.
///
/// # Invariantes de Zero-Allocation no Hot Path
///
/// 1. O `Sha256` hasher é inicializado UMA vez e reutilizado via
///    `finalize_reset()` — que limpa o estado interno sem realocar.
/// 2. O buffer de saída `hash_out: [u8; 32]` vive na stack de `run()`.
/// 3. O match em `digest_event` usa referências — sem clone, sem Box.
/// 4. `recv_timeout` de crossbeam retorna o `Event` por valor (cópia),
///    que é imediatamente consumido. O canal copia via `memcpy` do slot
///    interno — sem heap.
pub enum MmrMessage {
    Hash([u8; 32]),
    SealEpoch,
}

pub struct Digestor {
    rx: Receiver<Event>,
    running: Arc<AtomicBool>,
    pub metrics: DigestorMetrics,
    /// Canal para envio assíncrono dos hashes processados (opcional)
    pub hash_tx: Option<crossbeam_channel::Sender<MmrMessage>>,
}

impl Digestor {
    pub fn new(rx: Receiver<Event>, running: Arc<AtomicBool>) -> Self {
        Self {
            rx,
            running,
            metrics: DigestorMetrics::new(),
            hash_tx: None,
        }
    }

    /// Conecta um canal de saída de hashes ao Digestor.
    /// Cada `Event::Data` processado terá seu SHA-256 enviado por `try_send`
    /// neste canal — zero alocação, zero blocking.
    pub fn set_hash_channel(&mut self, tx: crossbeam_channel::Sender<MmrMessage>) {
        self.hash_tx = Some(tx);
    }

    /// Executa o loop principal de digestão. Bloqueia a thread chamadora.
    ///
    /// Para encerrar: `running.store(false, Ordering::Relaxed)` em outra thread.
    /// O loop percebe na próxima iteração (dentro de `RECV_TIMEOUT`).
    pub fn run(&mut self) {
        // ── Buffers de stack — alocados UMA vez aqui, nunca no hot path ──────
        let mut hasher = Sha256::new();
        let mut hash_out = [0u8; 32];
        // ─────────────────────────────────────────────────────────────────────

        // Estado local de histerese (sem necessidade de atomic — thread-local)
        let mut suppressed = false;

        while self.running.load(Ordering::Relaxed) {
            // ── 1. AVALIAÇÃO DE HISTERESE ─────────────────────────────────
            // `rx.len()` é O(1) e lock-free em crossbeam bounded channels.
            let backlog = self.rx.len();

            if suppressed {
                // Sai da supressão apenas quando a pressão cair bastante.
                // A assimetria (LOW << HIGH) é intencional: evita flapping.
                if backlog < HYSTERESIS_LOW {
                    suppressed = false;
                }
            } else if backlog >= HYSTERESIS_HIGH {
                suppressed = true;
                self.metrics.suppressions.fetch_add(1, Ordering::Relaxed);
            }

            // ── 2. RECEPÇÃO DO EVENTO ─────────────────────────────────────
            let event = match self.rx.recv_timeout(RECV_TIMEOUT) {
                Ok(ev) => ev,
                Err(RecvTimeoutError::Timeout) => continue, // canal vazio — ok
                Err(RecvTimeoutError::Disconnected) => break, // todos os Senders foram dropados
            };

            // ── 3. BACKPRESSURE EXPLÍCITO ─────────────────────────────────
            if suppressed {
                // Descarta o payload sem processá-lo.
                // IMPORTANTE: ainda recebemos do canal (linha acima) para DRENÁ-LO
                // e liberar espaço para os produtores. Sem isso, o canal
                // ficaria permanentemente cheio e os Senders jamais conseguiriam
                // injetar dados — deadlock lógico.
                self.metrics.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            // ── 4. DIGESTÃO ───────────────────────────────────────────────
            self.digest_event(event, &mut hasher, &mut hash_out);
        }
    }

    /// Processa um único evento.
    ///
    /// # Zero-Allocation Guarantee
    /// - `hasher` é passado por `&mut` — zero realloc. `finalize_reset()` limpa
    ///   o estado interno sem desalocar o buffer SHA interno (otimização sha2).
    /// - `out` é um `&mut [u8; 32]` na stack de `run()`.
    /// - Nenhum branch aloca heap.
    #[inline(always)]
    fn digest_event(&self, event: Event, hasher: &mut Sha256, out: &mut [u8; 32]) {
        match event {
            Event::Data(payload) => {
                // Alimenta o hasher com os 63 bytes fixos do payload.
                // `update` aceita qualquer `AsRef<[u8]>` — sem cópia extra.
                hasher.update(payload);

                // `finalize_reset` retorna um `GenericArray<u8, U32>` e
                // imediatamente reseta o estado interno do hasher.
                // A próxima chamada a `update` começa com SHA do zero.
                let result = hasher.finalize_reset();
                out.copy_from_slice(result.as_slice());

                // Apenas Data conta como processado (heartbeat e shutdown são infra)
                self.metrics.processed.fetch_add(1, Ordering::Relaxed);
                let count = self.metrics.processed.load(Ordering::Relaxed);
                println!(
                    "\x1b[36m[BIO] mastigado evento #{count}: SHA={:02x}{:02x}{:02x}{:02x}\x1b[0m",
                    out[0], out[1], out[2], out[3]
                );

                // `out` agora contém o SHA-256 do payload.
                // Encaminha para o epoch_mmr via hash_tx (se conectado).
                // `try_send` é non-blocking e zero-alloc — crossbeam copia
                // os 32 bytes por memcpy. Se o canal estourar, o hash é
                // dropped (backpressure natural).
                if let Some(ref tx) = self.hash_tx {
                    let _ = tx.try_send(MmrMessage::Hash(*out));
                }
            }

            Event::Heartbeat(tick) => {
                // Tick recebido do Coração — aciona tarefas periódicas.
                // Loop 2: selar época no epoch_mmr a cada 10 ticks (10s)
                if tick % 10 == 0 {
                    if let Some(ref tx) = self.hash_tx {
                        let _ = tx.try_send(MmrMessage::SealEpoch);
                    }
                }
            }

            Event::Shutdown => {
                // Encerramento gracioso: notifica o running flag.
                // O loop em `run()` verifica na próxima iteração.
                self.running.store(false, Ordering::Relaxed);
            }
        }
    }
}

// ─── Testes ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_membrane, Event};
    use std::sync::{atomic::AtomicBool, Arc};
    #[test]
    fn processes_data_events_without_panic() {
        let running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = create_membrane();
        let mut digestor = Digestor::new(rx, Arc::clone(&running));

        tx.send(Event::Data([0xAB; 63])).unwrap();
        tx.send(Event::Shutdown).unwrap();

        // O digestor deve encerrar ao receber Shutdown
        digestor.run();

        let (processed, dropped, _) = digestor.metrics.snapshot();
        assert_eq!(processed, 1, "deve ter processado o evento Data");
        assert_eq!(dropped, 0, "nenhum evento descartado");
    }

    #[test]
    fn hysteresis_drops_events_under_pressure() {
        let running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = create_membrane();
        let mut digestor = Digestor::new(rx, Arc::clone(&running));

        // Enche o canal além do HIGH_WATERMARK
        let fill_count = HYSTERESIS_HIGH + 10;
        for _ in 0..fill_count {
            // ignore erros de canal cheio
            let _ = tx.try_send(Event::Data([0x00; 63]));
        }

        // Envia shutdown para encerrar
        tx.send(Event::Shutdown).unwrap();
        digestor.run();

        let (_, dropped, suppressions) = digestor.metrics.snapshot();
        assert!(
            suppressions >= 1,
            "deve ter entrado em supressão ao menos uma vez"
        );
        // Em supressão, eventos são descartados
        assert!(
            dropped > 0,
            "eventos devem ter sido descartados sob pressão"
        );
    }

    #[test]
    fn heartbeat_does_not_increment_processed_counter() {
        let running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = create_membrane();
        let mut digestor = Digestor::new(rx, Arc::clone(&running));

        tx.send(Event::Heartbeat(42)).unwrap();
        tx.send(Event::Shutdown).unwrap();
        digestor.run();

        // Heartbeat e Shutdown não são contabilizados como "processados"
        // (apenas eventos Data geram hashes e avançam o estado do epoch_mmr)
        let (processed, _, _) = digestor.metrics.snapshot();
        assert_eq!(processed, 0);
    }
}
