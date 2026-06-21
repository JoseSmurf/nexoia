//! defense.rs — Camada de defesa do NEXOIA (Enterprise-Grade)
//!
//! Arquitetura Concorrente de Alta Performance:
//! Utiliza Sharded Locks (Striped Locking) e operações atômicas (wait-free)
//! para eliminar contenção de Mutex no caminho crítico (hot path). Projetado
//! para escalar linearmente com o número de threads do processador.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Validação de entrada
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    EmptyInput,
    ExceedsMaxSize { limit: usize, actual: usize },
    InvalidEncoding,
    SuspiciousPattern(String),
    MalformedStructure(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::EmptyInput => write!(f, "entrada vazia rejeitada"),
            ValidationError::ExceedsMaxSize { limit, actual } => {
                write!(
                    f,
                    "entrada excede limite: {} bytes (máximo: {})",
                    actual, limit
                )
            }
            ValidationError::InvalidEncoding => write!(f, "encoding inválido — esperado UTF-8"),
            ValidationError::SuspiciousPattern(p) => {
                write!(f, "padrão suspeito detectado: {}", p)
            }
            ValidationError::MalformedStructure(s) => write!(f, "estrutura malformada: {}", s),
        }
    }
}

impl std::error::Error for ValidationError {}

pub struct InputLimits {
    pub max_state_json_bytes: usize,
    pub max_records_per_batch: usize,
}

impl Default for InputLimits {
    fn default() -> Self {
        InputLimits {
            max_state_json_bytes: 1_048_576,
            max_records_per_batch: 10_000,
        }
    }
}

pub fn validate_raw_input(input: &str, max_bytes: usize) -> Result<(), ValidationError> {
    if input.is_empty() {
        return Err(ValidationError::EmptyInput);
    }
    if input.len() > max_bytes {
        return Err(ValidationError::ExceedsMaxSize {
            limit: max_bytes,
            actual: input.len(),
        });
    }
    if input.contains('\0') {
        return Err(ValidationError::SuspiciousPattern(
            "null byte encontrado".to_string(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Observabilidade Atômica (Wait-Free)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct DefenseStats {
    pub accepted: u64,
    pub rejected_rate_limit: u64,
    pub rejected_sources_limit: u64,
    pub rejected_source_key_too_long: u64,
    pub cleanup_runs: u64,
    pub sources_removed: u64,
}

struct AtomicStats {
    accepted: AtomicU64,
    rejected_rate_limit: AtomicU64,
    rejected_sources_limit: AtomicU64,
    rejected_source_key_too_long: AtomicU64,
    cleanup_runs: AtomicU64,
    sources_removed: AtomicU64,
}

impl AtomicStats {
    fn new() -> Self {
        Self {
            accepted: AtomicU64::new(0),
            rejected_rate_limit: AtomicU64::new(0),
            rejected_sources_limit: AtomicU64::new(0),
            rejected_source_key_too_long: AtomicU64::new(0),
            cleanup_runs: AtomicU64::new(0),
            sources_removed: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> DefenseStats {
        DefenseStats {
            accepted: self.accepted.load(Ordering::Relaxed),
            rejected_rate_limit: self.rejected_rate_limit.load(Ordering::Relaxed),
            rejected_sources_limit: self.rejected_sources_limit.load(Ordering::Relaxed),
            rejected_source_key_too_long: self
                .rejected_source_key_too_long
                .load(Ordering::Relaxed),
            cleanup_runs: self.cleanup_runs.load(Ordering::Relaxed),
            sources_removed: self.sources_removed.load(Ordering::Relaxed),
        }
    }
}

// ---------------------------------------------------------------------------
// Rate Limiting (Sharded & Lock-Free Global Counters)
// ---------------------------------------------------------------------------

const NUM_SHARDS: usize = 64;

struct Shard {
    history: HashMap<String, VecDeque<Instant>>,
}

struct SourceReservation<'a> {
    active_sources: &'a AtomicUsize,
    committed: bool,
}

impl<'a> SourceReservation<'a> {
    fn commit(mut self) {
        self.committed = true;
    }
}

impl<'a> Drop for SourceReservation<'a> {
    fn drop(&mut self) {
        if !self.committed {
            self.active_sources.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

fn trim_expired(timestamps: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while let Some(&front) = timestamps.front() {
        if now.duration_since(front) >= window {
            timestamps.pop_front();
        } else {
            break;
        }
    }
}

pub struct RateLimiter {
    shards: Arc<[Mutex<Shard>; NUM_SHARDS]>,
    stats: Arc<AtomicStats>,
    active_sources: Arc<AtomicUsize>,
    hash_builder: RandomState,

    max_requests: usize,
    window: Duration,
    max_sources: usize,
    max_source_key_len: usize,

    shutdown_tx: Sender<()>,
    worker_thread: Option<JoinHandle<()>>,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        let shards: [Mutex<Shard>; NUM_SHARDS] =
            std::array::from_fn(|_| Mutex::new(Shard { history: HashMap::new() }));
        let shards = Arc::new(shards);

        let stats = Arc::new(AtomicStats::new());
        let active_sources = Arc::new(AtomicUsize::new(0));

        let (shutdown_tx, shutdown_rx) = mpsc::channel();

        let shards_clone = Arc::clone(&shards);
        let active_sources_clone = Arc::clone(&active_sources);
        let stats_clone = Arc::clone(&stats);

        let worker_thread = thread::spawn(move || {
            let cleanup_interval = Duration::from_secs(60);
            loop {
                match shutdown_rx.recv_timeout(cleanup_interval) {
                    Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        let now = Instant::now();
                        let mut total_removed = 0usize;

                        for shard_mutex in shards_clone.iter() {
                            let mut shard = match shard_mutex.lock() {
                                Ok(guard) => guard,
                                Err(poisoned) => poisoned.into_inner(),
                            };
                            let sources_before = shard.history.len();
                            shard.history.retain(|_, timestamps| {
                                trim_expired(timestamps, now, window);
                                !timestamps.is_empty()
                            });
                            total_removed += sources_before.saturating_sub(shard.history.len());
                        }

                        if total_removed > 0 {
                            active_sources_clone
                                .fetch_sub(total_removed, Ordering::Relaxed);
                            stats_clone
                                .sources_removed
                                .fetch_add(total_removed as u64, Ordering::Relaxed);
                        }
                        stats_clone.cleanup_runs.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });

        RateLimiter {
            shards,
            stats,
            active_sources,
            hash_builder: RandomState::new(),
            max_requests,
            window,
            max_sources: 100_000,
            max_source_key_len: 128,
            shutdown_tx,
            worker_thread: Some(worker_thread),
        }
    }

    pub fn with_max_sources(mut self, max_sources: usize) -> Self {
        self.max_sources = max_sources.max(1);
        self
    }

    pub fn with_max_source_key_len(mut self, max_len: usize) -> Self {
        self.max_source_key_len = max_len.max(1);
        self
    }

    fn get_shard_index(&self, source_key: &str) -> usize {
        (self.hash_builder.hash_one(source_key) as usize) & (NUM_SHARDS - 1)
    }

    pub fn check(&self, source_key: &str) -> bool {
        if source_key.len() > self.max_source_key_len {
            self.stats
                .rejected_source_key_too_long
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }

        if self.max_requests == 0 {
            self.stats
                .rejected_rate_limit
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let shard_idx = self.get_shard_index(source_key);

        let mut shard = match self.shards[shard_idx].lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let now = Instant::now();

        if let Some(timestamps) = shard.history.get_mut(source_key) {
            trim_expired(timestamps, now, self.window);
            if timestamps.len() >= self.max_requests {
                self.stats
                    .rejected_rate_limit
                    .fetch_add(1, Ordering::Relaxed);
                return false;
            }
            timestamps.push_back(now);
            self.stats.accepted.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        let reserved = self.active_sources.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| {
                if current < self.max_sources {
                    Some(current + 1)
                } else {
                    None
                }
            },
        );

        if reserved.is_err() {
            self.stats
                .rejected_sources_limit
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let reservation = SourceReservation {
            active_sources: &self.active_sources,
            committed: false,
        };

        let mut timestamps = VecDeque::with_capacity(self.max_requests.min(16));
        timestamps.push_back(now);
        shard
            .history
            .insert(source_key.to_string(), timestamps);
        reservation.commit();

        self.stats.accepted.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn stats(&self) -> DefenseStats {
        self.stats.snapshot()
    }

    pub fn remaining(&self, source_key: &str) -> usize {
        let shard_idx = self.get_shard_index(source_key);

        let shard = match self.shards[shard_idx].lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        match shard.history.get(source_key) {
            Some(timestamps) => {
                let now = Instant::now();
                let expired_count = timestamps
                    .partition_point(|&t| now.duration_since(t) >= self.window);
                let active = timestamps.len() - expired_count;
                self.max_requests.saturating_sub(active)
            }
            None => self.max_requests,
        }
    }

    pub fn tracked_sources(&self) -> usize {
        self.active_sources.load(Ordering::Relaxed)
    }
}

impl Drop for RateLimiter {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(());
        if let Some(handle) = self.worker_thread.take() {
            let _ = handle.join();
        }
    }
}
