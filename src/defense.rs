//! defense.rs — Camada de defesa do NEXOIA

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    EmptyInput,
    ExceedsMaxSize { limit: usize, actual: usize },
    SuspiciousPattern(String),
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
            ValidationError::SuspiciousPattern(p) => {
                write!(f, "padrão suspeito detectado: {}", p)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

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
    active_sources: Arc<AtomicUsize>,
    hash_builder: RandomState,
    max_requests: usize,
    window: Duration,
    max_sources: usize,
    max_source_key_len: usize,
    shutdown_tx: Sender<()>,
    _worker_thread: Option<JoinHandle<()>>,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        let shards: [Mutex<Shard>; NUM_SHARDS] = std::array::from_fn(|_| {
            Mutex::new(Shard {
                history: HashMap::new(),
            })
        });
        let shards = Arc::new(shards);

        let active_sources = Arc::new(AtomicUsize::new(0));

        let (shutdown_tx, shutdown_rx) = mpsc::channel();

        let shards_clone = Arc::clone(&shards);
        let active_sources_clone = Arc::clone(&active_sources);

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
                            active_sources_clone.fetch_sub(total_removed, Ordering::Relaxed);
                        }
                    }
                }
            }
        });

        RateLimiter {
            shards,
            active_sources,
            hash_builder: RandomState::new(),
            max_requests,
            window,
            max_sources: 100_000,
            max_source_key_len: 128,
            shutdown_tx,
            _worker_thread: Some(worker_thread),
        }
    }

    fn get_shard_index(&self, source_key: &str) -> usize {
        (self.hash_builder.hash_one(source_key) as usize) & (NUM_SHARDS - 1)
    }

    pub fn check(&self, source_key: &str) -> bool {
        if source_key.len() > self.max_source_key_len {
            return false;
        }

        if self.max_requests == 0 {
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
                return false;
            }
            timestamps.push_back(now);
            return true;
        }

        let reserved =
            self.active_sources
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    if current < self.max_sources {
                        Some(current + 1)
                    } else {
                        None
                    }
                });

        if reserved.is_err() {
            return false;
        }

        let reservation = SourceReservation {
            active_sources: &self.active_sources,
            committed: false,
        };

        let mut timestamps = VecDeque::with_capacity(self.max_requests.min(16));
        timestamps.push_back(now);
        shard.history.insert(source_key.to_string(), timestamps);
        reservation.commit();

        true
    }
}

impl Drop for RateLimiter {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_empty_input() {
        assert!(validate_raw_input("", 1000).is_err());
    }

    #[test]
    fn validate_oversized_input() {
        let big = "x".repeat(2000);
        assert!(validate_raw_input(&big, 1000).is_err());
    }

    #[test]
    fn validate_null_bytes() {
        assert!(validate_raw_input("hello\x00world", 1000).is_err());
    }

    #[test]
    fn validate_valid_input() {
        assert!(validate_raw_input("hello", 1000).is_ok());
    }

    #[test]
    fn rate_limiter_blocks_after_limit() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.check("source_a"));
        assert!(limiter.check("source_a"));
        assert!(!limiter.check("source_a"));
    }

    #[test]
    fn rate_limiter_allows_different_sources() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check("source_a"));
        assert!(limiter.check("source_b"));
        assert!(!limiter.check("source_a"));
    }
}
