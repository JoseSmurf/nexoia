// NexoIA resource limits
// Changing these values affects memory usage and DoS resistance.
// All limits are enforced at insertion time with eviction or rejection.

/// Maximum simultaneous pending handshakes.
/// Excess entries are rejected. Protects against handshake flood.
pub const MAX_PENDING_HANDSHAKES: usize = 1_024;

/// Maximum known peers in the peer list.
/// PeerList evicts the oldest peer (FIFO by insertion order).
/// TrustedPeerList evicts the peer with the oldest `authenticated_at` timestamp.
/// No reputation reference is available inside these data structures
/// without cross-module coupling to ReputationStore.
pub const MAX_PEERS: usize = 512;

/// Maximum active sessions in SessionManager.
/// Evicts the session with the oldest `last_activity` timestamp (LRU).
/// Reputation-based eviction was deferred — SessionState is keyed by
/// SocketAddr (not node_id) and holds no reputation field.
pub const MAX_SESSIONS: usize = 4_096;

/// Maximum entries in ReputationStore.
/// Excess entries evict the entry with lowest success_count.
pub const MAX_REPUTATION_ENTRIES: usize = 10_000;

/// Maximum EPAs held in memory.
/// Excess entries evict oldest by received_at timestamp.
pub const MAX_EPA_ENTRIES: usize = 10_000;

/// Maximum distinct source keys tracked by the rate limiter.
/// Protects the source table from unbounded growth under sustained flood.
pub const MAX_RATE_LIMIT_SOURCES: usize = 100_000;

/// Maximum byte length of a single rate-limiter source key.
/// Rejects oversized keys to prevent hash-map memory abuse.
pub const MAX_RATE_LIMIT_KEY_LEN: usize = 128;
