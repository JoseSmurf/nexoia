// NexoIA resource limits
// Changing these values affects memory usage and DoS resistance.
// All limits are enforced at insertion time with eviction or rejection.

/// Maximum simultaneous pending handshakes.
/// Excess entries are rejected. Protects against handshake flood.
pub const MAX_PENDING_HANDSHAKES: usize = 1_024;

/// Maximum known peers in the peer list.
/// Excess entries evict the peer with lowest reputation score.
pub const MAX_PEERS: usize = 512;

/// Maximum active sessions in SessionManager.
/// Excess entries evict the session whose peer has the lowest
/// reputation score. If reputation is tied, evict oldest by timestamp.
pub const MAX_SESSIONS: usize = 4_096;

/// Maximum entries in ReputationStore.
/// Excess entries evict the entry with lowest success_count.
pub const MAX_REPUTATION_ENTRIES: usize = 10_000;

/// Maximum EPAs held in memory.
/// Excess entries evict oldest by received_at timestamp.
pub const MAX_EPA_ENTRIES: usize = 10_000;
