//! State shared by every handler.

use std::sync::Arc;

use sqlx::SqlitePool;

/// Handles and settings the handlers need. Cheap to clone — the pool is
/// reference-counted internally.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Connection pool for the dashboard database.
    pub pool: SqlitePool,
    /// SHA-224 of the admin token. Only the digest is kept, and it is compared
    /// in constant time, so neither the token nor its length is recoverable
    /// from timing.
    pub admin_digest: Arc<String>,
    /// Minimum seconds between `last_seen` writes for a node.
    pub node_last_seen_ttl: u64,
}
