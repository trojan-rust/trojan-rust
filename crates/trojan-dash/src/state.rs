//! State shared by every handler.

use std::sync::Arc;

use sea_orm::DatabaseConnection;

use crate::cache::Caches;
use crate::config::DashConfig;

/// Handles and settings the handlers need. Cheap to clone — the connection
/// and the caches are reference-counted internally.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Connection to the dashboard database.
    pub db: DatabaseConnection,
    /// The read paths nodes hammer.
    pub cache: Caches,
    /// SHA-224 of the admin token. Only the digest is kept, and it is compared
    /// in constant time, so neither the token nor its length is recoverable
    /// from timing.
    pub admin_digest: Arc<String>,
    /// Settings the handlers consult.
    pub cfg: Arc<DashConfig>,
}
