//! TLS certificate configuration.

use serde::{Deserialize, Serialize};

/// TLS certificate and key paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert: String,
    pub key: String,
}
