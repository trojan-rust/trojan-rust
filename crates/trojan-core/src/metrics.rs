//! TLS configuration for authenticated metrics listeners.

use serde::{Deserialize, Serialize};

/// Node-local PEM files required for mutual TLS on every metrics route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsTlsConfig {
    /// Server certificate chain, with the leaf certificate first.
    pub cert: String,
    /// Private key for the server certificate.
    pub key: String,
    /// Certificate authorities trusted to authenticate metrics clients.
    pub client_ca: String,
}

impl MetricsTlsConfig {
    /// Reject empty certificate paths before reading node-local files.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.cert.trim().is_empty() {
            return Err("metrics.tls.cert is empty");
        }
        if self.key.trim().is_empty() {
            return Err("metrics.tls.key is empty");
        }
        if self.client_ca.trim().is_empty() {
            return Err("metrics.tls.client_ca is empty");
        }
        Ok(())
    }
}
