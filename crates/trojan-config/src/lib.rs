//! Configuration loading and CLI definitions.

mod analytics;
mod cli;
mod defaults;
mod loader;
mod types;
mod validate;

use serde::{Deserialize, Serialize};

pub use analytics::*;
pub use cli::*;
pub use loader::*;
pub use types::*;
pub use validate::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub websocket: WebSocketConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub analytics: AnalyticsConfig,
}
