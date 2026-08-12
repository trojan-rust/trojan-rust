//! Service configuration.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

use crate::error::DashError;

/// Environment variable consulted for the admin token, so the secret need not
/// live in the config file.
pub const ADMIN_TOKEN_ENV: &str = "TROJAN_DASH_ADMIN_TOKEN";

/// Configuration for the dashboard service.
#[derive(Debug, Clone, Deserialize)]
pub struct DashConfig {
    /// Address to listen on.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,

    /// SQLite database. A bare path is fine; it is created if missing.
    #[serde(default = "default_database")]
    pub database: String,

    /// Bearer token guarding `/admin/*`.
    ///
    /// [`ADMIN_TOKEN_ENV`] takes precedence when set, which is the intended
    /// way to run: keep the secret out of the config file.
    #[serde(default)]
    pub admin_token: Option<String>,

    /// Directory holding the built panel. Served at `/` when set, with the
    /// single-page-app fallback; omit to run the API alone.
    #[serde(default)]
    pub panel_dir: Option<PathBuf>,

    /// Minimum interval, in seconds, between `last_seen` writes for a node.
    ///
    /// Nodes call `/verify` and `/traffic` continuously; without this every
    /// call would be a write.
    #[serde(default = "default_last_seen_ttl")]
    pub node_last_seen_ttl: u64,

    /// Log level override (e.g. "info", "debug").
    #[serde(default)]
    pub log_level: Option<String>,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}

fn default_database() -> String {
    "dash.db".to_owned()
}

fn default_last_seen_ttl() -> u64 {
    180
}

impl DashConfig {
    /// Resolve the admin token from the environment or the config file.
    pub fn resolve_admin_token(&self) -> Result<String, DashError> {
        std::env::var(ADMIN_TOKEN_ENV)
            .ok()
            .filter(|t| !t.is_empty())
            .or_else(|| self.admin_token.clone().filter(|t| !t.is_empty()))
            .ok_or_else(|| {
                DashError::Config(format!(
                    "no admin token: set {ADMIN_TOKEN_ENV} or `admin_token` in the config file"
                ))
            })
    }

    /// SQLite connection URL, creating the file if it does not exist.
    ///
    /// Paths are accepted verbatim in the config for convenience; sqlx wants a
    /// URL, and without `mode=rwc` it refuses to create a missing database.
    pub fn database_url(&self) -> String {
        if self.database.starts_with("sqlite:") {
            self.database.clone()
        } else {
            format!("sqlite://{}?mode=rwc", self.database)
        }
    }
}
