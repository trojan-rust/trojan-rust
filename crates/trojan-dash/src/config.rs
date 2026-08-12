//! Service configuration.
//!
//! Field names match the config the deployed panel already reads, so an
//! existing `config.toml` works unchanged.

use std::path::PathBuf;
use std::time::Duration;

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
    pub listen: String,

    /// SQLite connection URL. A bare path is accepted too.
    #[serde(default = "default_database_url", alias = "database")]
    pub database_url: String,

    /// Bearer token guarding `/admin/*`.
    ///
    /// [`ADMIN_TOKEN_ENV`] takes precedence when set, which is the intended
    /// way to run: keep the secret out of the config file.
    #[serde(default)]
    pub admin_token: Option<String>,

    /// Directory holding the built panel. Served at `/` when it exists, with
    /// the single-page-app fallback; omit to run the API alone.
    #[serde(default, alias = "panel_dir")]
    pub static_dir: Option<PathBuf>,

    /// Minimum interval, in seconds, between `last_seen` writes for a node.
    ///
    /// Nodes call `/verify` and `/traffic` continuously; without this every
    /// call would be a write.
    #[serde(default = "default_node_last_seen_ttl")]
    pub node_last_seen_ttl: u64,

    /// How long a verified user stays cached, in seconds.
    #[serde(default = "default_verify_cache_ttl")]
    pub verify_cache_ttl: u64,

    /// How long a subscription template stays cached, in seconds.
    #[serde(default = "default_sub_cache_ttl")]
    pub sub_cache_ttl: u64,

    /// How many days of hour-resolution traffic to keep.
    ///
    /// The hourly rollup exists for the short chart ranges and costs 24 rows a
    /// day per user per node; the daily table keeps history regardless. 0
    /// disables pruning.
    #[serde(default = "default_hourly_retention_days")]
    pub hourly_retention_days: u32,

    /// Log level override (e.g. "info", "debug").
    #[serde(default)]
    pub log_level: Option<String>,
}

fn default_listen() -> String {
    "127.0.0.1:8080".to_owned()
}

fn default_database_url() -> String {
    "sqlite://./dash.db?mode=rwc".to_owned()
}

fn default_node_last_seen_ttl() -> u64 {
    180
}

fn default_verify_cache_ttl() -> u64 {
    3600
}

fn default_sub_cache_ttl() -> u64 {
    3600
}

/// Twice the longest hour-resolution range, so a chart never runs into the
/// prune and the window can be widened without a config change.
fn default_hourly_retention_days() -> u32 {
    14
}

impl DashConfig {
    /// Resolve the admin token from the environment or the config file.
    pub fn resolve_admin_token(&self) -> Result<String, DashError> {
        std::env::var(ADMIN_TOKEN_ENV)
            .ok()
            .filter(|t| !t.is_empty())
            .or_else(|| self.admin_token.clone().filter(|t| !t.trim().is_empty()))
            .ok_or_else(|| {
                DashError::Config(format!(
                    "no admin token: set {ADMIN_TOKEN_ENV} or `admin_token` in the config file"
                ))
            })
    }

    /// Connection URL, accepting a bare path for convenience.
    ///
    /// Without `mode=rwc` sqlite refuses to create a missing database.
    ///
    /// A path becomes the URL's *path*, never its authority: `sqlite://C:\dir`
    /// parses with the drive letter as a host, and the database opens without
    /// one. Spelling out the empty authority and normalising separators keeps
    /// Windows and unix paths the same shape.
    pub fn database_url(&self) -> String {
        if self.database_url.starts_with("sqlite:") {
            return self.database_url.clone();
        }

        let path = self.database_url.replace('\\', "/");
        format!("sqlite:///{}?mode=rwc", path.trim_start_matches('/'))
    }

    pub fn verify_cache_ttl(&self) -> Duration {
        Duration::from_secs(self.verify_cache_ttl)
    }

    pub fn sub_cache_ttl(&self) -> Duration {
        Duration::from_secs(self.sub_cache_ttl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_database(database: &str) -> DashConfig {
        toml::from_str(&format!(
            "database_url = {}\nadmin_token = \"t\"",
            toml::Value::from(database)
        ))
        .expect("a backslashed path must not be read as a unicode escape")
    }

    /// A path becomes the URL's path, whatever separators it arrived with.
    ///
    /// `sqlite://C:\dir\dash.db` parses with `C` as the host, so the database
    /// opens without its drive letter. Asserting on the string means a
    /// regression fails everywhere, not only on the platform that has drives.
    #[test]
    fn a_windows_path_keeps_its_drive_letter() {
        assert_eq!(
            with_database(r"C:\ProgramData\trojan\dash.db").database_url(),
            "sqlite:///C:/ProgramData/trojan/dash.db?mode=rwc"
        );
    }

    #[test]
    fn a_unix_path_keeps_one_leading_slash() {
        assert_eq!(
            with_database("/var/lib/trojan-dash/dash.db").database_url(),
            "sqlite:///var/lib/trojan-dash/dash.db?mode=rwc"
        );
    }

    /// Anything already spelled as a URL is the operator's business.
    #[test]
    fn an_explicit_url_is_left_alone() {
        assert_eq!(
            with_database("sqlite://memory:?cache=shared").database_url(),
            "sqlite://memory:?cache=shared"
        );
    }
}
