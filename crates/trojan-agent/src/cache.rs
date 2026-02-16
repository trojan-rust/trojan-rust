//! Local config cache for panel-down resilience.
//!
//! Atomic write (tmp + rename) ensures we never read a half-written file.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::error::AgentError;
use crate::protocol::NodeType;

const CACHE_FILENAME: &str = "config.json";

/// Cached configuration persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedConfig {
    /// Config version from the panel.
    pub version: u32,
    /// Node type.
    pub node_type: NodeType,
    /// Report interval from the panel.
    pub report_interval_secs: u32,
    /// The full service config JSON.
    pub config: serde_json::Value,
    /// Unix timestamp when the config was cached.
    pub cached_at: u64,
}

/// Write config to the cache directory atomically.
pub async fn write_cache(cache_dir: &Path, cached: &CachedConfig) -> Result<(), AgentError> {
    tokio::fs::create_dir_all(cache_dir)
        .await
        .map_err(|e| AgentError::Cache(format!("failed to create cache dir: {e}")))?;

    let target = cache_dir.join(CACHE_FILENAME);
    let tmp = cache_dir.join(format!("{CACHE_FILENAME}.tmp"));

    let data = serde_json::to_string_pretty(cached)
        .map_err(|e| AgentError::Cache(format!("failed to serialize cache: {e}")))?;

    tokio::fs::write(&tmp, data.as_bytes())
        .await
        .map_err(|e| AgentError::Cache(format!("failed to write tmp cache: {e}")))?;

    tokio::fs::rename(&tmp, &target)
        .await
        .map_err(|e| AgentError::Cache(format!("failed to rename cache file: {e}")))?;

    debug!(path = %target.display(), version = cached.version, "config cached to disk");
    Ok(())
}

/// Read cached config from disk, returning `None` if not found or corrupted.
pub async fn read_cache(cache_dir: &Path) -> Option<CachedConfig> {
    let path = cache_dir.join(CACHE_FILENAME);
    match tokio::fs::read_to_string(&path).await {
        Ok(data) => match serde_json::from_str(&data) {
            Ok(cached) => {
                debug!(path = %path.display(), "loaded cached config from disk");
                Some(cached)
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "corrupted cache file, ignoring");
                None
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "failed to read cache file");
            None
        }
    }
}

/// Resolve the cache directory path.
pub fn resolve_cache_dir(configured: Option<&Path>) -> PathBuf {
    configured
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/var/cache/trojan"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_and_read_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cached = CachedConfig {
            version: 5,
            node_type: NodeType::Server,
            report_interval_secs: 30,
            config: serde_json::json!({"server": {"listen": "0.0.0.0:443"}}),
            cached_at: 1_700_000_000,
        };

        write_cache(dir.path(), &cached).await.unwrap();
        let loaded = read_cache(dir.path()).await.unwrap();
        assert_eq!(loaded.version, 5);
        assert_eq!(loaded.node_type, NodeType::Server);
        assert_eq!(loaded.report_interval_secs, 30);
    }

    #[tokio::test]
    async fn read_cache_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_cache(dir.path()).await.is_none());
    }

    #[tokio::test]
    async fn read_cache_corrupted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        tokio::fs::write(&path, b"not json").await.unwrap();
        assert!(read_cache(dir.path()).await.is_none());
    }
}
