//! HTTP-based rule-set provider with local file caching.
//!
//! Fetches rule-sets from remote URLs and caches them to the local filesystem.
//! On fetch failure, falls back to the cached version if available.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::RulesError;
use crate::rule::ParsedRule;

/// Default HTTP request timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Provider that fetches rule-sets from HTTP/HTTPS URLs with local caching.
pub struct HttpProvider {
    url: String,
    cache_path: Option<PathBuf>,
    format: String,
    behavior: Option<String>,
    timeout: Duration,
}

impl HttpProvider {
    /// Create a new HTTP provider.
    ///
    /// - `url`: Remote URL to fetch the rule-set from.
    /// - `cache_path`: Optional local path to cache the fetched content.
    /// - `format`: Rule-set format ("surge" or "clash").
    /// - `behavior`: Optional behavior hint ("domain", "ipcidr", "classical", "domain-set").
    pub fn new(
        url: impl Into<String>,
        cache_path: Option<PathBuf>,
        format: impl Into<String>,
        behavior: Option<String>,
    ) -> Self {
        Self {
            url: url.into(),
            cache_path,
            format: format.into(),
            behavior,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Set the HTTP request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Fetch the rule-set content from the remote URL.
    pub async fn fetch(&self) -> Result<String, RulesError> {
        tracing::debug!(url = %self.url, "fetching remote rule-set");

        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| RulesError::Http(format!("failed to build HTTP client: {e}")))?;

        let response = client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| RulesError::Http(format!("HTTP request failed for {}: {e}", self.url)))?;

        let status = response.status();
        if !status.is_success() {
            return Err(RulesError::Http(format!(
                "HTTP {} for {}",
                status, self.url
            )));
        }

        let content = response
            .text()
            .await
            .map_err(|e| RulesError::Http(format!("failed to read response body: {e}")))?;

        tracing::debug!(url = %self.url, bytes = content.len(), "fetched remote rule-set");

        // Update cache if path is configured
        if let Some(ref cache_path) = self.cache_path {
            if let Err(e) = write_cache(cache_path, &content).await {
                tracing::warn!(path = %cache_path.display(), error = %e, "failed to write cache");
            }
        }

        Ok(content)
    }

    /// Load the rule-set: try fetching from URL, fall back to cache on failure.
    pub async fn load(&self) -> Result<Vec<ParsedRule>, RulesError> {
        match self.fetch().await {
            Ok(content) => self.parse(&content),
            Err(fetch_err) => {
                // Try cache fallback
                if let Some(ref cache_path) = self.cache_path {
                    if cache_path.exists() {
                        tracing::warn!(
                            url = %self.url,
                            error = %fetch_err,
                            cache = %cache_path.display(),
                            "fetch failed, using cached rules"
                        );
                        let content = tokio::fs::read_to_string(cache_path)
                            .await
                            .map_err(|e| RulesError::Io(e))?;
                        return self.parse(&content);
                    }
                }
                Err(fetch_err)
            }
        }
    }

    /// Load from cache only (for startup before first fetch).
    pub fn load_cached(&self) -> Result<Option<Vec<ParsedRule>>, RulesError> {
        match &self.cache_path {
            Some(path) if path.exists() => {
                let content = std::fs::read_to_string(path)?;
                Ok(Some(self.parse(&content)?))
            }
            _ => Ok(None),
        }
    }

    /// Parse content using the configured format and behavior.
    fn parse(&self, content: &str) -> Result<Vec<ParsedRule>, RulesError> {
        crate::provider::FileProvider::parse(content, &self.format, self.behavior.as_deref())
    }

    /// Get the URL of this provider.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get the cache path of this provider.
    pub fn cache_path(&self) -> Option<&Path> {
        self.cache_path.as_deref()
    }
}

/// Write content to a cache file atomically (write-to-temp + rename).
///
/// This prevents truncated cache files if the process is killed mid-write.
/// On Windows, the destination is removed first since `rename` fails when
/// the target already exists.
async fn write_cache(path: &Path, content: &str) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp_path = path.with_extension("tmp");
    tokio::fs::write(&tmp_path, content).await?;
    // On Windows, rename fails if the destination exists; remove it first.
    #[cfg(target_os = "windows")]
    {
        let _ = tokio::fs::remove_file(path).await;
    }
    tokio::fs::rename(&tmp_path, path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_provider_new() {
        let p = HttpProvider::new(
            "https://example.com/rules.txt",
            Some(PathBuf::from("/tmp/cache.txt")),
            "surge",
            Some("domain-set".to_string()),
        );
        assert_eq!(p.url(), "https://example.com/rules.txt");
        assert_eq!(
            p.cache_path(),
            Some(Path::new("/tmp/cache.txt"))
        );
    }

    #[test]
    fn http_provider_parse_surge() {
        let p = HttpProvider::new("http://example.com", None, "surge", None);
        let rules = p.parse("DOMAIN,example.com\nDOMAIN-SUFFIX,test.com").unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn http_provider_parse_clash() {
        let p = HttpProvider::new(
            "http://example.com",
            None,
            "clash",
            Some("domain".to_string()),
        );
        let content = "payload:\n  - 'example.com'\n  - '+.test.com'";
        let rules = p.parse(content).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn load_cached_no_path() {
        let p = HttpProvider::new("http://example.com", None, "surge", None);
        assert!(p.load_cached().unwrap().is_none());
    }

    #[test]
    fn load_cached_nonexistent_path() {
        let p = HttpProvider::new(
            "http://example.com",
            Some(PathBuf::from("/nonexistent/path/rules.txt")),
            "surge",
            None,
        );
        assert!(p.load_cached().unwrap().is_none());
    }
}
