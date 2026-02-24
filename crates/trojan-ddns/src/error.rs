//! DDNS error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DdnsError {
    #[error("cloudflare API error: {0}")]
    Cloudflare(String),

    #[error("IP detection failed: all URLs exhausted")]
    IpDetection,

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("zone not found: {0}")]
    ZoneNotFound(String),

    #[error("config error: {0}")]
    Config(String),
}
