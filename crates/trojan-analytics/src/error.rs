//! Analytics error types.

use thiserror::Error;

/// Analytics module errors.
#[derive(Debug, Error)]
pub enum AnalyticsError {
    /// Analytics is disabled in configuration.
    #[error("analytics is disabled")]
    Disabled,

    /// Configuration error.
    #[error("config error: {0}")]
    Config(String),

    /// ClickHouse client error.
    #[error("clickhouse error: {0}")]
    ClickHouse(#[from] clickhouse::error::Error),

    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
