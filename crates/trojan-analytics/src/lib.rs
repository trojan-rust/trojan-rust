//! Analytics module for trojan-rs.
//!
//! This module provides detailed connection event collection and export to ClickHouse
//! for traffic analysis, billing, and auditing.
//!
//! # Feature Gating
//!
//! This crate should be used with the `analytics` feature in `trojan-server`:
//!
//! ```toml
//! [features]
//! analytics = ["trojan-analytics"]
//! ```
//!
//! # Example
//!
//! ```ignore
//! use trojan_analytics::{EventCollector, init};
//! use trojan_analytics::AnalyticsConfig;
//!
//! // Initialize analytics
//! let collector = init(config).await?;
//!
//! // Record connection events
//! let event = collector.connection(conn_id, peer)
//!     .user("user123")
//!     .target("example.com", 443, TargetType::Domain)
//!     .protocol(Protocol::Tcp);
//!
//! // Event is automatically sent on drop
//! ```

#[cfg(feature = "collector")]
mod collector;
pub mod config;
#[cfg(feature = "collector")]
mod error;
#[cfg(feature = "collector")]
mod event;
/// Backend writers.
///
/// Public so integration tests can reuse the shipped table schema instead of
/// keeping a second copy that could drift from it.
#[cfg(feature = "collector")]
pub mod writer;

#[cfg(feature = "collector")]
pub use collector::{ConnectionEventBuilder, EventCollector};
pub use config::{
    AnalyticsBufferConfig, AnalyticsConfig, AnalyticsPrivacyConfig, AnalyticsSamplingConfig,
    ClickHouseConfig, GeoPrecision,
};
#[cfg(feature = "collector")]
pub use error::AnalyticsError;
#[cfg(feature = "collector")]
pub use event::*;

#[cfg(feature = "collector")]
use std::sync::Arc;
#[cfg(feature = "collector")]
use tokio::sync::mpsc;
#[cfg(feature = "collector")]
use tracing::info;

/// Initialize the analytics module.
///
/// Returns an `EventCollector` that can be cloned and used across threads
/// to record connection events.
///
/// # Errors
///
/// Returns an error if ClickHouse configuration is missing or connection fails.
#[cfg(feature = "collector")]
pub async fn init(config: AnalyticsConfig) -> Result<EventCollector, AnalyticsError> {
    if !config.enabled {
        return Err(AnalyticsError::Disabled);
    }

    let clickhouse_config = config.clickhouse.as_ref().ok_or(AnalyticsError::Config(
        "clickhouse config is required".into(),
    ))?;

    // Create bounded channel for events
    let buffer_size = config.buffer.size;
    let (tx, rx) = mpsc::channel(buffer_size);

    // Create ClickHouse client
    let client = writer::clickhouse::create_client(clickhouse_config)?;

    // Start background writer task
    let writer_config = config.clone();
    tokio::spawn(async move {
        writer::run_writer(rx, client, writer_config).await;
    });

    info!(
        buffer_size = buffer_size,
        batch_size = config.buffer.batch_size,
        flush_interval_secs = config.buffer.flush_interval_secs,
        "analytics initialized"
    );

    Ok(EventCollector::new(tx, Arc::new(config)))
}
