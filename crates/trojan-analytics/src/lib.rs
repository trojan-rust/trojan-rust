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
//! use trojan_config::AnalyticsConfig;
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

mod collector;
mod error;
mod event;
mod writer;

pub use collector::{ConnectionEventBuilder, EventCollector};
pub use error::AnalyticsError;
pub use event::*;
pub use trojan_config::{
    AnalyticsBufferConfig, AnalyticsConfig, AnalyticsPrivacyConfig, AnalyticsSamplingConfig,
    ClickHouseConfig,
};

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

/// Initialize the analytics module.
///
/// Returns an `EventCollector` that can be cloned and used across threads
/// to record connection events.
///
/// # Errors
///
/// Returns an error if ClickHouse configuration is missing or connection fails.
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
