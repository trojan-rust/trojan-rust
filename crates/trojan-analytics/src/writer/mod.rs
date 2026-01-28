//! Event writers for persisting analytics data.

pub mod clickhouse;
mod file;

use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};
use trojan_config::AnalyticsConfig;

use crate::event::ConnectionEvent;

/// Run the background writer task.
///
/// This task receives events from the channel, batches them, and writes
/// to ClickHouse. If ClickHouse fails, it falls back to local file storage.
pub async fn run_writer(
    mut rx: mpsc::Receiver<ConnectionEvent>,
    client: ::clickhouse::Client,
    config: AnalyticsConfig,
) {
    let batch_size = config.buffer.batch_size;
    let flush_interval = Duration::from_secs(config.buffer.flush_interval_secs);
    let table = config
        .clickhouse
        .as_ref()
        .map(|c| c.table.clone())
        .unwrap_or_else(|| "connections".to_string());

    let mut buffer: Vec<ConnectionEvent> = Vec::with_capacity(batch_size);
    let mut flush_timer = interval(flush_interval);
    flush_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    info!(
        batch_size = batch_size,
        flush_interval_secs = flush_interval.as_secs(),
        "analytics writer started"
    );

    loop {
        tokio::select! {
            biased;

            // Receive events
            event = rx.recv() => {
                match event {
                    Some(e) => {
                        buffer.push(e);
                        if buffer.len() >= batch_size {
                            flush_batch(&client, &table, &mut buffer, &config).await;
                        }
                    }
                    None => {
                        // Channel closed, flush remaining and exit
                        if !buffer.is_empty() {
                            flush_batch(&client, &table, &mut buffer, &config).await;
                        }
                        info!("analytics writer stopped");
                        return;
                    }
                }
            }

            // Periodic flush
            _ = flush_timer.tick() => {
                if !buffer.is_empty() {
                    flush_batch(&client, &table, &mut buffer, &config).await;
                }
            }
        }
    }
}

/// Flush a batch of events to ClickHouse.
async fn flush_batch(
    client: &::clickhouse::Client,
    table: &str,
    buffer: &mut Vec<ConnectionEvent>,
    config: &AnalyticsConfig,
) {
    let count = buffer.len();
    debug!(count = count, "flushing analytics batch");

    let write_timeout = Duration::from_secs(
        config
            .clickhouse
            .as_ref()
            .map(|c| c.write_timeout_secs)
            .unwrap_or(30),
    );

    // Try to write to ClickHouse
    match timeout(write_timeout, write_to_clickhouse(client, table, buffer)).await {
        Ok(Ok(())) => {
            debug!(count = count, "batch written to ClickHouse");
            buffer.clear();
        }
        Ok(Err(e)) => {
            error!(count = count, error = %e, "failed to write to ClickHouse");
            // Fall back to local file
            if let Some(ref path) = config.buffer.fallback_path {
                if let Err(e) = file::write_fallback(path, buffer).await {
                    error!(error = %e, "failed to write fallback file");
                } else {
                    warn!(count = count, path = path, "wrote to fallback file");
                    buffer.clear();
                }
            }
        }
        Err(_) => {
            error!(count = count, "ClickHouse write timed out");
            // Fall back to local file
            if let Some(ref path) = config.buffer.fallback_path {
                if let Err(e) = file::write_fallback(path, buffer).await {
                    error!(error = %e, "failed to write fallback file");
                } else {
                    warn!(count = count, path = path, "wrote to fallback file");
                    buffer.clear();
                }
            }
        }
    }
}

/// Write events to ClickHouse.
async fn write_to_clickhouse(
    client: &::clickhouse::Client,
    table: &str,
    events: &[ConnectionEvent],
) -> Result<(), ::clickhouse::error::Error> {
    let mut insert = client.insert(table)?;

    for event in events {
        insert.write(event).await?;
    }

    insert.end().await?;
    Ok(())
}
