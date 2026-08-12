//! Background heartbeat and traffic batch reporter.
//!
//! Sends periodic heartbeat and traffic messages to the panel
//! via the WS send channel.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sysinfo::System;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
use trojan_metrics::NodeStats;

use crate::collector::TrafficCollector;
use crate::protocol::AgentMessage;

/// Run the background reporter loop.
///
/// Sends heartbeat and traffic messages at the configured interval
/// until the shutdown token is cancelled.
pub async fn run_reporter(
    tx: mpsc::Sender<AgentMessage>,
    collector: TrafficCollector,
    stats: Arc<NodeStats>,
    interval: Duration,
    shutdown: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let start = Instant::now();

    let mut sys = System::new();

    loop {
        tokio::select! {
            biased;

            _ = shutdown.cancelled() => {
                debug!("reporter shutting down");
                return;
            }

            _ = ticker.tick() => {
                let uptime_secs = start.elapsed().as_secs();

                // Refresh system info for memory/cpu
                sys.refresh_memory();
                sys.refresh_cpu_usage();

                let memory_rss_bytes = Some(sys.used_memory());
                let cpu_usage_percent = {
                    let cpus = sys.cpus();
                    if cpus.is_empty() {
                        None
                    } else {
                        let total: f32 = cpus.iter().map(|c| c.cpu_usage()).sum();
                        let count = cpus.len() as f32;
                        Some(total / count)
                    }
                };

                // Totals since the service started, not a delta: the panel
                // diffs them, and a heartbeat lost in a reconnect then costs
                // nothing.
                let snapshot = stats.snapshot();
                let heartbeat = AgentMessage::Heartbeat {
                    connections_active: u32::try_from(snapshot.connections_active)
                        .unwrap_or(u32::MAX),
                    bytes_in: snapshot.bytes_in,
                    bytes_out: snapshot.bytes_out,
                    uptime_secs,
                    memory_rss_bytes,
                    cpu_usage_percent,
                };

                if let Err(e) = tx.send(heartbeat).await {
                    warn!(error = %e, "failed to send heartbeat, channel closed");
                    return;
                }

                // Drain and send traffic records
                let records = collector.drain();
                if !records.is_empty() {
                    debug!(count = records.len(), "sending traffic report");
                    let traffic = AgentMessage::Traffic { records };
                    if let Err(e) = tx.send(traffic).await {
                        warn!(error = %e, "failed to send traffic report, channel closed");
                        return;
                    }
                }
            }
        }
    }
}
