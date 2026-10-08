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
/// Sends heartbeat and user traffic messages until the shutdown token is cancelled.
/// Caps the heartbeat interval at 30 seconds for the panel's 90-second liveness window.
/// Keep `start` unchanged across panel sessions to preserve uptime.
pub async fn run_reporter(
    tx: mpsc::Sender<AgentMessage>,
    collector: TrafficCollector,
    stats: Arc<NodeStats>,
    interval: Duration,
    shutdown: CancellationToken,
    start: Instant,
) {
    let mut heartbeat_tick = tokio::time::interval(interval.min(Duration::from_secs(30)));
    heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut traffic_tick = tokio::time::interval(interval);
    traffic_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut sys = System::new();

    loop {
        tokio::select! {
            biased;

            _ = shutdown.cancelled() => {
                debug!("reporter shutting down");
                return;
            }

            _ = heartbeat_tick.tick() => {
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

                // Heartbeats expose live counters; durable node reports own quota accounting.
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
            }

            _ = traffic_tick.tick() => {
                // Drain and send traffic records
                let permit = match tx.reserve().await {
                    Ok(permit) => permit,
                    Err(e) => {
                        warn!(error = %e, "traffic channel closed; retaining pending records");
                        return;
                    }
                };
                let records = collector.drain();
                if !records.is_empty() {
                    debug!(count = records.len(), "sending traffic report");
                    let traffic = AgentMessage::Traffic { records };
                    permit.send(traffic);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn long_report_interval_keeps_heartbeats_inside_the_liveness_window() {
        let (tx, mut rx) = mpsc::channel(8);
        let collector = TrafficCollector::new();
        collector.record("alice", 7);
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run_reporter(
            tx,
            collector.clone(),
            NodeStats::new(),
            Duration::from_secs(120),
            shutdown.clone(),
            Instant::now(),
        ));
        assert!(matches!(
            rx.recv().await,
            Some(AgentMessage::Heartbeat { .. })
        ));
        assert!(matches!(
            rx.recv().await,
            Some(AgentMessage::Traffic { .. })
        ));
        collector.record("alice", 13);

        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(30)).await;
            assert!(matches!(
                rx.recv().await,
                Some(AgentMessage::Heartbeat { .. })
            ));
            assert!(
                rx.try_recv().is_err(),
                "user traffic must retain its 120-second interval"
            );
        }
        tokio::time::advance(Duration::from_secs(30)).await;
        assert!(matches!(
            rx.recv().await,
            Some(AgentMessage::Heartbeat { .. })
        ));
        let Some(AgentMessage::Traffic { records }) = rx.recv().await else {
            panic!("expected user traffic at the configured interval")
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].bytes, 13);
        shutdown.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn cancelling_a_blocked_reporter_preserves_unsent_traffic() {
        let (tx, rx) = mpsc::channel(1);
        let collector = TrafficCollector::new();
        collector.record("alice", 42);
        let task = tokio::spawn(run_reporter(
            tx,
            collector.clone(),
            NodeStats::new(),
            Duration::from_secs(60),
            CancellationToken::new(),
            Instant::now(),
        ));
        tokio::time::timeout(Duration::from_secs(2), async {
            while rx.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let pending = collector.drain();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].user_id, "alice");
        assert_eq!(pending[0].bytes, 42);
    }
}
