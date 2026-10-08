//! Local metrics for durable node accounting. Labels contain no node or user identities.

use std::time::Instant;

use metrics::{Gauge, counter, gauge, histogram};

use super::Journal;

pub(super) enum Operation {
    Sample,
    Acknowledge,
    Send,
}

pub(super) fn operation(operation: Operation, started: Instant, succeeded: bool) {
    let operation = match operation {
        Operation::Sample => "sample",
        Operation::Acknowledge => "ack",
        Operation::Send => "send",
    };
    let outcome = if succeeded { "success" } else { "error" };
    counter!("trojan_agent_node_traffic_operations_total", "operation" => operation, "outcome" => outcome).increment(1);
    histogram!("trojan_agent_node_traffic_operation_duration_seconds", "operation" => operation)
        .record(started.elapsed().as_secs_f64());
}

pub(super) struct Backlog {
    enabled: Gauge,
    reports: Gauge,
    bytes: Gauge,
    oldest: Gauge,
}

impl Backlog {
    pub(super) fn new() -> Self {
        Self {
            enabled: gauge!("trojan_agent_node_traffic_enabled"),
            reports: gauge!("trojan_agent_node_traffic_pending_reports"),
            bytes: gauge!("trojan_agent_node_traffic_pending_bytes"),
            oldest: gauge!("trojan_agent_node_traffic_oldest_pending_timestamp_seconds"),
        }
    }

    pub(super) fn publish(self, journal: &Journal) {
        self.enabled.set(f64::from(u8::from(journal.enabled)));
        self.reports.set(journal.saved.pending.len() as f64);
        self.bytes.set(journal.pending_bytes);
        self.oldest.set(
            journal
                .saved
                .pending
                .front()
                .map_or(0, |report| report.observed_at) as f64,
        );
    }
}

pub(super) fn sampled(observed_at: u64) {
    gauge!("trojan_agent_node_traffic_last_sample_timestamp_seconds").set(observed_at as f64);
}

pub(super) fn rejected() {
    counter!("trojan_agent_node_traffic_panel_rejections_total").increment(1);
}
