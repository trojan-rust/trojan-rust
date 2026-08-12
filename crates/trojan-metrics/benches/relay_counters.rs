//! Benchmarks for the relay's per-flush byte reporting.
//!
//! The relay reports bytes once per flush rather than once per connection, so
//! the cost of a single report sits directly on the data path. These compare
//! resolving the metric on every report — what the server did before
//! [`RelayCounters`] — against a handle resolved once per session.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use metrics::counter;
use metrics_exporter_prometheus::PrometheusBuilder;
use trojan_metrics::{BYTES_RECEIVED_TOTAL, RelayCounters, TARGET_BYTES_TOTAL};

/// One relay buffer's worth of bytes, the typical report size.
const REPORT_BYTES: u64 = 32 * 1024;

const TARGET: &str = "www.example.com";

fn bench_byte_report(c: &mut Criterion) {
    // A real recorder is required: without one, `counter!` resolves against
    // the no-op recorder and the comparison measures nothing.
    let _handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("install prometheus recorder");

    // Warm the registry entries so every variant measures a steady-state
    // lookup rather than a first insert.
    RelayCounters::with_target(TARGET).add_to_target(0);

    let mut group = c.benchmark_group("relay_byte_report");

    // Resolve per report: builds a labelled key (allocating a Vec and a
    // String) and hashes it against the registry, every time.
    group.bench_function("resolve_per_report", |b| {
        b.iter(|| {
            counter!(BYTES_RECEIVED_TOTAL).increment(black_box(REPORT_BYTES));
            counter!(
                TARGET_BYTES_TOTAL,
                "target" => TARGET.to_owned(),
                "direction" => "sent"
            )
            .increment(black_box(REPORT_BYTES));
        });
    });

    // Handle resolved once per session, then reused for every report.
    let per_target = RelayCounters::with_target(TARGET);
    group.bench_function("hoisted_handle", |b| {
        b.iter(|| per_target.add_to_target(black_box(REPORT_BYTES)));
    });

    // Same, with `metrics.per_target = false`.
    let global = RelayCounters::global();
    group.bench_function("hoisted_handle_global_only", |b| {
        b.iter(|| global.add_to_target(black_box(REPORT_BYTES)));
    });

    group.finish();
}

/// Resolving the handles is the cost moved off the data path — it now happens
/// once per connection, so it should stay cheap relative to a connection.
fn bench_handle_resolution(c: &mut Criterion) {
    let mut group = c.benchmark_group("relay_counters_new");

    group.bench_function("with_target", |b| {
        b.iter(|| RelayCounters::with_target(black_box(TARGET)));
    });

    group.bench_function("global", |b| {
        b.iter(RelayCounters::global);
    });

    group.finish();
}

criterion_group!(benches, bench_byte_report, bench_handle_resolution);
criterion_main!(benches);
