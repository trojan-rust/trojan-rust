# trojan-metrics

Prometheus metrics collection and HTTP exporter for trojan-rs.

## Overview

This crate instruments the trojan server with counters, gauges, and histograms exposed via a Prometheus-compatible HTTP endpoint.

## Endpoints

| Path | Description |
|------|-------------|
| `/metrics` | Prometheus metrics scrape endpoint |
| `/health` | Health check (always returns 200) |
| `/ready` | Readiness check |

## Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `trojan_connections_total` | Counter | Total accepted connections |
| `trojan_connections_active` | Gauge | Currently active connections |
| `trojan_auth_success_total` | Counter | Successful authentications |
| `trojan_auth_failure_total` | Counter | Failed authentications |
| `trojan_bytes_received_total` | Counter | Bytes received from clients |
| `trojan_bytes_sent_total` | Counter | Bytes sent to clients |
| `trojan_errors_total` | Counter | Errors by type |
| `trojan_connection_duration_seconds` | Summary | Connection lifetime |
| `trojan_tls_handshake_duration_seconds` | Summary | TLS handshake time |
| `trojan_dns_resolve_duration_seconds` | Summary | DNS resolution time |
| `trojan_target_connect_duration_seconds` | Summary | Target connection time |
| `trojan_target_connections_total` | Counter | Connections, labelled by destination |
| `trojan_target_bytes_total` | Counter | Bytes, labelled by destination and direction |
| `trojan_route_selections_total` | Counter | Entry route selection by configured `rule` and `outcome`: `selected` or `unavailable` |
| `trojan_route_setup_total` | Counter | Tunnel setup by configured `rule` and `outcome`: `connected`, `relay_error`, `destination_error`, or `cancelled` |
| `trojan_route_setup_duration_seconds` | Summary | Tunnel setup time with the same labels as setup counts |
| `trojan_route_failovers_total` | Counter | Actual alternate route attempts by configured `rule` and failure `reason`: `relay` or `destination` |

Destination metrics are disabled by default. Set `metrics.per_target = true` to emit `trojan_target_bytes_total` and `trojan_target_connections_total` for a bounded destination set. Each destination adds persistent time series. Leave the option off on general-purpose exit nodes. Global byte and connection counters remain available.

Connection lifetimes include cancelled and aborted sessions. Entry route labels use configured rule names and fixed outcomes. A setup attempt covers dialing and every tunnel handshake before client payload forwarding. `unavailable` includes both initially ineligible routes and exhausted retry candidates; the selector does not expose a more specific reason. A failure with no alternate candidate does not increment the failover counter.

The server does not emit `trojan_connection_queue_depth`: semaphore availability does not measure the TCP accept backlog. The existing constant and setter remain available for callers with an actual queue measurement.

Duration observations use the metrics crate's histogram API. The default Prometheus exporter renders them as summaries with `_sum`, `_count`, and quantile series, without `_bucket` series.

## Traffic rates

Use each node's scrape target to measure upload and download rates in bytes per second:

```promql
rate(trojan_bytes_received_total[5m])
rate(trojan_bytes_sent_total[5m])
```

Multiply a rate by `8` for bits per second. These counters measure bytes forwarded by the service, not network interface traffic or provider billing. A chain counts forwarded bytes at each node; summing its nodes counts the same payload more than once. The measured rate describes current traffic load, not the node's available bandwidth limit.

## Usage

```rust
use trojan_metrics::{ConnectionMetrics, RelayCounters, init_metrics_server};

// Install the recorder before resolving any metric handles.
let exporter = init_metrics_server("127.0.0.1:9100", None)?;

// Keep the guard in the session until the connection closes.
let connection = ConnectionMetrics::start();
let counters = RelayCounters::global();
counters.add_to_client(1024);
drop(connection);
```

## License

GPL-3.0-only
