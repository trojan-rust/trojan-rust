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
| `trojan_connection_duration_seconds` | Histogram | Connection lifetime |
| `trojan_tls_handshake_duration_seconds` | Histogram | TLS handshake time |
| `trojan_dns_resolve_duration_seconds` | Histogram | DNS resolution time |
| `trojan_target_connect_duration_seconds` | Histogram | Target connection time |

## Usage

```rust
use trojan_metrics::{init_metrics_server, record_connection_accepted, record_bytes_sent};

// Start metrics server
init_metrics_server("127.0.0.1:9100").await;

// Record events
record_connection_accepted();
record_bytes_sent(1024);
```

## License

GPL-3.0-only
