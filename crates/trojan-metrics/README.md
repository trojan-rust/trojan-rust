# trojan-metrics

Prometheus metrics collection and HTTP or mutually authenticated HTTPS exporter for trojan-rs.

## Overview

This crate instruments server, relay, and entry nodes with counters, gauges, and histograms exposed through a Prometheus-compatible endpoint.

## Endpoints

| Path | Description |
|------|-------------|
| `/metrics` | Prometheus metrics scrape endpoint |
| `/health` | Health check (always returns 200) |
| `/ready` | Readiness check |

## Mutual TLS

Add this block to a server, relay, or entry configuration:

```toml
[metrics]
listen = "0.0.0.0:19001"

[metrics.tls]
cert = "/etc/trojan/metrics/server.crt"
key = "/etc/trojan/metrics/server.key"
client_ca = "/etc/trojan/metrics/clients-ca.crt"
```

The equivalent Agent service configuration uses the same fields in JSON:

```json
{
  "metrics": {
    "listen": "0.0.0.0:19001",
    "tls": {
      "cert": "/etc/trojan/metrics/server.crt",
      "key": "/etc/trojan/metrics/server.key",
      "client_ca": "/etc/trojan/metrics/clients-ca.crt"
    }
  }
}
```

Merge this section into the complete service configuration. Dashboard stores and transmits only the path strings. The node reads the files locally; Dashboard does not read remote files or transfer private keys. The service account must have permission to read the files.

Without `metrics.tls`, `metrics.listen` retains the existing HTTP behavior. Without either field, the exporter remains disabled. With `metrics.tls`, `listen`, `cert`, `key`, and `client_ca` are required. Empty fields, unreadable or invalid certificate files, mismatched keys, and bind failures fail service startup. The exporter never falls back to HTTP. Existing server `metrics.geoip` and `metrics.per_target` settings keep their behavior.

Use a PEM server certificate chain, a matching PEM private key, and a PEM CA bundle that trusts the scraping clients. Client certificates must be valid for client authentication and within their validity period. The exporter validates the client certificate chain. Clients without a trusted, valid certificate fail at the TLS layer. There is no anonymous-client option. `/metrics`, `/health`, `/ready`, and any extra routes on this listener use the same authentication policy. The server's `/debug/rules/match` route also keeps its existing loopback restriction. Metrics TLS is independent of proxy TLS, proxy SNI, and proxy routing.

The server certificate must be valid for server authentication. Its Subject Alternative Name (SAN) must match the hostname or IP address that Prometheus uses to scrape. Prometheus must verify the server CA and identity. Do not set `insecure_skip_verify`.

```yaml
scrape_configs:
  - job_name: trojan-mtls
    scheme: https
    metrics_path: /metrics
    static_configs:
      - targets: ["node-a.metrics.example:19001"]
    tls_config:
      ca_file: /etc/prometheus/pki/servers-ca.crt
      cert_file: /etc/prometheus/pki/prometheus.crt
      key_file: /etc/prometheus/pki/prometheus.key
```

Verify a successful scrape with a client certificate:

```sh
curl --fail --cacert /etc/prometheus/pki/servers-ca.crt \
  --cert /etc/prometheus/pki/prometheus.crt \
  --key /etc/prometheus/pki/prometheus.key \
  https://node-a.metrics.example:19001/metrics
```

The same request without a client certificate must fail with a TLS error and no metrics response:

```sh
curl --fail --cacert /etc/prometheus/pki/servers-ca.crt \
  https://node-a.metrics.example:19001/metrics
```

Plain HTTP requests to the mTLS port also fail. No additional anonymous metrics listener is opened.

Each listener accepts at most 128 concurrent connections, including TLS handshakes. A TLS handshake must complete within 5 seconds. Failed handshakes close only their own connection.

### Upgrade and certificate replacement

Older binaries can silently ignore unknown configuration fields. Upgrade every affected node binary before enabling `metrics.tls`. Verify authenticated HTTPS and rejected anonymous requests before expanding the listener's network exposure. Do not send TLS fields to an old binary and then widen a public listener.

Certificate files are loaded at service startup. There is no certificate hot reload. To change the listener address, server certificate, private key, or client CA:

1. Install the replacement files on the node and update the service configuration if paths change.
2. For a standalone node, stop the service and wait for shutdown, then start `trojan server`, `trojan relay`, or `trojan entry` with its configuration. Server SIGHUP reloads authentication only; it does not reload metrics certificates.
3. For an Agent-managed node, save the complete service JSON in Dashboard and restart the Agent to register and receive the saved configuration. Dashboard PATCH does not send a live `ConfigPush`. A panel that implements `ConfigPush` must set `restart_required=true`; an explicit restart also reloads files when the JSON paths are unchanged.
4. Repeat both curl checks and confirm Prometheus can scrape the expected address and server identity.

A normal reconnect with unchanged configuration preserves the service and does not reload certificates. Agent startup can run cached configuration before registration. If Dashboard has a new mTLS configuration but the cache still contains HTTP, the node can serve cached HTTP until registration succeeds and the service restarts. Offline startup uses only cached configuration and the certificate files currently present on the node. Confirm the new configuration with authenticated and anonymous requests before changing network exposure. Keep `cache_dir`, traffic journals, and persistent state intact during upgrades and restarts.

Service shutdown closes the metrics listener and all metrics connections before a replacement can bind. This also closes HTTP keep-alive connections when switching to mTLS. Restart interrupts scrapes and proxy connections: server proxy connections may drain for up to 30 seconds, while entry and relay tunnels close immediately; an Agent push may shorten the drain timeout. Process-local Prometheus counters survive an in-process service restart because the recorder is shared. A process restart resets those counters; durable Agent traffic accounting remains separate.

TLS protects reachable connections. It does not make an unreachable node reachable or backfill scrapes missed during an outage. Certificate issuance and renewal, `remote_write`, alerts, deployment, and SSH tunnel removal are outside this feature.

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
let exporter = init_metrics_server("127.0.0.1:9100", None, None).await?;

// Keep the guard in the session until the connection closes.
let connection = ConnectionMetrics::start();
let counters = RelayCounters::global();
counters.add_to_client(1024);
drop(connection);

// Drive the listener for the lifetime of the owning service.
exporter.run_until(service_future).await?;
```

`init_metrics_server` validates TLS and binds before returning. The process installs one Prometheus recorder and reuses it across service restarts. Build metric handles after initialization. `MetricsServer::run_until` owns the listener and its connections within the service future, so completion or cancellation closes them without detached exporter tasks. Additional routes supplied at initialization inherit the listener's HTTP or mTLS policy.

## License

GPL-3.0-only
