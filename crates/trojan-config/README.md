# trojan-config

Configuration loading, validation, and CLI override support for trojan-rs.

## Overview

This crate handles all configuration concerns:

- **Multi-format loading** — TOML, YAML, JSON, and JSONC (JSON with comments)
- **Typed config structs** — Strongly-typed configuration with serde, including defaults for all optional fields
- **CLI overrides** — Every config option can be overridden via command-line flags
- **Validation** — Comprehensive config validation with clear error messages

## Module Structure

| Module | Description |
|--------|-------------|
| `types` | Server, TLS, WebSocket, auth, metrics, logging config structs |
| `analytics` | ClickHouse analytics configuration |
| `cli` | CLI override struct and `apply_overrides()` |
| `loader` | File loading with format detection by extension |
| `validate` | Configuration validation rules |
| `defaults` | Default value functions backed by `trojan-core` constants |

## Supported Formats

| Extension | Format |
|-----------|--------|
| `.toml` | TOML |
| `.yaml`, `.yml` | YAML |
| `.json` | JSON (with comment support) |
| `.jsonc` | JSON with comments |

## Usage

```rust
use trojan_config::{load_config, validate_config, apply_overrides};

let mut config = load_config("config.toml")?;
apply_overrides(&mut config, &cli_overrides);
validate_config(&config)?;
```

## Key Types

- **`Config`** — Top-level configuration with `server`, `tls`, `auth`, `websocket`, `metrics`, `logging`, `analytics` sections
- **`ServerConfig`** — Listen address, fallback, timeouts, rate limiting, connection pool, TCP options
- **`TcpConfig`** — TCP_NODELAY, Keep-Alive, SO_REUSEPORT, TCP Fast Open
- **`TlsConfig`** — Certificate, key, ALPN, TLS version range, mTLS, cipher suites
- **`CliOverrides`** — Clap-derived struct for command-line overrides

## IPv6 Server Listener Mode

The optional `server.tcp.ipv6_only` setting determines whether IPv6
listener sockets accept IPv4-mapped connections:

- Omitted: keep the operating system's existing default.
- `true`: IPv6-only.
- `false`: enable dual-stack. Bind the IPv6 wildcard address
  `[::]` to accept both IPv4 and IPv6 on the same TCP port.

```toml
[server]
listen = "[::]:444"

[server.tcp]
ipv6_only = false
```

The corresponding CLI override is `--tcp-ipv6-only false` (or
`--tcp-ipv6-only true`), using the same explicit boolean-value
convention as the existing `--tcp-reuse-port` option. CLI overrides
take precedence over the configuration file. The option applies only to
IPv6 sockets and cannot turn an IPv4-bound address into an IPv6 listener.
Binding one specific IPv6 address does not necessarily enable IPv4 access.

On Windows, an effective IPv6 dual-stack listener requests exclusive
address binding to prevent a second IPv4 listener from overlapping its
port; unsupported socket options or binding failures abort startup.

## Metrics TLS

`MetricsConfig` accepts an optional `tls` object with required `cert`, `key`, and `client_ca` path strings. TOML `[metrics.tls]` and JSON `metrics.tls` have the same meaning. TLS requires `metrics.listen`; omitting TLS preserves HTTP. Configuration validation checks required fields, and service startup reads and validates the local files. Existing `geoip` and `per_target` fields are unchanged. See the [minimal configuration and Prometheus example](../trojan-metrics/README.md#mutual-tls).

## License

GPL-3.0-only
