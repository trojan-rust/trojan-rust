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

## License

GPL-3.0-only
