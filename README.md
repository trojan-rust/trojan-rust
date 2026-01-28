# trojan-rs

A high-performance Rust implementation of the [Trojan](https://trojan-gfw.github.io/trojan/protocol) protocol.

## Features

- **High Performance** - Built with async Rust and Tokio for maximum throughput
- **TLS 1.3 Support** - Modern encryption with configurable TLS versions
- **WebSocket Transport** - Optional WebSocket encapsulation for CDN compatibility
- **Multiple Auth Backends** - Memory, SQLite, PostgreSQL, and MySQL support
- **User Management** - Full CLI for managing users with traffic limits
- **Prometheus Metrics** - Built-in metrics exporter for monitoring
- **Rate Limiting** - Per-IP connection rate limiting
- **Fallback Server** - Configurable fallback for non-Trojan traffic
- **Self-Upgrade** - Auto-update from GitHub releases (optional feature)
- **Cross-Platform** - Linux, macOS, and Windows support

## Installation

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/trojan-rs/trojan-rs/releases).

### Cargo

```bash
cargo install trojan
```

### From Source

```bash
git clone https://github.com/trojan-rs/trojan-rs
cd trojan-rs
cargo build --release
```

## Usage

### Server

```bash
# Run with config file
trojan server -c config.toml

# Run with CLI options
trojan server --listen 0.0.0.0:443 \
  --tls-cert /path/to/cert.pem \
  --tls-key /path/to/key.pem \
  --password "your-password" \
  --fallback 127.0.0.1:80
```

### User Management (SQL Backend)

```bash
# Initialize database
trojan auth init --database sqlite://users.db

# Add user
trojan auth add --database sqlite://users.db \
  --password "user-password" \
  --upload-limit 10737418240 \
  --download-limit 107374182400

# List users
trojan auth list --database sqlite://users.db

# Remove user
trojan auth remove --database sqlite://users.db --password "user-password"
```

## Configuration

Create a `config.toml` file:

```toml
[server]
listen = "0.0.0.0:443"
fallback = "127.0.0.1:80"
tcp_idle_timeout_secs = 600
udp_timeout_secs = 60

[tls]
cert = "/etc/trojan/cert.pem"
key = "/etc/trojan/key.pem"
alpn = ["http/1.1"]

[auth]
passwords = ["password1", "password2"]

[metrics]
listen = "127.0.0.1:9100"

[logging]
level = "info"
```

JSON and YAML formats are also supported.

## Supported Platforms

| Platform | Architecture |
|----------|--------------|
| Linux | x86_64, aarch64, armv7, i686 |
| Linux (musl) | x86_64, aarch64, armv7, i686 |
| macOS | x86_64, aarch64 (Apple Silicon) |
| Windows | x86_64 |

## Crates

| Crate | Description |
|-------|-------------|
| `trojan-core` | Core types and utilities |
| `trojan-proto` | Protocol encoding/decoding |
| `trojan-auth` | Authentication backends |
| `trojan-config` | Configuration parsing |
| `trojan-metrics` | Prometheus metrics |
| `trojan-analytics` | Connection tracking |
| `trojan-server` | Server implementation |

## License

GPL-3.0-only
