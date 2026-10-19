# trojan-client

SOCKS5 proxy client that tunnels traffic through a Trojan protocol server.

## Overview

This crate implements a local SOCKS5 proxy that forwards traffic over a TLS connection to a remote trojan-server:

- **SOCKS5 proxy** — Listens locally and accepts SOCKS5 CONNECT and UDP ASSOCIATE requests
- **TLS transport** — Connects to the remote server via TLS with configurable SNI and custom CA support
- **TCP CONNECT** — Proxies TCP connections with header coalescing for reduced round trips
- **UDP ASSOCIATE** — Full UDP relay with SOCKS5 encapsulation and idle timeout
- **Graceful shutdown** — CancellationToken-based shutdown with SIGTERM/SIGINT handling

## Architecture

```text
Application ──SOCKS5──▶ trojan-client ──TLS──▶ trojan-server ──▶ Target
                           │
               ┌───────────┼───────────┐
               ▼                       ▼
          TCP CONNECT            UDP ASSOCIATE
          (relay)                (UDP relay loop)
```

## Usage

### As a binary (via main crate)

```bash
trojan client -c client.toml
trojan client --listen 127.0.0.1:1080 --remote server.example.com:443 --password secret
```

### As a library

```rust
use trojan_client::{ClientArgs, run};
use tokio_util::sync::CancellationToken;

let token = CancellationToken::new();
run(client_config, token).await?;
```

## Configuration

```toml
[client]
listen = "127.0.0.1:1080"
remote = "server.example.com:443"
password = "your-password"

[client.tls]
sni = "server.example.com"
alpn = ["h2", "http/1.1"]
skip_verify = false
# ca = "/path/to/ca.pem"       # Custom CA certificate

[client.tcp]
no_delay = true
keepalive_secs = 60

[logging]
level = "info"
format = "pretty"
```

### Dual-stack SOCKS5 listener

To accept IPv4 and IPv6 on one TCP listening socket, configure:

```toml
[client]
listen = "[::]:1080"

[client.tcp]
ipv6_only = false
```

Set `ipv6_only = true` for IPv6-only listening. Omitting the option retains
the previous OS-default behavior; `127.0.0.1:1080` remains IPv4-only.

**Security:** SOCKS5 is unauthenticated. Binding to `[::]` exposes the proxy
on all IPv4 and IPv6 interfaces; restrict access with firewall rules. Keep
`127.0.0.1` for a local-only proxy.

### CLI Overrides

```bash
trojan client -c config.toml \
  --listen 127.0.0.1:1080 \
  --remote server:443 \
  --password secret \
  --skip-verify \
  --log-level debug
```

## License

GPL-3.0-only
