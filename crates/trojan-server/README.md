# trojan-server

High-performance Trojan protocol server implementation.

## Overview

This crate contains the complete server runtime:

- **TLS termination** — rustls-based TLS with configurable versions, cipher suites, and mTLS
- **Protocol handling** — TCP proxy (CONNECT) and UDP relay (UDP ASSOCIATE)
- **WebSocket transport** — Optional WebSocket encapsulation for CDN traversal (mixed or split mode)
- **Fallback server** — Non-Trojan traffic is forwarded to a configurable backend, with optional connection warm pool
- **Rate limiting** — Per-IP connection throttling with automatic cleanup
- **TCP tuning** — TCP_NODELAY, Keep-Alive, SO_REUSEPORT, TCP Fast Open
- **Graceful shutdown** — Connection draining on SIGTERM/SIGINT, config reload on SIGHUP (Unix)

## Architecture

```text
Client ──TLS──▶ Acceptor ──▶ Protocol Parser
                                │
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
                TCP Handler  UDP Handler  Fallback
                    │           │           │
                    ▼           ▼           ▼
                 Target      UDP Relay   HTTP Backend
```

## Usage

### As a binary (via main crate)

```bash
trojan server -c config.toml
```

### As a library

```rust
use trojan_server::{run_with_shutdown, CancellationToken};
use trojan_config::Config;

let token = CancellationToken::new();
run_with_shutdown(config, token.clone()).await?;
```

## Features

| Feature | Description |
|---------|-------------|
| `websocket` | WebSocket transport support |
| `analytics` | Connection event tracking |

## License

GPL-3.0-only
