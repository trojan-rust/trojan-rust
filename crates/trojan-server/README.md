# trojan-server

High-performance Trojan protocol server implementation.

## Overview

This crate contains the complete server runtime:

- **TLS termination** — rustls-based TLS with configurable versions, cipher suites, and mTLS
- **Protocol handling** — TCP proxy (CONNECT) and UDP relay (UDP ASSOCIATE)
- **WebSocket transport** — Optional WebSocket encapsulation for CDN traversal (mixed or split mode)
- **Fallback server** — Non-Trojan traffic is forwarded to a configurable backend, with optional connection warm pool
- **Rate limiting** — Per-IP connection throttling with automatic cleanup
- **PROXY protocol** — Optional v2 header from trusted senders, naming the real client and the relay chain
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

## Behind a relay chain or load balancer

Every connection through a proxy arrives from the proxy's address, so without
help the server rate-limits, geo-tags and logs the hop instead of the client.
List the senders whose PROXY protocol v2 header should be believed:

```toml
[server.proxy_protocol]
# Addresses or CIDR blocks. Empty (the default) turns the feature off — a
# header is a claim about someone else, and believing anyone would let a
# client pick the address it is limited as and the nodes it is billed to.
trusted = ["10.0.0.0/24", "203.0.113.7"]
```

Trusted senders may still connect directly: a connection without a header is
attributed to its own address, as before. Headers written by `trojan entry`
also carry the chain's node ids, and the server credits those hops when it
reports the connection's traffic — they cannot report it themselves, having
never seen whose traffic they carried.

## Features

| Feature | Description |
|---------|-------------|
| `websocket` | WebSocket transport support |
| `analytics` | Connection event tracking |

## License

GPL-3.0-only
