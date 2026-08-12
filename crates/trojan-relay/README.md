# trojan-relay

Multi-hop relay chain for trojan-rs, enabling flexible traffic routing through intermediate nodes.

## Overview

This crate implements the relay chain system:

- **Entry Node (A)** — Accepts client TCP connections, constructs multi-hop tunnels via named chains and rule-based routing
- **Relay Node (B)** — Pluggable transport listener (TLS or plain TCP), authenticates upstream via relay handshake, forwards traffic to next hop
- **Pluggable Transport** — `TransportAcceptor`/`TransportConnector` traits with TLS and plain TCP implementations
- **Per-hop Transport Control** — Entry tells each relay what transport/SNI to use via handshake metadata
- **Auto-generated TLS Certs** — Relay nodes generate self-signed ECDSA certificates at startup via `rcgen`

## Architecture

```text
Client ──TCP──▶ A(entry) ──TLS──▶ B1(relay) ──Plain──▶ B2(relay) ──Plain──▶ C(trojan-server)
                  │                   │                    │
                  │ match rule        │ verify password    │ verify password
                  │ lookup chain      │ read metadata      │ read metadata
                  │ build tunnel      │ connect next hop   │ connect dest
```

### Relay Handshake Protocol

```text
hex(SHA224(password)) CRLF
target_addr:port      CRLF
metadata (key=value)  CRLF
```

Metadata carries `transport=tls|plain` and `sni=...` hints for per-hop control.

## Usage

### As a library

```rust
use trojan_relay::{entry, relay};
use tokio_util::sync::CancellationToken;

// Start a relay node
let config: relay::RelayConfig = toml::from_str(&config_str)?;
relay::run(config, CancellationToken::new()).await?;

// Start an entry node
let config: entry::EntryConfig = toml::from_str(&config_str)?;
entry::run(config, CancellationToken::new()).await?;
```

## Configuration

### Entry Node

```toml
[chains.jp]
nodes = [
  { addr = "relay-hk:443", password = "secret", transport = "tls", sni = "crates.io" },
]

[[rules]]
name = "japan"
listen = "127.0.0.1:1080"
chain = "jp"
dest = "trojan-jp:443"

# Optional: serve /metrics, /health and /ready.
[metrics]
listen = "127.0.0.1:9101"
```

### Relay Node

```toml
[relay]
listen = "0.0.0.0:443"
transport = "tls"

[relay.auth]
password = "secret"

[relay.outbound]
sni = "crates.io"

[metrics]
listen = "127.0.0.1:9102"
```

## Traffic accounting

Both node types count the bytes they carry. Totals go to two places: the
Prometheus exporter above (`trojan_bytes_received_total`,
`trojan_bytes_sent_total`, `trojan_connections_active`, plus
`trojan_entry_rule_bytes_total{rule,direction}` on entry nodes), and an
in-process `NodeStats` handle that `entry::run_with_stats` /
`relay::run_with_stats` accumulate into, which the panel agent drains for its
heartbeats.

This is node-level only. Entry and relay nodes never see who the traffic
belongs to — the client's trojan handshake is inside end-to-end TLS that only
the exit server terminates — so per-user accounting for a chain is attributed
by the exit, which knows both the user and (via the entry's PROXY protocol
header) the chain the connection came through.

## License

GPL-3.0-only
