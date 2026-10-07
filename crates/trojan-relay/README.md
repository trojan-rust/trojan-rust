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

New entries also send `ack=1`. Each relay connects to its target, then returns four bytes: `TR`, version `1`, and status `0` (connected), `1` (target connection failed), or `2` (authentication failed). The entry must receive success before sending the next hop's handshake or client data. Response frames never reach the client or exit.

Upgrade every relay in a chain before upgrading its entry. New relays accept legacy handshakes without adding response bytes. New entries require connection responses from every relay; old relays cannot serve new entries. A missing or invalid response fails the connection without changing destination health.

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
# Id this node is known by on the panel, for chain traffic attribution.
node_id = "entry-sh"

[chains.jp]
nodes = [
  { addr = "relay-hk:443", node_id = "relay-hk", password = "secret", transport = "tls", sni = "crates.io" },
]

[[rules]]
name = "japan"
listen = "127.0.0.1:1080"
chain = "jp"
dest = "trojan-jp:443"
# Tell the exit who the client is and which hops carried the connection.
# The exit must have `proxy_protocol` enabled, or it reads the header as a
# broken TLS handshake.
proxy_protocol = true

# Optional: serve /metrics, /health and /ready.
[metrics]
listen = "127.0.0.1:9101"
```

For destination failover, replace the rule's destination with a list:

```toml
dest = ["trojan-jp-1:443", "trojan-jp-2:443"]
strategy = "failover"
failover_cooldown_secs = 30
```

The entry retries a failed destination connection within the same client connection. Each destination address is attempted at most once per client connection, including when the cooldown is zero. Only a failed direct dial or an explicit failure from the final relay marks a destination unhealthy. Intermediate relay failures, authentication failures, and missing responses terminate the connection without marking a destination unhealthy. The other load-balancing strategies keep their existing selection behavior.

After payload forwarding starts, the entry must not retry: replaying client data could duplicate an operation. Cooldown recovery remains passive; a later selection retries the destination after the cooldown. If every destination is unhealthy, failover still attempts the configured destinations, with the same per-connection attempt limit.

Each transport connection uses `connect_timeout_secs`. Each relay response has a timeout of `connect_timeout_secs + handshake_timeout_secs` on the entry. Set relay connect timeouts no higher than the entry's connect timeout so relays can report dial timeouts before the entry stops waiting. Confirmations add one round trip per relay during tunnel setup.

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

That header is what `proxy_protocol = true` on a rule turns on. The entry
prefixes the tunnel with a PROXY v2 header naming the real client and listing
`node_id` for itself and every hop in the chain; relays forward it as ordinary
payload, and the exit reads it before the TLS handshake it precedes. Hops with
no `node_id` are left out of the list and go uncredited.

## License

GPL-3.0-only
