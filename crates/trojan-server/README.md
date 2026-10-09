# trojan-server

Target connections alternate resolved IPv4 and IPv6 addresses, starting another attempt after 250 ms. All attempts share a 10-second deadline. Named direct outbounds preserve their configured bind address and socket buffers. Trojan outbounds apply a 10-second deadline to resolution, TCP, TLS, and the request header together.

Destination metric labels are disabled by default. Set `metrics.per_target = true` only for a bounded destination set; global counters remain available with the option off.

Set `metrics.tls.cert`, `metrics.tls.key`, and `metrics.tls.client_ca` to require mutual TLS on the metrics listener. `/metrics`, health checks, and `/debug/rules/match` share that policy; the debug route also retains its loopback restriction. Existing HTTP configurations remain supported. Metrics TLS does not change proxy TLS or routing. See [configuration, Prometheus, and restart instructions](../trojan-metrics/README.md#mutual-tls). SIGHUP does not reload metrics certificates.

Shutdown closes every listener and allows established connections to drain for up to 30 seconds. After the deadline, the server closes and joins remaining connection tasks before returning.

TCP payloads and UDP responses count each successful stream write before flush. A cancelled or failed connection retains bytes accepted by the writer, including partial initial payloads and partial UDP frames.

UDP associations process up to 16 datagrams concurrently. DNS work and response backpressure do not block the opposite direction or idle expiry. Datagram completion order may differ from arrival order. The pending datagrams use at most 16 payload buffers in addition to `max_udp_buffer_bytes` and the response buffers.

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

Clients must authenticate within 10 seconds after TLS completes. This deadline
includes the WebSocket upgrade and authentication backend response. Authenticated
connections use the configured idle timeout.

UDP routing rules apply to each datagram destination. Rejected datagrams are
dropped. UDP supports DIRECT and named direct outbounds without a bind address;
other named outbounds are dropped because UDP forwarding through them is unsupported.

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

Run the [network benchmark](benches/network/README.md) to measure TCP/TLS throughput,
P99 latency, server CPU usage, and resident memory at different connection counts.

| Feature | Description |
|---------|-------------|
| `websocket` | WebSocket transport support |
| `analytics` | Connection event tracking |

## License

GPL-3.0-only
