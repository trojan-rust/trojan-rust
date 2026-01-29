# trojan-analytics

Connection event collection and ClickHouse export for trojan-rs.

## Overview

This crate provides detailed per-connection event tracking for traffic analysis, billing, and auditing:

- **Event collection** — Non-blocking, lock-free event recording with configurable buffer size
- **ClickHouse export** — Batched writes to ClickHouse for scalable analytics
- **Sampling** — Configurable sampling rate for high-traffic deployments
- **Privacy controls** — Options to mask IPs, truncate user IDs, and control SNI recording

## Architecture

```text
Connection Handler
    │
    ▼
EventCollector ──▶ Ring Buffer ──▶ Batch Writer ──▶ ClickHouse
    │                                    │
    └─ sampling check              fallback file
```

Events are recorded non-blocking via a bounded channel. A background task flushes events in batches to ClickHouse. Failed writes fall back to a local file.

## Usage

```rust
use trojan_analytics::{init, EventCollector, Protocol, TargetType};

// Initialize from config
let collector = init(config).await?;

// Record a connection event (builder pattern)
let event = collector.connection(conn_id, peer_addr)
    .user("user123")
    .target("example.com", 443, TargetType::Domain)
    .protocol(Protocol::Tcp)
    .transport(Transport::Tls);
// Event is automatically sent when the builder is dropped
```

## Configuration

```toml
[analytics]
enabled = true
server_id = "node-1"

[analytics.clickhouse]
url = "http://localhost:8123"
database = "trojan"

[analytics.sampling]
rate = 0.1  # 10% sampling

[analytics.privacy]
record_peer_ip = false
full_user_id = false
```

## License

GPL-3.0-only
