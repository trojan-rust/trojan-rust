# trojan-core

Core types and constants shared across all trojan-rs crates.

## Overview

This crate provides the foundational building blocks used by the trojan-rs workspace:

- **Default constants** — Timeout values, buffer sizes, TCP socket options, TLS version defaults, WebSocket defaults, and protocol constants
- **Error classification** — Standardized error type constants for metrics and logging
- **I/O utilities** — Bidirectional relay, `PrefixedStream` for prepending buffered data to a stream
- **Transport adapters** — WebSocket transport layer (feature-gated)

## Usage

```rust
use trojan_core::defaults;
use trojan_core::io::{relay_bidirectional, PrefixedStream};

// Access default configuration values
let timeout = defaults::DEFAULT_TCP_TIMEOUT_SECS; // 600
let nodelay = defaults::DEFAULT_TCP_NO_DELAY;     // true

// Relay data between two streams
let metrics = relay_bidirectional(&mut stream_a, &mut stream_b).await?;
```

## Features

| Feature | Description |
|---------|-------------|
| `websocket` | Enable WebSocket transport adapter |

## License

GPL-3.0-only
