# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Build
cargo build --workspace
cargo build --release                          # optimized (LTO + strip)

# Test
cargo test --workspace                         # all tests
cargo test -p trojan-server                    # single crate
cargo test -p trojan-relay test_router_resolve # single test

# Lint (matches CI exactly)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Check (fast compile check)
cargo check --workspace --all-targets

# Benchmarks
cargo bench -p trojan-proto
```

CI runs: check, fmt, clippy, test (linux/macos/windows), doc, MSRV (1.90).

## Architecture

Cargo workspace with 13 crates. Rust 2024 edition, version 0.4.0.

**Three roles in the network:**
- **Entry (A)** — accepts client SOCKS5 connections, builds multi-hop tunnel, does NOT parse Trojan protocol
- **Relay (B)** — authenticates relay password, forwards to next hop, does NOT know final target
- **Exit (C)** — standard trojan-server, authenticates client via Trojan protocol, connects to target

```
Client → A(entry) → B1(relay) → ... → C(trojan-server) → Target
```

**Crate dependency flow:**

```
trojan (unified CLI binary)
├── trojan-server ← trojan-core, trojan-proto, trojan-auth, trojan-config, trojan-metrics
├── trojan-client ← trojan-proto, trojan-auth, trojan-config
└── trojan-relay  ← trojan-transport, trojan-lb, trojan-core, trojan-proto
```

**Standalone utility crates (no trojan internal dependencies):**
- `trojan-transport` — `TransportAcceptor`/`TransportConnector` traits + plain/TLS/WS implementations
- `trojan-lb` — `LbPolicy` trait + round-robin, IP hash, least-connections, failover strategies
- `trojan-config` — loads TOML/YAML/JSON/JSONC via serde
- `trojan-proto` — zero-copy Trojan protocol parser using `bytes::BytesMut`

**Key trait abstractions:**
- `AuthBackend` (trojan-auth) — `verify_password()`, `record_traffic()` with Memory/SQL/Reloadable impls
- `TransportAcceptor`/`TransportConnector` (trojan-transport) — pluggable transport layer
- `LbPolicy` (trojan-lb) — `fn select(&self, backends, peer_ip) -> Option<usize>`

## Patterns & Conventions

- **Async runtime:** Tokio multi-threaded. All I/O is async.
- **Error handling:** `thiserror` enums per crate (e.g., `ServerError`, `RelayError`, `TransportError`).
- **Graceful shutdown:** `tokio_util::sync::CancellationToken` propagated through all long-lived tasks.
- **Config reload:** SIGHUP triggers `ReloadableAuth` refresh (Unix only).
- **Password hashing:** SHA-224 hex encoding (Trojan protocol spec). Auth uses constant-time comparison.
- **Serde patterns:** `#[serde(default)]` for optional fields, `#[serde(untagged)]` for one-or-many deserialization (e.g., `dest` in relay config accepts string or array).
- **TLS:** rustls with `aws_lc_rs` crypto backend. No OpenSSL.
- **Logging:** `tracing` + `tracing-subscriber` with structured fields.
- **Metrics:** `metrics` crate → Prometheus exporter via Axum HTTP server on `/metrics`.

## Running

```bash
trojan server -c config.toml        # exit node (trojan-server)
trojan client -c client.toml        # SOCKS5 proxy client
trojan entry -c entry.toml          # relay entry node
trojan relay -c relay.toml          # relay middle node
trojan auth init --database sqlite://users.db
trojan cert generate --domain example.com --output /etc/trojan
```

## Docker

```bash
docker buildx build -t trojan-rs .                              # build image
docker buildx build --target export --output type=local,dest=out .  # extract binary
```

3-stage Dockerfile: build (debian bullseye) → runtime (bullseye-slim) → export (scratch).
