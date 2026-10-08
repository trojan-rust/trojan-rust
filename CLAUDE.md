# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

Run these commands inside the tracked `devenv` environment, for example `devenv shell -- cargo test --workspace`.

```bash
# Build
cargo build --workspace
cargo build --release                          # optimized (LTO + strip)

# Test
cargo test --workspace                         # all tests
cargo test --workspace --all-features          # also the feature-gated tests
cargo test -p trojan-server                    # single crate
cargo test -p trojan-relay test_router_resolve # single test

# Lint (matches CI exactly)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Check (fast compile check)
cargo check --workspace --all-targets --all-features

# Benchmarks
cargo bench -p trojan-proto
```

**`--all-targets` does not imply `--all-features`.** Tests behind a feature —
`geoip_rules`, `analytics_clickhouse` — do not compile without it, so a change
that breaks them leaves the plain clippy and test runs green and fails CI.
Run both forms before pushing.

CI runs: check, fmt, clippy, test (linux/macos/windows), interop, analytics
(ClickHouse), coverage, doc, MSRV (1.90).

## Architecture

Cargo workspace with 19 crates plus the root `trojan` binary. Rust 2024 edition.

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
├── trojan-relay  ← trojan-transport, trojan-lb, trojan-core, trojan-proto, trojan-metrics
└── trojan-dash   ← trojan-auth (protocol), trojan-protocol, trojan-core
```

**Dashboard:** `trojan-dash` is the other end of `trojan-auth`'s HTTP backend —
an axum + SQLite service holding users, node tokens, traffic and subscription
templates. Both ends share one definition of the wire format
(`trojan_auth::protocol`, behind the `protocol` feature), so the contract cannot
drift. It also serves `/ws/agent`, where `trojan-agent` registers with its node
token, receives its service config, and reports heartbeats, durable node traffic, and per-user traffic
(`trojan_protocol`, shared the same way). Its web UI lives in a separate
repository and is served from `panel_dir` as static files.

**Traffic accounting:** every service records node totals in Prometheus and `NodeStats`.
The agent persists samples until the dashboard acknowledges committed reports.
The dashboard keeps timestamped node history and monthly quota policies separate from user quotas.
Agent protocol version 1 enables node accounting only after both WebSocket peers negotiate `x-trojan-node-traffic: 1`.
Live node snapshots let managed entries filter unavailable relay paths and exits without restarting services.
User-level accounting for a chain is attributed by the exit: entry and relay
nodes never learn whose bytes they carry, so the entry prefixes each tunnel
with a PROXY protocol v2 header (real client + chain node ids), and the exit
credits each hop over `/traffic/chain` when it settles the user.

**Standalone utility crates (no trojan internal dependencies):**
- `trojan-transport` — `TransportAcceptor`/`TransportConnector` traits + plain/TLS/WS implementations
- `trojan-config` — loads TOML/YAML/JSON/JSONC via serde. It owns the shape of a
  node's config file, not every crate's settings: analytics, GeoIP acquisition
  and the like are defined by the crate that reads them
- `trojan-proto` — zero-copy Trojan protocol parser using `bytes::BytesMut`

`trojan-lb` provides `LbPolicy`, five selection strategies, and live node budgets. It depends on `trojan-protocol` for node snapshots.

**Key trait abstractions:**
- `AuthBackend` (trojan-auth) — `verify_password()`, `record_traffic()`, `record_chain_traffic()` with Memory/SQL/Reloadable impls
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
trojan dash -c dash.toml            # dashboard service (admin API + panel)
trojan auth init --database sqlite://users.db
trojan cert generate --domain example.com --output /etc/trojan
```

## Docker

```bash
docker buildx build -t trojan-rs .                              # build image
docker buildx build --target export --output type=local,dest=out .  # extract binary
```

3-stage Dockerfile: build (debian bullseye) → runtime (bullseye-slim) → export (scratch).
