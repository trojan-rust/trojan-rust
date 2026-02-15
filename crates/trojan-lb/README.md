# trojan-lb

Generic load balancer for trojan-rs with four built-in strategies.

## Overview

This crate provides a thread-safe, pluggable load balancer for distributing connections across multiple backend servers:

- **Round Robin** — Cycles through backends sequentially
- **IP Hash** — Deterministically maps a client IP to a backend for session affinity
- **Least Connections** — Picks the backend with the fewest active connections (RAII-tracked)
- **Failover** — Always uses the first healthy backend, with automatic recovery after cooldown

## Usage

```rust
use trojan_lb::{LoadBalancer, LbStrategy};
use std::time::Duration;

let backends = vec![
    "backend-1:443".to_string(),
    "backend-2:443".to_string(),
    "backend-3:443".to_string(),
];

let lb = LoadBalancer::new(backends, LbStrategy::LeastConnections, Duration::from_secs(60));

// Select a backend
let selection = lb.select(peer_ip)?;
println!("Routing to {}", selection.addr);

// Hold the guard for the lifetime of the connection (tracks active connections)
let _guard = selection.guard;
```

### Health Management

```rust
// Mark backend as unhealthy (failover will skip it)
lb.mark_unhealthy("backend-1:443");

// Mark backend as healthy again
lb.mark_healthy("backend-1:443");
```

### Custom Policies

```rust
use trojan_lb::{LoadBalancer, LbPolicy, Backend, LbStrategy};
use std::sync::Arc;
use std::net::IpAddr;

struct MyPolicy;

impl LbPolicy for MyPolicy {
    fn select(&self, backends: &[Arc<Backend>], peer_ip: IpAddr) -> Option<usize> {
        // Custom selection logic
        Some(0)
    }
}

let lb = LoadBalancer::with_policy(
    backends,
    Box::new(MyPolicy),
    LbStrategy::RoundRobin,
    Duration::from_secs(60),
);
```

## Key Types

- **`LoadBalancer`** — Main entry point, `Send + Sync + 'static`, shareable via `Arc`
- **`LbStrategy`** — Serde-friendly enum for config files (`round_robin`, `ip_hash`, `least_connections`, `failover`)
- **`LbPolicy`** — Trait for custom selection logic
- **`Selection`** — Result with backend address and optional `ConnectionGuard`
- **`ConnectionGuard`** — RAII guard that tracks active connections (increments on create, decrements on drop)

## License

GPL-3.0-only
