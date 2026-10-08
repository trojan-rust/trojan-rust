# trojan-lb

Generic load balancer for trojan-rs with five built-in strategies and live node budgets.

## Overview

This crate provides a thread-safe, pluggable load balancer for distributing connections across multiple backend servers:

- **Round Robin** — Cycles through backends sequentially
- **IP Hash** — Deterministically maps a client IP to a backend for session affinity
- **Least Connections** — Picks the backend with the fewest active connections (RAII-tracked)
- **Failover** — Always uses the first healthy backend, with automatic recovery after cooldown
- **Traffic Aware** — Maximizes remaining quota fraction divided by active connections plus one

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

Call `select_excluding(peer_ip, &attempted_addresses)` when retrying a connection. The excluded addresses cannot be selected again, even if their cooldown has expired or every remaining backend is unhealthy.

Call `select_available(peer_ip, &attempted_addresses, capacity)` to apply node quotas. The callback returns a remaining fraction in `(0, 1]`, or `None` for an unavailable route. A route uses the minimum fraction across its entry, relays, and exit. Unlimited nodes have a fraction of `1`. Equal scores prefer configuration order.

Every strategy excludes unhealthy and unavailable backends. An empty eligible pool returns an error. Health cooldowns never restore depleted quota. `NodeStateStore` accepts live panel snapshots; missing, disabled, offline, depleted, expired, and old-period states are unavailable until a fresh snapshot arrives. Existing connections keep their guards and continue forwarding.

### Health Management

```rust
// All strategies skip unhealthy backends until the cooldown expires.
lb.mark_unhealthy("backend-1:443");

// Mark backend as healthy again
lb.mark_healthy("backend-1:443");
```

### Custom Policies

Custom policies receive eligible backends only. `with_policy` uses the policy's `recovery_cooldown`; the default requires explicit `mark_healthy` recovery. `Failover` provides its configured cooldown.

```rust
use trojan_lb::{LoadBalancer, LbPolicy, Backend, LbStrategy};
use std::sync::Arc;
use std::net::IpAddr;

struct MyPolicy;

impl LbPolicy for MyPolicy {
    fn select(&self, backends: &[Arc<Backend>], peer_ip: IpAddr) -> Option<usize> {
        (!backends.is_empty()).then_some(0)
    }
}

let lb = LoadBalancer::with_policy(
    vec!["backend-1:443".to_string()],
    Box::new(MyPolicy),
    LbStrategy::RoundRobin,
);
```

## Key Types

- **`LoadBalancer`** — Main entry point, `Send + Sync + 'static`, shareable via `Arc`
- **`LbStrategy`** — Serde-friendly enum for config files (`round_robin`, `ip_hash`, `least_connections`, `failover`, `traffic_aware`)
- **`LbPolicy`** — Trait for custom selection logic
- **`Selection`** — Result with backend address and optional `ConnectionGuard`
- **`ConnectionGuard`** — RAII guard that tracks active connections (increments on create, decrements on drop)

## License

GPL-3.0-only
