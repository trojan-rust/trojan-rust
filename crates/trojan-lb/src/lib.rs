//! Generic load balancer for trojan-rs.
//!
//! Provides a trait-based load balancing abstraction with four built-in
//! strategies: round-robin, IP hash, least connections, and failover.
//!
//! The [`LoadBalancer`] is `Send + Sync + 'static` and designed to be
//! shared across async tasks via `Arc<LoadBalancer>`.

pub mod guard;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

pub use guard::{BackendCounter, ConnectionGuard};

// ── Errors ──

#[derive(Error, Debug)]
pub enum LbError {
    #[error("no backends configured")]
    NoBackends,

    #[error("no healthy backend available")]
    NoHealthyBackend,
}

// ── Strategy enum (for serde config) ──

/// Load balancing strategy identifier, used in configuration files.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LbStrategy {
    #[default]
    RoundRobin,
    IpHash,
    LeastConnections,
    Failover,
}

// ── Policy trait ──

/// Trait for load balancing policies.
///
/// Implementations receive a slice of [`Backend`] references and the
/// client's IP address, and return the index of the selected backend.
pub trait LbPolicy: Send + Sync + 'static {
    /// Select a backend index from `backends`.
    ///
    /// Returns `None` if no suitable backend is available.
    fn select(&self, backends: &[Arc<Backend>], peer_ip: IpAddr) -> Option<usize>;
}

// ── Backend ──

/// A single backend destination with health and connection tracking state.
pub struct Backend {
    addr: String,
    /// Active connection count (used by LeastConnections).
    pub(crate) active_conns: BackendCounter,
    /// Whether this backend is considered healthy (used by Failover).
    healthy: AtomicBool,
    /// When the backend was last marked unhealthy.
    last_failure: RwLock<Option<Instant>>,
}

impl Backend {
    fn new(addr: String) -> Self {
        Self {
            addr,
            active_conns: BackendCounter::new(),
            healthy: AtomicBool::new(true),
            last_failure: RwLock::new(None),
        }
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn active_connections(&self) -> usize {
        self.active_conns.load()
    }
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backend")
            .field("addr", &self.addr)
            .field("active_conns", &self.active_conns.load())
            .field("healthy", &self.is_healthy())
            .finish()
    }
}

// ── Selection result ──

/// Result of a load balancer selection.
pub struct Selection {
    /// The selected backend address.
    pub addr: String,
    /// Optional connection guard (present for LeastConnections).
    /// Must be held alive for the duration of the connection.
    pub guard: Option<ConnectionGuard>,
}

// ── LoadBalancer ──

/// Generic load balancer holding backends and a pluggable policy.
pub struct LoadBalancer {
    backends: Vec<Arc<Backend>>,
    policy: Box<dyn LbPolicy>,
    strategy: LbStrategy,
    #[allow(dead_code)]
    failover_cooldown: Duration,
}

impl LoadBalancer {
    /// Create a new load balancer with the given addresses and strategy.
    pub fn new(
        addrs: Vec<String>,
        strategy: LbStrategy,
        failover_cooldown: Duration,
    ) -> Self {
        let policy: Box<dyn LbPolicy> = match &strategy {
            LbStrategy::RoundRobin => Box::new(RoundRobin::new()),
            LbStrategy::IpHash => Box::new(IpHash),
            LbStrategy::LeastConnections => Box::new(LeastConnections),
            LbStrategy::Failover => Box::new(Failover { cooldown: failover_cooldown }),
        };
        Self::with_policy(addrs, policy, strategy, failover_cooldown)
    }

    /// Create a load balancer with a custom policy.
    pub fn with_policy(
        addrs: Vec<String>,
        policy: Box<dyn LbPolicy>,
        strategy: LbStrategy,
        failover_cooldown: Duration,
    ) -> Self {
        let backends = addrs.into_iter().map(|a| Arc::new(Backend::new(a))).collect();
        Self {
            backends,
            policy,
            strategy,
            failover_cooldown,
        }
    }

    /// Select a backend based on the policy and peer IP.
    pub fn select(&self, peer_ip: IpAddr) -> Result<Selection, LbError> {
        if self.backends.is_empty() {
            return Err(LbError::NoBackends);
        }

        let idx = self.policy.select(&self.backends, peer_ip)
            .ok_or(LbError::NoHealthyBackend)?;

        let backend = &self.backends[idx];

        // For LeastConnections, acquire a guard to track active connections.
        // For other strategies, no guard is needed — we detect this by checking
        // if the policy is LeastConnections via a marker method would be over-
        // engineering. Instead, always acquire a guard; for non-LC strategies
        // the overhead is two atomic ops which is negligible.
        let guard = Some(ConnectionGuard::acquire(&backend.active_conns));

        Ok(Selection {
            addr: backend.addr.clone(),
            guard,
        })
    }

    /// Mark a backend as unhealthy (for failover).
    pub fn mark_unhealthy(&self, addr: &str) {
        for backend in &self.backends {
            if backend.addr == addr {
                backend.healthy.store(false, Ordering::Relaxed);
                // Non-blocking: spawn a task-local write. Since this is
                // called rarely (on failure), blocking briefly is acceptable.
                let last_failure = &backend.last_failure;
                // Use try_write to avoid blocking; if contended, the timestamp
                // is "close enough" from the previous write.
                if let Ok(mut guard) = last_failure.try_write() {
                    *guard = Some(Instant::now());
                }
                return;
            }
        }
    }

    /// Mark a backend as healthy.
    pub fn mark_healthy(&self, addr: &str) {
        for backend in &self.backends {
            if backend.addr == addr {
                backend.healthy.store(true, Ordering::Relaxed);
                return;
            }
        }
    }

    /// Number of backends.
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }

    /// Whether this load balancer uses the failover strategy.
    pub fn is_failover(&self) -> bool {
        self.strategy == LbStrategy::Failover
    }

    /// The configured strategy.
    pub fn strategy(&self) -> &LbStrategy {
        &self.strategy
    }
}

impl std::fmt::Debug for LoadBalancer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadBalancer")
            .field("backends", &self.backends)
            .field("backend_count", &self.backends.len())
            .finish()
    }
}

// ── Built-in policies ──

/// Round-robin policy: cycles through backends sequentially.
pub struct RoundRobin {
    counter: AtomicUsize,
}

impl RoundRobin {
    pub fn new() -> Self {
        Self {
            counter: AtomicUsize::new(0),
        }
    }
}

impl LbPolicy for RoundRobin {
    fn select(&self, backends: &[Arc<Backend>], _peer_ip: IpAddr) -> Option<usize> {
        if backends.is_empty() {
            return None;
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % backends.len();
        Some(idx)
    }
}

/// IP hash policy: deterministically maps a client IP to a backend.
pub struct IpHash;

impl LbPolicy for IpHash {
    fn select(&self, backends: &[Arc<Backend>], peer_ip: IpAddr) -> Option<usize> {
        if backends.is_empty() {
            return None;
        }
        let mut hasher = DefaultHasher::new();
        peer_ip.hash(&mut hasher);
        let hash = hasher.finish();
        Some((hash as usize) % backends.len())
    }
}

/// Least connections policy: picks the backend with the fewest active connections.
pub struct LeastConnections;

impl LbPolicy for LeastConnections {
    fn select(&self, backends: &[Arc<Backend>], _peer_ip: IpAddr) -> Option<usize> {
        if backends.is_empty() {
            return None;
        }
        let mut min_idx = 0;
        let mut min_conns = backends[0].active_connections();
        for (i, b) in backends.iter().enumerate().skip(1) {
            let conns = b.active_connections();
            if conns < min_conns {
                min_conns = conns;
                min_idx = i;
            }
        }
        Some(min_idx)
    }
}

/// Failover policy: always picks the first healthy backend.
/// Unhealthy backends recover after a cooldown period.
pub struct Failover {
    pub cooldown: Duration,
}

impl LbPolicy for Failover {
    fn select(&self, backends: &[Arc<Backend>], _peer_ip: IpAddr) -> Option<usize> {
        if backends.is_empty() {
            return None;
        }

        for (i, b) in backends.iter().enumerate() {
            if b.is_healthy() {
                return Some(i);
            }

            // Check cooldown: if enough time has passed, consider it recovered.
            if let Ok(guard) = b.last_failure.try_read() {
                if let Some(when) = *guard {
                    if when.elapsed() >= self.cooldown {
                        // Auto-recover
                        b.healthy.store(true, Ordering::Relaxed);
                        return Some(i);
                    }
                }
            }
        }

        // All backends unhealthy and within cooldown — return first as last resort.
        Some(0)
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn addrs(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("backend-{}:443", i)).collect()
    }

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    // ── RoundRobin ──

    #[test]
    fn round_robin_cycles() {
        let lb = LoadBalancer::new(addrs(3), LbStrategy::RoundRobin, Duration::ZERO);
        let results: Vec<String> = (0..6)
            .map(|_| lb.select(localhost()).unwrap().addr)
            .collect();
        assert_eq!(results, vec![
            "backend-0:443", "backend-1:443", "backend-2:443",
            "backend-0:443", "backend-1:443", "backend-2:443",
        ]);
    }

    #[test]
    fn round_robin_single() {
        let lb = LoadBalancer::new(addrs(1), LbStrategy::RoundRobin, Duration::ZERO);
        for _ in 0..5 {
            assert_eq!(lb.select(localhost()).unwrap().addr, "backend-0:443");
        }
    }

    // ── IpHash ──

    #[test]
    fn ip_hash_consistent() {
        let lb = LoadBalancer::new(addrs(5), LbStrategy::IpHash, Duration::ZERO);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let first = lb.select(ip).unwrap().addr;
        for _ in 0..20 {
            assert_eq!(lb.select(ip).unwrap().addr, first);
        }
    }

    #[test]
    fn ip_hash_distributes() {
        let lb = LoadBalancer::new(addrs(3), LbStrategy::IpHash, Duration::ZERO);
        let mut seen = std::collections::HashSet::new();
        // Try many different IPs — should hit multiple backends
        for i in 0..100u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            seen.insert(lb.select(ip).unwrap().addr);
        }
        assert!(seen.len() > 1, "IP hash should distribute across backends");
    }

    #[test]
    fn ip_hash_ipv6() {
        let lb = LoadBalancer::new(addrs(3), LbStrategy::IpHash, Duration::ZERO);
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let result = lb.select(ip).unwrap();
        assert!(result.addr.starts_with("backend-"));
    }

    // ── LeastConnections ──

    #[test]
    fn least_connections_picks_minimum() {
        let lb = LoadBalancer::new(addrs(3), LbStrategy::LeastConnections, Duration::ZERO);

        // Acquire guards on backend-0 and backend-1
        let _g0 = lb.select(localhost()).unwrap().guard; // backend-0 gets 1 conn
        let _g1a = lb.select(localhost()).unwrap().guard; // backend-1 gets 1 conn (0 already has 1)

        // Wait, LeastConnections picks min. After first select, backend-0 has 1.
        // Second select: backend-1 has 0 (min), so it picks backend-1.
        // Third select: backend-2 has 0 (min), so it picks backend-2.
        // Fourth select: backend-1 and backend-2 both have 1, backend-0 has 1 — picks backend-0 (first min).

        // Actually let's verify step by step.
        let lb = LoadBalancer::new(addrs(3), LbStrategy::LeastConnections, Duration::ZERO);
        let s0 = lb.select(localhost()).unwrap();
        assert_eq!(s0.addr, "backend-0:443"); // all at 0, picks first

        let s1 = lb.select(localhost()).unwrap();
        assert_eq!(s1.addr, "backend-1:443"); // 0 has 1, 1 has 0

        let s2 = lb.select(localhost()).unwrap();
        assert_eq!(s2.addr, "backend-2:443"); // 0 has 1, 1 has 1, 2 has 0

        // Now all have 1
        let s3 = lb.select(localhost()).unwrap();
        assert_eq!(s3.addr, "backend-0:443"); // all at 1, picks first

        // Drop s1 → backend-1 goes to 0
        drop(s1);
        let s4 = lb.select(localhost()).unwrap();
        assert_eq!(s4.addr, "backend-1:443"); // 0:2, 1:0, 2:1
    }

    // ── Failover ──

    #[test]
    fn failover_prefers_first() {
        let lb = LoadBalancer::new(addrs(3), LbStrategy::Failover, Duration::from_secs(60));
        for _ in 0..5 {
            assert_eq!(lb.select(localhost()).unwrap().addr, "backend-0:443");
        }
    }

    #[test]
    fn failover_skips_unhealthy() {
        let lb = LoadBalancer::new(addrs(3), LbStrategy::Failover, Duration::from_secs(60));
        lb.mark_unhealthy("backend-0:443");
        assert_eq!(lb.select(localhost()).unwrap().addr, "backend-1:443");

        lb.mark_unhealthy("backend-1:443");
        assert_eq!(lb.select(localhost()).unwrap().addr, "backend-2:443");
    }

    #[test]
    fn failover_recovers_after_cooldown() {
        let lb = LoadBalancer::new(addrs(2), LbStrategy::Failover, Duration::from_millis(50));
        lb.mark_unhealthy("backend-0:443");
        assert_eq!(lb.select(localhost()).unwrap().addr, "backend-1:443");

        // Wait for cooldown
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(lb.select(localhost()).unwrap().addr, "backend-0:443");
    }

    #[test]
    fn failover_all_unhealthy_returns_first() {
        let lb = LoadBalancer::new(addrs(2), LbStrategy::Failover, Duration::from_secs(60));
        lb.mark_unhealthy("backend-0:443");
        lb.mark_unhealthy("backend-1:443");
        // Falls back to first
        assert_eq!(lb.select(localhost()).unwrap().addr, "backend-0:443");
    }

    #[test]
    fn failover_mark_healthy_recovers() {
        let lb = LoadBalancer::new(addrs(2), LbStrategy::Failover, Duration::from_secs(60));
        lb.mark_unhealthy("backend-0:443");
        assert_eq!(lb.select(localhost()).unwrap().addr, "backend-1:443");

        lb.mark_healthy("backend-0:443");
        assert_eq!(lb.select(localhost()).unwrap().addr, "backend-0:443");
    }

    // ── Edge cases ──

    #[test]
    fn empty_backends_error() {
        let lb = LoadBalancer::new(vec![], LbStrategy::RoundRobin, Duration::ZERO);
        assert!(lb.select(localhost()).is_err());
    }

    #[test]
    fn send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LoadBalancer>();
    }
}
