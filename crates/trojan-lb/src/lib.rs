//! Generic load balancer for trojan-rs.
//!
//! Provides round-robin, IP hash, least connections, failover, and
//! traffic-aware strategies with shared health and quota filtering.
//!
//! The [`LoadBalancer`] is `Send + Sync + 'static` and designed to be
//! shared across async tasks via `Arc<LoadBalancer>`.

pub mod guard;
mod node_state;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use guard::{BackendCounter, ConnectionGuard};
pub use node_state::{NodeStateStore, NodeStateView};

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
    /// Prefer routes with more remaining quota and fewer active connections.
    TrafficAware,
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

    /// Return the health recovery delay; the default requires explicit recovery.
    fn recovery_cooldown(&self) -> Duration {
        Duration::MAX
    }

    /// Select among eligible backends with normalized remaining capacities.
    fn select_with_capacity(
        &self,
        backends: &[Arc<Backend>],
        _capacity: &[f64],
        peer_ip: IpAddr,
    ) -> Option<usize> {
        self.select(backends, peer_ip)
    }
}

// ── Backend ──

/// A single backend destination with health and connection tracking state.
pub struct Backend {
    addr: String,
    /// Active connections used by least-connections and traffic-aware selection.
    pub(crate) active_conns: BackendCounter,
    /// Whether every selection policy may consider this backend.
    healthy: AtomicBool,
    /// When the backend was last marked unhealthy.
    last_failure: Mutex<Option<Instant>>,
}

impl Backend {
    fn new(addr: String) -> Self {
        Self {
            addr,
            active_conns: BackendCounter::new(),
            healthy: AtomicBool::new(true),
            last_failure: Mutex::new(None),
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
#[derive(Debug)]
pub struct Selection {
    /// The selected backend address.
    pub addr: String,
    /// Connection guard for every successful selection.
    /// Must be held alive for the duration of the connection.
    pub guard: Option<ConnectionGuard>,
}

// ── LoadBalancer ──

/// Generic load balancer holding backends and a pluggable policy.
pub struct LoadBalancer {
    backends: Vec<Arc<Backend>>,
    policy: Box<dyn LbPolicy>,
    strategy: LbStrategy,
    cooldown: Duration,
}

impl LoadBalancer {
    /// Create a new load balancer with the given addresses and strategy.
    ///
    /// Failed backends recover after `failover_cooldown` for every strategy.
    pub fn new(addrs: Vec<String>, strategy: LbStrategy, failover_cooldown: Duration) -> Self {
        let policy: Box<dyn LbPolicy> = match &strategy {
            LbStrategy::RoundRobin => Box::new(RoundRobin::new()),
            LbStrategy::IpHash => Box::new(IpHash),
            LbStrategy::LeastConnections => Box::new(LeastConnections),
            LbStrategy::Failover => Box::new(Failover {
                cooldown: failover_cooldown,
            }),
            LbStrategy::TrafficAware => Box::new(TrafficAware),
        };
        let mut balancer = Self::with_policy(addrs, policy, strategy);
        balancer.cooldown = failover_cooldown;
        balancer
    }

    /// Create a load balancer with a custom policy.
    ///
    /// Uses the policy's recovery delay before passing eligible backends to it.
    pub fn with_policy(
        addrs: Vec<String>,
        policy: Box<dyn LbPolicy>,
        strategy: LbStrategy,
    ) -> Self {
        let backends = addrs
            .into_iter()
            .map(|a| Arc::new(Backend::new(a)))
            .collect();
        let cooldown = policy.recovery_cooldown();
        Self {
            backends,
            policy,
            strategy,
            cooldown,
        }
    }

    /// Select a backend based on the policy and peer IP.
    pub fn select(&self, peer_ip: IpAddr) -> Result<Selection, LbError> {
        self.select_available(peer_ip, &[], |_| Some(1.0))
    }

    /// Select a backend that this connection has not already attempted.
    ///
    /// Exclusions apply even after cooldown expiry or when all backends are unhealthy.
    pub fn select_excluding(
        &self,
        peer_ip: IpAddr,
        excluded: &[String],
    ) -> Result<Selection, LbError> {
        self.select_available(peer_ip, excluded, |_| Some(1.0))
    }

    /// Filter health and quota before running any policy.
    ///
    /// `capacity` returns a remaining fraction in `(0, 1]`, or `None` when
    /// unavailable. Quota exclusions never recover through the health cooldown.
    pub fn select_available(
        &self,
        peer_ip: IpAddr,
        excluded: &[String],
        mut capacity: impl FnMut(&str) -> Option<f64>,
    ) -> Result<Selection, LbError> {
        if self.backends.is_empty() {
            return Err(LbError::NoBackends);
        }
        let mut backends = Vec::with_capacity(self.backends.len());
        let mut capacities = Vec::with_capacity(self.backends.len());
        for backend in &self.backends {
            if excluded.contains(&backend.addr) {
                continue;
            }
            let Some(remaining) = capacity(&backend.addr) else {
                continue;
            };
            if !(remaining > 0.0 && remaining <= 1.0) {
                continue;
            }
            if !backend.is_healthy() {
                let last_failure = backend
                    .last_failure
                    .lock()
                    .expect("backend health lock poisoned");
                if !last_failure.is_some_and(|when| when.elapsed() >= self.cooldown) {
                    continue;
                }
                // Serialize recovery with new failures so recovery cannot erase a newer failure.
                backend.healthy.store(true, Ordering::Relaxed);
            }
            backends.push(backend.clone());
            capacities.push(remaining);
        }
        if backends.is_empty() {
            return Err(LbError::NoHealthyBackend);
        }

        let idx = self
            .policy
            .select_with_capacity(&backends, &capacities, peer_ip)
            .ok_or(LbError::NoHealthyBackend)?;

        let backend = &backends[idx];

        // Guards also let traffic-aware selection account for ongoing transfers.
        let guard = Some(ConnectionGuard::acquire(&backend.active_conns));

        Ok(Selection {
            addr: backend.addr.clone(),
            guard,
        })
    }

    /// Exclude a backend from every policy until recovery.
    pub fn mark_unhealthy(&self, addr: &str) {
        for backend in &self.backends {
            if backend.addr == addr {
                let mut last_failure = backend
                    .last_failure
                    .lock()
                    .expect("backend health lock poisoned");
                *last_failure = Some(Instant::now());
                backend.healthy.store(false, Ordering::Relaxed);
                return;
            }
        }
    }

    /// Mark a backend as healthy.
    pub fn mark_healthy(&self, addr: &str) {
        for backend in &self.backends {
            if backend.addr == addr {
                let _last_failure = backend
                    .last_failure
                    .lock()
                    .expect("backend health lock poisoned");
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
#[derive(Debug)]
pub struct RoundRobin {
    counter: AtomicUsize,
}

impl Default for RoundRobin {
    fn default() -> Self {
        Self::new()
    }
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
#[derive(Debug)]
pub struct IpHash;

impl LbPolicy for IpHash {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "narrowing the hash on a 32-bit target only changes which \
                  backend a peer maps to, not that the mapping is stable"
    )]
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
#[derive(Debug)]
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
#[derive(Debug)]
pub struct Failover {
    pub cooldown: Duration,
}

impl LbPolicy for Failover {
    fn recovery_cooldown(&self) -> Duration {
        self.cooldown
    }

    fn select(&self, backends: &[Arc<Backend>], _peer_ip: IpAddr) -> Option<usize> {
        if backends.is_empty() {
            return None;
        }

        for (i, b) in backends.iter().enumerate() {
            if b.is_healthy() {
                return Some(i);
            }

            // Check cooldown: if enough time has passed, consider it recovered.
            let last_failure = b.last_failure.lock().expect("backend health lock poisoned");
            if last_failure.is_some_and(|when| when.elapsed() >= self.cooldown) {
                // Auto-recover
                b.healthy.store(true, Ordering::Relaxed);
                return Some(i);
            }
        }

        None
    }
}

/// Prefer the highest remaining fraction divided by active connections plus one.
#[derive(Debug)]
pub struct TrafficAware;

impl LbPolicy for TrafficAware {
    fn select(&self, backends: &[Arc<Backend>], peer_ip: IpAddr) -> Option<usize> {
        LeastConnections.select(backends, peer_ip)
    }

    fn select_with_capacity(
        &self,
        backends: &[Arc<Backend>],
        capacity: &[f64],
        _peer_ip: IpAddr,
    ) -> Option<usize> {
        let mut best = None;
        let mut best_score = -1.0;
        for (index, (backend, remaining)) in backends.iter().zip(capacity).enumerate() {
            let score = remaining / (backend.active_connections() as f64 + 1.0);
            if score > best_score {
                best = Some(index);
                best_score = score;
            }
        }
        best
    }
}

// ── Tests ──

#[cfg(test)]
mod tests;
