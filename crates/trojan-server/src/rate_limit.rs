//! Per-IP rate limiting for connection throttling.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::RwLock;
use tokio::sync::Notify;
use tracing::debug;

/// Rate limiter that tracks connections per IP address.
pub struct RateLimiter {
    /// Map of IP -> (connection count, window start time)
    entries: Arc<RwLock<HashMap<IpAddr, RateLimitEntry>>>,
    /// Maximum connections allowed per IP in the time window
    max_connections: u32,
    /// Time window for rate limiting
    window: Duration,
    /// Notify for shutdown
    shutdown: Arc<Notify>,
}

#[derive(Clone)]
struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(max_connections_per_ip: u32, window_secs: u64) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_connections: max_connections_per_ip,
            window: Duration::from_secs(window_secs),
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Start the background cleanup task.
    pub fn start_cleanup_task(&self, cleanup_interval: Duration) {
        let entries = self.entries.clone();
        let window = self.window;
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.notified() => {
                        debug!("rate limiter cleanup task shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(cleanup_interval) => {
                        let now = Instant::now();
                        let mut map = entries.write();
                        let before = map.len();
                        map.retain(|_, entry| {
                            now.duration_since(entry.window_start) < window
                        });
                        let removed = before - map.len();
                        if removed > 0 {
                            debug!(removed, remaining = map.len(), "rate limit entries cleaned up");
                        }
                    }
                }
            }
        });
    }

    /// Check if a connection from the given IP is allowed.
    /// Returns true if allowed, false if rate limited.
    pub fn check_and_increment(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut map = self.entries.write();

        if let Some(entry) = map.get_mut(&ip) {
            // Check if window has expired
            if now.duration_since(entry.window_start) >= self.window {
                // Reset window
                entry.count = 1;
                entry.window_start = now;
                true
            } else if entry.count >= self.max_connections {
                // Rate limited
                false
            } else {
                // Increment and allow
                entry.count += 1;
                true
            }
        } else {
            // New IP, create entry
            map.insert(
                ip,
                RateLimitEntry {
                    count: 1,
                    window_start: now,
                },
            );
            true
        }
    }

    /// Signal shutdown to cleanup task.
    pub fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }
}

impl Drop for RateLimiter {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_allows_under_limit() {
        let limiter = RateLimiter::new(5, 60);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Should allow 5 connections
        for _ in 0..5 {
            assert!(limiter.check_and_increment(ip));
        }

        // 6th should be blocked
        assert!(!limiter.check_and_increment(ip));
    }

    #[test]
    fn test_rate_limit_different_ips() {
        let limiter = RateLimiter::new(2, 60);
        let ip1: IpAddr = "127.0.0.1".parse().unwrap();
        let ip2: IpAddr = "127.0.0.2".parse().unwrap();

        // Both IPs should get their own quota
        assert!(limiter.check_and_increment(ip1));
        assert!(limiter.check_and_increment(ip1));
        assert!(!limiter.check_and_increment(ip1)); // blocked

        assert!(limiter.check_and_increment(ip2));
        assert!(limiter.check_and_increment(ip2));
        assert!(!limiter.check_and_increment(ip2)); // blocked
    }

    #[test]
    fn test_rate_limit_window_reset() {
        // Use a very short window for testing
        let limiter = RateLimiter::new(1, 0); // 0 second window = always resets
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // First connection
        assert!(limiter.check_and_increment(ip));
        // Window has "expired" (0 seconds), so this resets and allows
        assert!(limiter.check_and_increment(ip));
    }
}
