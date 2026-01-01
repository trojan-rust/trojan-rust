//! Connection pool for fallback backend.
//!
//! Warm pool strategy: pre-connect N fresh connections and hand them out once.
//! Connections are not returned to the pool after use.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use tokio::net::TcpStream;
use tracing::debug;
use trojan_metrics::{record_fallback_pool_warm_fail, set_fallback_pool_size};

/// A pooled connection with metadata.
struct PooledConnection {
    stream: TcpStream,
    created_at: Instant,
}

/// Connection pool for a single backend address.
pub struct ConnectionPool {
    addr: SocketAddr,
    connections: Arc<Mutex<VecDeque<PooledConnection>>>,
    max_idle: usize,
    max_age: Duration,
    fill_batch: usize,
    fill_delay: Duration,
}

impl ConnectionPool {
    /// Create a new connection pool.
    pub fn new(
        addr: SocketAddr,
        max_idle: usize,
        max_age_secs: u64,
        fill_batch: usize,
        fill_delay_ms: u64,
    ) -> Self {
        let pool = Self {
            addr,
            connections: Arc::new(Mutex::new(VecDeque::new())),
            max_idle,
            max_age: Duration::from_secs(max_age_secs),
            fill_batch,
            fill_delay: Duration::from_millis(fill_delay_ms),
        };
        set_fallback_pool_size(0);
        pool
    }

    /// Get a fresh connection from the pool or create a new one.
    pub async fn get(&self) -> std::io::Result<TcpStream> {
        // Pop one fresh connection if available
        let pooled = {
            let mut pool = self.connections.lock();
            let pooled = pool.pop_front();
            set_fallback_pool_size(pool.len());
            pooled
        };
        if let Some(pooled) = pooled {
            if pooled.created_at.elapsed() < self.max_age {
                debug!(addr = %self.addr, "using pooled connection");
                return Ok(pooled.stream);
            }
            debug!(addr = %self.addr, "discarding expired pooled connection");
        }

        // No valid pooled connection, create new one
        debug!(addr = %self.addr, "creating new connection");
        TcpStream::connect(self.addr).await
    }

    /// Warm pool maintains fresh connections; used connections are not returned.
    /// Clean up expired connections.
    pub fn cleanup(&self) {
        let mut pool = self.connections.lock();
        let before = pool.len();
        pool.retain(|conn| conn.created_at.elapsed() < self.max_age);
        let removed = before - pool.len();
        set_fallback_pool_size(pool.len());
        if removed > 0 {
            debug!(addr = %self.addr, removed, remaining = pool.len(), "cleaned up expired connections");
        }
    }

    /// Start a background warm-fill task.
    pub fn start_cleanup_task(self: &Arc<Self>, interval: Duration) {
        let pool = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                pool.cleanup();
                pool.warm_fill().await;
            }
        });
    }

    /// Get current pool size.
    pub fn size(&self) -> usize {
        self.connections.lock().len()
    }

    /// Fill the pool with fresh connections up to max_idle.
    async fn warm_fill(&self) {
        let need = {
            let pool = self.connections.lock();
            if pool.len() >= self.max_idle {
                return;
            }
            self.max_idle - pool.len()
        };
        if need == 0 {
            return;
        }
        let batch = self.fill_batch.min(need);
        for idx in 0..batch {
            match TcpStream::connect(self.addr).await {
                Ok(stream) => {
                    let mut pool = self.connections.lock();
                    if pool.len() < self.max_idle {
                        pool.push_back(PooledConnection {
                            stream,
                            created_at: Instant::now(),
                        });
                        set_fallback_pool_size(pool.len());
                        debug!(addr = %self.addr, size = pool.len(), "warm connection added");
                    }
                }
                Err(err) => {
                    record_fallback_pool_warm_fail();
                    debug!(addr = %self.addr, error = %err, "warm connection failed");
                    break;
                }
            }
            if self.fill_delay > Duration::from_millis(0) && idx + 1 < batch {
                tokio::time::sleep(self.fill_delay).await;
            }
        }
    }
}

#[cfg(test)]
impl ConnectionPool {
    async fn warm_fill_once(&self) {
        self.warm_fill().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[tokio::test]
    async fn test_pool_basic() {
        // Start a simple TCP listener
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept connections in background
        std::thread::spawn(move || {
            while let Ok((_, _)) = listener.accept() {
                // Just accept, don't do anything
            }
        });

        let pool = ConnectionPool::new(addr, 2, 60, 2, 0);

        // Warm-fill the pool (fills up to max_idle=2 connections)
        pool.warm_fill_once().await;
        let initial_size = pool.size();
        assert!(initial_size <= 2);

        // Get a connection (takes one from pool)
        let conn1 = pool.get().await.unwrap();
        // Pool should have one less connection (or 0 if only 1 was added)
        assert_eq!(pool.size(), initial_size.saturating_sub(1));

        drop(conn1);
    }

    #[tokio::test]
    async fn test_pool_max_idle() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        std::thread::spawn(move || while let Ok((_, _)) = listener.accept() {});

        let pool = ConnectionPool::new(addr, 2, 60, 2, 0);

        // Warm-fill should not exceed max_idle
        pool.warm_fill_once().await;
        assert!(pool.size() <= 2);
    }
}
