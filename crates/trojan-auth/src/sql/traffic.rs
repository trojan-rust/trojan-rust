//! Async traffic recording with batching support.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::AuthError;

/// Traffic update message.
struct TrafficUpdate {
    user_id: String,
    bytes: u64,
}

/// Flush function type for batched traffic updates.
pub type FlushFn = Arc<dyn Fn(HashMap<String, u64>) -> FlushFuture + Send + Sync + 'static>;

/// Future type for flush operations.
pub type FlushFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AuthError>> + Send + 'static>>;

/// Traffic recorder that batches updates.
pub struct TrafficRecorder {
    sender: mpsc::UnboundedSender<TrafficUpdate>,
    #[allow(dead_code)]
    pending: Arc<Mutex<HashMap<String, u64>>>,
}

impl TrafficRecorder {
    /// Create a new traffic recorder with batching.
    pub fn new(flush_interval: Duration, max_pending: usize, flush_fn: FlushFn) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<TrafficUpdate>();
        let pending: Arc<Mutex<HashMap<String, u64>>> = Arc::new(Mutex::new(HashMap::new()));
        let pending_clone = pending.clone();

        // Background task for batching
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(flush_interval);

            loop {
                tokio::select! {
                    Some(update) = rx.recv() => {
                        // Check if we need to flush after adding this update
                        let batch_to_flush = {
                            let mut map = pending_clone.lock();
                            *map.entry(update.user_id).or_insert(0) += update.bytes;

                            // Take batch if too many pending
                            if map.len() >= max_pending {
                                Some(std::mem::take(&mut *map))
                            } else {
                                None
                            }
                        }; // MutexGuard dropped here

                        // Flush outside of lock
                        if let Some(batch) = batch_to_flush {
                            let _ = flush_fn(batch).await;
                        }
                    }
                    _ = ticker.tick() => {
                        // Take batch if not empty
                        let batch_to_flush = {
                            let mut map = pending_clone.lock();
                            if !map.is_empty() {
                                Some(std::mem::take(&mut *map))
                            } else {
                                None
                            }
                        }; // MutexGuard dropped here

                        // Flush outside of lock
                        if let Some(batch) = batch_to_flush {
                            let _ = flush_fn(batch).await;
                        }
                    }
                }
            }
        });

        Self {
            sender: tx,
            pending,
        }
    }

    /// Record traffic (non-blocking, queues for batch).
    #[inline]
    pub fn record(&self, user_id: String, bytes: u64) {
        let _ = self.sender.send(TrafficUpdate { user_id, bytes });
    }
}
