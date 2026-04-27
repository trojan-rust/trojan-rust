//! Async traffic recording with batching support.
//!
//! This module is only compiled when the `batched-traffic` feature is enabled.
//!
//! ## Bytes lifecycle
//!
//! Each call to [`TrafficRecorder::record`] enqueues bytes that pass through
//! three stages before reaching the backend:
//!
//! 1. **mpsc** — in the unbounded channel between callers and the loop task.
//! 2. **pending** — coalesced into the `pending` map keyed by user_id; awaits
//!    either the next tick or the unique-users threshold.
//! 3. **in-flight** — taken from `pending` and currently being flushed by a
//!    task tracked in the loop's [`tokio::task::JoinSet`]. Bytes stay in
//!    `in_flight` until the flush future resolves (success *or* failure),
//!    then they are subtracted.
//!
//! [`TrafficRecorder::pending_for`] reports `pending + in_flight` so callers
//! that need to know "how much have we recorded but not yet seen reflected in
//! the backend?" — notably the cache revalidation path — get an accurate
//! number.
//!
//! Flushes are spawned into the loop's `JoinSet` rather than detached via
//! [`tokio::spawn`], so [`TrafficRecorder::shutdown`] can deterministically
//! await every in-flight flush before returning.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

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
    /// Bytes coalesced but not yet handed to a flush task.
    pending: Arc<Mutex<HashMap<String, u64>>>,
    /// Bytes handed to an in-progress flush task.
    in_flight: Arc<Mutex<HashMap<String, u64>>>,
    shutdown: CancellationToken,
    /// Background loop join handle, taken on shutdown.
    task: StdMutex<Option<JoinHandle<()>>>,
}

impl TrafficRecorder {
    /// Create a new traffic recorder with batching.
    ///
    /// `max_unique_users` triggers a flush as soon as the pending map contains
    /// that many distinct user_ids (it does *not* count total updates).
    pub fn new(flush_interval: Duration, max_unique_users: usize, flush_fn: FlushFn) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<TrafficUpdate>();
        let pending: Arc<Mutex<HashMap<String, u64>>> = Arc::new(Mutex::new(HashMap::new()));
        let in_flight: Arc<Mutex<HashMap<String, u64>>> = Arc::new(Mutex::new(HashMap::new()));
        let shutdown = CancellationToken::new();

        let pending_loop = pending.clone();
        let in_flight_loop = in_flight.clone();
        let shutdown_loop = shutdown.clone();
        let flush_fn_loop = flush_fn;

        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(flush_interval);
            // First tick fires immediately; skip it so we don't flush an empty
            // map before any record() has happened.
            ticker.tick().await;

            // All in-flight flushes are tracked here so shutdown can wait for
            // them, and so a slow flush doesn't pin memory by leaking the
            // JoinHandle.
            let mut flush_set: JoinSet<()> = JoinSet::new();

            loop {
                tokio::select! {
                    biased;
                    () = shutdown_loop.cancelled() => {
                        // Drain any updates still sitting in the channel.
                        while let Ok(update) = rx.try_recv() {
                            let mut map = pending_loop.lock();
                            *map.entry(update.user_id).or_insert(0) += update.bytes;
                        }
                        // Final flush — schedule it and then wait for *all*
                        // in-flight flushes (including ones spawned earlier
                        // that may still be running).
                        let final_batch = {
                            let mut map = pending_loop.lock();
                            std::mem::take(&mut *map)
                        };
                        if !final_batch.is_empty() {
                            let fut = build_flush_task(
                                in_flight_loop.clone(),
                                flush_fn_loop.clone(),
                                final_batch,
                            );
                            flush_set.spawn(fut);
                        }
                        while flush_set.join_next().await.is_some() {}
                        break;
                    }
                    Some(update) = rx.recv() => {
                        let batch = {
                            let mut map = pending_loop.lock();
                            *map.entry(update.user_id).or_insert(0) += update.bytes;
                            if map.len() >= max_unique_users {
                                Some(std::mem::take(&mut *map))
                            } else {
                                None
                            }
                        };
                        if let Some(batch) = batch {
                            let fut = build_flush_task(
                                in_flight_loop.clone(),
                                flush_fn_loop.clone(),
                                batch,
                            );
                            flush_set.spawn(fut);
                        }
                    }
                    _ = ticker.tick() => {
                        let batch = {
                            let mut map = pending_loop.lock();
                            if map.is_empty() {
                                None
                            } else {
                                Some(std::mem::take(&mut *map))
                            }
                        };
                        if let Some(batch) = batch {
                            let fut = build_flush_task(
                                in_flight_loop.clone(),
                                flush_fn_loop.clone(),
                                batch,
                            );
                            flush_set.spawn(fut);
                        }
                    }
                    // Reap completed flushes so JoinSet doesn't grow without
                    // bound when many flushes complete quickly.
                    Some(_) = flush_set.join_next(), if !flush_set.is_empty() => {}
                }
            }
        });

        Self {
            sender: tx,
            pending,
            in_flight,
            shutdown,
            task: StdMutex::new(Some(task)),
        }
    }

    /// Record traffic (non-blocking, queues for batch).
    #[inline]
    pub fn record(&self, user_id: String, bytes: u64) {
        let _ = self.sender.send(TrafficUpdate { user_id, bytes });
    }

    /// Bytes recorded for `user_id` that have not yet reached the backend.
    ///
    /// Sums the pending map (waiting for next flush) and the in-flight map
    /// (currently being flushed). Use this on cache revalidation to seed the
    /// in-memory traffic delta so freshly-fetched DB values do not appear
    /// artificially low while bytes are still on the wire.
    ///
    /// Bytes still sitting in the mpsc channel before the loop has consumed
    /// them are *not* included; the channel turnover is sub-millisecond, so
    /// missing them does not change the answer in practice.
    pub fn pending_for(&self, user_id: &str) -> u64 {
        let pending = self.pending.lock().get(user_id).copied().unwrap_or(0);
        let in_flight = self.in_flight.lock().get(user_id).copied().unwrap_or(0);
        pending.saturating_add(in_flight)
    }

    /// Stop accepting new updates, drain everything pending, and wait for the
    /// final flush to complete.
    ///
    /// Idempotent: calling twice is safe; the second call is a no-op.
    pub async fn shutdown(&self) {
        if self.shutdown.is_cancelled() {
            return;
        }
        self.shutdown.cancel();
        let handle = self
            .task
            .lock()
            .expect("traffic recorder task lock poisoned")
            .take();
        if let Some(h) = handle {
            let _ = h.await;
        }
    }
}

impl std::fmt::Debug for TrafficRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrafficRecorder")
            .field("pending_users", &self.pending.lock().len())
            .field("in_flight_users", &self.in_flight.lock().len())
            .field("shutdown", &self.shutdown.is_cancelled())
            .finish()
    }
}

impl Drop for TrafficRecorder {
    fn drop(&mut self) {
        // Best-effort: cancel so the loop exits even if shutdown() was not
        // awaited. Pending bytes that haven't been flushed yet are still lost
        // unless the caller invoked shutdown().await before drop.
        self.shutdown.cancel();
    }
}

/// Register `batch` as in-flight, then return the future that performs the
/// flush and decrements `in_flight` when it completes (success or failure).
///
/// Registering happens synchronously before the future is returned, so callers
/// of [`TrafficRecorder::pending_for`] see the bytes the moment this function
/// returns — not whenever the spawned task happens to be scheduled.
fn build_flush_task(
    in_flight: Arc<Mutex<HashMap<String, u64>>>,
    flush_fn: FlushFn,
    batch: HashMap<String, u64>,
) -> impl std::future::Future<Output = ()> + Send + 'static {
    let entries: Vec<(String, u64)> = {
        let mut map = in_flight.lock();
        batch
            .iter()
            .map(|(uid, &bytes)| {
                *map.entry(uid.clone()).or_insert(0) += bytes;
                (uid.clone(), bytes)
            })
            .collect()
    };

    async move {
        if let Err(e) = flush_fn(batch).await {
            tracing::warn!(error = %e, "traffic flush failed; bytes lost");
        }
        let mut map = in_flight.lock();
        for (uid, bytes) in entries {
            if let Some(entry) = map.get_mut(&uid) {
                *entry = entry.saturating_sub(bytes);
                if *entry == 0 {
                    map.remove(&uid);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A flush_fn that just sums batches into a counter.
    fn counting_flush(total: Arc<AtomicU64>) -> FlushFn {
        Arc::new(move |batch| {
            let total = total.clone();
            Box::pin(async move {
                let sum: u64 = batch.values().sum();
                total.fetch_add(sum, Ordering::SeqCst);
                Ok(())
            })
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_flushes_remaining() {
        let total = Arc::new(AtomicU64::new(0));
        let recorder = TrafficRecorder::new(
            Duration::from_secs(60), // long interval — won't fire during test
            10_000,
            counting_flush(total.clone()),
        );

        recorder.record("alice".into(), 100);
        recorder.record("bob".into(), 200);
        recorder.record("alice".into(), 50);

        // Give the loop a moment to drain mpsc into pending.
        tokio::time::sleep(Duration::from_millis(50)).await;

        recorder.shutdown().await;

        assert_eq!(total.load(Ordering::SeqCst), 350);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_for_includes_in_flight() {
        // A flush_fn that hangs on a barrier so we can observe in_flight.
        let gate = Arc::new(tokio::sync::Notify::new());
        let gate_clone = gate.clone();
        let total = Arc::new(AtomicU64::new(0));
        let total_clone = total.clone();
        let flush_fn: FlushFn = Arc::new(move |batch| {
            let gate = gate_clone.clone();
            let total = total_clone.clone();
            Box::pin(async move {
                gate.notified().await;
                let sum: u64 = batch.values().sum();
                total.fetch_add(sum, Ordering::SeqCst);
                Ok(())
            })
        });

        let recorder = TrafficRecorder::new(Duration::from_millis(50), 10_000, flush_fn);

        recorder.record("alice".into(), 1000);
        // Wait for tick + spawn → the flush is now in-flight, blocked on `gate`.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // pending should be empty, in_flight should hold the 1000.
        assert_eq!(recorder.pending_for("alice"), 1000);

        // Release the flush, wait for completion.
        gate.notify_one();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(recorder.pending_for("alice"), 0);
        assert_eq!(total.load(Ordering::SeqCst), 1000);

        recorder.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_flush_does_not_block_loop() {
        // A slow flush_fn that takes 200ms. The loop must still pick up the
        // second batch despite the first flush still running.
        let total = Arc::new(AtomicU64::new(0));
        let total_clone = total.clone();
        let flush_fn: FlushFn = Arc::new(move |batch| {
            let total = total_clone.clone();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let sum: u64 = batch.values().sum();
                total.fetch_add(sum, Ordering::SeqCst);
                Ok(())
            })
        });

        let recorder = TrafficRecorder::new(Duration::from_millis(50), 10_000, flush_fn);

        recorder.record("u1".into(), 100);
        tokio::time::sleep(Duration::from_millis(80)).await;
        recorder.record("u2".into(), 200);
        tokio::time::sleep(Duration::from_millis(80)).await;
        // shutdown waits for both in-flight flushes to drain.
        recorder.shutdown().await;

        assert_eq!(total.load(Ordering::SeqCst), 300);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn flush_failure_does_not_leak_in_flight() {
        let flush_fn: FlushFn = Arc::new(move |_batch| {
            Box::pin(async move { Err(AuthError::Backend("simulated".into())) })
        });

        let recorder = TrafficRecorder::new(Duration::from_millis(50), 10_000, flush_fn);
        recorder.record("alice".into(), 500);
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Even though the flush failed, in_flight must have been decremented.
        assert_eq!(recorder.pending_for("alice"), 0);
        recorder.shutdown().await;
    }
}
