//! Bounded traffic recording with one in-flight batch per recorder.
//!
//! The channel and each batch hold at most `max_unique_users` entries.
//! [`TrafficRecorder::record`] waits when the channel is full.
//! [`TrafficRecorder::pending_for`] includes queued, pending, and in-flight bytes.
//! A failed flush logs the lost batch and removes its outstanding bytes.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::AuthError;

/// Key used to coalesce traffic updates into a batch.
pub trait BatchKey: Eq + Hash + Clone + Send + Sync + 'static {}
impl<K: Eq + Hash + Clone + Send + Sync + 'static> BatchKey for K {}

struct TrafficUpdate<K> {
    key: K,
    bytes: u64,
}

/// Backend operation for one batch of traffic updates.
pub type FlushFn<K = String> = Arc<dyn Fn(HashMap<K, u64>) -> FlushFuture + Send + Sync + 'static>;

/// Future returned by a backend flush operation.
pub type FlushFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AuthError>> + Send + 'static>>;

/// Traffic recorder with bounded buffering and backend concurrency.
pub struct TrafficRecorder<K: BatchKey = String> {
    sender: mpsc::Sender<TrafficUpdate<K>>,
    outstanding: Arc<Mutex<HashMap<K, u64>>>,
    shutdown: CancellationToken,
    task: StdMutex<Option<JoinHandle<()>>>,
}

impl<K: BatchKey> TrafficRecorder<K> {
    /// Create a recorder with a positive channel capacity and batch key limit.
    ///
    /// `max_unique_users` bounds each batch and the number of queued updates.
    /// One batch may accumulate while the previous batch is being flushed.
    pub fn new(flush_interval: Duration, max_unique_users: usize, flush_fn: FlushFn<K>) -> Self {
        let (sender, mut receiver) = mpsc::channel::<TrafficUpdate<K>>(max_unique_users);
        let outstanding = Arc::new(Mutex::new(HashMap::new()));
        let shutdown = CancellationToken::new();
        let totals = outstanding.clone();
        let stop = shutdown.clone();

        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(flush_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            let mut pending = HashMap::new();
            let mut flushes = JoinSet::new();
            let mut flush_due = false;
            let mut closing = false;
            let mut drained = false;

            loop {
                if !pending.is_empty()
                    && flushes.is_empty()
                    && (flush_due || drained || pending.len() >= max_unique_users)
                {
                    flushes.spawn(flush_batch(
                        totals.clone(),
                        flush_fn.clone(),
                        std::mem::take(&mut pending),
                    ));
                    flush_due = false;
                }
                if drained && pending.is_empty() && flushes.is_empty() {
                    break;
                }
                tokio::select! {
                    () = stop.cancelled(), if !closing => {
                        receiver.close();
                        closing = true;
                    }
                    update = receiver.recv(), if !drained && pending.len() < max_unique_users => {
                        match update {
                            Some(update) => *pending.entry(update.key).or_insert(0) += update.bytes,
                            None => {
                                drained = true;
                                closing = true;
                            }
                        }
                    }
                    _ = ticker.tick(), if !closing => flush_due = true,
                    Some(result) = flushes.join_next(), if !flushes.is_empty() => {
                        result.expect("traffic flush task panicked");
                    }
                }
            }
        });

        Self {
            sender,
            outstanding,
            shutdown,
            task: StdMutex::new(Some(task)),
        }
    }

    /// Queue an update, waiting for capacity. Return an error after shutdown.
    pub async fn record(&self, key: K, bytes: u64) -> Result<(), AuthError> {
        let permit = self.sender.reserve().await.map_err(AuthError::backend)?;
        // No await may separate accounting from send: cancellation must not strand bytes.
        *self.outstanding.lock().entry(key.clone()).or_insert(0) += bytes;
        permit.send(TrafficUpdate { key, bytes });
        Ok(())
    }

    /// Return accepted bytes whose backend flush has not completed.
    pub fn pending_for<Q>(&self, key: &Q) -> u64
    where
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.outstanding.lock().get(key).copied().unwrap_or(0)
    }

    /// Stop accepting updates, drain queued updates, and await backend flushes.
    pub async fn shutdown(&self) {
        self.shutdown.cancel();
        let handle = self
            .task
            .lock()
            .expect("traffic recorder task lock poisoned")
            .take();
        if let Some(handle) = handle {
            handle.await.expect("traffic recorder task panicked");
        }
    }
}

impl<K: BatchKey> std::fmt::Debug for TrafficRecorder<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrafficRecorder")
            .field("outstanding_keys", &self.outstanding.lock().len())
            .field("shutdown", &self.shutdown.is_cancelled())
            .finish()
    }
}

impl<K: BatchKey> Drop for TrafficRecorder<K> {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

async fn flush_batch<K: BatchKey>(
    outstanding: Arc<Mutex<HashMap<K, u64>>>,
    flush_fn: FlushFn<K>,
    batch: HashMap<K, u64>,
) {
    let entries: Vec<_> = batch
        .iter()
        .map(|(key, &bytes)| (key.clone(), bytes))
        .collect();
    if let Err(error) = flush_fn(batch).await {
        tracing::warn!(%error, "traffic flush failed; bytes lost");
    }
    let mut totals = outstanding.lock();
    for (key, bytes) in entries {
        if let Some(total) = totals.get_mut(&key) {
            *total -= bytes;
            if *total == 0 {
                totals.remove(&key);
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

    #[tokio::test]
    async fn bounded_recording_preserves_queued_bytes_and_drains_on_shutdown() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let total = Arc::new(AtomicU64::new(0));
        let active = Arc::new(AtomicU64::new(0));
        let peak = Arc::new(AtomicU64::new(0));
        let (started, mut starts) = mpsc::channel(3);
        let flush: FlushFn = {
            let (gate, total, active, peak) =
                (gate.clone(), total.clone(), active.clone(), peak.clone());
            Arc::new(move |batch| {
                let (gate, total, active, peak, started) = (
                    gate.clone(),
                    total.clone(),
                    active.clone(),
                    peak.clone(),
                    started.clone(),
                );
                Box::pin(async move {
                    let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(count, Ordering::SeqCst);
                    started.send(()).await.unwrap();
                    gate.acquire().await.unwrap().forget();
                    total.fetch_add(batch.values().sum(), Ordering::SeqCst);
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                })
            })
        };
        let recorder = TrafficRecorder::new(Duration::from_secs(60), 1, flush);
        recorder.record("alice".into(), 1).await.unwrap();
        starts.recv().await.unwrap();
        recorder.record("alice".into(), 2).await.unwrap();
        recorder.record("alice".into(), 3).await.unwrap();
        assert_eq!(recorder.pending_for("alice"), 6);
        tokio::time::timeout(
            Duration::from_millis(20),
            recorder.record("alice".into(), 4),
        )
        .await
        .expect_err("recording must wait when the backend and both buffers are full");
        assert_eq!(recorder.pending_for("alice"), 6);

        gate.add_permits(3);
        tokio::time::timeout(Duration::from_secs(5), recorder.shutdown())
            .await
            .unwrap();
        assert_eq!(total.load(Ordering::SeqCst), 6);
        assert_eq!(peak.load(Ordering::SeqCst), 1);
        assert_eq!(recorder.pending_for("alice"), 0);
        recorder.record("alice".into(), 7).await.unwrap_err();
        assert_eq!(recorder.pending_for("alice"), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_flushes_remaining() {
        let total = Arc::new(AtomicU64::new(0));
        let recorder = TrafficRecorder::new(
            Duration::from_secs(60), // long interval — won't fire during test
            10_000,
            counting_flush(total.clone()),
        );

        recorder.record("alice".into(), 100).await.unwrap();
        recorder.record("bob".into(), 200).await.unwrap();
        recorder.record("alice".into(), 50).await.unwrap();

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

        recorder.record("alice".into(), 1000).await.unwrap();
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

        recorder.record("u1".into(), 100).await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        recorder.record("u2".into(), 200).await.unwrap();
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
        recorder.record("alice".into(), 500).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Even though the flush failed, in_flight must have been decremented.
        assert_eq!(recorder.pending_for("alice"), 0);
        recorder.shutdown().await;
    }
}
