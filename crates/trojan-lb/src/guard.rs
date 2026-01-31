//! RAII connection guard for tracking active connections.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Shared active-connection counter for a single backend.
///
/// Cloned cheaply via `Arc`; the actual counter is shared.
#[derive(Debug, Clone)]
pub struct BackendCounter(pub(crate) Arc<AtomicUsize>);

impl BackendCounter {
    pub fn new() -> Self {
        Self(Arc::new(AtomicUsize::new(0)))
    }

    pub fn load(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

/// RAII guard that increments the backend's active connection count on
/// creation and decrements it on drop. This ensures the count stays
/// accurate even if the connection handler panics.
pub struct ConnectionGuard {
    counter: Arc<AtomicUsize>,
}

impl ConnectionGuard {
    pub(crate) fn acquire(counter: &BackendCounter) -> Self {
        counter.0.fetch_add(1, Ordering::Relaxed);
        Self {
            counter: counter.0.clone(),
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_increments_and_decrements() {
        let counter = BackendCounter::new();
        assert_eq!(counter.load(), 0);

        let g1 = ConnectionGuard::acquire(&counter);
        assert_eq!(counter.load(), 1);

        let g2 = ConnectionGuard::acquire(&counter);
        assert_eq!(counter.load(), 2);

        drop(g1);
        assert_eq!(counter.load(), 1);

        drop(g2);
        assert_eq!(counter.load(), 0);
    }
}
