//! Connection metrics that follow the lifetime of an owned session.

use std::time::{Duration, Instant};

use metrics::{Gauge, Histogram, counter, gauge, histogram};

use crate::{CONNECTION_DURATION_SECONDS, CONNECTIONS_ACTIVE, CONNECTIONS_TOTAL};

/// Records an accepted connection until the session completes, panics, or is cancelled.
///
/// Create the guard after installing the recorder and before spawning the session.
/// Keep the guard in the session until the connection closes.
#[must_use = "dropping the guard records the connection as closed"]
#[derive(Debug)]
pub struct ConnectionMetrics {
    active: Gauge,
    duration: Histogram,
    started: Instant,
}

impl ConnectionMetrics {
    /// Count an accepted connection and begin measuring its lifetime.
    pub fn start() -> Self {
        let active = gauge!(CONNECTIONS_ACTIVE);
        let duration = histogram!(CONNECTION_DURATION_SECONDS);
        counter!(CONNECTIONS_TOTAL).increment(1);
        active.increment(1.0);
        Self {
            active,
            duration,
            started: Instant::now(),
        }
    }

    /// Return the elapsed connection lifetime.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

impl Drop for ConnectionMetrics {
    fn drop(&mut self) {
        self.active.decrement(1.0);
        self.duration.record(self.elapsed().as_secs_f64());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use metrics::with_local_recorder;
    use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

    fn assert_lifetimes(handle: &PrometheusHandle, total: u64, active: u64) {
        let rendered = handle.render();
        for metric in [
            format!("{CONNECTIONS_TOTAL} {total}"),
            format!("{CONNECTIONS_ACTIVE} {active}"),
            format!("{CONNECTION_DURATION_SECONDS}_count {}", total - active),
        ] {
            assert!(rendered.lines().any(|line| line == metric), "{rendered}");
        }
    }

    #[test]
    fn task_completion_abort_and_panic_release_connection_metrics() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        runtime.block_on(async {
            // Handles must remain valid when task cleanup runs outside the local recorder scope.
            let connection = with_local_recorder(&recorder, ConnectionMetrics::start);
            tokio::spawn(async move { drop(connection) }).await.unwrap();
            assert_lifetimes(&handle, 1, 0);

            let connection = with_local_recorder(&recorder, ConnectionMetrics::start);
            let task = tokio::spawn(async move {
                let _connection = connection;
                std::future::pending::<()>().await;
            });
            tokio::task::yield_now().await;
            assert_lifetimes(&handle, 2, 1);
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert_lifetimes(&handle, 2, 0);

            let connection = with_local_recorder(&recorder, ConnectionMetrics::start);
            let task = tokio::spawn(async move {
                let _connection = connection;
                panic!("test session panic");
            });
            assert!(task.await.unwrap_err().is_panic());
            assert_lifetimes(&handle, 3, 0);

            let connection = with_local_recorder(&recorder, ConnectionMetrics::start);
            let task = tokio::spawn(async move {
                let _connection = connection;
                std::future::pending::<()>().await;
            });
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert_lifetimes(&handle, 4, 0);
        });
    }
}
