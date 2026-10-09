//! Recorder conflicts require a separate process because global recorders cannot be replaced.

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;
    use trojan_metrics::{MetricsError, init_metrics_server};

    #[tokio::test]
    async fn an_existing_foreign_recorder_is_an_error_and_releases_the_port() {
        metrics::set_global_recorder(metrics::NoopRecorder).unwrap();
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);
        for _ in 0..2 {
            let error = init_metrics_server(&address.to_string(), None, None)
                .await
                .unwrap_err();
            assert!(matches!(error, MetricsError::Recorder(_)), "{error}");
            drop(
                TcpListener::bind(address)
                    .await
                    .expect("failed recorder initialization must release the listener"),
            );
        }
    }
}
