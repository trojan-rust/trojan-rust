use super::*;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

fn value(handle: &PrometheusHandle, name: &str) -> f64 {
    let rendered = handle.render();
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name} ")))
        .unwrap_or_else(|| panic!("missing {name}: {rendered}"))
        .parse()
        .unwrap()
}

fn assert_backlog(handle: &PrometheusHandle, reports: f64, bytes: f64) {
    assert_eq!(
        value(handle, "trojan_agent_node_traffic_pending_reports"),
        reports
    );
    assert_eq!(
        value(handle, "trojan_agent_node_traffic_pending_bytes"),
        bytes
    );
}

#[tokio::test]
async fn late_recorder_tracks_committed_backlog_and_failed_sample_ack_replay() {
    let directory = tempfile::tempdir().unwrap();
    let config = serde_json::from_value(serde_json::json!({
        "panel_url": "ws://localhost:8080/ws/agent", "token": "token"
    }))
    .unwrap();
    let traffic = NodeTraffic::open(directory.path(), &config, 30)
        .await
        .unwrap();
    let stats = NodeStats::new();
    traffic.enable(stats.clone()).await.unwrap();
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _guard = metrics::set_default_local_recorder(&recorder);
    let counters = trojan_metrics::RelayCounters::global().with_node_stats(stats.clone());
    counters.add_to_target(12);
    counters.add_to_client(5);
    traffic.sample_stats(stats.clone()).await.unwrap();
    assert_backlog(&handle, 1.0, 17.0);
    assert_eq!(value(&handle, "trojan_agent_node_traffic_enabled"), 1.0);
    let timestamp = value(
        &handle,
        "trojan_agent_node_traffic_last_sample_timestamp_seconds",
    );
    assert!(timestamp > 0.0);
    assert_eq!(
        value(
            &handle,
            "trojan_agent_node_traffic_oldest_pending_timestamp_seconds"
        ),
        timestamp
    );
    let report = traffic
        .with_journal(|journal| Ok(journal.saved.pending.front().cloned().unwrap()))
        .await
        .unwrap();
    let before = std::fs::read(directory.path().join(FILENAME)).unwrap();

    std::fs::create_dir(directory.path().join("node-traffic.json.tmp")).unwrap();
    counters.add_to_target(3);
    counters.add_to_client(4);
    assert!(traffic.sample_stats(stats.clone()).await.is_err());
    assert!(
        traffic
            .acknowledge(report.stream_id.clone(), report.sequence)
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(directory.path().join(FILENAME)).unwrap(),
        before
    );
    assert_backlog(&handle, 1.0, 17.0);
    assert_eq!(
        value(
            &handle,
            "trojan_agent_node_traffic_last_sample_timestamp_seconds"
        ),
        timestamp
    );
    assert_eq!(
        value(
            &handle,
            "trojan_agent_node_traffic_operations_total{operation=\"sample\",outcome=\"error\"}"
        ),
        1.0
    );
    assert_eq!(
        value(
            &handle,
            "trojan_agent_node_traffic_operations_total{operation=\"ack\",outcome=\"error\"}"
        ),
        1.0
    );

    let (tx, rx) = mpsc::channel(1);
    drop(rx);
    assert!(matches!(
        traffic.send_pending(tx).await,
        Err(AgentError::ConnectionClosed)
    ));
    assert_eq!(
        value(
            &handle,
            "trojan_agent_node_traffic_operations_total{operation=\"send\",outcome=\"error\"}"
        ),
        1.0
    );
    let (tx, mut rx) = mpsc::channel(1);
    tokio::select! {
        result = traffic.send_pending(tx) => panic!("unexpected sender completion: {result:?}"),
        message = rx.recv() => {
            let AgentMessage::NodeTraffic { report: replayed } = message.unwrap() else { panic!("missing report") };
            assert_eq!((replayed.sequence, replayed.bytes_in, replayed.bytes_out), (report.sequence, 12, 5));
        }
    }
    assert_eq!(
        value(
            &handle,
            "trojan_agent_node_traffic_operations_total{operation=\"send\",outcome=\"success\"}"
        ),
        1.0
    );
    NodeTraffic::record_rejection();
    assert_eq!(
        value(&handle, "trojan_agent_node_traffic_panel_rejections_total"),
        1.0
    );

    std::fs::remove_dir(directory.path().join("node-traffic.json.tmp")).unwrap();
    traffic
        .acknowledge(report.stream_id, report.sequence)
        .await
        .unwrap();
    assert_backlog(&handle, 0.0, 0.0);
    assert_eq!(
        value(
            &handle,
            "trojan_agent_node_traffic_oldest_pending_timestamp_seconds"
        ),
        0.0
    );
    traffic.sample_stats(stats).await.unwrap();
    assert_backlog(&handle, 1.0, 7.0);
}
