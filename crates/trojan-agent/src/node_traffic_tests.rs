use super::*;

#[tokio::test]
#[ignore = "durable I/O benchmark; run with --release --ignored --nocapture"]
async fn journal_backlog_benchmark() {
    const OPERATIONS: u64 = 5;
    for backlog in [100_u64, 1_000, 10_000] {
        let directory = tempfile::tempdir().unwrap();
        let traffic = open(directory.path(), &config(), 30).await;
        let stream = traffic
            .with_journal(move |journal| {
                let mut saved = journal.saved.clone();
                saved.last_sequence = backlog;
                saved.pending = (1..=backlog)
                    .map(|sequence| NodeTrafficReport {
                        stream_id: saved.stream_id.clone(),
                        sequence,
                        observed_at: 1_800_000_000 + sequence,
                        bytes_in: 1_024,
                        bytes_out: 2_048,
                    })
                    .collect();
                let stream = saved.stream_id.clone();
                journal.commit(saved)?;
                Ok(stream)
            })
            .await
            .unwrap();
        let started = std::time::Instant::now();
        for count in 1..=OPERATIONS {
            traffic
                .sample(counters(count, count), 1_800_010_001 + count)
                .await
                .unwrap();
        }
        let sample = started.elapsed().as_secs_f64() / OPERATIONS as f64;
        let started = std::time::Instant::now();
        for sequence in 1..=OPERATIONS {
            traffic.acknowledge(stream.clone(), sequence).await.unwrap();
        }
        let ack = started.elapsed().as_secs_f64() / OPERATIONS as f64;
        drop(traffic);
        let started = std::time::Instant::now();
        let recovered = NodeTraffic::open(directory.path(), &config(), 30)
            .await
            .unwrap();
        let recovery = started.elapsed().as_secs_f64();
        assert_eq!(pending(&recovered).await.len() as u64, backlog);
        let size = std::fs::metadata(directory.path().join(FILENAME))
            .unwrap()
            .len();
        println!(
            "backlog={backlog} sample_ms={:.3} ack_ms={:.3} recovery_ms={:.3} file_bytes={size}",
            sample * 1_000.0,
            ack * 1_000.0,
            recovery * 1_000.0
        );
    }
}

async fn open(path: &Path, config: &AgentConfig, interval: u64) -> NodeTraffic {
    let traffic = NodeTraffic::open(path, config, interval).await.unwrap();
    traffic.enable(NodeStats::new()).await.unwrap();
    traffic
}

impl NodeTraffic {
    async fn sample(&self, snapshot: NodeSnapshot, observed_at: u64) -> Result<(), AgentError> {
        self.with_journal(move |journal| journal.sample(snapshot, observed_at))
            .await
    }
}

fn config() -> AgentConfig {
    serde_json::from_value(serde_json::json!({
        "panel_url": "ws://localhost:8080/ws/agent", "token": "node-token"
    }))
    .unwrap()
}

fn counters(bytes_in: u64, bytes_out: u64) -> NodeSnapshot {
    NodeSnapshot {
        bytes_in,
        bytes_out,
        ..NodeSnapshot::default()
    }
}

async fn pending(traffic: &NodeTraffic) -> Vec<NodeTrafficReport> {
    traffic
        .with_journal(|journal| Ok(journal.saved.pending.iter().cloned().collect()))
        .await
        .unwrap()
}

#[tokio::test]
async fn offline_reports_survive_restart_with_original_timestamps_and_new_counter_baseline() {
    let dir = tempfile::tempdir().unwrap();
    let traffic = open(dir.path(), &config(), 30).await;
    traffic.bind_node("node-1").await.unwrap();
    traffic
        .sample(counters(12, 5), 1_800_000_000)
        .await
        .unwrap();
    traffic
        .sample(counters(17, 8), 1_800_000_030)
        .await
        .unwrap();
    let before = pending(&traffic).await;
    drop(traffic);

    let restarted = open(dir.path(), &config(), 30).await;
    restarted
        .sample(counters(3, 4), 1_800_000_060)
        .await
        .unwrap();
    let after = pending(&restarted).await;
    assert_eq!(after.len(), 3);
    assert_eq!(after[0].stream_id, before[0].stream_id);
    assert_eq!(after[0].observed_at, 1_800_000_000);
    assert_eq!(after[1].observed_at, 1_800_000_030);
    assert_eq!((after[1].bytes_in, after[1].bytes_out), (5, 3));
    assert_eq!(
        (after[2].sequence, after[2].bytes_in, after[2].bytes_out),
        (3, 3, 4)
    );
    assert_eq!(
        after
            .iter()
            .map(|report| report.bytes_in + report.bytes_out)
            .sum::<u64>(),
        32
    );
}

#[tokio::test]
async fn replay_survives_lost_ack_and_ack_checkpoint_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let traffic = open(dir.path(), &config(), 30).await;
    traffic
        .sample(counters(42, 11), 1_800_000_000)
        .await
        .unwrap();
    let (tx, mut rx) = mpsc::channel(1);
    let sending = tokio::spawn({
        let traffic = traffic.clone();
        async move { traffic.send_pending(tx).await }
    });
    let AgentMessage::NodeTraffic { report: sent } = rx.recv().await.unwrap() else {
        panic!("expected node report")
    };
    sending.abort();
    assert!(sending.await.unwrap_err().is_cancelled());
    drop(traffic);

    let restarted = open(dir.path(), &config(), 30).await;
    let replay = pending(&restarted).await;
    assert_eq!(
        (replay[0].stream_id.as_str(), replay[0].sequence),
        (sent.stream_id.as_str(), sent.sequence)
    );
    assert_eq!(
        (
            replay[0].bytes_in,
            replay[0].bytes_out,
            replay[0].observed_at
        ),
        (42, 11, 1_800_000_000)
    );
    restarted
        .acknowledge(sent.stream_id.clone(), sent.sequence)
        .await
        .unwrap();
    restarted
        .acknowledge(sent.stream_id.clone(), sent.sequence)
        .await
        .unwrap();
    drop(restarted);

    let acknowledged = open(dir.path(), &config(), 30).await;
    assert!(pending(&acknowledged).await.is_empty());
    acknowledged
        .sample(counters(7, 8), 1_800_000_100)
        .await
        .unwrap();
    let next = pending(&acknowledged).await;
    assert_eq!(next[0].sequence, 2);
    assert_eq!(next[0].stream_id, sent.stream_id);
}

#[tokio::test]
async fn acknowledgement_cannot_discard_another_stream_or_future_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let traffic = open(dir.path(), &config(), 30).await;
    traffic.sample(counters(9, 2), 1_800_000_000).await.unwrap();
    let report = pending(&traffic).await.remove(0);
    assert!(
        traffic
            .acknowledge("another-stream".into(), 1)
            .await
            .is_err()
    );
    assert!(traffic.acknowledge(report.stream_id, 2).await.is_err());
    assert_eq!(pending(&traffic).await.len(), 1);
}

#[tokio::test]
async fn journal_rejects_identity_changes_concurrent_owners_and_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let traffic = open(dir.path(), &config(), 30).await;
    traffic.bind_node("node-1").await.unwrap();
    assert!(traffic.bind_node("node-2").await.is_err());
    assert!(NodeTraffic::open(dir.path(), &config(), 30).await.is_err());
    drop(traffic);
    let mut changed = config();
    changed.panel_url = "ws://other.example/ws/agent".into();
    assert!(NodeTraffic::open(dir.path(), &changed, 30).await.is_err());
    std::fs::write(dir.path().join(FILENAME), b"invalid json").unwrap();
    assert!(NodeTraffic::open(dir.path(), &config(), 30).await.is_err());
}

#[tokio::test]
async fn credential_rotation_preserves_pending_reports_only_for_the_authenticated_same_node() {
    let dir = tempfile::tempdir().unwrap();
    let traffic = open(dir.path(), &config(), 30).await;
    traffic.bind_node("node-1").await.unwrap();
    traffic
        .sample(counters(13, 7), 1_800_000_000)
        .await
        .unwrap();
    let original = pending(&traffic).await.remove(0);
    drop(traffic);

    let mut rotated = config();
    rotated.token = "rotated-token".into();
    let traffic = open(dir.path(), &rotated, 30).await;
    assert!(!traffic.can_start_cached().await.unwrap());
    assert!(traffic.bind_node("node-2").await.is_err());
    assert!(!traffic.can_start_cached().await.unwrap());
    traffic.bind_node("node-1").await.unwrap();
    assert!(traffic.can_start_cached().await.unwrap());
    drop(traffic);

    let traffic = open(dir.path(), &rotated, 30).await;
    assert!(traffic.can_start_cached().await.unwrap());
    let report = pending(&traffic).await.remove(0);
    assert_eq!(report.stream_id, original.stream_id);
    assert_eq!(report.sequence, original.sequence);
    assert_eq!((report.bytes_in, report.bytes_out), (13, 7));
}

#[tokio::test]
async fn sampler_records_without_a_panel_and_flushes_on_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let traffic = open(dir.path(), &config(), 1).await;
    let stats = NodeStats::new();
    let counters = trojan_metrics::RelayCounters::global().with_node_stats(stats.clone());
    let shutdown = CancellationToken::new();
    let sampler = tokio::spawn({
        let traffic = traffic.clone();
        let shutdown = shutdown.clone();
        async move { traffic.run_sampler(stats, shutdown).await }
    });
    counters.add_to_target(123);
    tokio::time::timeout(Duration::from_secs(5), async {
        while pending(&traffic).await.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    counters.add_to_client(321);
    shutdown.cancel();
    sampler.await.unwrap().unwrap();
    let reports = pending(&traffic).await;
    assert_eq!(
        reports.iter().map(|report| report.bytes_in).sum::<u64>(),
        123
    );
    assert_eq!(
        reports.iter().map(|report| report.bytes_out).sum::<u64>(),
        321
    );
    assert!(reports[0].observed_at > 0);
}

#[tokio::test]
async fn journal_write_failure_stops_accounting_instead_of_sending_uncommitted_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let traffic = open(dir.path(), &config(), 30).await;
    std::fs::create_dir(dir.path().join("node-traffic.json.tmp")).unwrap();
    assert!(matches!(
        traffic.sample(counters(9, 2), 1_800_000_000).await,
        Err(AgentError::AccountingStorage(_))
    ));
    assert!(pending(&traffic).await.is_empty());
    let saved: SavedTraffic =
        serde_json::from_slice(&std::fs::read(dir.path().join(FILENAME)).unwrap()).unwrap();
    assert!(saved.pending.is_empty());
}

#[tokio::test]
async fn legacy_sampling_retains_pending_reports_without_adding_or_rebilling_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let traffic = open(dir.path(), &config(), 30).await;
    traffic.sample(counters(9, 2), 1_800_000_000).await.unwrap();
    let original = pending(&traffic).await;
    drop(traffic);

    let traffic = NodeTraffic::open(dir.path(), &config(), 30).await.unwrap();
    assert!(traffic.requires_support().await.unwrap());
    let stats = NodeStats::new();
    let counters = trojan_metrics::RelayCounters::global().with_node_stats(stats.clone());
    for _ in 0..100 {
        counters.add_to_target(50);
        traffic.sample_stats(stats.clone()).await.unwrap();
    }
    counters.add_to_client(70);
    traffic.enable(stats.clone()).await.unwrap();
    counters.add_to_target(3);
    counters.add_to_client(4);
    traffic.sample_stats(stats).await.unwrap();
    let after = pending(&traffic).await;
    assert_eq!(after.len(), 2);
    assert_eq!(
        serde_json::to_value(&after[0]).unwrap(),
        serde_json::to_value(&original[0]).unwrap()
    );
    assert_eq!((after[1].bytes_in, after[1].bytes_out), (3, 4));
}
