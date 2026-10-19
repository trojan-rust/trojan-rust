use super::*;
use std::time::Duration;
use trojan_protocol::NodeState;

fn snapshot() -> NodeStateSnapshot {
    let now = crate::runtime::unix_now();
    NodeStateSnapshot {
        generated_at: now - 120,
        valid_until: now - 30,
        nodes: vec![NodeState {
            node_id: "entry".into(),
            enabled: true,
            online: true,
            traffic_supported: true,
            traffic_limit: 100,
            used_bytes: 80,
            period_start: 0,
            reset_at: now - 60,
        }],
    }
}

#[tokio::test]
async fn restart_preserves_snapshot_age_usage_and_the_newest_disk_state() {
    let directory = tempfile::tempdir().unwrap();
    let store = NodeStateStore::with_grace(Duration::from_secs(172_800));
    load(directory.path(), &store).await.unwrap();
    assert_eq!(store.remaining_fraction("entry"), None);
    let state = snapshot();
    update(directory.path(), &store, state.clone())
        .await
        .unwrap();
    let mut older = state.clone();
    older.generated_at -= 1;
    older.nodes[0].enabled = false;
    update(directory.path(), &store, older).await.unwrap();
    let persisted: NodeStateSnapshot = serde_json::from_slice(
        &tokio::fs::read(directory.path().join(FILENAME))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(persisted, state);

    let restored = NodeStateStore::with_grace(Duration::from_secs(172_800));
    load(directory.path(), &restored).await.unwrap();
    assert_eq!(restored.snapshot().generated_at(), Some(state.generated_at));
    assert_eq!(restored.remaining_fraction("entry"), Some(0.2));
    for grace in [0, 120] {
        let expired = NodeStateStore::with_grace(Duration::from_secs(grace));
        load(directory.path(), &expired).await.unwrap();
        assert_eq!(expired.remaining_fraction("entry"), None);
    }
}

#[tokio::test]
async fn failed_replacement_preserves_the_previous_file_and_corruption_is_an_error() {
    let directory = tempfile::tempdir().unwrap();
    let store = NodeStateStore::default();
    let state = snapshot();
    update(directory.path(), &store, state.clone())
        .await
        .unwrap();
    let path = directory.path().join(FILENAME);
    let before = tokio::fs::read(&path).await.unwrap();
    tokio::fs::create_dir(path.with_extension("json.tmp"))
        .await
        .unwrap();
    let mut newer = state;
    newer.generated_at += 1;
    assert!(matches!(
        update(directory.path(), &store, newer).await,
        Err(AgentError::Cache(_))
    ));
    assert_eq!(tokio::fs::read(&path).await.unwrap(), before);
    tokio::fs::write(&path, b"invalid snapshot").await.unwrap();
    assert!(matches!(
        load(directory.path(), &store).await,
        Err(AgentError::Cache(_))
    ));
}

#[test]
fn late_recorder_reports_old_snapshot_age_and_missing_state() {
    let store = NodeStateStore::default();
    let state = snapshot();
    let generated_at = state.generated_at;
    store.update(state);
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _guard = metrics::set_default_local_recorder(&recorder);
    record_age(&store);
    let value = || -> f64 {
        handle
            .render()
            .lines()
            .find_map(|line| {
                line.strip_prefix("trojan_agent_node_state_age_seconds ")
                    .map(|value| value.parse().unwrap())
            })
            .unwrap()
    };
    assert!(value() >= 120.0);
    store.update(NodeStateSnapshot {
        generated_at: generated_at + 60,
        ..snapshot()
    });
    record_age(&store);
    assert!((60.0..120.0).contains(&value()));
    store.clear();
    record_age(&store);
    assert_eq!(value(), -1.0);
}
