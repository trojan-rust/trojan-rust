//! Live scheduling snapshots, independent of service configuration.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use sea_orm::{EntityTrait, QueryOrder};
use serde::Serialize;
use tokio::sync::{Mutex, Notify, watch};
use tokio_util::sync::CancellationToken;
use trojan_protocol::{NodeState, NodeStateSnapshot};

use crate::entity::nodes;
use crate::error::DashError;
use crate::node_observation::{HeartbeatRates, HeartbeatSample, HeartbeatStatus};
use crate::node_traffic;
use crate::state::AppState;
use crate::types::nonneg;
use crate::util::now_secs;

const STATE_TTL: u64 = 90;
const REFRESH_INTERVAL: Duration = Duration::from_secs(15);

/// Socket presence and the latest complete scheduling snapshot.
#[derive(Debug)]
pub(crate) struct NodeMonitor {
    connections: Mutex<BTreeMap<i64, NodeConnections>>,
    pub snapshots: watch::Sender<NodeStateSnapshot>,
    pub refresh: Notify,
}

#[derive(Debug, Default, Clone)]
struct NodeConnections {
    total: usize,
    accounting: usize,
    heartbeat: HeartbeatRates,
}

impl NodeMonitor {
    pub fn new() -> Self {
        Self {
            connections: Mutex::new(BTreeMap::new()),
            snapshots: watch::channel(NodeStateSnapshot::default()).0,
            refresh: Notify::new(),
        }
    }

    pub async fn connected(&self, node_id: i64, traffic_supported: bool) {
        let mut connections = self.connections.lock().await;
        let node = connections.entry(node_id).or_default();
        node.total += 1;
        node.accounting += usize::from(traffic_supported);
        node.heartbeat = HeartbeatRates::default();
        self.refresh.notify_one();
    }

    pub async fn disconnected(&self, node_id: i64, traffic_supported: bool) {
        let mut connections = self.connections.lock().await;
        if let Some(node) = connections.get_mut(&node_id) {
            node.total -= 1;
            node.accounting -= usize::from(traffic_supported);
            node.heartbeat = HeartbeatRates::default();
            if node.total == 0 {
                connections.remove(&node_id);
            }
        }
        self.refresh.notify_one();
    }

    pub async fn heartbeat(&self, node_id: i64, sample: HeartbeatSample) {
        if let Some(node) = self.connections.lock().await.get_mut(&node_id)
            && node.total == 1
        {
            node.heartbeat.observe(sample);
        }
    }
}

/// Current-period accounting and availability returned by node management APIs.
#[derive(Debug, Serialize)]
pub(crate) struct NodeTrafficStatus {
    pub traffic_limit: u64,
    pub reset_day: i64,
    pub reset_timezone: String,
    pub period_start: u64,
    pub reset_at: u64,
    pub period_bytes_in: u64,
    pub period_bytes_out: u64,
    pub traffic_used: u64,
    /// True only when every live session supports durable node accounting.
    pub traffic_supported: bool,
    /// Absent for an unlimited node or incomplete node accounting.
    pub traffic_remaining: Option<u64>,
    pub online: bool,
    pub unavailable_reason: Option<&'static str>,
    /// Report age does not imply stale accounting: idle agents need not send a delta.
    pub traffic_last_observed_at: Option<u64>,
    pub traffic_last_received_at: Option<u64>,
    #[serde(flatten)]
    pub heartbeat: HeartbeatStatus,
}

pub(crate) async fn status(
    state: &AppState,
    node: &nodes::Model,
    now: u64,
) -> Result<NodeTrafficStatus, DashError> {
    let period = node_traffic::period(node.reset_day, &node.reset_timezone, now)?;
    let usage = node_traffic::current_usage(&state.db, node, period).await?;
    let sessions = state
        .nodes
        .connections
        .lock()
        .await
        .get(&node.id)
        .cloned()
        .unwrap_or_default();
    build_status(node, period, usage, &sessions, now)
}

fn build_status(
    node: &nodes::Model,
    period: node_traffic::Period,
    usage: node_traffic::Usage,
    sessions: &NodeConnections,
    now: u64,
) -> Result<NodeTrafficStatus, DashError> {
    let used = usage.total()?;
    let limit = nonneg(node.traffic_limit);
    let connected = sessions.total > 0;
    let traffic_supported = connected && sessions.accounting == sessions.total;
    let online = connected && nonneg(node.last_seen).saturating_add(STATE_TTL) > now;
    Ok(NodeTrafficStatus {
        traffic_limit: limit,
        reset_day: node.reset_day,
        reset_timezone: node.reset_timezone.clone(),
        period_start: nonneg(period.start),
        reset_at: nonneg(period.end),
        period_bytes_in: nonneg(usage.bytes_in),
        period_bytes_out: nonneg(usage.bytes_out),
        traffic_used: used,
        traffic_supported,
        traffic_remaining: (traffic_supported && limit > 0).then(|| limit.saturating_sub(used)),
        online,
        traffic_last_observed_at: node.traffic_last_observed_at.map(nonneg),
        traffic_last_received_at: node.traffic_last_received_at.map(nonneg),
        heartbeat: sessions.heartbeat.status(sessions.total, Instant::now()),
        unavailable_reason: if node.enabled == 0 {
            Some("disabled")
        } else if !online {
            Some("offline")
        } else if limit > 0 && !traffic_supported {
            Some("traffic_unsupported")
        } else if limit > 0 && used >= limit {
            Some("traffic_exhausted")
        } else {
            None
        },
    })
}

/// Resolve shared calendars once and refresh all expired windows in bounded batches.
pub(crate) async fn statuses(
    state: &AppState,
    nodes: Vec<nodes::Model>,
    now: u64,
) -> Result<Vec<(nodes::Model, NodeTrafficStatus)>, DashError> {
    let mut calendars = BTreeMap::new();
    let mut periods = Vec::with_capacity(nodes.len());
    let mut expired = Vec::new();
    for node in &nodes {
        let key = (node.reset_day, node.reset_timezone.as_str());
        let period = if let Some(period) = calendars.get(&key) {
            *period
        } else {
            let period = node_traffic::period(key.0, key.1, now)?;
            calendars.insert(key, period);
            period
        };
        if node.traffic_period_start != period.start || node.traffic_period_end != period.end {
            expired.push((node.id, period));
        }
        periods.push(period);
    }
    let mut refreshed = node_traffic::refresh_usage(&state.db, &expired).await?;
    let connections = state.nodes.connections.lock().await.clone();
    let mut result = Vec::with_capacity(nodes.len());
    for (node, period) in nodes.into_iter().zip(periods) {
        let usage =
            if node.traffic_period_start == period.start && node.traffic_period_end == period.end {
                node_traffic::Usage {
                    bytes_in: node.traffic_period_bytes_in,
                    bytes_out: node.traffic_period_bytes_out,
                }
            } else if let Some(usage) = refreshed.remove(&node.id) {
                usage
            } else {
                // A deleted node has no rebuilt window and must not reappear in a snapshot.
                continue;
            };
        let sessions = connections.get(&node.id).cloned().unwrap_or_default();
        let status = build_status(&node, period, usage, &sessions, now)?;
        result.push((node, status));
    }
    Ok(result)
}

async fn snapshot(state: &AppState) -> Result<NodeStateSnapshot, DashError> {
    snapshot_at(state, now_secs()).await
}

async fn snapshot_at(state: &AppState, now: u64) -> Result<NodeStateSnapshot, DashError> {
    let nodes = nodes::Entity::find()
        .order_by_asc(nodes::Column::Id)
        .all(&state.db)
        .await?;
    snapshot_from_nodes(state, now, nodes).await
}

async fn snapshot_from_nodes(
    state: &AppState,
    now: u64,
    nodes: Vec<nodes::Model>,
) -> Result<NodeStateSnapshot, DashError> {
    let mut snapshot = NodeStateSnapshot {
        generated_at: now,
        valid_until: now.saturating_add(STATE_TTL),
        nodes: Vec::with_capacity(nodes.len()),
    };
    for (node, status) in statuses(state, nodes, now).await? {
        // Expire the snapshot at a reset boundary rather than carrying an old quota into a new month.
        snapshot.valid_until = snapshot.valid_until.min(status.reset_at);
        if status.online {
            snapshot.valid_until = snapshot
                .valid_until
                .min(nonneg(node.last_seen).saturating_add(STATE_TTL));
        }
        snapshot.nodes.push(NodeState {
            node_id: node.id.to_string(),
            enabled: node.enabled != 0,
            online: status.online,
            traffic_supported: status.traffic_supported,
            traffic_limit: status.traffic_limit,
            used_bytes: status.traffic_used,
            period_start: status.period_start,
            reset_at: status.reset_at,
        });
    }
    Ok(snapshot)
}

/// Publish on mutations, heartbeat expiry and calendar rollover, including after downtime.
pub(crate) async fn run(state: AppState, shutdown: CancellationToken) -> Result<(), DashError> {
    let mut ticker = tokio::time::interval(REFRESH_INTERVAL);
    loop {
        let snapshot = snapshot(&state).await?;
        let reset = snapshot.valid_until.saturating_sub(now_secs()).max(1);
        state.nodes.snapshots.send_replace(snapshot);
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            _ = state.nodes.refresh.notified() => {},
            _ = ticker.tick() => {},
            _ = tokio::time::sleep(Duration::from_secs(reset)) => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
    use trojan_protocol::NodeTrafficReport;

    use super::*;
    use crate::{DashConfig, cache::Caches};

    #[tokio::test]
    async fn snapshot_restores_quota_at_reset_and_expires_on_lost_heartbeat() {
        let db = crate::db::connect("sqlite::memory:").await.unwrap();
        let reset = "2025-02-01T00:00:00Z"
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second();
        db.execute(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
            "INSERT INTO nodes (id, name, token, traffic_limit, last_seen) VALUES (1, 'entry', 'token', 100, ?1)",
            [reset.into()],
        )).await.unwrap();
        let config: DashConfig = toml::from_str("admin_token = 'test'").unwrap();
        let state = AppState {
            db,
            cache: Caches::new(Duration::ZERO, Duration::ZERO),
            admin_digest: Arc::new(String::new()),
            cfg: Arc::new(config),
            nodes: Arc::new(NodeMonitor::new()),
        };
        state.nodes.connected(1, true).await;
        node_traffic::record(
            &state.db,
            1,
            &NodeTrafficReport {
                stream_id: "stream".into(),
                sequence: 1,
                observed_at: (reset - 1).cast_unsigned(),
                bytes_in: 100,
                bytes_out: 0,
            },
            reset.cast_unsigned(),
        )
        .await
        .unwrap();
        let before = snapshot_at(&state, (reset - 1).cast_unsigned())
            .await
            .unwrap();
        assert_eq!(before.nodes[0].used_bytes, 100);
        assert_eq!(before.valid_until, reset.cast_unsigned());
        let after = snapshot_at(&state, reset.cast_unsigned()).await.unwrap();
        assert_eq!(after.nodes[0].used_bytes, 0);
        assert_eq!(after.nodes[0].period_start, reset.cast_unsigned());
        assert!(after.nodes[0].online);
        let expired = snapshot_at(&state, reset.cast_unsigned() + STATE_TTL)
            .await
            .unwrap();
        assert!(!expired.nodes[0].online);
    }

    #[tokio::test]
    async fn deletion_during_snapshot_construction_removes_only_that_node() {
        let db = crate::db::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(
            "INSERT INTO nodes (id, name, token) VALUES (1, 'removed', 't1'), (2, 'present', 't2')",
        )
        .await
        .unwrap();
        let rows = nodes::Entity::find()
            .order_by_asc(nodes::Column::Id)
            .all(&db)
            .await
            .unwrap();
        nodes::Entity::delete_by_id(1).exec(&db).await.unwrap();
        let config: DashConfig = toml::from_str("admin_token = 'test'").unwrap();
        let state = AppState {
            db,
            cache: Caches::new(Duration::ZERO, Duration::ZERO),
            admin_digest: Arc::new(String::new()),
            cfg: Arc::new(config),
            nodes: Arc::new(NodeMonitor::new()),
        };
        let snapshot = snapshot_from_nodes(&state, now_secs(), rows).await.unwrap();
        assert_eq!(snapshot.nodes.len(), 1);
        assert_eq!(snapshot.nodes[0].node_id, "2");
        state
            .db
            .execute_unprepared("UPDATE nodes SET reset_timezone = 'invalid/timezone'")
            .await
            .unwrap();
        assert!(matches!(
            super::snapshot(&state).await,
            Err(DashError::Calendar(_))
        ));
    }
}

#[cfg(test)]
#[path = "node_states/benchmarks.rs"]
mod benchmarks;
