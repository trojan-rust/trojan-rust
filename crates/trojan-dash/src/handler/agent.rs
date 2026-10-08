//! The socket agents connect to: `GET /ws/agent`.
//!
//! An agent registers with its node token, is handed the service config the
//! panel holds for it, and then reports: heartbeats carrying the node's own
//! totals, and traffic records carrying what each user spent. Both are numbers
//! only this end can persist, and only that end can observe.
//!
//! Messages are bincode frames of [`AgentMessage`] / [`PanelMessage`], the
//! same definitions the agent compiles against, so the two cannot drift.
//!
//! Config *push* is not implemented: an agent picks up a changed config when
//! it next registers. Nothing here sends [`PanelMessage::ConfigPush`].

use std::net::SocketAddr;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::response::Response;
use tracing::{debug, info, warn};
use trojan_protocol::{
    AgentMessage, ErrorCode, NodeType, PROTOCOL_VERSION, PanelMessage, TrafficRecord,
};

use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, Unchanged,
};

use crate::entity::nodes;
use crate::error::DashError;
use crate::handler::node_api::apply_traffic;
use crate::node_traffic;
use crate::state::AppState;
use crate::types::clamp_i64;
use crate::util::now_secs;

/// How often an agent should report, in seconds.
///
/// Not configurable per node yet; the agent's own config may shorten it.
const REPORT_INTERVAL_SECS: u32 = 30;

/// `GET /ws/agent` — upgrade, then run one agent session.
pub async fn ws(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    upgrade: WebSocketUpgrade,
) -> Response {
    upgrade.on_upgrade(move |socket| async move {
        if let Err(e) = session(socket, state, peer).await {
            debug!(peer = %peer, error = %e, "agent session ended with error");
        }
    })
}

/// Register the agent, then serve it until it disconnects.
async fn session(
    mut socket: WebSocket,
    state: AppState,
    peer: SocketAddr,
) -> Result<(), DashError> {
    let Some(node) = register(&mut socket, &state, peer).await? else {
        return Ok(());
    };

    info!(
        node_id = node.id,
        name = %node.name,
        node_type = %node.node_type,
        peer = %peer,
        "agent registered"
    );

    state.nodes.connected(node.id).await;
    let result = serve_registered(&mut socket, &state, node.id).await;
    state.nodes.disconnected(node.id).await;
    info!(node_id = node.id, "agent disconnected");
    result
}

async fn serve_registered(
    socket: &mut WebSocket,
    state: &AppState,
    node_id: i64,
) -> Result<(), DashError> {
    let mut snapshots = state.nodes.snapshots.subscribe();
    // One publisher preserves ordering when snapshots share a second-resolution timestamp.
    let snapshot = snapshots.borrow_and_update().clone();
    send(socket, &PanelMessage::NodeStates { snapshot }).await?;

    loop {
        let frame = tokio::select! {
            changed = snapshots.changed() => {
                if changed.is_err() {
                    break;
                }
                let snapshot = snapshots.borrow_and_update().clone();
                send(socket, &PanelMessage::NodeStates { snapshot }).await?;
                continue;
            },
            frame = socket.recv() => frame,
        };
        let bytes = match frame {
            Some(Ok(Message::Binary(bytes))) => bytes,
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            _ => break,
        };
        let message: AgentMessage = match bincode::deserialize(&bytes) {
            Ok(message) => message,
            Err(e) => {
                warn!(node_id, error = %e, "undecodable agent message");
                continue;
            }
        };

        match message {
            AgentMessage::Heartbeat {
                connections_active,
                bytes_in,
                bytes_out,
                uptime_secs,
                ..
            } => {
                record_heartbeat(
                    state,
                    node_id,
                    Heartbeat {
                        connections_active,
                        bytes_in,
                        bytes_out,
                        uptime_secs,
                    },
                )
                .await?;
            }
            AgentMessage::Traffic { records } => {
                record_traffic(state, node_id, &records).await?;
            }
            AgentMessage::NodeTraffic { report } => {
                let sequence =
                    match node_traffic::record(&state.db, node_id, &report, now_secs()).await {
                        Ok(sequence) => sequence,
                        Err(error @ (DashError::BadRequest(_) | DashError::Calendar(_))) => {
                            send(
                                socket,
                                &PanelMessage::Error {
                                    code: ErrorCode::InvalidTrafficReport,
                                    message: error.to_string(),
                                },
                            )
                            .await?;
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                state.nodes.refresh.notify_one();
                send(
                    socket,
                    &PanelMessage::NodeTrafficAck {
                        stream_id: report.stream_id,
                        sequence,
                    },
                )
                .await?;
            }
            AgentMessage::ServiceStatus {
                status,
                config_version,
                ..
            } => {
                debug!(node_id, ?status, config_version, "service status");
            }
            AgentMessage::ConfigAck { version, ok, .. } => {
                debug!(node_id, version, ok, "config ack");
            }
            // A second Register on a live socket, or a Pong to a Ping this
            // end never sends: nothing to do either way.
            AgentMessage::Register { .. } | AgentMessage::Pong => {}
        }
    }

    Ok(())
}

/// Read the opening `Register`, answer it, and return the node it named.
///
/// `Ok(None)` means the agent was turned away and told why.
async fn register(
    socket: &mut WebSocket,
    state: &AppState,
    peer: SocketAddr,
) -> Result<Option<nodes::Model>, DashError> {
    let Some(Ok(Message::Binary(bytes))) = socket.recv().await else {
        return Ok(None);
    };

    let AgentMessage::Register {
        protocol_version,
        token,
        version,
        ..
    } = bincode::deserialize(&bytes).map_err(|e| DashError::BadRequest(e.to_string()))?
    else {
        reject(socket, ErrorCode::ProtocolMismatch, "expected Register").await;
        return Ok(None);
    };

    if protocol_version != PROTOCOL_VERSION {
        reject(
            socket,
            ErrorCode::ProtocolMismatch,
            &format!("panel speaks protocol {PROTOCOL_VERSION}, agent speaks {protocol_version}"),
        )
        .await;
        return Ok(None);
    }

    let node = nodes::Entity::find()
        .filter(nodes::Column::Token.eq(&token))
        .one(&state.db)
        .await?;

    let Some(node) = node else {
        reject(socket, ErrorCode::InvalidToken, "unknown node token").await;
        return Ok(None);
    };
    if node.enabled == 0 {
        reject(socket, ErrorCode::NodeDisabled, "node is disabled").await;
        return Ok(None);
    }

    let node_type = match node.node_type.as_str() {
        "entry" => NodeType::Entry,
        "relay" => NodeType::Relay,
        "server" => NodeType::Server,
        other => {
            // Only an operator can produce this, by writing a node_type the
            // agent has no runner for. Refusing beats booting the wrong thing.
            reject(
                socket,
                ErrorCode::InternalError,
                &format!("node {} has unknown node_type {other:?}", node.id),
            )
            .await;
            return Ok(None);
        }
    };

    nodes::ActiveModel {
        id: Unchanged(node.id),
        ip: Set(peer.ip().to_string()),
        last_seen: Set(clamp_i64(now_secs())),
        agent_version: Set(version),
        ..Default::default()
    }
    .update(&state.db)
    .await?;

    let registered = PanelMessage::Registered {
        node_id: node.id.to_string(),
        node_type,
        config_version: u32::try_from(node.config_version).unwrap_or(u32::MAX),
        report_interval_secs: REPORT_INTERVAL_SECS,
        config: node.config.clone().into_bytes(),
    };
    send(socket, &registered).await?;

    Ok(Some(node))
}

/// The heartbeat fields worth keeping, so the row update takes one argument.
struct Heartbeat {
    connections_active: u32,
    bytes_in: u64,
    bytes_out: u64,
    uptime_secs: u64,
}

/// Store the latest heartbeat as the node's current state.
///
/// The counts are totals since the agent started, not deltas, so a heartbeat
/// lost to a reconnect costs nothing: the next one is still correct.
async fn record_heartbeat(
    state: &AppState,
    node_id: i64,
    beat: Heartbeat,
) -> Result<(), DashError> {
    nodes::ActiveModel {
        id: Unchanged(node_id),
        last_seen: Set(clamp_i64(now_secs())),
        connections_active: Set(i64::from(beat.connections_active)),
        bytes_in: Set(clamp_i64(beat.bytes_in)),
        bytes_out: Set(clamp_i64(beat.bytes_out)),
        uptime_secs: Set(clamp_i64(beat.uptime_secs)),
        ..Default::default()
    }
    .update(&state.db)
    .await?;

    state.nodes.refresh.notify_one();

    Ok(())
}

/// Apply one batch of per-user traffic to this node's account.
async fn record_traffic(
    state: &AppState,
    node_id: i64,
    records: &[TrafficRecord],
) -> Result<(), DashError> {
    for record in records {
        let Ok(user_id) = record.user_id.parse::<i64>() else {
            warn!(node_id, user_id = %record.user_id, "traffic for an unparseable user id");
            continue;
        };
        // A user deleted while a node still held bytes for them is expected,
        // not an error worth dropping the rest of the batch over.
        if !apply_traffic(state, user_id, node_id, record.bytes).await? {
            warn!(node_id, user_id, "traffic for a user that no longer exists");
        }
    }

    Ok(())
}

/// End the session if the peer cannot receive state or accounting acknowledgments.
async fn send(socket: &mut WebSocket, message: &PanelMessage) -> Result<(), DashError> {
    let bytes = bincode::serialize(message).map_err(|e| DashError::Serde(e.to_string()))?;
    socket
        .send(Message::Binary(bytes.into()))
        .await
        .map_err(|e| DashError::Io(std::io::Error::other(e)))
}

/// Tell the agent why it is not welcome, then let the session end.
async fn reject(socket: &mut WebSocket, code: ErrorCode, message: &str) {
    warn!(?code, message, "agent registration refused");
    if let Err(error) = send(
        socket,
        &PanelMessage::Error {
            code,
            message: message.to_owned(),
        },
    )
    .await
    {
        debug!(%error, "could not send registration rejection");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use futures_util::{SinkExt, StreamExt};
    use sea_orm::ConnectionTrait;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite};
    use trojan_protocol::{NodeState, NodeStateSnapshot};

    use super::*;
    use crate::{DashConfig, cache::Caches, node_states::NodeMonitor};

    async fn receive(socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>) -> PanelMessage {
        let tungstenite::Message::Binary(bytes) = socket.next().await.unwrap().unwrap() else {
            panic!("expected a panel binary message");
        };
        bincode::deserialize(&bytes).unwrap()
    }

    #[tokio::test]
    async fn registration_and_updates_use_one_ordered_snapshot_publisher() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let db = crate::db::connect("sqlite::memory:").await.unwrap();
            db.execute_unprepared(
                "INSERT INTO nodes (id, name, token, traffic_limit) VALUES (1, 'entry', 'token', 100)",
            )
            .await
            .unwrap();
            let nodes = Arc::new(NodeMonitor::new());
            let now = now_secs();
            let mut published = NodeStateSnapshot {
                generated_at: now,
                valid_until: now + 90,
                nodes: vec![NodeState {
                    node_id: "1".into(),
                    enabled: true,
                    online: true,
                    traffic_limit: 100,
                    used_bytes: 90,
                    period_start: now - 1,
                    reset_at: now + 90,
                }],
            };
            // Published state differs from the database so an independent snapshot cannot pass.
            nodes.snapshots.send_replace(published.clone());
            let config: DashConfig = toml::from_str("admin_token = 'test'").unwrap();
            let state = AppState {
                db,
                cache: Caches::new(Duration::ZERO, Duration::ZERO),
                admin_digest: Arc::new(String::new()),
                cfg: Arc::new(config),
                nodes: nodes.clone(),
            };
            let app = crate::routes::router(state, None);
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .unwrap();
            });
            let (mut socket, _) =
                tokio_tungstenite::connect_async(format!("ws://{address}/ws/agent"))
                    .await
                    .unwrap();
            let register = AgentMessage::Register {
                protocol_version: PROTOCOL_VERSION,
                token: "token".into(),
                version: "test".into(),
                hostname: "test".into(),
                os: "test".into(),
                arch: "test".into(),
            };
            socket
                .send(tungstenite::Message::Binary(
                    bincode::serialize(&register).unwrap().into(),
                ))
                .await
                .unwrap();
            assert!(matches!(
                receive(&mut socket).await,
                PanelMessage::Registered { .. }
            ));
            let PanelMessage::NodeStates { snapshot } = receive(&mut socket).await else {
                panic!("expected initial published state");
            };
            assert_eq!(snapshot, published);

            // A later publication in the same second must follow the initial state.
            published.nodes[0].used_bytes = 100;
            nodes.snapshots.send_replace(published.clone());
            let PanelMessage::NodeStates { snapshot } = receive(&mut socket).await else {
                panic!("expected updated published state");
            };
            assert_eq!(snapshot, published);
            socket.close(None).await.unwrap();
            server.abort();
            assert!(server.await.unwrap_err().is_cancelled());
        })
        .await
        .expect("snapshot publication did not reach the agent");
    }
}
