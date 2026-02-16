//! WebSocket client — connects to the panel, registers, and provides
//! send/receive channels.
//!
//! Protocol messages are serialized with bincode and sent as WS binary frames.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::AgentConfig;
use crate::error::AgentError;
use crate::protocol::{AgentMessage, PROTOCOL_VERSION, PanelMessage};

/// Registration result returned on successful panel handshake.
#[derive(Debug)]
pub struct RegistrationResult {
    pub node_id: String,
    pub node_type: crate::protocol::NodeType,
    pub config_version: u32,
    pub report_interval_secs: u32,
    /// Service config parsed from the opaque JSON bytes in the protocol message.
    pub config: serde_json::Value,
}

/// Connect to the panel, perform registration, and return channels for
/// ongoing communication.
///
/// Returns the registration result plus:
/// - A sender for outgoing `AgentMessage`s (agent → panel)
/// - A receiver for incoming `PanelMessage`s (panel → agent)
pub async fn connect_and_register(
    config: &AgentConfig,
    shutdown: CancellationToken,
) -> Result<
    (
        RegistrationResult,
        mpsc::Sender<AgentMessage>,
        mpsc::Receiver<PanelMessage>,
    ),
    AgentError,
> {
    info!(url = %config.panel_url, "connecting to panel");

    let (ws_stream, _response) = tokio_tungstenite::connect_async(&config.panel_url).await?;

    let (mut ws_sink, mut ws_source) = ws_stream.split();

    // Send registration message
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let register = AgentMessage::Register {
        protocol_version: PROTOCOL_VERSION,
        token: config.token.clone(),
        version: trojan_core::VERSION.to_string(),
        hostname,
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
    };

    let register_bytes = bincode::serialize(&register)?;
    ws_sink.send(Message::Binary(register_bytes.into())).await?;

    // Wait for Registered response with timeout
    let registration = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(msg) = ws_source.next().await {
            let msg = msg?;
            match msg {
                Message::Binary(data) => {
                    let panel_msg: PanelMessage = bincode::deserialize(&data)?;
                    match panel_msg {
                        PanelMessage::Registered {
                            node_id,
                            node_type,
                            config_version,
                            report_interval_secs,
                            config,
                        } => {
                            // Parse opaque JSON bytes into Value at the boundary
                            let config_value = serde_json::from_slice(&config).map_err(|e| {
                                AgentError::Registration(format!(
                                    "invalid config JSON from panel: {e}"
                                ))
                            })?;
                            return Ok(RegistrationResult {
                                node_id,
                                node_type,
                                config_version,
                                report_interval_secs,
                                config: config_value,
                            });
                        }
                        PanelMessage::Error { code, message } => {
                            return Err(AgentError::Panel { code, message });
                        }
                        _ => {
                            debug!(
                                ?panel_msg,
                                "ignoring unexpected message during registration"
                            );
                        }
                    }
                }
                Message::Close(_) => return Err(AgentError::ConnectionClosed),
                _ => {} // ignore text/ping/pong frames
            }
        }
        Err(AgentError::ConnectionClosed)
    })
    .await
    .map_err(|_| AgentError::Registration("registration timed out (30s)".to_string()))??;

    info!(
        node_id = %registration.node_id,
        node_type = %registration.node_type,
        config_version = registration.config_version,
        "registered with panel"
    );

    // Set up ongoing send/receive channels
    let (agent_tx, mut agent_rx) = mpsc::channel::<AgentMessage>(64);
    let (panel_tx, panel_rx) = mpsc::channel::<PanelMessage>(64);

    // Spawn send task: agent_rx → ws_sink (bincode → Binary)
    let send_shutdown = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;

                _ = send_shutdown.cancelled() => {
                    debug!("ws send task shutting down");
                    let _ = ws_sink.close().await;
                    return;
                }

                msg = agent_rx.recv() => {
                    match msg {
                        Some(agent_msg) => {
                            match bincode::serialize(&agent_msg) {
                                Ok(data) => {
                                    if let Err(e) = ws_sink.send(Message::Binary(data.into())).await {
                                        error!(error = %e, "failed to send ws message");
                                        return;
                                    }
                                }
                                Err(e) => {
                                    error!(error = %e, "failed to serialize agent message");
                                }
                            }
                        }
                        None => {
                            debug!("agent send channel closed");
                            let _ = ws_sink.close().await;
                            return;
                        }
                    }
                }
            }
        }
    });

    // Spawn recv task: ws_source → panel_tx (Binary → bincode, handles Ping → Pong)
    let recv_shutdown = shutdown.clone();
    let pong_tx = agent_tx.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;

                _ = recv_shutdown.cancelled() => {
                    debug!("ws recv task shutting down");
                    return;
                }

                msg = ws_source.next() => {
                    match msg {
                        Some(Ok(Message::Binary(data))) => {
                            match bincode::deserialize::<PanelMessage>(&data) {
                                Ok(PanelMessage::Ping) => {
                                    debug!("received ping, sending pong");
                                    if let Err(e) = pong_tx.send(AgentMessage::Pong).await {
                                        warn!(error = %e, "failed to send pong");
                                        return;
                                    }
                                }
                                Ok(panel_msg) => {
                                    if panel_tx.send(panel_msg).await.is_err() {
                                        debug!("panel receive channel closed");
                                        return;
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, "failed to deserialize panel message");
                                }
                            }
                        }
                        Some(Ok(Message::Close(_))) => {
                            info!("panel closed websocket connection");
                            return;
                        }
                        Some(Ok(_)) => {} // ignore text/ping/pong frames
                        Some(Err(e)) => {
                            error!(error = %e, "websocket error");
                            return;
                        }
                        None => {
                            info!("websocket stream ended");
                            return;
                        }
                    }
                }
            }
        }
    });

    Ok((registration, agent_tx, panel_rx))
}
