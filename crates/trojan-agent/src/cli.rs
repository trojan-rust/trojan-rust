//! CLI entry point for the agent subcommand.

use std::io;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::cache::{self, CachedConfig};
use crate::client::{self, RegistrationResult};
use crate::collector::TrafficCollector;
use crate::config::AgentConfig;
use crate::error::AgentError;
use crate::protocol::{AgentMessage, PanelMessage, ServiceState};
use crate::reporter;
use crate::runner;

/// CLI arguments for the agent subcommand.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "trojan-agent",
    version,
    about = "Panel agent — connects to management panel, receives config, boots services"
)]
pub struct AgentArgs {
    /// Config file path (TOML).
    #[arg(short, long, default_value = "agent.toml")]
    pub config: PathBuf,

    /// Log level override (e.g. "info", "debug", "trace").
    #[arg(long)]
    pub log_level: Option<String>,
}

/// Run the agent with the given CLI arguments.
pub async fn run(args: AgentArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config_str = std::fs::read_to_string(&args.config)
        .map_err(|e| format!("failed to read config file {:?}: {e}", args.config))?;
    let config: AgentConfig =
        toml::from_str(&config_str).map_err(|e| format!("failed to parse agent config: {e}"))?;

    let log_level = args
        .log_level
        .as_deref()
        .or(config.log_level.as_deref())
        .unwrap_or("info");
    init_tracing(log_level);

    info!(
        version = trojan_core::VERSION,
        panel_url = %config.panel_url,
        "trojan agent starting"
    );

    // Set up graceful shutdown on SIGTERM/SIGINT
    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        shutdown_signal_handler().await;
        info!("shutdown signal received");
        shutdown_signal.cancel();
    });

    agent_loop(config, shutdown).await;
    Ok(())
}

/// Outer reconnect loop with exponential backoff.
///
/// Keeps reconnecting to the panel until shutdown is signalled.
async fn agent_loop(config: AgentConfig, shutdown: CancellationToken) {
    let mut delay_ms = config.reconnect.initial_delay_ms;

    loop {
        match run_session(&config, shutdown.clone()).await {
            Ok(()) => {
                info!("session ended cleanly");
                if shutdown.is_cancelled() {
                    return;
                }
                // Reset backoff on clean exit
                delay_ms = config.reconnect.initial_delay_ms;
            }
            Err(e) => {
                if shutdown.is_cancelled() {
                    return;
                }
                warn!(error = %e, "session failed");
            }
        }

        if shutdown.is_cancelled() {
            return;
        }

        // Apply jitter: delay * (1 ± jitter)
        let jitter_factor = 1.0 + config.reconnect.jitter * (2.0 * rand_f64() - 1.0);
        #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let actual_delay = (delay_ms as f64 * jitter_factor) as u64;
        let delay = Duration::from_millis(actual_delay);

        info!(delay_ms = actual_delay, "reconnecting after delay");

        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(delay) => {}
        }

        // Exponential backoff
        #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let next = (delay_ms as f64 * config.reconnect.multiplier) as u64;
        delay_ms = next.min(config.reconnect.max_delay_ms);
    }
}

/// Run a single agent session (connect → register → run service → event loop).
async fn run_session(config: &AgentConfig, shutdown: CancellationToken) -> Result<(), AgentError> {
    let cache_dir = cache::resolve_cache_dir(config.cache_dir.as_deref());

    // Try to connect and register with the panel
    let (reg, agent_tx, mut panel_rx) =
        match client::connect_and_register(config, shutdown.clone()).await {
            Ok(result) => result,
            Err(e) => {
                // Connection failed — try cached config for degraded mode
                warn!(error = %e, "failed to connect to panel, checking local cache");
                return run_degraded_mode(&cache_dir, shutdown).await;
            }
        };

    let RegistrationResult {
        node_id,
        node_type,
        config_version,
        report_interval_secs,
        config: service_config,
    } = reg;

    // Cache the received config
    let cached = CachedConfig {
        version: config_version,
        node_type,
        report_interval_secs,
        config: service_config.clone(),
        cached_at: unix_now(),
    };
    if let Err(e) = cache::write_cache(&cache_dir, &cached).await {
        warn!(error = %e, "failed to cache config (non-fatal)");
    }

    // Determine report interval
    let report_interval = Duration::from_secs(
        config
            .report_interval_secs
            .unwrap_or_else(|| u64::from(report_interval_secs)),
    );

    // Spawn the service
    let service_shutdown = CancellationToken::new();
    let service_config_clone = service_config.clone();
    let service_shutdown_clone = service_shutdown.clone();
    let service_handle = tokio::spawn(async move {
        runner::run_service(node_type, &service_config_clone, service_shutdown_clone).await
    });

    // Send initial service status
    let started_at = unix_now();
    let _ = agent_tx
        .send(AgentMessage::ServiceStatus {
            status: ServiceState::Running,
            started_at,
            config_version,
        })
        .await;

    // Spawn reporter
    let collector = TrafficCollector::new();
    let reporter_shutdown = CancellationToken::new();
    let reporter_handle = tokio::spawn(reporter::run_reporter(
        agent_tx.clone(),
        collector.clone(),
        report_interval,
        reporter_shutdown.clone(),
    ));

    // Event loop: handle panel messages, service exit, and shutdown
    let mut current_config_version = config_version;

    // Pin the service handle so we can poll it across loop iterations
    let mut service_handle = std::pin::pin!(service_handle);

    let result = loop {
        tokio::select! {
            biased;

            _ = shutdown.cancelled() => {
                info!("shutdown requested, stopping service");
                service_shutdown.cancel();
                reporter_shutdown.cancel();
                break Ok(());
            }

            // Service exited on its own
            service_result = &mut *service_handle => {
                reporter_shutdown.cancel();
                match service_result {
                    Ok(Ok(())) => {
                        info!(node_id = %node_id, "service exited cleanly");
                        break Ok(());
                    }
                    Ok(Err(e)) => {
                        error!(node_id = %node_id, error = %e, "service exited with error");
                        let _ = agent_tx.send(AgentMessage::ServiceStatus {
                            status: ServiceState::Error,
                            started_at,
                            config_version: current_config_version,
                        }).await;
                        break Err(e);
                    }
                    Err(e) => {
                        error!(error = %e, "service task panicked");
                        break Err(AgentError::Service("service task panicked".to_string()));
                    }
                }
            }

            // Panel messages
            panel_msg = panel_rx.recv() => {
                match panel_msg {
                    Some(PanelMessage::ConfigPush { version, restart_required, drain_timeout_secs, config: config_bytes }) => {
                        info!(
                            version,
                            restart_required,
                            "received config push from panel"
                        );

                        // Parse opaque JSON bytes into Value
                        let new_config: serde_json::Value = match serde_json::from_slice(&config_bytes) {
                            Ok(v) => v,
                            Err(e) => {
                                error!(error = %e, "invalid config JSON in config push");
                                let _ = agent_tx.send(AgentMessage::ConfigAck {
                                    version,
                                    ok: false,
                                    message: Some(format!("invalid config JSON: {e}")),
                                }).await;
                                continue;
                            }
                        };

                        // Cache new config
                        let cached = CachedConfig {
                            version,
                            node_type,
                            report_interval_secs,
                            config: new_config,
                            cached_at: unix_now(),
                        };
                        if let Err(e) = cache::write_cache(&cache_dir, &cached).await {
                            warn!(error = %e, "failed to cache updated config");
                        }

                        if restart_required {
                            // Restart the service with new config
                            let _ = agent_tx.send(AgentMessage::ServiceStatus {
                                status: ServiceState::Restarting,
                                started_at,
                                config_version: current_config_version,
                            }).await;

                            // Graceful shutdown of current service
                            let drain_timeout = drain_timeout_secs
                                .map(|s| Duration::from_secs(u64::from(s)))
                                .unwrap_or(Duration::from_secs(30));
                            service_shutdown.cancel();
                            let _ = tokio::time::timeout(drain_timeout, &mut *service_handle).await;

                            let _ = agent_tx.send(AgentMessage::ConfigAck {
                                version,
                                ok: true,
                                message: None,
                            }).await;

                            // Session will end, outer loop will reconnect and re-register
                            // which will boot the new config
                            reporter_shutdown.cancel();
                            break Ok(());
                        }

                        // Non-restart config push — just ack for now
                        // TODO: hot-reload auth via ReloadableAuth
                        current_config_version = version;

                        let _ = agent_tx.send(AgentMessage::ConfigAck {
                            version,
                            ok: true,
                            message: None,
                        }).await;
                    }

                    Some(PanelMessage::Error { code, message }) => {
                        error!(?code, %message, "received error from panel");
                        // Continue running — the panel might recover
                    }

                    Some(PanelMessage::Registered { .. }) => {
                        warn!("unexpected duplicate registration message");
                    }

                    Some(PanelMessage::Ping) => {
                        // Handled by the recv task in client.rs
                    }

                    None => {
                        warn!("panel connection lost");
                        // Don't stop service — let it keep running
                        // The outer loop will reconnect
                        reporter_shutdown.cancel();
                        break Err(AgentError::ConnectionClosed);
                    }
                }
            }
        }
    };

    // Wait for reporter to finish
    let _ = reporter_handle.await;

    result
}

/// Run in degraded mode from cached config (no panel connection).
async fn run_degraded_mode(
    cache_dir: &std::path::Path,
    shutdown: CancellationToken,
) -> Result<(), AgentError> {
    let cached = match cache::read_cache(cache_dir).await {
        Some(c) => c,
        None => {
            return Err(AgentError::Registration(
                "panel unreachable and no cached config available".to_string(),
            ));
        }
    };

    warn!(
        node_type = %cached.node_type,
        config_version = cached.version,
        cached_at = cached.cached_at,
        "running in degraded mode from cached config (no panel connection)"
    );

    runner::run_service(cached.node_type, &cached.config, shutdown).await
}

/// Wait for shutdown signals (SIGTERM, SIGINT).
async fn shutdown_signal_handler() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!("failed to listen for Ctrl+C: {e}");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                warn!("failed to listen for SIGTERM: {e}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

fn init_tracing(level: &str) {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(io::stderr))
        .init();
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Simple pseudo-random f64 in [0, 1) for jitter.
/// Uses system time nanoseconds — good enough for backoff jitter.
fn rand_f64() -> f64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    f64::from(nanos) / f64::from(u32::MAX)
}
