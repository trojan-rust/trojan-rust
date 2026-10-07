//! CLI entry point for the agent subcommand.

use std::io;
use std::path::PathBuf;

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::AgentConfig;

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

    crate::runtime::run(config, shutdown).await?;
    Ok(())
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
