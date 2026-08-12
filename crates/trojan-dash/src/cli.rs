//! CLI entry point for the `dash` subcommand.

use std::io;
use std::path::PathBuf;

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::DashConfig;

/// CLI arguments for the dash subcommand.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "trojan-dash",
    version,
    about = "Dashboard service — users, node tokens, traffic accounting, subscriptions"
)]
pub struct DashArgs {
    /// Config file path (TOML).
    #[arg(short, long, default_value = "dash.toml")]
    pub config: PathBuf,

    /// Log level override (e.g. "info", "debug", "trace").
    #[arg(long)]
    pub log_level: Option<String>,
}

/// Run the dashboard with the given CLI arguments.
pub async fn run(args: DashArgs) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(&args.config)
        .map_err(|e| format!("failed to read config file {:?}: {e}", args.config))?;
    let config: DashConfig =
        toml::from_str(&text).map_err(|e| format!("failed to parse dash config: {e}"))?;

    let log_level = args
        .log_level
        .as_deref()
        .or(config.log_level.as_deref())
        .unwrap_or("info");
    init_tracing(log_level);

    info!(version = trojan_core::VERSION, "trojan dash starting");

    let shutdown = CancellationToken::new();
    let signalled = shutdown.clone();
    tokio::spawn(async move {
        shutdown_signal_handler().await;
        info!("shutdown signal received");
        signalled.cancel();
    });

    crate::run(config, shutdown).await?;
    Ok(())
}

fn init_tracing(level: &str) {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(io::stderr))
        .init();
}

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
