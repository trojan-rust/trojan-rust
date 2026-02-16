//! CLI module for trojan-relay entry and relay nodes.

use std::io;
use std::path::PathBuf;

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::{EntryConfig, RelayNodeConfig};

/// CLI arguments for the relay entry node (A).
#[derive(Parser, Debug, Clone)]
#[command(
    name = "trojan-entry",
    version,
    about = "Relay chain entry node — routes client traffic through multi-hop tunnels"
)]
pub struct EntryArgs {
    /// Config file path (toml).
    #[arg(short, long, default_value = "entry.toml")]
    pub config: PathBuf,

    /// Log level override (e.g. "info", "debug", "trace").
    #[arg(long)]
    pub log_level: Option<String>,
}

/// CLI arguments for the relay node (B).
#[derive(Parser, Debug, Clone)]
#[command(
    name = "trojan-relay",
    version,
    about = "Relay node — accepts upstream connections and forwards to next hop"
)]
pub struct RelayArgs {
    /// Config file path (toml).
    #[arg(short, long, default_value = "relay.toml")]
    pub config: PathBuf,

    /// Log level override (e.g. "info", "debug", "trace").
    #[arg(long)]
    pub log_level: Option<String>,
}

/// Run the entry node with the given CLI arguments.
pub async fn run_entry(args: EntryArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config_str = std::fs::read_to_string(&args.config)
        .map_err(|e| format!("failed to read config file {:?}: {e}", args.config))?;
    let config: EntryConfig =
        toml::from_str(&config_str).map_err(|e| format!("failed to parse entry config: {e}"))?;

    init_tracing(args.log_level.as_deref());

    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();

    tokio::spawn(async move {
        shutdown_signal_handler().await;
        info!("shutdown signal received");
        shutdown_signal.cancel();
    });

    crate::entry::run(config, shutdown)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

/// Run the relay node with the given CLI arguments.
pub async fn run_relay(args: RelayArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config_str = std::fs::read_to_string(&args.config)
        .map_err(|e| format!("failed to read config file {:?}: {e}", args.config))?;
    let config: RelayNodeConfig =
        toml::from_str(&config_str).map_err(|e| format!("failed to parse relay config: {e}"))?;

    init_tracing(args.log_level.as_deref());

    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();

    tokio::spawn(async move {
        shutdown_signal_handler().await;
        info!("shutdown signal received");
        shutdown_signal.cancel();
    });

    crate::relay::run(config, shutdown)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
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

fn init_tracing(level: Option<&str>) {
    let level = level.unwrap_or("info");
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(io::stderr))
        .init();
}
