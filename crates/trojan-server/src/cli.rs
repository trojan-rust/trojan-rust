//! CLI module for trojan-server.
//!
//! This module provides the command-line interface that can be used either
//! as a standalone binary or as a subcommand of the main trojan-rs CLI.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::{
    EnvFilter,
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
};
use trojan_auth::{MemoryAuth, ReloadableAuth};
use trojan_config::{CliOverrides, LoggingConfig, apply_overrides, load_config, validate_config};

use crate::{CancellationToken, run_with_shutdown};

/// Trojan server CLI arguments.
#[derive(Parser, Debug, Clone)]
#[command(name = "trojan-server", version, about = "Trojan server in Rust")]
pub struct ServerArgs {
    /// Config file path (json/yaml/toml)
    #[arg(short, long, default_value = "config.toml")]
    pub config: PathBuf,

    #[command(flatten)]
    pub overrides: CliOverrides,
}

/// Run the trojan server with the given arguments.
///
/// This is the main entry point for the server CLI, used by both the
/// standalone binary and the unified trojan-rs CLI.
pub async fn run(args: ServerArgs) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config(&args.config)?;
    apply_overrides(&mut config, &args.overrides);
    validate_config(&config)?;

    init_tracing(&config.logging);

    if let Some(listen) = &config.metrics.listen {
        match trojan_metrics::init_metrics_server(listen) {
            Ok(_handle) => info!(
                "metrics server listening on {} (/metrics, /health, /ready)",
                listen
            ),
            Err(e) => warn!("failed to start metrics server: {}", e),
        }
    }

    // Set up graceful shutdown on SIGTERM/SIGINT
    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();

    tokio::spawn(async move {
        shutdown_signal_handler().await;
        info!("shutdown signal received");
        shutdown_signal.cancel();
    });

    // Create reloadable auth backend
    let auth = Arc::new(ReloadableAuth::new(MemoryAuth::from_passwords(
        &config.auth.passwords,
    )));

    // Set up SIGHUP handler for config reload
    #[cfg(unix)]
    {
        let config_path = args.config.clone();
        let overrides = args.overrides.clone();
        let auth_reload = auth.clone();
        tokio::spawn(async move {
            reload_signal_handler(config_path, overrides, auth_reload).await;
        });
    }

    run_with_shutdown(config, auth, shutdown).await?;
    Ok(())
}

/// Wait for shutdown signals (SIGTERM, SIGINT).
async fn shutdown_signal_handler() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!("failed to listen for Ctrl+C: {}", e);
            // Fall back to waiting forever
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
                warn!("failed to listen for SIGTERM: {}", e);
                // Fall back to waiting forever
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

/// Handle SIGHUP for config reload (Unix only).
#[cfg(unix)]
async fn reload_signal_handler(
    config_path: PathBuf,
    overrides: CliOverrides,
    auth: Arc<ReloadableAuth>,
) {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(sig) => sig,
        Err(e) => {
            warn!(
                "failed to install SIGHUP handler: {}, config reload disabled",
                e
            );
            return;
        }
    };

    loop {
        sighup.recv().await;
        info!("SIGHUP received, reloading configuration");

        match reload_config(&config_path, &overrides, &auth) {
            Ok(()) => info!("configuration reloaded successfully"),
            Err(e) => warn!("failed to reload configuration: {}", e),
        }
    }
}

/// Reload configuration from file.
#[cfg(unix)]
fn reload_config(
    config_path: &PathBuf,
    overrides: &CliOverrides,
    auth: &Arc<ReloadableAuth>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config(config_path)?;
    apply_overrides(&mut config, overrides);
    validate_config(&config)?;

    // Reload auth passwords
    let new_auth = MemoryAuth::from_passwords(&config.auth.passwords);
    auth.reload(new_auth);
    info!(
        password_count = config.auth.passwords.len(),
        "auth passwords reloaded"
    );

    // Note: TLS certificates and other settings require server restart
    // Future enhancement: implement TLS cert hot-reload via rustls ResolvesServerCert

    Ok(())
}

/// Initialize tracing subscriber with the given logging configuration.
///
/// Supports:
/// - `level`: Base log level (trace, debug, info, warn, error)
/// - `format`: Output format (json, pretty, compact). Default: pretty
/// - `output`: Output target (stdout, stderr). Default: stderr
/// - `filters`: Per-module log level overrides
fn init_tracing(config: &LoggingConfig) {
    // Build the env filter from base level and per-module filters
    let base_level = config.level.as_deref().unwrap_or("info");
    let mut filter_str = base_level.to_string();

    for (module, level) in &config.filters {
        filter_str.push(',');
        filter_str.push_str(module);
        filter_str.push('=');
        filter_str.push_str(level);
    }

    let filter = EnvFilter::try_new(&filter_str).unwrap_or_else(|_| EnvFilter::new("info"));

    let format = config.format.as_deref().unwrap_or("pretty");
    let output = config.output.as_deref().unwrap_or("stderr");

    // Create the subscriber based on format and output
    match (format, output) {
        ("json", "stdout") => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json().with_writer(io::stdout))
                .init();
        }
        ("json", _) => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json().with_writer(io::stderr))
                .init();
        }
        ("compact", "stdout") => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().compact().with_writer(io::stdout))
                .init();
        }
        ("compact", _) => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().compact().with_writer(io::stderr))
                .init();
        }
        (_, "stdout") => {
            // pretty is default
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().with_writer(io::stdout))
                .init();
        }
        _ => {
            // pretty to stderr is default
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().with_writer(io::stderr))
                .init();
        }
    }
}
