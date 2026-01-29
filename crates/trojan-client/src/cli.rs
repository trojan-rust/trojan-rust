//! CLI module for trojan-client.

use std::io;
use std::path::PathBuf;

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use trojan_config::LoggingConfig;

use crate::config::load_client_config;

/// Trojan client CLI arguments.
#[derive(Parser, Debug, Clone)]
#[command(name = "trojan-client", version, about = "Trojan SOCKS5 proxy client")]
pub struct ClientArgs {
    /// Config file path (toml/json/jsonc).
    #[arg(short, long, default_value = "client.toml")]
    pub config: PathBuf,

    /// Override SOCKS5 listen address.
    #[arg(short, long)]
    pub listen: Option<String>,

    /// Override remote trojan server address.
    #[arg(short, long)]
    pub remote: Option<String>,

    /// Override password.
    #[arg(short, long)]
    pub password: Option<String>,

    /// Skip TLS certificate verification.
    #[arg(long)]
    pub skip_verify: bool,

    /// Log level override.
    #[arg(long)]
    pub log_level: Option<String>,
}

/// Run the trojan client with the given CLI arguments.
pub async fn run(args: ClientArgs) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_client_config(&args.config)?;

    // Apply CLI overrides
    if let Some(listen) = &args.listen {
        config.client.listen = listen.clone();
    }
    if let Some(remote) = &args.remote {
        config.client.remote = remote.clone();
    }
    if let Some(password) = &args.password {
        config.client.password = password.clone();
    }
    if args.skip_verify {
        config.client.tls.skip_verify = true;
    }
    if let Some(level) = &args.log_level {
        config.logging.level = Some(level.clone());
    }

    init_tracing(&config.logging);

    // Graceful shutdown
    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();

    tokio::spawn(async move {
        shutdown_signal_handler().await;
        info!("shutdown signal received");
        shutdown_signal.cancel();
    });

    crate::run(config, shutdown).await?;
    Ok(())
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

fn init_tracing(config: &LoggingConfig) {
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
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().with_writer(io::stdout))
                .init();
        }
        _ => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().with_writer(io::stderr))
                .init();
        }
    }
}
