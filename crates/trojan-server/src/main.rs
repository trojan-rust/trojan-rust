use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use trojan_auth::{MemoryAuth, ReloadableAuth};
use trojan_config::{CliOverrides, apply_overrides, load_config, validate_config};
use trojan_metrics::init_prometheus;
use trojan_server::{CancellationToken, run_with_shutdown};

#[derive(Parser, Debug)]
#[command(name = "trojan-server", version, about = "Trojan server in Rust")]
struct Args {
    /// Config file path (json/yaml/toml)
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
    #[command(flatten)]
    overrides: CliOverrides,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut config = load_config(&args.config)?;
    apply_overrides(&mut config, &args.overrides);
    validate_config(&config)?;

    let level = config.logging.level.as_deref().unwrap_or("info");
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    if let Some(listen) = &config.metrics.listen {
        match init_prometheus(listen) {
            Ok(()) => info!("prometheus metrics server listening on {}", listen),
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
    let auth = Arc::new(ReloadableAuth::new(MemoryAuth::from_plain(
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
    let new_auth = MemoryAuth::from_plain(&config.auth.passwords);
    auth.reload(new_auth);
    info!(
        password_count = config.auth.passwords.len(),
        "auth passwords reloaded"
    );

    // Note: TLS certificates and other settings require server restart
    // Future enhancement: implement TLS cert hot-reload via rustls ResolvesServerCert

    Ok(())
}
