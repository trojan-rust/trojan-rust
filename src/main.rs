//! Unified trojan CLI.
//!
//! This binary provides a unified interface to all trojan components:
//! - `trojan server` - Run the trojan server
//! - `trojan auth` - Manage authentication users (SQL backend)
//! - `trojan cert` - Generate self-signed certificates (requires `cert` feature)
//! - `trojan upgrade` - Self-upgrade from GitHub releases (requires `upgrade` feature)
//!
//! Each subcommand can also be run as a standalone binary.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[cfg(feature = "upgrade")]
mod upgrade;

/// Trojan unified CLI.
#[derive(Parser)]
#[command(
    name = "trojan",
    version,
    about = "A Rust implementation of the Trojan protocol",
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the trojan server.
    #[command(name = "server", alias = "serve")]
    Server(Box<trojan_server::ServerArgs>),

    /// Manage authentication users (SQL backend).
    #[command(name = "auth")]
    Auth(trojan_auth::AuthArgs),

    /// Generate and manage TLS certificates.
    #[cfg(feature = "cert")]
    #[command(name = "cert")]
    Cert(trojan_cert::CertArgs),

    /// Upgrade to latest version from GitHub releases.
    #[cfg(feature = "upgrade")]
    #[command(name = "upgrade", alias = "update")]
    Upgrade(upgrade::UpgradeArgs),
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let result: Result<(), String> = match cli.command {
        Commands::Server(args) => trojan_server::cli::run(*args)
            .await
            .map_err(|e| e.to_string()),
        Commands::Auth(args) => trojan_auth::cli::run(args).await.map_err(|e| e.to_string()),
        #[cfg(feature = "cert")]
        Commands::Cert(args) => trojan_cert::run(args).map_err(|e| e.to_string()),
        #[cfg(feature = "upgrade")]
        Commands::Upgrade(args) => upgrade::run(args).await.map_err(|e| e.to_string()),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}
