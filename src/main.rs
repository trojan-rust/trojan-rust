//! Unified trojan-rs CLI.
//!
//! This binary provides a unified interface to all trojan components:
//! - `trojan-rs server` - Run the trojan server
//! - `trojan-rs auth` - Manage authentication users (SQL backend)
//!
//! Each subcommand can also be run as a standalone binary.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Trojan-rs unified CLI.
#[derive(Parser)]
#[command(
    name = "trojan-rs",
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
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Server(args) => trojan_server::cli::run(*args).await,
        Commands::Auth(args) => trojan_auth::cli::run(args).await,
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}
