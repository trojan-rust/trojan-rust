//! Trojan auth standalone binary.

use std::process::ExitCode;

use clap::Parser;
use trojan_auth::{AuthArgs, cli};

#[tokio::main]
async fn main() -> ExitCode {
    let args = AuthArgs::parse();

    match cli::run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}
