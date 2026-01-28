//! Trojan server standalone binary.

use clap::Parser;
use trojan_server::{ServerArgs, cli};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = ServerArgs::parse();
    cli::run(args).await
}
