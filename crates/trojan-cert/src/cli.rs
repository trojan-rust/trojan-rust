//! CLI definitions for certificate management.

use clap::{Args, Parser, Subcommand};
use std::net::IpAddr;
use std::path::PathBuf;

/// Certificate management for trojan.
#[derive(Parser, Debug, Clone)]
#[command(name = "trojan-cert", version, about = "Certificate management for trojan")]
pub struct CertArgs {
    #[command(subcommand)]
    pub command: CertCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CertCommands {
    /// Generate a self-signed certificate.
    Generate(GenerateArgs),
}

#[derive(Args, Debug, Clone)]
pub struct GenerateArgs {
    /// Domain names to include in the certificate (can specify multiple).
    #[arg(short, long, required = true)]
    pub domain: Vec<String>,

    /// IP addresses to include in Subject Alternative Names.
    #[arg(long)]
    pub ip: Vec<IpAddr>,

    /// Output directory for certificate and key files.
    #[arg(short, long, default_value = ".")]
    pub output: PathBuf,

    /// Certificate validity period in days.
    #[arg(long, default_value = "365")]
    pub days: u32,

    /// Certificate filename (without .pem extension).
    #[arg(long, default_value = "cert")]
    pub cert_name: String,

    /// Private key filename (without .pem extension).
    #[arg(long, default_value = "key")]
    pub key_name: String,
}
