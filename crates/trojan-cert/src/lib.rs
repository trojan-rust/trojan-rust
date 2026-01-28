//! Certificate generation utilities for trojan-rs.
//!
//! This crate provides CLI tools for generating self-signed TLS certificates.
//!
//! # Usage
//!
//! ```bash
//! trojan cert generate --domain example.com --ip 127.0.0.1 --output /etc/trojan/
//! ```

pub mod cli;
pub mod generate;

pub use cli::{CertArgs, CertCommands, GenerateArgs};
pub use generate::{generate, CertError};

/// Run the cert CLI with the given arguments.
pub fn run(args: CertArgs) -> Result<(), CertError> {
    match args.command {
        CertCommands::Generate(args) => generate(&args),
    }
}
