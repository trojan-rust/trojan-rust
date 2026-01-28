//! Self-signed certificate generation.

use crate::cli::GenerateArgs;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};
use std::fs;
use thiserror::Error;

/// Errors that can occur during certificate generation.
#[derive(Error, Debug)]
pub enum CertError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Certificate generation failed: {0}")]
    CertGeneration(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid domain name: {0}")]
    InvalidDomain(String),
}

/// Generate a self-signed certificate with the given parameters.
pub fn generate(args: &GenerateArgs) -> Result<(), CertError> {
    // 1. Generate key pair using ECDSA P-256 (compatible with aws-lc-rs)
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| CertError::KeyGeneration(e.to_string()))?;

    // 2. Configure certificate parameters
    let mut params = CertificateParams::default();

    // Add domain names to Subject Alternative Names
    for domain in &args.domain {
        let san = SanType::DnsName(
            domain
                .clone()
                .try_into()
                .map_err(|_| CertError::InvalidDomain(domain.clone()))?,
        );
        params.subject_alt_names.push(san);
    }

    // Add IP addresses to Subject Alternative Names
    for ip in &args.ip {
        params.subject_alt_names.push(SanType::IpAddress(*ip));
    }

    // Set validity period
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(args.days as i64);

    // 3. Generate self-signed certificate
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| CertError::CertGeneration(e.to_string()))?;

    // 4. Ensure output directory exists
    fs::create_dir_all(&args.output)?;

    // 5. Write certificate and private key to files
    let cert_path = args.output.join(format!("{}.pem", args.cert_name));
    let key_path = args.output.join(format!("{}.pem", args.key_name));

    fs::write(&cert_path, cert.pem())?;
    fs::write(&key_path, key_pair.serialize_pem())?;

    // 6. Print summary
    println!("Certificate generated successfully:");
    println!("  Certificate: {}", cert_path.display());
    println!("  Private key: {}", key_path.display());
    println!("  Valid for:   {} days", args.days);
    println!("  Domains:     {}", args.domain.join(", "));
    if !args.ip.is_empty() {
        println!(
            "  IPs:         {}",
            args.ip
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    Ok(())
}
