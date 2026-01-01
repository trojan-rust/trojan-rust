//! TLS configuration loading.

use std::sync::Arc;

use tokio_rustls::rustls::{self, RootCertStore, server::WebPkiClientVerifier};
use tracing::{info, warn};
use trojan_config::TlsConfig;

use crate::error::ServerError;

/// Load TLS configuration from config.
pub fn load_tls_config(cfg: &TlsConfig) -> Result<rustls::ServerConfig, ServerError> {
    let certs = load_certs(&cfg.cert)?;
    let key = load_private_key(&cfg.key)?;

    // Build TLS versions based on config
    // Use static slices to avoid heap allocation
    let versions: &[&'static rustls::SupportedProtocolVersion] =
        match (cfg.min_version.as_str(), cfg.max_version.as_str()) {
            ("tls13", "tls13") => &[&rustls::version::TLS13],
            ("tls12", "tls12") => &[&rustls::version::TLS12],
            _ => &[&rustls::version::TLS12, &rustls::version::TLS13],
        };

    // Get default crypto provider
    let default_provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));

    // Build crypto provider with custom cipher suites if specified
    let provider = if cfg.cipher_suites.is_empty() {
        default_provider
    } else {
        let all_suites = &default_provider.cipher_suites;
        let mut selected = Vec::with_capacity(cfg.cipher_suites.len());
        let mut not_found = Vec::with_capacity(cfg.cipher_suites.len());

        for name in &cfg.cipher_suites {
            // Match cipher suite by exact Debug name comparison
            let suite_name = name.trim();
            if let Some(suite) = all_suites.iter().find(|s| {
                let debug_name = format!("{:?}", s.suite());
                debug_name == suite_name || debug_name.ends_with(suite_name)
            }) {
                selected.push(*suite);
            } else {
                not_found.push(suite_name);
            }
        }

        if !not_found.is_empty() {
            warn!(
                not_found = ?not_found,
                available = ?all_suites.iter().map(|s| format!("{:?}", s.suite())).collect::<Vec<_>>(),
                "some cipher suites not found"
            );
        }

        if selected.is_empty() {
            return Err(ServerError::Config(
                "no valid cipher suites specified".into(),
            ));
        }

        Arc::new(rustls::crypto::CryptoProvider {
            cipher_suites: selected,
            kx_groups: default_provider.kx_groups.clone(),
            signature_verification_algorithms: default_provider.signature_verification_algorithms,
            secure_random: default_provider.secure_random,
            key_provider: default_provider.key_provider,
        })
    };

    let builder = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| ServerError::Config(format!("TLS version error: {}", e)))?;

    // Configure client authentication
    let config = if let Some(ref ca_path) = cfg.client_ca {
        let ca_certs = load_certs(ca_path)?;
        let mut root_store = RootCertStore::empty();
        for cert in ca_certs {
            root_store
                .add(cert)
                .map_err(|e| ServerError::Config(format!("failed to add CA cert: {}", e)))?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| ServerError::Config(format!("client verifier error: {}", e)))?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?
    } else {
        builder.with_no_client_auth().with_single_cert(certs, key)?
    };

    let mut config = config;
    if !cfg.alpn.is_empty() {
        config.alpn_protocols = cfg.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    }

    info!(
        min_version = %cfg.min_version,
        max_version = %cfg.max_version,
        mtls = cfg.client_ca.is_some(),
        cipher_suites = ?cfg.cipher_suites,
        "TLS configured"
    );

    Ok(config)
}

/// Load certificates from a PEM file.
fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, ServerError> {
    let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader)
        .filter_map(|c| c.ok().map(|v| v.into_owned()))
        .collect();
    Ok(certs)
}

/// Load private key from a PEM file.
fn load_private_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, ServerError> {
    let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);
    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => {
                return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(key));
            }
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => {
                return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(key));
            }
            Some(_) => continue,
            None => break,
        }
    }
    Err(ServerError::Config("no private key found".into()))
}
