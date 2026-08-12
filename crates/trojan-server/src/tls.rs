//! TLS configuration loading.

use std::sync::Arc;

use tokio_rustls::rustls::{self, RootCertStore, server::WebPkiClientVerifier};
use tracing::{info, warn};
use trojan_config::{TlsConfig, TlsVersion};
use trojan_core::defaults;
use trojan_core::tls::load_keypair;

use crate::error::ServerError;

/// Load TLS configuration from config.
pub fn load_tls_config(cfg: &TlsConfig) -> Result<rustls::ServerConfig, ServerError> {
    let (certs, key) = load_keypair(&cfg.cert, &cfg.key)?;

    // Static slices, so selecting a range allocates nothing. `validate_config`
    // rejects an inverted range, and the type rules out any other pairing.
    let versions: &[&'static rustls::SupportedProtocolVersion] =
        match (cfg.min_version, cfg.max_version) {
            (TlsVersion::Tls13, TlsVersion::Tls13) => &[&rustls::version::TLS13],
            (TlsVersion::Tls12, TlsVersion::Tls12) => &[&rustls::version::TLS12],
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
        let ca_certs = trojan_core::tls::load_certs(ca_path)?;
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

    // Session resumption. rustls defaults to `NeverProducesTickets` plus a
    // 256-entry stateful cache, so on a busy server nearly every client pays
    // for a full handshake — the dominant per-connection CPU cost when the
    // proxy terminates TLS. A ticketer moves both TLS 1.3 and TLS 1.2
    // resumption onto stateless tickets; the enlarged cache still backs
    // TLS 1.2 session-ID resumption for clients that offer no ticket.
    //
    // Ticket keys are generated per process and rotate, so under
    // `server.tcp.reuse_port` a client landing on a different worker still
    // falls back to a full handshake.
    config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new()?;
    config.session_storage =
        rustls::server::ServerSessionMemoryCache::new(defaults::DEFAULT_TLS_SESSION_CACHE_SIZE);

    info!(
        min_version = ?cfg.min_version,
        max_version = ?cfg.max_version,
        mtls = cfg.client_ca.is_some(),
        cipher_suites = ?cfg.cipher_suites,
        session_cache = defaults::DEFAULT_TLS_SESSION_CACHE_SIZE,
        "TLS configured"
    );

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The end-to-end resumption test also passes on rustls' default stateful
    /// cache, so it does not pin down *how* sessions resume. Stateless tickets
    /// are what lets resumption survive past that cache's 256-entry bound, so
    /// assert the ticketer directly.
    #[test]
    fn server_config_issues_stateless_tickets() {
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = CertificateParams::default().self_signed(&key_pair).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();

        let cfg = TlsConfig {
            cert: cert_path.to_string_lossy().into_owned(),
            key: key_path.to_string_lossy().into_owned(),
            alpn: vec![],
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            client_ca: None,
            cipher_suites: vec![],
        };

        let server_config = load_tls_config(&cfg).expect("load tls config");
        assert!(
            server_config.ticketer.enabled(),
            "server must issue stateless session tickets"
        );
    }
}
