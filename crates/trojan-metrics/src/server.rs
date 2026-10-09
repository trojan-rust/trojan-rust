//! Service-owned metrics listeners with process-wide Prometheus recording.

use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use axum::{Extension, Router, extract::ConnectInfo, routing::get};
use futures_util::{StreamExt, stream::FuturesUnordered};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use metrics_exporter_prometheus::{BuildError, PrometheusBuilder, PrometheusHandle};
use rustls::{RootCertStore, server::WebPkiClientVerifier};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use trojan_core::{
    metrics::MetricsTlsConfig,
    tls::{TlsError, load_certs, load_private_key},
};

const MAX_CONNECTIONS: usize = 128;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

static RECORDER: OnceLock<Result<PrometheusHandle, Arc<BuildError>>> = OnceLock::new();

/// Failure to configure or run a metrics listener.
#[derive(Debug, Error)]
pub enum MetricsError {
    /// The listen address is not a socket address.
    #[error("invalid metrics.listen: {0}")]
    Address(#[from] std::net::AddrParseError),
    /// A required TLS field is empty.
    #[error("{0}")]
    Config(&'static str),
    /// Certificate or private-key material could not be read.
    #[error("invalid metrics.tls material: {0}")]
    Material(#[from] TlsError),
    /// A client trust anchor is not a valid certificate.
    #[error("invalid metrics.tls.client_ca {path}: {source}")]
    ClientCa {
        /// Configured client CA path.
        path: String,
        /// Certificate parsing failure.
        source: rustls::Error,
    },
    /// Client certificate verification could not be configured.
    #[error("invalid metrics.tls.client_ca: {0}")]
    Verifier(#[from] rustls::server::VerifierBuilderError),
    /// The server certificate and private key are invalid or do not match.
    #[error("invalid metrics.tls.cert or metrics.tls.key: {0}")]
    Tls(#[from] rustls::Error),
    /// The listener could not bind the configured address.
    #[error("failed to bind metrics.listen {address}: {source}")]
    Bind {
        /// Configured socket address.
        address: SocketAddr,
        /// Operating-system bind failure.
        source: std::io::Error,
    },
    /// The listener failed to accept a connection.
    #[error("metrics listener failed: {0}")]
    Io(#[from] std::io::Error),
    /// Installing the process-wide recorder failed.
    #[error("failed to install Prometheus recorder: {0}")]
    Recorder(#[source] Arc<BuildError>),
}

/// A bound metrics listener that belongs to one running service.
///
/// Call [`Self::run_until`] to serve requests during the service lifetime.
/// Dropping the server releases the listener without changing the global recorder.
#[must_use = "call run_until to serve metrics during the service lifetime"]
pub struct MetricsServer {
    listener: TcpListener,
    app: Router,
    tls: Option<TlsAcceptor>,
}

impl std::fmt::Debug for MetricsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsServer")
            .field("listener", &self.listener)
            .field("mtls", &self.tls.is_some())
            .finish_non_exhaustive()
    }
}

impl MetricsServer {
    /// Return the bound address, including the assigned port when port zero was requested.
    pub fn local_addr(&self) -> Result<SocketAddr, MetricsError> {
        Ok(self.listener.local_addr()?)
    }

    /// Serve metrics until the service completes, propagating listener failures.
    ///
    /// Completion or cancellation closes the listener and all accepted connections.
    /// The caller must await an aborted service task before starting a replacement.
    pub async fn run_until<F: Future>(self, service: F) -> Result<F::Output, MetricsError> {
        tokio::select! {
            result = service => Ok(result),
            result = self.serve() => Err(result),
        }
    }

    async fn serve(self) -> MetricsError {
        // Poll connections here so cancellation drops every socket before the service exits.
        let mut connections = FuturesUnordered::new();
        loop {
            tokio::select! {
                result = self.listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                    let (stream, peer) = match result {
                        Ok(connection) => connection,
                        Err(error) => return error.into(),
                    };
                    connections.push(serve_connection(stream, peer, self.app.clone(), self.tls.clone()));
                }
                Some(()) = connections.next(), if !connections.is_empty() => {}
            }
        }
    }
}

/// Bind an HTTP or mandatory-mTLS metrics listener and initialize the global recorder once.
///
/// Every route, including additional routes, uses the same transport and client verification.
/// Create cached metric handles only after this function succeeds.
///
/// # Errors
/// Returns certificate, client-CA, recorder, or bind errors before the service reports startup.
pub async fn init_metrics_server(
    listen: &str,
    tls: Option<&MetricsTlsConfig>,
    extra_routes: Option<Router>,
) -> Result<MetricsServer, MetricsError> {
    let address: SocketAddr = listen.parse()?;
    let tls = tls.map(load_tls).transpose()?;
    let listener = TcpListener::bind(address)
        .await
        .map_err(|source| MetricsError::Bind { address, source })?;
    let handle = RECORDER
        .get_or_init(|| {
            PrometheusBuilder::new()
                .install_recorder()
                .map_err(Arc::new)
        })
        .as_ref()
        .map_err(|error| MetricsError::Recorder(Arc::clone(error)))?
        .clone();
    let mut app = Router::new()
        .route(
            "/metrics",
            get(move || {
                let handle = handle.clone();
                async move { handle.render() }
            }),
        )
        .route("/health", get(|| async { "OK" }))
        .route("/ready", get(|| async { "READY" }));
    if let Some(extra) = extra_routes {
        app = app.merge(extra);
    }
    Ok(MetricsServer { listener, app, tls })
}

fn load_tls(config: &MetricsTlsConfig) -> Result<TlsAcceptor, MetricsError> {
    config.validate().map_err(MetricsError::Config)?;
    let certificates = load_certs(&config.cert)?;
    let key = load_private_key(&config.key)?;
    let mut roots = RootCertStore::empty();
    for certificate in load_certs(&config.client_ca)? {
        roots
            .add(certificate)
            .map_err(|source| MetricsError::ClientCa {
                path: config.client_ca.clone(),
                source,
            })?;
    }
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()?;
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, key)?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(tls)))
}

async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    app: Router,
    tls: Option<TlsAcceptor>,
) {
    let app = app.layer(Extension(ConnectInfo(peer)));
    if let Some(tls) = tls {
        match timeout(HANDSHAKE_TIMEOUT, tls.accept(stream)).await {
            Ok(Ok(stream)) => serve_http(stream, app).await,
            Ok(Err(error)) => tracing::debug!(%peer, %error, "metrics TLS handshake rejected"),
            Err(_) => tracing::debug!(%peer, "metrics TLS handshake timed out"),
        }
    } else {
        serve_http(stream, app).await;
    }
}

async fn serve_http<I: AsyncRead + AsyncWrite + Unpin + Send + 'static>(stream: I, app: Router) {
    if let Err(error) = Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), TowerToHyperService::new(app))
        .await
    {
        tracing::debug!(%error, "metrics HTTP connection closed with an error");
    }
}

#[cfg(test)]
mod tests;
