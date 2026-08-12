//! The accept loop, and what a connection goes through before a handler sees it.
//!
//! A server may listen on more than one port — the main one, and a dedicated
//! WebSocket port in `split` mode — but the two differ only in which handler
//! their connections end in. Everything between `accept` and that handler is
//! the same work: socket options, admission, the PROXY header, TLS.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, info_span, warn};

use trojan_auth::AuthBackend;
use trojan_core::defaults;
use trojan_metrics::{
    ERROR_TLS_HANDSHAKE, record_connection_accepted, record_connection_closed,
    record_connection_rejected, record_error, record_tls_handshake_duration,
    set_connection_queue_depth,
};

use crate::error::ServerError;
use crate::handler::{Connection, handle_conn};
use crate::rate_limit::RateLimiter;
use crate::state::ServerState;
use crate::util::{ConnectionTracker, apply_tcp_options};

/// Global connection ID counter.
static CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Generate a unique connection ID.
#[inline]
fn next_conn_id() -> u64 {
    CONN_ID.fetch_add(1, Ordering::Relaxed)
}

/// What a listener does with the connections it accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenerKind {
    /// The main port. Carries a trojan stream directly, or a WebSocket one
    /// when `mixed` mode is configured; the handler decides per connection.
    Trojan,
    /// A dedicated WebSocket port, where anything that does not upgrade is
    /// refused rather than passed to the fallback.
    #[cfg(feature = "ws")]
    WebSocket,
}

/// Everything every listener on this server shares.
///
/// Cloned per listener and again per connection, so all of it is cheap to
/// clone by design.
pub(crate) struct ListenerContext<A: ?Sized> {
    /// Terminates the TLS every listener speaks.
    pub tls: TlsAcceptor,
    pub state: Arc<ServerState>,
    pub auth: Arc<A>,
    /// Active-connection count the graceful drain waits on.
    pub tracker: ConnectionTracker,
    /// Caps connections across all listeners at once; `None` is unlimited.
    pub conn_limit: Option<Arc<Semaphore>>,
    /// Per-IP connection rate limit; `None` is disabled.
    pub rate_limiter: Option<Arc<RateLimiter>>,
}

// Hand-written: the derive would demand `A: Clone`, and an auth backend is
// shared through the `Arc`, not cloned.
impl<A: ?Sized> Clone for ListenerContext<A> {
    fn clone(&self) -> Self {
        Self {
            tls: self.tls.clone(),
            state: self.state.clone(),
            auth: self.auth.clone(),
            tracker: self.tracker.clone(),
            conn_limit: self.conn_limit.clone(),
            rate_limiter: self.rate_limiter.clone(),
        }
    }
}

impl<A: ?Sized> ListenerContext<A> {
    /// A listener serving `tcp` under this context.
    pub fn listener(&self, tcp: TcpListener, kind: ListenerKind) -> Listener<A> {
        Listener {
            tcp,
            kind,
            ctx: self.clone(),
        }
    }
}

/// One listening socket and the context its connections run in.
pub(crate) struct Listener<A: ?Sized> {
    tcp: TcpListener,
    kind: ListenerKind,
    ctx: ListenerContext<A>,
}

impl<A> Listener<A>
where
    A: AuthBackend + ?Sized + 'static,
{
    /// Accept until the shutdown token fires.
    ///
    /// An accept error ends the loop rather than retrying: the failures a
    /// listener sees are exhausted file descriptors and the like, where
    /// spinning on `accept` would only burn a core.
    pub async fn serve(self, shutdown: CancellationToken) -> Result<(), ServerError> {
        loop {
            tokio::select! {
                biased;

                _ = shutdown.cancelled() => {
                    info!(kind = ?self.kind, "shutdown signal received, stopping accept loop");
                    return Ok(());
                }

                result = self.tcp.accept() => {
                    let (tcp, peer) = result?;
                    self.admit(tcp, peer);
                }
            }
        }
    }

    /// Take one connection through admission, then hand it to its own task.
    ///
    /// A connection refused here is dropped where it stands, which closes it.
    fn admit(&self, tcp: TcpStream, peer: SocketAddr) {
        if let Err(e) = apply_tcp_options(&tcp, &self.ctx.state.tcp_config) {
            debug!(error = %e, "failed to apply TCP options");
        }

        if let Some(ref sem) = self.ctx.conn_limit {
            set_connection_queue_depth(sem.available_permits() as f64);
        }

        // A trusted proxy's address stands for every client behind it, so
        // limiting on it would throttle a whole relay chain as if it were one
        // caller. Those connections are limited in `Session::serve` instead,
        // once the header names the client they belong to.
        let introduced_by_proxy = self.ctx.state.proxy_protocol.trusts(peer.ip());

        if !introduced_by_proxy
            && let Some(ref limiter) = self.ctx.rate_limiter
            && !limiter.check_and_increment(peer.ip())
        {
            debug!(peer = %peer, reason = "rate_limit", "connection rejected");
            record_connection_rejected("rate_limit");
            return;
        }

        let permit: Option<OwnedSemaphorePermit> = match self.ctx.conn_limit {
            Some(ref sem) => match sem.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    debug!(peer = %peer, reason = "max_connections", "connection rejected");
                    record_connection_rejected("max_connections");
                    return;
                }
            },
            None => None,
        };

        let id = next_conn_id();
        debug!(conn_id = id, peer = %peer, "new connection");

        let span = match self.kind {
            ListenerKind::Trojan => info_span!("conn", id, peer = %peer),
            #[cfg(feature = "ws")]
            ListenerKind::WebSocket => info_span!("conn", id, peer = %peer, transport = "ws"),
        };

        let session = Session {
            tcp,
            peer,
            id,
            introduced_by_proxy,
            kind: self.kind,
            ctx: self.ctx.clone(),
        };
        let active = self.ctx.tracker.connection_started();

        tokio::spawn(
            async move {
                // Both outlive the connection: the permit holds its slot in
                // the global cap, the guard its place in the drain count.
                let _permit = permit;
                let _active = active;
                session.run().await;
            }
            .instrument(span),
        );
    }
}

/// One accepted connection, on its way to a handler.
struct Session<A: ?Sized> {
    tcp: TcpStream,
    /// The transport peer. Behind a trusted proxy this is the last hop, not
    /// the client — `serve` replaces it once the header says who that is.
    peer: SocketAddr,
    id: u64,
    /// Whether `peer` is a proxy trusted to name the real client.
    introduced_by_proxy: bool,
    kind: ListenerKind,
    ctx: ListenerContext<A>,
}

impl<A> Session<A>
where
    A: AuthBackend + ?Sized + 'static,
{
    /// Serve the connection to its end, recording how it went.
    async fn run(self) {
        record_connection_accepted();
        let start = Instant::now();

        let result = self.serve().await;

        let duration_secs = start.elapsed().as_secs_f64();
        record_connection_closed(duration_secs);

        match result {
            Ok(()) => debug!(duration_secs, "connection closed"),
            Err(ref err) => {
                record_error(err.error_type());
                warn!(duration_secs, error = %err, "connection closed with error");
            }
        }
    }

    /// Read any PROXY header, complete the TLS handshake, then dispatch.
    async fn serve(self) -> Result<(), ServerError> {
        let introduced =
            crate::proxy::introduce(self.tcp, self.peer, &self.ctx.state.proxy_protocol).await?;

        // The deferred half of the accept-time check, now that the client
        // behind the proxy has a name.
        if self.introduced_by_proxy
            && let Some(ref limiter) = self.ctx.rate_limiter
            && !limiter.check_and_increment(introduced.peer.ip())
        {
            debug!(client = %introduced.peer, reason = "rate_limit", "connection rejected");
            record_connection_rejected("rate_limit");
            return Ok(());
        }

        let conn = Connection {
            peer: introduced.peer,
            id: self.id,
            chain: introduced.chain,
        };

        let Some(tls) = handshake(&self.ctx.tls, introduced.stream).await else {
            return Ok(());
        };

        match self.kind {
            ListenerKind::Trojan => handle_conn(tls, self.ctx.state, self.ctx.auth, conn).await,
            #[cfg(feature = "ws")]
            ListenerKind::WebSocket => {
                crate::handler::handle_ws_only(tls, self.ctx.state, self.ctx.auth, conn).await
            }
        }
    }
}

/// Complete the TLS handshake under a timeout.
///
/// `None` means the connection is over: a client that cannot handshake has
/// nothing more to say, and there is no error to report upwards for it.
async fn handshake<S>(
    acceptor: &TlsAcceptor,
    stream: S,
) -> Option<tokio_rustls::server::TlsStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let timeout = Duration::from_secs(defaults::DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS);
    let start = Instant::now();

    match tokio::time::timeout(timeout, acceptor.accept(stream)).await {
        Ok(Ok(tls)) => {
            let duration = start.elapsed().as_secs_f64();
            record_tls_handshake_duration(duration);
            debug!(duration_ms = duration * 1000.0, "TLS handshake completed");
            Some(tls)
        }
        Ok(Err(err)) => {
            record_error(ERROR_TLS_HANDSHAKE);
            warn!(error = %err, "TLS handshake failed");
            None
        }
        Err(_) => {
            record_error(ERROR_TLS_HANDSHAKE);
            warn!(timeout_secs = timeout.as_secs(), "TLS handshake timed out");
            None
        }
    }
}
