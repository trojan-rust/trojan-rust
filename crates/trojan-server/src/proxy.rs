//! Taking a connection's real identity from the PROXY protocol header that
//! introduces it.
//!
//! Behind a relay chain or a load balancer every connection arrives from the
//! same address, so without this the server rate-limits, geo-tags and logs the
//! last hop instead of the client, and cannot tell which nodes carried the
//! traffic it is about to bill.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::TcpStream;
use tracing::debug;
use trojan_config::ProxyProtocolConfig;
use trojan_core::defaults;
use trojan_core::io::PrefixedStream;
use trojan_core::proxy_protocol::{self, ChainInfo};

use crate::error::ServerError;

/// A connection, once any PROXY header in front of it has been consumed.
#[derive(Debug)]
pub(crate) struct Introduced {
    /// The stream to hand to TLS. Replays whatever was read past the header.
    pub stream: PrefixedStream<TcpStream>,
    /// The address to attribute the connection to: the client the header
    /// named, or the transport peer when there was nothing to believe.
    pub peer: SocketAddr,
    /// The relay hops that carried the connection, empty for a direct one.
    pub chain: ChainInfo,
}

/// Read the PROXY header introducing `tcp`, when `peer` is trusted to send one.
///
/// Connections from anywhere else are passed through untouched — their bytes
/// are the client's own. A trusted sender that simply does not send a header
/// is fine too, and is attributed to its own address: a claim is required to
/// be believed, not to be allowed.
pub(crate) async fn introduce(
    mut tcp: TcpStream,
    peer: SocketAddr,
    config: &ProxyProtocolConfig,
) -> Result<Introduced, ServerError> {
    if !config.trusts(peer.ip()) {
        return Ok(Introduced {
            stream: PrefixedStream::new(Bytes::new(), tcp),
            peer,
            chain: ChainInfo::default(),
        });
    }

    // Shares the TLS handshake's budget: a sender that opens a connection and
    // then says nothing must not hold a slot indefinitely.
    let timeout = Duration::from_secs(defaults::DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS);
    let accepted = tokio::time::timeout(timeout, proxy_protocol::accept(&mut tcp))
        .await
        .map_err(|_| {
            ServerError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out reading PROXY protocol header",
            ))
        })??;

    let Some(header) = accepted.header else {
        return Ok(Introduced {
            stream: PrefixedStream::new(accepted.residue, tcp),
            peer,
            chain: ChainInfo::default(),
        });
    };

    let client = proxy_protocol::effective_peer(Some(&header), peer);
    debug!(
        transport_peer = %peer,
        client = %client,
        chain = ?header.chain.nodes,
        "connection introduced by a trusted proxy"
    );

    Ok(Introduced {
        stream: PrefixedStream::new(accepted.residue, tcp),
        peer: client,
        chain: header.chain,
    })
}
