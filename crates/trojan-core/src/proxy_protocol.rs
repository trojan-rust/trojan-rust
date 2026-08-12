//! PROXY protocol v2, plus the relay-chain TLV this project sends in one.
//!
//! A relay chain hands the exit server a plain byte stream, so the exit sees
//! the last hop's address as the peer and has no idea a chain exists at all.
//! Both facts matter: rate limiting, geo tagging and logs attribute to the
//! wrong address, and per-user traffic cannot be credited to the hops that
//! carried it.
//!
//! The entry node answers both by prefixing the tunnel with a PROXY v2 header.
//! Relays forward it untouched — to them it is just the first bytes of the
//! payload — and the exit consumes it before the TLS handshake it precedes.
//!
//! The header carries the original endpoints, as the standard intends, and the
//! chain's node ids in a private TLV ([`CHAIN_TLV_TYPE`], inside the range the
//! spec reserves for application use). Choosing the standard framing over a
//! bespoke preamble also means an haproxy or nginx in front of the exit
//! interoperates, and that the 12-byte signature cannot be confused with the
//! `0x16` a TLS ClientHello opens with.
//!
//! Reference: <https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt>

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::Bytes;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

/// The 12-byte block every v2 header opens with.
///
/// Contains a NUL at position 5, so it must never be treated as a C string.
pub const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Bytes before the address block: signature, version/command, family, length.
const HEADER_LEN: usize = 16;

/// Version 2 in the high nibble of the 13th byte.
const VERSION_2: u8 = 0x20;

/// `LOCAL`: the sender originated the connection itself; addresses are absent.
const COMMAND_LOCAL: u8 = 0x0;
/// `PROXY`: the header describes another node's connection.
const COMMAND_PROXY: u8 = 0x1;

/// `AF_UNSPEC` + `UNSPEC`: no address information follows.
const FAMILY_UNSPEC: u8 = 0x00;
/// `AF_INET` + `STREAM`: two 4-byte addresses and two ports.
const FAMILY_TCP4: u8 = 0x11;
/// `AF_INET6` + `STREAM`: two 16-byte addresses and two ports.
const FAMILY_TCP6: u8 = 0x21;

/// TLV type carrying the relay chain, from the range the spec reserves for
/// application-specific data (`PP2_TYPE_MIN_CUSTOM`..=`PP2_TYPE_MAX_CUSTOM`).
pub const CHAIN_TLV_TYPE: u8 = 0xE0;

/// Bytes a TLV spends on its type and length.
const TLV_HEADER_LEN: usize = 3;

/// What went wrong reading or writing a header.
#[derive(Debug, Error)]
pub enum ProxyProtocolError {
    /// The stream ended before the header did.
    #[error("truncated PROXY protocol header")]
    Truncated,
    /// The version nibble was not 2, or the command was unassigned.
    #[error("unsupported PROXY protocol version or command: {0:#04x}")]
    UnsupportedVersion(u8),
    /// The address family byte named a family this implementation rejects.
    #[error("unsupported PROXY protocol address family: {0:#04x}")]
    UnsupportedFamily(u8),
    /// The declared length disagrees with the address family, or a TLV runs
    /// past the end of the header.
    #[error("malformed PROXY protocol header: {0}")]
    Malformed(&'static str),
    /// The header would not fit the 16-bit length field.
    #[error("PROXY protocol header too long to encode")]
    TooLong,
    /// Reading from the stream failed.
    #[error("io error reading PROXY protocol header: {0}")]
    Io(#[from] std::io::Error),
}

/// The original connection, as the sender saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoints {
    /// Where the connection came from — the real client.
    pub source: SocketAddr,
    /// Where it was addressed to — the listener the client reached.
    pub destination: SocketAddr,
}

/// The relay chain a connection travelled before arriving.
///
/// Node ids are opaque strings chosen by whoever operates the chain; the exit
/// only passes them on when it reports traffic, so their meaning belongs to
/// the panel, not to the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainInfo {
    /// Ids of the hops the connection passed through, entry node first.
    pub nodes: Vec<String>,
}

impl ChainInfo {
    /// A chain over the given node ids.
    pub fn new(nodes: Vec<String>) -> Self {
        Self { nodes }
    }

    /// Whether any hop identified itself.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Encode as the comma-separated list the TLV carries.
    fn encode(&self) -> Vec<u8> {
        self.nodes.join(",").into_bytes()
    }

    /// Decode the TLV payload, dropping empty entries.
    ///
    /// Anything that is not UTF-8 is treated as no chain at all rather than as
    /// a fatal error: a header from some other sender that happens to use the
    /// same private type must not cost us the connection.
    fn decode(value: &[u8]) -> Self {
        let Ok(text) = std::str::from_utf8(value) else {
            return Self::default();
        };
        Self {
            nodes: text
                .split(',')
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .collect(),
        }
    }
}

/// A PROXY protocol v2 header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyHeader {
    /// The original endpoints, absent for a `LOCAL` header or an unspecified
    /// address family.
    pub endpoints: Option<Endpoints>,
    /// The relay chain, empty unless the sender described one.
    pub chain: ChainInfo,
}

impl ProxyHeader {
    /// A `PROXY` header describing one connection's endpoints.
    pub fn new(source: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            endpoints: Some(Endpoints {
                source,
                destination,
            }),
            chain: ChainInfo::default(),
        }
    }

    /// Attach the chain the connection travelled.
    pub fn with_chain(mut self, chain: ChainInfo) -> Self {
        self.chain = chain;
        self
    }

    /// The real client address, when the header carries one.
    pub fn source(&self) -> Option<SocketAddr> {
        self.endpoints.map(|e| e.source)
    }

    /// Serialize for the wire.
    ///
    /// Fails only when the chain is long enough to overflow the header's
    /// 16-bit length field, which takes thousands of hops.
    pub fn encode(&self) -> Result<Vec<u8>, ProxyProtocolError> {
        let mut body = Vec::new();

        let family = match self.endpoints {
            Some(Endpoints {
                source: SocketAddr::V4(source),
                destination: SocketAddr::V4(destination),
            }) => {
                body.extend_from_slice(&source.ip().octets());
                body.extend_from_slice(&destination.ip().octets());
                body.extend_from_slice(&source.port().to_be_bytes());
                body.extend_from_slice(&destination.port().to_be_bytes());
                FAMILY_TCP4
            }
            Some(Endpoints {
                source: SocketAddr::V6(source),
                destination: SocketAddr::V6(destination),
            }) => {
                body.extend_from_slice(&source.ip().octets());
                body.extend_from_slice(&destination.ip().octets());
                body.extend_from_slice(&source.port().to_be_bytes());
                body.extend_from_slice(&destination.port().to_be_bytes());
                FAMILY_TCP6
            }
            // A v4 client reaching a v6 listener (or the reverse) has no
            // representation in this protocol: the spec gives one family byte
            // for both addresses. Send the connection as unspecified rather
            // than inventing a mapping the receiver would misread.
            _ => FAMILY_UNSPEC,
        };

        if !self.chain.is_empty() {
            let value = self.chain.encode();
            let len = u16::try_from(value.len()).map_err(|_| ProxyProtocolError::TooLong)?;
            body.push(CHAIN_TLV_TYPE);
            body.extend_from_slice(&len.to_be_bytes());
            body.extend_from_slice(&value);
        }

        let body_len = u16::try_from(body.len()).map_err(|_| ProxyProtocolError::TooLong)?;

        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.extend_from_slice(&SIGNATURE);
        out.push(VERSION_2 | COMMAND_PROXY);
        out.push(family);
        out.extend_from_slice(&body_len.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Parse the bytes that follow the fixed 16-byte header.
    fn decode_body(family: u8, body: &[u8]) -> Result<Self, ProxyProtocolError> {
        let (endpoints, rest) = match family {
            FAMILY_TCP4 => {
                const ADDR_LEN: usize = 12;
                if body.len() < ADDR_LEN {
                    return Err(ProxyProtocolError::Malformed(
                        "IPv4 address block too short",
                    ));
                }
                let source = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
                let destination = Ipv4Addr::new(body[4], body[5], body[6], body[7]);
                let source_port = u16::from_be_bytes([body[8], body[9]]);
                let destination_port = u16::from_be_bytes([body[10], body[11]]);
                (
                    Some(Endpoints {
                        source: SocketAddr::V4(SocketAddrV4::new(source, source_port)),
                        destination: SocketAddr::V4(SocketAddrV4::new(
                            destination,
                            destination_port,
                        )),
                    }),
                    &body[ADDR_LEN..],
                )
            }
            FAMILY_TCP6 => {
                const ADDR_LEN: usize = 36;
                if body.len() < ADDR_LEN {
                    return Err(ProxyProtocolError::Malformed(
                        "IPv6 address block too short",
                    ));
                }
                let source = ipv6_at(body, 0);
                let destination = ipv6_at(body, 16);
                let source_port = u16::from_be_bytes([body[32], body[33]]);
                let destination_port = u16::from_be_bytes([body[34], body[35]]);
                (
                    Some(Endpoints {
                        source: SocketAddr::V6(SocketAddrV6::new(source, source_port, 0, 0)),
                        destination: SocketAddr::V6(SocketAddrV6::new(
                            destination,
                            destination_port,
                            0,
                            0,
                        )),
                    }),
                    &body[ADDR_LEN..],
                )
            }
            // The spec requires receivers to accept UNSPEC and fall back to
            // the transport's own addresses. Other families (AF_UNIX) cannot
            // describe a connection this server could have accepted.
            FAMILY_UNSPEC => (None, body),
            other => return Err(ProxyProtocolError::UnsupportedFamily(other)),
        };

        Ok(Self {
            endpoints,
            chain: decode_chain_tlv(rest)?,
        })
    }
}

/// Read the 16 bytes at `offset` as an IPv6 address.
///
/// The caller has already checked the slice is long enough.
fn ipv6_at(body: &[u8], offset: usize) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&body[offset..offset + 16]);
    Ipv6Addr::from(octets)
}

/// Walk the TLV block, returning the chain if one is present.
///
/// Unknown types are skipped: a proxy ahead of us may add its own, and the
/// spec expects receivers to tolerate them.
fn decode_chain_tlv(mut rest: &[u8]) -> Result<ChainInfo, ProxyProtocolError> {
    let mut chain = ChainInfo::default();
    while !rest.is_empty() {
        if rest.len() < TLV_HEADER_LEN {
            return Err(ProxyProtocolError::Malformed("truncated TLV header"));
        }
        let tlv_type = rest[0];
        let len = usize::from(u16::from_be_bytes([rest[1], rest[2]]));
        let value_end = TLV_HEADER_LEN
            .checked_add(len)
            .filter(|end| *end <= rest.len())
            .ok_or(ProxyProtocolError::Malformed("TLV runs past header end"))?;

        if tlv_type == CHAIN_TLV_TYPE {
            chain = ChainInfo::decode(&rest[TLV_HEADER_LEN..value_end]);
        }
        rest = &rest[value_end..];
    }
    Ok(chain)
}

/// What a stream turned out to start with.
#[derive(Debug)]
pub struct Accepted {
    /// The header, absent when the stream did not begin with the signature.
    pub header: Option<ProxyHeader>,
    /// Bytes read while deciding that belong to whatever follows the header.
    ///
    /// Always replay these before reading the stream again: for a stream with
    /// no header they are its first bytes, and for one with a header the
    /// sender's next message often arrives in the same read.
    pub residue: Bytes,
}

/// Read a PROXY v2 header from `stream` if it starts with one.
///
/// Streams that do not are left effectively untouched — every byte read while
/// checking comes back as [`Accepted::residue`] — so a listener can take
/// proxied and direct connections on one port.
pub async fn accept<S>(stream: &mut S) -> Result<Accepted, ProxyProtocolError>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(HEADER_LEN);

    // Stop at the first byte that cannot be the signature, so a direct client
    // is never held up waiting for bytes it has no reason to send.
    while buf.len() < SIGNATURE.len() {
        if !SIGNATURE.starts_with(&buf) {
            return Ok(Accepted {
                header: None,
                residue: Bytes::from(buf),
            });
        }
        if read_more(stream, &mut buf).await? == 0 {
            return Ok(Accepted {
                header: None,
                residue: Bytes::from(buf),
            });
        }
    }

    if !buf.starts_with(&SIGNATURE) {
        return Ok(Accepted {
            header: None,
            residue: Bytes::from(buf),
        });
    }

    while buf.len() < HEADER_LEN {
        if read_more(stream, &mut buf).await? == 0 {
            return Err(ProxyProtocolError::Truncated);
        }
    }

    let ver_cmd = buf[12];
    if ver_cmd & 0xF0 != VERSION_2 {
        return Err(ProxyProtocolError::UnsupportedVersion(ver_cmd));
    }
    let family = buf[13];
    let body_len = usize::from(u16::from_be_bytes([buf[14], buf[15]]));

    while buf.len() < HEADER_LEN + body_len {
        if read_more(stream, &mut buf).await? == 0 {
            return Err(ProxyProtocolError::Truncated);
        }
    }

    let body = &buf[HEADER_LEN..HEADER_LEN + body_len];
    let header = match ver_cmd & 0x0F {
        // A LOCAL header describes the sender's own connection, so the
        // addresses in it — if any — say nothing about a client.
        COMMAND_LOCAL => ProxyHeader::default(),
        COMMAND_PROXY => ProxyHeader::decode_body(family, body)?,
        _ => return Err(ProxyProtocolError::UnsupportedVersion(ver_cmd)),
    };

    let residue = Bytes::copy_from_slice(&buf[HEADER_LEN + body_len..]);
    Ok(Accepted {
        header: Some(header),
        residue,
    })
}

/// Append one read's worth of bytes to `buf`, returning how many arrived.
async fn read_more<S>(stream: &mut S, buf: &mut Vec<u8>) -> Result<usize, ProxyProtocolError>
where
    S: AsyncRead + Unpin,
{
    let mut chunk = [0u8; 256];
    let n = stream.read(&mut chunk).await?;
    buf.extend_from_slice(&chunk[..n]);
    Ok(n)
}

/// The address to attribute a connection to, given what the header said.
///
/// Falls back to the transport's own peer address whenever the header carried
/// no usable source — a `LOCAL` header, an unspecified family, or no header.
pub fn effective_peer(header: Option<&ProxyHeader>, transport_peer: SocketAddr) -> SocketAddr {
    header
        .and_then(ProxyHeader::source)
        .unwrap_or(transport_peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn v4(addr: &str) -> SocketAddr {
        addr.parse().unwrap()
    }

    async fn roundtrip(header: &ProxyHeader, trailing: &[u8]) -> Accepted {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let mut wire = header.encode().unwrap();
        wire.extend_from_slice(trailing);
        client.write_all(&wire).await.unwrap();
        client.flush().await.unwrap();
        accept(&mut server).await.unwrap()
    }

    #[tokio::test]
    async fn ipv4_endpoints_and_chain_survive_a_roundtrip() {
        let sent = ProxyHeader::new(v4("203.0.113.7:51234"), v4("198.51.100.9:443"))
            .with_chain(ChainInfo::new(vec!["entry-1".into(), "relay-hk".into()]));

        let accepted = roundtrip(&sent, b"").await;

        assert_eq!(accepted.header, Some(sent));
        assert!(accepted.residue.is_empty());
    }

    #[tokio::test]
    async fn ipv6_endpoints_survive_a_roundtrip() {
        let sent = ProxyHeader::new(v4("[2001:db8::1]:51234"), v4("[2001:db8::2]:443"));

        let accepted = roundtrip(&sent, b"").await;

        assert_eq!(accepted.header.unwrap().endpoints, sent.endpoints);
    }

    /// The header precedes a TLS handshake that usually arrives in the same
    /// read; dropping those bytes would break the connection it describes.
    #[tokio::test]
    async fn bytes_after_the_header_come_back_as_residue() {
        let sent = ProxyHeader::new(v4("203.0.113.7:1"), v4("198.51.100.9:443"));

        let accepted = roundtrip(&sent, b"\x16\x03\x01hello").await;

        assert!(accepted.header.is_some());
        assert_eq!(accepted.residue.as_ref(), b"\x16\x03\x01hello");
    }

    /// A client that speaks TLS straight at the port must be handed back every
    /// byte it sent, or the handshake it started is lost.
    #[tokio::test]
    async fn a_stream_without_a_header_is_returned_intact() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(b"\x16\x03\x01\x00\xff").await.unwrap();
        client.flush().await.unwrap();

        let accepted = accept(&mut server).await.unwrap();

        assert!(accepted.header.is_none());
        assert_eq!(accepted.residue.as_ref(), b"\x16\x03\x01\x00\xff");
    }

    /// The signature shares its first bytes with a CRLF-led protocol, so the
    /// check must not commit until it diverges.
    #[tokio::test]
    async fn a_stream_that_only_starts_like_the_signature_is_returned_intact() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(b"\r\n\r\nnot-proxy").await.unwrap();
        client.flush().await.unwrap();

        let accepted = accept(&mut server).await.unwrap();

        assert!(accepted.header.is_none());
        assert_eq!(accepted.residue.as_ref(), b"\r\n\r\nnot-proxy");
    }

    #[tokio::test]
    async fn unknown_tlvs_are_skipped_and_the_chain_still_reads() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&SIGNATURE);
        wire.push(VERSION_2 | COMMAND_PROXY);
        wire.push(FAMILY_TCP4);

        let mut body = vec![203, 0, 113, 7, 198, 51, 100, 9, 0xC0, 0x00, 0x01, 0xBB];
        // An unrelated TLV (PP2_TYPE_AUTHORITY) ahead of ours.
        body.extend_from_slice(&[0x02, 0x00, 0x03]);
        body.extend_from_slice(b"abc");
        body.push(CHAIN_TLV_TYPE);
        body.extend_from_slice(&3u16.to_be_bytes());
        body.extend_from_slice(b"a,b");

        wire.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(&body);

        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(&wire).await.unwrap();
        client.flush().await.unwrap();

        let header = accept(&mut server).await.unwrap().header.unwrap();

        assert_eq!(header.chain.nodes, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(header.source(), Some(v4("203.0.113.7:49152")));
    }

    #[tokio::test]
    async fn a_local_header_carries_no_client() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&SIGNATURE);
        wire.push(VERSION_2 | COMMAND_LOCAL);
        wire.push(FAMILY_UNSPEC);
        wire.extend_from_slice(&0u16.to_be_bytes());

        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(&wire).await.unwrap();
        client.flush().await.unwrap();

        let header = accept(&mut server).await.unwrap().header.unwrap();

        assert_eq!(header.source(), None);
        assert!(header.chain.is_empty());
    }

    #[tokio::test]
    async fn a_v1_header_is_rejected() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&SIGNATURE);
        wire.push(0x10); // version 1 in the high nibble
        wire.push(FAMILY_TCP4);
        wire.extend_from_slice(&0u16.to_be_bytes());

        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(&wire).await.unwrap();
        client.flush().await.unwrap();

        let err = accept(&mut server).await.unwrap_err();

        assert!(matches!(err, ProxyProtocolError::UnsupportedVersion(0x10)));
    }

    #[tokio::test]
    async fn a_header_cut_short_is_an_error() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let wire = ProxyHeader::new(v4("203.0.113.7:1"), v4("198.51.100.9:443"))
            .encode()
            .unwrap();
        client.write_all(&wire[..HEADER_LEN + 4]).await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        let err = accept(&mut server).await.unwrap_err();

        assert!(matches!(err, ProxyProtocolError::Truncated));
    }

    /// One family byte covers both addresses, so a crossed pair has to degrade
    /// to unspecified rather than silently claiming the wrong family.
    #[tokio::test]
    async fn mixed_address_families_degrade_to_unspecified() {
        let sent = ProxyHeader::new(v4("203.0.113.7:1"), v4("[2001:db8::2]:443"));

        let accepted = roundtrip(&sent, b"").await;

        assert_eq!(accepted.header.unwrap().endpoints, None);
    }

    #[test]
    fn effective_peer_prefers_the_header() {
        let header = ProxyHeader::new(v4("203.0.113.7:51234"), v4("198.51.100.9:443"));
        let transport = v4("10.0.0.1:40000");

        assert_eq!(
            effective_peer(Some(&header), transport),
            v4("203.0.113.7:51234")
        );
        assert_eq!(effective_peer(None, transport), transport);
        assert_eq!(
            effective_peer(Some(&ProxyHeader::default()), transport),
            transport
        );
    }
}
