//! SOCKS5 handshake: method negotiation and command parsing (RFC 1928).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use trojan_proto::{AddressRef, HostRef};

use crate::error::Socks5Error;

const SOCKS5_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// SOCKS5 reply codes.
pub const REPLY_SUCCEEDED: u8 = 0x00;
pub const REPLY_GENERAL_FAILURE: u8 = 0x01;
pub const REPLY_CONNECTION_NOT_ALLOWED: u8 = 0x02;
pub const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REPLY_HOST_UNREACHABLE: u8 = 0x04;
pub const REPLY_CONNECTION_REFUSED: u8 = 0x05;
pub const REPLY_TTL_EXPIRED: u8 = 0x06;
pub const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// Parsed SOCKS5 request.
#[derive(Debug)]
pub struct Socks5Request {
    pub command: u8,
    pub atyp: u8,
    /// Raw address bytes (without atyp byte): for IPv4 = 4 bytes, IPv6 = 16 bytes,
    /// domain = 1 byte length + domain bytes.
    pub addr_data: Vec<u8>,
    pub port: u16,
}

impl Socks5Request {
    /// Convert to a trojan-proto `AddressRef`.
    ///
    /// Returns `None` if address type is unsupported.
    pub fn to_address_ref(&self) -> Option<AddressRef<'_>> {
        let host = match self.atyp {
            ATYP_IPV4 => {
                let ip: [u8; 4] = self.addr_data[..4].try_into().ok()?;
                HostRef::Ipv4(ip)
            }
            ATYP_DOMAIN => {
                // addr_data[0] = length, addr_data[1..] = domain
                let domain = &self.addr_data[1..];
                HostRef::Domain(domain)
            }
            ATYP_IPV6 => {
                let ip: [u8; 16] = self.addr_data[..16].try_into().ok()?;
                HostRef::Ipv6(ip)
            }
            _ => return None,
        };
        Some(AddressRef {
            host,
            port: self.port,
        })
    }
}

/// Perform SOCKS5 method negotiation (server side).
///
/// Reads the client's greeting and responds with NO AUTH (0x00).
pub async fn negotiate_method<S>(stream: &mut S) -> Result<(), Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read version
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| Socks5Error::InvalidVersion(0))?;

    if header[0] != SOCKS5_VERSION {
        return Err(Socks5Error::InvalidVersion(header[0]));
    }

    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|_| Socks5Error::NoAcceptableMethods)?;

    if methods.contains(&METHOD_NO_AUTH) {
        stream
            .write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH])
            .await
            .map_err(|_| Socks5Error::NoAcceptableMethods)?;
        Ok(())
    } else {
        let _ = stream
            .write_all(&[SOCKS5_VERSION, METHOD_NO_ACCEPTABLE])
            .await;
        Err(Socks5Error::NoAcceptableMethods)
    }
}

/// Read the SOCKS5 request after method negotiation.
pub async fn read_request<S>(stream: &mut S) -> Result<Socks5Request, Socks5Error>
where
    S: AsyncRead + Unpin,
{
    // VER CMD RSV ATYP
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| Socks5Error::InvalidVersion(0))?;

    if header[0] != SOCKS5_VERSION {
        return Err(Socks5Error::InvalidVersion(header[0]));
    }

    let command = header[1];
    // header[2] is RSV (reserved)
    let atyp = header[3];

    let (addr_data, port) = read_address(stream, atyp).await?;

    Ok(Socks5Request {
        command,
        atyp,
        addr_data,
        port,
    })
}

/// Read address based on address type.
async fn read_address<S>(stream: &mut S, atyp: u8) -> Result<(Vec<u8>, u16), Socks5Error>
where
    S: AsyncRead + Unpin,
{
    match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6]; // 4 addr + 2 port
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|_| Socks5Error::UnsupportedAddressType(atyp))?;
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok((buf[..4].to_vec(), port))
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream
                .read_exact(&mut len_buf)
                .await
                .map_err(|_| Socks5Error::UnsupportedAddressType(atyp))?;
            let domain_len = len_buf[0] as usize;
            let mut domain = vec![0u8; domain_len + 2]; // domain + port
            stream
                .read_exact(&mut domain)
                .await
                .map_err(|_| Socks5Error::UnsupportedAddressType(atyp))?;
            let port = u16::from_be_bytes([domain[domain_len], domain[domain_len + 1]]);
            // Store as: [len_byte] + domain_bytes
            let mut addr_data = Vec::with_capacity(1 + domain_len);
            addr_data.push(len_buf[0]);
            addr_data.extend_from_slice(&domain[..domain_len]);
            Ok((addr_data, port))
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 18]; // 16 addr + 2 port
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|_| Socks5Error::UnsupportedAddressType(atyp))?;
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok((buf[..16].to_vec(), port))
        }
        _ => Err(Socks5Error::UnsupportedAddressType(atyp)),
    }
}

/// Send a SOCKS5 reply.
pub async fn send_reply<S>(
    stream: &mut S,
    reply: u8,
    bind_addr: &std::net::SocketAddr,
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(32);
    buf.push(SOCKS5_VERSION);
    buf.push(reply);
    buf.push(0x00); // RSV

    match bind_addr {
        std::net::SocketAddr::V4(addr) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        std::net::SocketAddr::V6(addr) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
    }

    stream.write_all(&buf).await
}

/// Send a SOCKS5 reply with a zeroed bind address (0.0.0.0:0).
pub async fn send_reply_unspecified<S>(stream: &mut S, reply: u8) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 0u16));
    send_reply(stream, reply, &addr).await
}
