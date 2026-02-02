//! SOCKS5 UDP relay packet parsing/encoding (RFC 1928 section 7).
//!
//! ```text
//! +----+------+------+----------+----------+----------+
//! |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +----+------+------+----------+----------+----------+
//! | 2  |  1   |  1   | Variable |    2     | Variable |
//! +----+------+------+----------+----------+----------+
//! ```

use trojan_proto::{AddressRef, HostRef};

use crate::error::Socks5Error;

/// Parsed SOCKS5 UDP datagram header.
#[derive(Debug)]
pub struct Socks5UdpHeader<'a> {
    pub address: AddressRef<'a>,
    /// Offset to the payload data within the original buffer.
    pub header_len: usize,
    pub payload: &'a [u8],
}

/// Parse a SOCKS5 UDP datagram from a buffer.
pub fn parse_socks5_udp(buf: &[u8]) -> Result<Socks5UdpHeader<'_>, Socks5Error> {
    if buf.len() < 4 {
        return Err(Socks5Error::FragmentedUdp);
    }

    // RSV = 2 bytes (must be 0x0000)
    // FRAG = 1 byte (must be 0x00, no fragmentation support)
    let frag = buf[2];
    if frag != 0x00 {
        return Err(Socks5Error::FragmentedUdp);
    }

    let atyp = buf[3];
    let mut offset = 4;

    let (host, addr_len) = match atyp {
        0x01 => {
            // IPv4: 4 bytes
            if buf.len() < offset + 6 {
                return Err(Socks5Error::UnsupportedAddressType(atyp));
            }
            let ip: [u8; 4] = buf[offset..offset + 4].try_into().unwrap();
            (HostRef::Ipv4(ip), 4)
        }
        0x03 => {
            // Domain: 1 byte len + domain
            if buf.len() < offset + 1 {
                return Err(Socks5Error::UnsupportedAddressType(atyp));
            }
            let domain_len = buf[offset] as usize;
            if buf.len() < offset + 1 + domain_len + 2 {
                return Err(Socks5Error::UnsupportedAddressType(atyp));
            }
            let domain = &buf[offset + 1..offset + 1 + domain_len];
            (HostRef::Domain(domain), 1 + domain_len)
        }
        0x04 => {
            // IPv6: 16 bytes
            if buf.len() < offset + 18 {
                return Err(Socks5Error::UnsupportedAddressType(atyp));
            }
            let ip: [u8; 16] = buf[offset..offset + 16].try_into().unwrap();
            (HostRef::Ipv6(ip), 16)
        }
        _ => return Err(Socks5Error::UnsupportedAddressType(atyp)),
    };

    offset += addr_len;
    if buf.len() < offset + 2 {
        return Err(Socks5Error::UnsupportedAddressType(atyp));
    }
    let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    offset += 2;

    Ok(Socks5UdpHeader {
        address: AddressRef { host, port },
        header_len: offset,
        payload: &buf[offset..],
    })
}

/// Write a SOCKS5 UDP datagram header + payload into a buffer.
///
/// Returns the full packet bytes.
#[allow(clippy::cast_possible_truncation)]
pub fn write_socks5_udp(address: &AddressRef<'_>, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + payload.len());

    // RSV (2 bytes) + FRAG (1 byte)
    buf.extend_from_slice(&[0x00, 0x00, 0x00]);

    // ATYP + address
    match &address.host {
        HostRef::Ipv4(ip) => {
            buf.push(0x01);
            buf.extend_from_slice(ip);
        }
        HostRef::Domain(domain) => {
            buf.push(0x03);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain);
        }
        HostRef::Ipv6(ip) => {
            buf.push(0x04);
            buf.extend_from_slice(ip);
        }
    }

    // Port
    buf.extend_from_slice(&address.port.to_be_bytes());

    // Payload
    buf.extend_from_slice(payload);

    buf
}

#[cfg(test)]
mod tests {
    use super::{parse_socks5_udp, write_socks5_udp};
    use trojan_proto::{AddressRef, HostRef};

    #[test]
    fn parse_roundtrip_ipv4() {
        let address = AddressRef {
            host: HostRef::Ipv4([8, 8, 8, 8]),
            port: 53,
        };
        let payload = b"ping";
        let packet = write_socks5_udp(&address, payload);
        let parsed = parse_socks5_udp(&packet).unwrap();

        assert_eq!(parsed.address, address);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn parse_rejects_fragmented_udp() {
        let address = AddressRef {
            host: HostRef::Ipv4([1, 1, 1, 1]),
            port: 53,
        };
        let payload = b"data";
        let mut packet = write_socks5_udp(&address, payload);
        packet[2] = 0x01; // FRAG != 0
        parse_socks5_udp(&packet).unwrap_err();
    }
}
