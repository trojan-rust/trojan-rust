//! Relay handshake protocol: encode and decode.
//!
//! Format:
//! ```text
//! +----------------------------+---------+-------------------+---------+
//! | hex(SHA224(relay_password)) |  CRLF   | target_addr:port  |  CRLF   |
//! +----------------------------+---------+-------------------+---------+
//! |            56              | X'0D0A' |     Variable      | X'0D0A' |
//! +----------------------------+---------+-------------------+---------+
//! |               metadata (key=value,...)                   |  CRLF   |
//! +----------------------------------------------------------+---------+
//! |                     Variable                             | X'0D0A' |
//! ```
//!
//! The metadata line is always present on the wire. It carries comma-separated
//! key=value pairs (e.g. `transport=tls,sni=crates.io`). An empty metadata
//! line (bare CRLF) means "use relay node defaults".

use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::TransportType;
use crate::error::RelayError;

const HASH_LEN: usize = 56;
const CRLF: &[u8; 2] = b"\r\n";

/// Maximum target address length (host:port).
const MAX_TARGET_LEN: usize = 260;

/// Maximum metadata line length.
const MAX_METADATA_LEN: usize = 512;

/// Compute the SHA-224 hex hash of a password.
pub fn hash_password(password: &str) -> String {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Metadata sent alongside the relay handshake.
///
/// Tells the relay node what transport/sni to use for its outbound connection.
#[derive(Debug, Clone, Default)]
pub struct HandshakeMetadata {
    /// Outbound transport type. `None` = use relay node default.
    pub transport: Option<TransportType>,
    /// Outbound TLS SNI. `None` = use relay node default.
    pub sni: Option<String>,
}

impl HandshakeMetadata {
    /// Encode to wire format: `key=value,key=value`
    fn encode(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref t) = self.transport {
            let val = match t {
                TransportType::Tls => "tls",
                TransportType::Plain => "plain",
            };
            parts.push(format!("transport={}", val));
        }
        if let Some(ref sni) = self.sni {
            parts.push(format!("sni={}", sni));
        }
        parts.join(",")
    }

    /// Parse from wire format.
    fn parse(s: &str) -> Self {
        let mut meta = Self::default();
        if s.is_empty() {
            return meta;
        }
        for part in s.split(',') {
            if let Some((key, value)) = part.split_once('=') {
                match key.trim() {
                    "transport" => {
                        meta.transport = match value.trim() {
                            "tls" => Some(TransportType::Tls),
                            "plain" => Some(TransportType::Plain),
                            _ => None,
                        };
                    }
                    "sni" => {
                        meta.sni = Some(value.trim().to_string());
                    }
                    _ => {} // ignore unknown keys for forward compat
                }
            }
        }
        meta
    }
}

/// Write a relay handshake to the stream.
///
/// Sends: `hex(SHA224(password)) + CRLF + target + CRLF + metadata + CRLF`
pub async fn write_handshake<W>(
    writer: &mut W,
    password: &str,
    target: &str,
    metadata: &HandshakeMetadata,
) -> Result<(), RelayError>
where
    W: AsyncWrite + Unpin,
{
    let hash = hash_password(password);
    debug_assert_eq!(hash.len(), HASH_LEN);

    let meta_str = metadata.encode();

    let mut buf = Vec::with_capacity(HASH_LEN + 2 + target.len() + 2 + meta_str.len() + 2);
    buf.extend_from_slice(hash.as_bytes());
    buf.extend_from_slice(CRLF);
    buf.extend_from_slice(target.as_bytes());
    buf.extend_from_slice(CRLF);
    buf.extend_from_slice(meta_str.as_bytes());
    buf.extend_from_slice(CRLF);

    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

/// Parsed relay handshake.
#[derive(Debug, Clone)]
pub struct RelayHandshake {
    /// The 56-byte hex hash from the wire.
    pub hash: String,
    /// The target address (host:port).
    pub target: String,
    /// Metadata (transport/sni hints from the entry node).
    pub metadata: HandshakeMetadata,
}

/// Read and parse a relay handshake from the stream.
///
/// Reads: `56-byte-hash + CRLF + target + CRLF + metadata + CRLF`
pub async fn read_handshake<R>(reader: &mut R) -> Result<RelayHandshake, RelayError>
where
    R: AsyncRead + Unpin,
{
    // Read 56-byte hash
    let mut hash_buf = [0u8; HASH_LEN];
    reader.read_exact(&mut hash_buf).await?;

    let hash = std::str::from_utf8(&hash_buf)
        .map_err(|_| RelayError::Handshake("invalid hash encoding".into()))?;

    // Validate hex chars
    if !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RelayError::Handshake("invalid hash characters".into()));
    }

    // Read CRLF after hash
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await?;
    if &crlf != CRLF {
        return Err(RelayError::Handshake("expected CRLF after hash".into()));
    }

    // Read target address until CRLF
    let target = read_line(reader, MAX_TARGET_LEN, "target").await?;
    if target.is_empty() {
        return Err(RelayError::Handshake("empty target address".into()));
    }

    // Read metadata line until CRLF
    let meta_str = read_line(reader, MAX_METADATA_LEN, "metadata").await?;
    let metadata = HandshakeMetadata::parse(&meta_str);

    Ok(RelayHandshake {
        hash: hash.to_string(),
        target,
        metadata,
    })
}

/// Read bytes until CRLF, returning the content before it.
async fn read_line<R>(reader: &mut R, max_len: usize, field: &str) -> Result<String, RelayError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(64);
    loop {
        let byte = reader.read_u8().await?;
        if byte == b'\r' {
            let next = reader.read_u8().await?;
            if next == b'\n' {
                break;
            }
            return Err(RelayError::Handshake(
                format!("expected LF after CR in {}", field),
            ));
        }
        buf.push(byte);
        if buf.len() > max_len {
            return Err(RelayError::Handshake(format!("{} too long", field)));
        }
    }
    String::from_utf8(buf)
        .map_err(|_| RelayError::Handshake(format!("invalid {} encoding", field)))
}

/// Verify that a handshake hash matches the expected password.
pub fn verify_hash(handshake: &RelayHandshake, password: &str) -> bool {
    let expected = hash_password(password);
    handshake.hash == expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn test_hash_password() {
        let hash = hash_password("test-password");
        assert_eq!(hash.len(), HASH_LEN);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_verify_hash() {
        let hs = RelayHandshake {
            hash: hash_password("secret"),
            target: "example.com:443".into(),
            metadata: HandshakeMetadata::default(),
        };
        assert!(verify_hash(&hs, "secret"));
        assert!(!verify_hash(&hs, "wrong"));
    }

    #[tokio::test]
    async fn test_handshake_roundtrip() {
        let (mut client, mut server) = duplex(1024);

        let password = "relay-test-password";
        let target = "b2.example.com:443";
        let meta = HandshakeMetadata::default();

        let write_handle = tokio::spawn(async move {
            write_handshake(&mut client, password, target, &meta).await.unwrap();
            client
        });

        let hs = read_handshake(&mut server).await.unwrap();
        assert_eq!(hs.target, target);
        assert!(verify_hash(&hs, password));
        assert!(hs.metadata.transport.is_none());
        assert!(hs.metadata.sni.is_none());

        write_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_handshake_with_metadata() {
        let (mut client, mut server) = duplex(1024);

        let password = "secret";
        let target = "dest:443";
        let meta = HandshakeMetadata {
            transport: Some(TransportType::Plain),
            sni: Some("cdn.example.com".to_string()),
        };

        let write_handle = tokio::spawn(async move {
            write_handshake(&mut client, password, target, &meta).await.unwrap();
            client
        });

        let hs = read_handshake(&mut server).await.unwrap();
        assert_eq!(hs.target, target);
        assert!(verify_hash(&hs, password));
        assert_eq!(hs.metadata.transport, Some(TransportType::Plain));
        assert_eq!(hs.metadata.sni.as_deref(), Some("cdn.example.com"));

        write_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_handshake_invalid_hash() {
        let (mut client, mut server) = duplex(1024);

        tokio::spawn(async move {
            client.write_all(&[b'X'; HASH_LEN]).await.unwrap();
            client.write_all(CRLF).await.unwrap();
            client.write_all(b"target:443").await.unwrap();
            client.write_all(CRLF).await.unwrap();
            client.write_all(CRLF).await.unwrap(); // empty metadata
            client.flush().await.unwrap();
        });

        let result = read_handshake(&mut server).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handshake_empty_target() {
        let (mut client, mut server) = duplex(1024);

        tokio::spawn(async move {
            let hash = hash_password("test");
            client.write_all(hash.as_bytes()).await.unwrap();
            client.write_all(CRLF).await.unwrap();
            client.write_all(CRLF).await.unwrap(); // empty target
            client.flush().await.unwrap();
        });

        let result = read_handshake(&mut server).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_metadata_roundtrip() {
        let meta = HandshakeMetadata {
            transport: Some(TransportType::Tls),
            sni: Some("crates.io".to_string()),
        };
        let encoded = meta.encode();
        assert_eq!(encoded, "transport=tls,sni=crates.io");

        let parsed = HandshakeMetadata::parse(&encoded);
        assert_eq!(parsed.transport, Some(TransportType::Tls));
        assert_eq!(parsed.sni.as_deref(), Some("crates.io"));
    }

    #[test]
    fn test_metadata_empty() {
        let meta = HandshakeMetadata::default();
        assert_eq!(meta.encode(), "");

        let parsed = HandshakeMetadata::parse("");
        assert!(parsed.transport.is_none());
        assert!(parsed.sni.is_none());
    }
}
