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
                TransportType::Ws => "ws",
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
                            "ws" => Some(TransportType::Ws),
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
    write_handshake_prehashed(writer, &hash, target, metadata).await
}

/// Write a relay handshake using a pre-computed password hash.
///
/// Same as [`write_handshake`] but skips SHA-224 hashing — useful when the
/// hash is computed once and reused across many connections.
pub async fn write_handshake_prehashed<W>(
    writer: &mut W,
    hash_hex: &str,
    target: &str,
    metadata: &HandshakeMetadata,
) -> Result<(), RelayError>
where
    W: AsyncWrite + Unpin,
{
    debug_assert_eq!(hash_hex.len(), HASH_LEN);

    let meta_str = metadata.encode();

    let mut buf = Vec::with_capacity(HASH_LEN + 2 + target.len() + 2 + meta_str.len() + 2);
    buf.extend_from_slice(hash_hex.as_bytes());
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
///
/// The variable-length part (target + metadata) is read into a single buffer
/// to minimize read syscalls on TLS streams, where each small read triggers
/// a separate decryption operation.
///
/// Returns the parsed handshake plus any **residue bytes** read past the
/// second CRLF. The caller MUST forward these bytes to the next hop before
/// starting bidirectional copy — they belong to the upstream's next message
/// (e.g. the next hop's handshake in a multi-hop chain, or the client's
/// payload), and dropping them desyncs the stream.
pub async fn read_handshake<R>(reader: &mut R) -> Result<(RelayHandshake, Vec<u8>), RelayError>
where
    R: AsyncRead + Unpin,
{
    // Read the fixed-size hash + CRLF in one shot (58 bytes)
    let mut header = [0u8; HASH_LEN + 2];
    reader.read_exact(&mut header).await?;

    let hash = std::str::from_utf8(&header[..HASH_LEN])
        .map_err(|_| RelayError::Handshake("invalid hash encoding".into()))?;

    if !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RelayError::Handshake("invalid hash characters".into()));
    }

    if &header[HASH_LEN..] != CRLF {
        return Err(RelayError::Handshake("expected CRLF after hash".into()));
    }

    // Read the variable-length part (target + CRLF + metadata + CRLF) incrementally.
    // Use a single buffer to minimize read syscalls on TLS streams.
    let max_remaining = MAX_TARGET_LEN + 2 + MAX_METADATA_LEN + 2;
    let mut buf = Vec::with_capacity(128);
    let mut tmp = [0u8; 256];

    loop {
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            return Err(RelayError::Handshake("unexpected EOF in handshake".into()));
        }
        buf.extend_from_slice(&tmp[..n]);

        // Check if we have at least two CRLF sequences
        if buf.windows(2).filter(|w| *w == CRLF).count() >= 2 {
            break;
        }

        if buf.len() > max_remaining {
            return Err(RelayError::Handshake("handshake data too long".into()));
        }
    }

    // Parse target (up to first CRLF) and metadata (between first and second CRLF)
    let first_crlf = buf
        .windows(2)
        .position(|w| w == CRLF)
        .ok_or_else(|| RelayError::Handshake("missing CRLF after target".into()))?;

    let target_bytes = &buf[..first_crlf];
    if target_bytes.is_empty() {
        return Err(RelayError::Handshake("empty target address".into()));
    }
    if target_bytes.len() > MAX_TARGET_LEN {
        return Err(RelayError::Handshake("target too long".into()));
    }
    let target = std::str::from_utf8(target_bytes)
        .map_err(|_| RelayError::Handshake("invalid target encoding".into()))?
        .to_string();

    let meta_start = first_crlf + 2;
    let second_crlf = buf[meta_start..]
        .windows(2)
        .position(|w| w == CRLF)
        .ok_or_else(|| RelayError::Handshake("missing CRLF after metadata".into()))?;

    let meta_bytes = &buf[meta_start..meta_start + second_crlf];
    if meta_bytes.len() > MAX_METADATA_LEN {
        return Err(RelayError::Handshake("metadata too long".into()));
    }
    let meta_str = std::str::from_utf8(meta_bytes)
        .map_err(|_| RelayError::Handshake("invalid metadata encoding".into()))?;
    let metadata = HandshakeMetadata::parse(meta_str);

    // Anything past the second CRLF is residue belonging to the next message.
    let residue_start = meta_start + second_crlf + 2;
    let residue = if residue_start < buf.len() {
        buf[residue_start..].to_vec()
    } else {
        Vec::new()
    };

    Ok((
        RelayHandshake {
            hash: hash.to_string(),
            target,
            metadata,
        },
        residue,
    ))
}

/// Verify that a handshake hash matches a pre-computed expected hash.
/// Uses constant-time comparison to prevent timing side-channels.
pub fn verify_hash_precomputed(handshake: &RelayHandshake, expected_hash: &str) -> bool {
    if handshake.hash.len() != expected_hash.len() {
        return false;
    }
    // Constant-time comparison
    handshake
        .hash
        .as_bytes()
        .iter()
        .zip(expected_hash.as_bytes().iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Verify that a handshake hash matches the expected password.
/// Uses constant-time comparison to prevent timing side-channels.
pub fn verify_hash(handshake: &RelayHandshake, password: &str) -> bool {
    let expected = hash_password(password);
    verify_hash_precomputed(handshake, &expected)
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
            write_handshake(&mut client, password, target, &meta)
                .await
                .unwrap();
            client
        });

        let (hs, residue) = read_handshake(&mut server).await.unwrap();
        assert_eq!(hs.target, target);
        assert!(verify_hash(&hs, password));
        assert!(hs.metadata.transport.is_none());
        assert!(hs.metadata.sni.is_none());
        assert!(residue.is_empty());

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
            write_handshake(&mut client, password, target, &meta)
                .await
                .unwrap();
            client
        });

        let (hs, residue) = read_handshake(&mut server).await.unwrap();
        assert_eq!(hs.target, target);
        assert!(verify_hash(&hs, password));
        assert_eq!(hs.metadata.transport, Some(TransportType::Plain));
        assert_eq!(hs.metadata.sni.as_deref(), Some("cdn.example.com"));
        assert!(residue.is_empty());

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
        result.unwrap_err();
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
        result.unwrap_err();
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

    /// Regression for the v0.9.0 over-read bug: when the upstream pipelines
    /// a follow-up message in the same TCP/TLS read window, `read_handshake`
    /// must hand those bytes back as `residue` rather than dropping them.
    #[tokio::test]
    async fn test_handshake_returns_residue_for_pipelined_data() {
        let (mut client, mut server) = duplex(4096);

        let pw1 = "first-hop";
        let pw2 = "second-hop";
        let target1 = "B2:443";
        let target2 = "C:443";

        let mut expected_h2 = Vec::new();
        let h2 = hash_password(pw2);
        expected_h2.extend_from_slice(h2.as_bytes());
        expected_h2.extend_from_slice(CRLF);
        expected_h2.extend_from_slice(target2.as_bytes());
        expected_h2.extend_from_slice(CRLF);
        expected_h2.extend_from_slice(CRLF);

        let writer = tokio::spawn(async move {
            write_handshake(&mut client, pw1, target1, &HandshakeMetadata::default())
                .await
                .unwrap();
            write_handshake(&mut client, pw2, target2, &HandshakeMetadata::default())
                .await
                .unwrap();
            client
        });

        let (hs, residue) = read_handshake(&mut server).await.unwrap();
        assert_eq!(hs.target, target1);
        assert!(verify_hash(&hs, pw1));

        // Whatever was over-read must equal a prefix of the second handshake;
        // the rest (if any) stays on the wire to be picked up by a follow-up read.
        assert!(
            !residue.is_empty(),
            "in-process duplex pipes the second write together with the first; \
             residue should not be empty"
        );
        assert_eq!(residue, expected_h2[..residue.len()]);

        if residue.len() < expected_h2.len() {
            let mut tail = vec![0u8; expected_h2.len() - residue.len()];
            tokio::io::AsyncReadExt::read_exact(&mut server, &mut tail)
                .await
                .unwrap();
            let mut combined = residue.clone();
            combined.extend_from_slice(&tail);
            assert_eq!(combined, expected_h2);
        }

        let _ = writer.await.unwrap();
    }
}
