# trojan-transport

Pluggable transport abstraction for trojan-rs (TLS, plain TCP, WebSocket).

## Overview

This crate defines transport traits and provides three built-in implementations, allowing the relay system to work with different transports without changing core logic:

- **Plain TCP** — Direct pass-through, useful for trusted networks or testing
- **TLS** — Auto-generated self-signed certificates or file-based certs, with insecure connector for relay-to-relay connections
- **WebSocket** — WebSocket upgrade using `tokio-tungstenite`, reusing `trojan_core::transport::WsIo`

## Usage

### Transport Traits

```rust
use trojan_transport::{TransportAcceptor, TransportConnector, TransportStream};

// Any type implementing AsyncRead + AsyncWrite + Unpin + Send + 'static
// automatically implements TransportStream.

// TransportAcceptor: wraps incoming TCP connections
// TransportConnector: establishes outbound connections
```

### Plain TCP

```rust
use trojan_transport::plain::{PlainTransportAcceptor, PlainTransportConnector};

let acceptor = PlainTransportAcceptor;
let stream = acceptor.accept(tcp_stream).await?;

let connector = PlainTransportConnector;
let stream = connector.connect("target:443").await?;
```

### TLS (auto-generated cert)

```rust
use trojan_transport::tls::{TlsTransportAcceptor, TlsTransportConnector};

// Auto-generate self-signed ECDSA P-256 certificate
let acceptor = TlsTransportAcceptor::new(None)?;
let stream = acceptor.accept(tcp_stream).await?;

// Insecure connector (skips cert verification, for relay nodes)
let connector = TlsTransportConnector::new_insecure("crates.io".into());
let stream = connector.connect("relay:443").await?;

// Reuse config with different SNI
let connector2 = connector.with_sni("cdn.example.com".into());
```

### TLS (file-based cert)

```rust
use trojan_transport::tls::TlsTransportAcceptor;
use trojan_transport::tls_config::TlsConfig;

let config = TlsConfig {
    cert: "/path/to/cert.pem".into(),
    key: "/path/to/key.pem".into(),
};
let acceptor = TlsTransportAcceptor::new(Some(&config))?;
```

### WebSocket

```rust
use trojan_transport::ws::{WsTransportAcceptor, WsTransportConnector};

let acceptor = WsTransportAcceptor;
let stream = acceptor.accept(tcp_stream).await?;

let connector = WsTransportConnector;
let stream = connector.connect("target:80").await?;
```

## Key Types

- **`TransportStream`** — Marker trait for `AsyncRead + AsyncWrite + Unpin + Send + 'static`
- **`TransportAcceptor`** — Trait for wrapping inbound TCP connections
- **`TransportConnector`** — Trait for establishing outbound connections
- **`TransportError`** — Unified error type (I/O, TLS, config, cert generation)

## License

GPL-3.0-only
