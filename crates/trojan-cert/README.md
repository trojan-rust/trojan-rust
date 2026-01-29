# trojan-cert

Certificate generation utilities for trojan-rs.

## Overview

This crate provides a CLI for generating self-signed TLS certificates, useful for development and testing.

- **ECDSA P-256** — Fast, modern elliptic curve key pair
- **SAN support** — Multiple domain names and IP addresses
- **PEM output** — Standard certificate and key files

## Usage

```bash
# Generate a self-signed certificate
trojan cert generate \
  --domain example.com \
  --domain localhost \
  --ip 127.0.0.1 \
  --output /etc/trojan \
  --days 365
```

Output:
```
Certificate generated successfully:
  Certificate: /etc/trojan/cert.pem
  Private key: /etc/trojan/key.pem
  Valid for: 365 days
  Domains: example.com, localhost
  IPs: 127.0.0.1
```

### As a library

```rust
use trojan_cert::{generate, GenerateArgs};

let args = GenerateArgs {
    domain: vec!["example.com".into()],
    ip: vec!["127.0.0.1".parse().unwrap()],
    output: "/etc/trojan".into(),
    days: 365,
    cert_name: "cert".into(),
    key_name: "key".into(),
};
generate(&args)?;
```

## License

GPL-3.0-only
