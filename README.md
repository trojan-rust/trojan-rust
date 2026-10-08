# Trojan Rust

[![Crates.io](https://img.shields.io/crates/v/trojan.svg)](https://crates.io/crates/trojan)
[![CI](https://github.com/trojan-rust/trojan-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/trojan-rust/trojan-rust/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/trojan.svg)](https://github.com/trojan-rust/trojan-rust/blob/master/LICENSE)

A high-performance Rust implementation of the [Trojan](https://trojan-gfw.github.io/trojan/protocol) protocol.

## Documentation

See the full documentation at [trojan.rs](https://trojan.rs).

For multi-hop routing, destination failover, and relay upgrade ordering, see [trojan-relay](crates/trojan-relay/README.md).

For persistent node traffic accounting and monthly quotas, see [trojan-dash](crates/trojan-dash/README.md#node-quotas). Managed entries use live quota and health information to select relay paths and exits.

## License

GPL-3.0-only
