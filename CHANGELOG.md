# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
## [0.1.8](https://github.com/trojan-rust/trojan-rust/compare/v0.1.4...v0.1.8) - 2026-01-28

### Bug Fixes

- suppress unused variable warning on Windows


### CI

- add git-cliff for automated release notes


### Chores

- update Cargo.lock dependencies

- release v0.1.5

- release v0.1.6

- adopt release-plz

- release v0.1.7 ([#4](https://github.com/trojan-rust/trojan-rust/pull/4))


### Documentation

- add changelog scaffold


### Features

- add self-signed certificate generation

- add TCP socket configuration options

## [0.1.7](https://github.com/trojan-rust/trojan-rust/compare/v0.1.4...v0.1.7) - 2026-01-28

### Bug Fixes

- suppress unused variable warning on Windows


### CI

- add git-cliff for automated release notes


### Chores

- update Cargo.lock dependencies

- release v0.1.5

- release v0.1.6

- adopt release-plz


### Documentation

- add changelog scaffold


### Features

- add self-signed certificate generation

- add TCP socket configuration options


## 0.1.6 - 2026-01-28

### <!-- 5 -->🎨 Styling

- apply cargo fmt to trojan-cert

## 0.1.5 - 2026-01-28

### <!-- 0 -->🚀 Features

- add self-signed certificate generation

- add TCP socket configuration options


### <!-- 3 -->📚 Documentation

- add changelog scaffold


### <!-- 7 -->⚙️ Miscellaneous Tasks

- add git-cliff for automated release notes

- release v0.1.5

## 0.1.4 - 2026-01-28

### <!-- 1 -->🐛 Bug Fixes

- add zip dependency for Windows builds


### <!-- 2 -->🚜 Refactor

- use workspace dependencies for internal crates


### <!-- 3 -->📚 Documentation

- add README and strict issue templates

- add badges to README


### <!-- 7 -->⚙️ Miscellaneous Tasks

- enhance .gitignore for better privacy protection

- bump version to 0.1.3 and add trojan-rs placeholder crate

- bump version to 0.1.4 and fix workspace dependencies

## 0.1.3 - 2026-01-28

### <!-- 1 -->🐛 Bug Fixes

- use cross for i686-unknown-linux-musl target

## 0.1.2 - 2026-01-28

### <!-- 1 -->🐛 Bug Fixes

- use rustls instead of native-tls for musl compatibility

## 0.1.1 - 2026-01-28

### <!-- 0 -->🚀 Features

- add SQL auth backend and unified CLI

- add authentication caching with TTL support

- add WebSocket transport with mixed/split modes

- add connection tracing, health endpoints, and latency metrics

- add criterion benchmarks for proto, auth, and core

- add criterion benchmarks

- rename crate trojan-rs to trojan and expand release targets

- add upgrade subcommand for self-update from GitHub releases

- add trojan-analytics crate for connection tracking


### <!-- 1 -->🐛 Bug Fixes

- resolve clippy warnings

- use aws-lc-rs backend for rcgen to match rustls

- increase server startup wait time for Windows CI

- use ECDSA P-256 for cross-platform certificate generation

- fix flaky TLS test on Windows by using unique temp dirs


### <!-- 10 -->💼 Other

- bump rust-dependencies group with 6 updates

- bump the github-actions group with 3 updates (#1)

- bump clap from 4.5.54 to 4.5.55 in the rust-dependencies group across 1 directory (#3)


### <!-- 2 -->🚜 Refactor

- split monolithic lib.rs into modular structure

- extract shared I/O and transport modules


### <!-- 4 -->⚡ Performance

- reduce allocations in hot paths


### <!-- 5 -->🎨 Styling

- apply cargo fmt formatting


### <!-- 7 -->⚙️ Miscellaneous Tasks

- add GitHub Actions workflows for CI and release

- add license file

## 0.1.0 - 2026-01-27

### <!-- 0 -->🚀 Features

- initial trojan-rs server implementation

