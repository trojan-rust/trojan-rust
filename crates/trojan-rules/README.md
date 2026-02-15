# trojan-rules

Rule-based routing engine for trojan-rs, compatible with Surge and Clash rule formats.

## Overview

This crate evaluates routing rules to decide how each connection should be handled:

- **Domain matching** — Exact, suffix, and keyword matching via hash sets and Aho-Corasick automaton
- **IP CIDR matching** — IPv4 and IPv6 CIDR ranges
- **GeoIP matching** — Country-level routing using MaxMind mmdb databases with auto-download and background updates
- **Port matching** — Destination port rules
- **Source IP matching** — Rules based on client IP
- **Rule providers** — Load rules from local files or remote URLs (Surge `.list` and Clash YAML formats)
- **Hot reload** — Lock-free rule engine swapping via `ArcSwap`

## Usage

```rust
use trojan_rules::{RuleEngineBuilder, MatchDecision, Action};
use trojan_rules::rule::MatchContext;

let engine = RuleEngineBuilder::new()
    .add_inline_rule("DOMAIN-SUFFIX", "google.com", Action::Outbound("proxy".into()))?
    .add_inline_rule("GEOIP", "CN", Action::Direct)?
    .set_final(Action::Outbound("proxy".into()))
    .build()?;

let ctx = MatchContext {
    domain: Some("www.google.com"),
    dest_ip: None,
    dest_port: 443,
    src_ip: None,
};

match engine.match_rules(&ctx) {
    MatchDecision::Matched(action) => println!("Action: {:?}", action),
    MatchDecision::NeedIp(action) => println!("Need IP resolution, tentative: {:?}", action),
}
```

### Hot Reload

```rust
use trojan_rules::HotRuleEngine;

let hot = HotRuleEngine::new(engine);

// Read current engine (lock-free)
let current = hot.load();
let result = current.match_rules(&ctx);

// Swap with a new engine (lock-free)
hot.store(new_engine);
```

### Rule Providers

```rust
use trojan_rules::provider::FileProvider;

// Load Surge-format rules from a file
let rules = FileProvider::load("rules.list", "surge", None)?;

// Load Clash-format rules with behavior hint
let rules = FileProvider::load("rules.yaml", "clash", Some("domain".into()))?;
```

## Supported Rule Types

| Rule Type | Example | Description |
|-----------|---------|-------------|
| `DOMAIN` | `example.com` | Exact domain match |
| `DOMAIN-SUFFIX` | `.google.com` | Domain suffix match |
| `DOMAIN-KEYWORD` | `youtube` | Keyword in domain |
| `IP-CIDR` | `10.0.0.0/8` | IPv4 CIDR range |
| `IP-CIDR6` | `2001:db8::/32` | IPv6 CIDR range |
| `GEOIP` | `CN` | GeoIP country code |
| `DST-PORT` | `443` | Destination port |
| `SRC-IP-CIDR` | `192.168.1.0/24` | Source IP range |
| `RULE-SET` | `provider-name` | Reference a rule provider |
| `FINAL` | — | Default/fallback action |

## Features

| Feature | Description |
|---------|-------------|
| `geoip` | MaxMind mmdb GeoIP database support |
| `http` | HTTP provider for remote rule sets and GeoIP auto-download |

Both features are enabled by default.

## GeoIP Database

Built-in CDN sources via [ip-location-db](https://github.com/sapics/ip-location-db):

- `geolite2-country`, `geolite2-city`, `geolite2-asn`
- `dbip-country`, `dbip-city`, `dbip-asn`
- `iptoasn-country`, `iptoasn-asn`
- `geo-whois-asn-country`, `asn-country`

Databases are cached locally and updated automatically in the background.

## License

GPL-3.0-only
