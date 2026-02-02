//! Rule and action type definitions.

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// A parsed rule from a rule-set file.
#[derive(Debug, Clone)]
pub enum ParsedRule {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    IpCidr(IpNet),
    /// Match on destination port.
    DstPort(u16),
    /// Match on source IP CIDR.
    SrcIpCidr(IpNet),
    // GEOIP and FINAL are handled at the engine level, not in rule-sets.
}

/// Action to take when a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Action {
    /// Connect directly to the target.
    Direct,
    /// Reject the connection.
    Reject,
    /// Route through a named outbound.
    #[serde(untagged)]
    Outbound(String),
}

impl Action {
    /// Check if this is the DIRECT action.
    pub fn is_direct(&self) -> bool {
        matches!(self, Action::Direct)
    }

    /// Check if this is the REJECT action.
    pub fn is_reject(&self) -> bool {
        matches!(self, Action::Reject)
    }
}

/// A compiled rule in the engine's rule list.
#[derive(Debug)]
pub(crate) enum EngineRule {
    /// Match against a named rule-set.
    RuleSet {
        name: String,
        action: Action,
    },
    /// Match against a GEOIP country code.
    GeoIp {
        code: String,
        action: Action,
    },
    /// Inline single rule (type + value).
    Inline {
        rule: ParsedRule,
        action: Action,
    },
    /// Final catch-all rule.
    Final {
        action: Action,
    },
}

/// Context for matching a request against rules.
#[derive(Debug)]
pub struct MatchContext<'a> {
    /// Target domain name (when the target is a domain).
    pub domain: Option<&'a str>,
    /// Target IP address (when the target is an IP or after DNS resolution).
    pub dest_ip: Option<IpAddr>,
    /// Target port.
    pub dest_port: u16,
    /// Source (client) IP address.
    pub src_ip: IpAddr,
}
