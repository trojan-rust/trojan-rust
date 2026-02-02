//! Surge rule-set parser (.list format).

use crate::error::RulesError;
use crate::rule::ParsedRule;

/// Parse a Surge classical rule-set (.list format).
///
/// Each line has the format: `TYPE,VALUE`
/// Lines starting with `#` are comments. Empty lines are skipped.
pub fn parse_surge_ruleset(content: &str) -> Result<Vec<ParsedRule>, RulesError> {
    let mut rules = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let rule = parse_surge_line(line)?;
        rules.push(rule);
    }

    Ok(rules)
}

/// Parse a Surge DOMAIN-SET file.
///
/// Each line is a domain. Lines starting with `.` match the domain and all subdomains.
/// Lines starting with `#` are comments.
pub fn parse_surge_domain_set(content: &str) -> Result<Vec<ParsedRule>, RulesError> {
    let mut rules = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(suffix) = line.strip_prefix('.') {
            rules.push(ParsedRule::DomainSuffix(suffix.to_string()));
        } else {
            rules.push(ParsedRule::Domain(line.to_string()));
        }
    }

    Ok(rules)
}

/// Parse a single Surge rule line (e.g., "DOMAIN-SUFFIX,apple.com").
///
/// Extra comma-separated fields after the value (e.g. `no-resolve`, policy
/// names like `Proxy`) are silently stripped.  This matches real-world Surge
/// and Clash rule-set files which commonly include such trailing fields.
fn parse_surge_line(line: &str) -> Result<ParsedRule, RulesError> {
    let (rule_type, rest) = line
        .split_once(',')
        .ok_or_else(|| RulesError::Parse(format!("missing comma in rule: {line}")))?;

    let rule_type = rule_type.trim();
    // Take only the first value; ignore trailing fields like ",no-resolve" or ",Proxy"
    let value = rest.split(',').next().unwrap_or("").trim();

    match rule_type {
        "DOMAIN" => Ok(ParsedRule::Domain(value.to_string())),
        "DOMAIN-SUFFIX" => Ok(ParsedRule::DomainSuffix(value.to_string())),
        "DOMAIN-KEYWORD" => Ok(ParsedRule::DomainKeyword(value.to_string())),
        "IP-CIDR" | "IP-CIDR6" => {
            let net = value
                .parse()
                .map_err(|e| RulesError::InvalidCidr(format!("{value}: {e}")))?;
            Ok(ParsedRule::IpCidr(net))
        }
        "DST-PORT" => {
            let port: u16 = value
                .parse()
                .map_err(|e| RulesError::Parse(format!("invalid port '{value}': {e}")))?;
            Ok(ParsedRule::DstPort(port))
        }
        "SRC-IP-CIDR" | "SRC-IP-CIDR6" => {
            let net = value
                .parse()
                .map_err(|e| RulesError::InvalidCidr(format!("{value}: {e}")))?;
            Ok(ParsedRule::SrcIpCidr(net))
        }
        _ => Err(RulesError::InvalidRuleType(rule_type.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_classical_ruleset() {
        let content = r#"
# Surge rule-set example
DOMAIN,api.example.com
DOMAIN-SUFFIX,apple.com
DOMAIN-KEYWORD,google
IP-CIDR,192.168.0.0/16
IP-CIDR6,2001:db8::/32
"#;
        let rules = parse_surge_ruleset(content).unwrap();
        assert_eq!(rules.len(), 5);
        assert!(matches!(&rules[0], ParsedRule::Domain(d) if d == "api.example.com"));
        assert!(matches!(&rules[1], ParsedRule::DomainSuffix(d) if d == "apple.com"));
        assert!(matches!(&rules[2], ParsedRule::DomainKeyword(d) if d == "google"));
        assert!(matches!(&rules[3], ParsedRule::IpCidr(_)));
        assert!(matches!(&rules[4], ParsedRule::IpCidr(_)));
    }

    #[test]
    fn parse_comments_and_blank_lines() {
        let content = r#"
# comment

DOMAIN,example.com

# another comment
DOMAIN-SUFFIX,test.com
"#;
        let rules = parse_surge_ruleset(content).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn parse_domain_set() {
        let content = r#"
# Domain set
example.com
.apple.com
.google.com
specific.host.com
"#;
        let rules = parse_surge_domain_set(content).unwrap();
        assert_eq!(rules.len(), 4);
        assert!(matches!(&rules[0], ParsedRule::Domain(d) if d == "example.com"));
        assert!(matches!(&rules[1], ParsedRule::DomainSuffix(d) if d == "apple.com"));
        assert!(matches!(&rules[2], ParsedRule::DomainSuffix(d) if d == "google.com"));
        assert!(matches!(&rules[3], ParsedRule::Domain(d) if d == "specific.host.com"));
    }

    #[test]
    fn parse_invalid_rule_type() {
        let content = "UNKNOWN,example.com";
        let result = parse_surge_ruleset(content);
        result.unwrap_err();
    }

    #[test]
    fn parse_invalid_cidr() {
        let content = "IP-CIDR,not-a-cidr";
        let result = parse_surge_ruleset(content);
        result.unwrap_err();
    }

    #[test]
    fn parse_missing_comma() {
        let content = "DOMAIN example.com";
        let result = parse_surge_ruleset(content);
        result.unwrap_err();
    }

    #[test]
    fn parse_dst_port() {
        let content = "DST-PORT,80";
        let rules = parse_surge_ruleset(content).unwrap();
        assert_eq!(rules.len(), 1);
        assert!(matches!(&rules[0], ParsedRule::DstPort(80)));
    }

    #[test]
    fn parse_dst_port_invalid() {
        let content = "DST-PORT,not-a-port";
        parse_surge_ruleset(content).unwrap_err();
    }

    #[test]
    fn parse_src_ip_cidr() {
        let content = "SRC-IP-CIDR,10.0.0.0/8\nSRC-IP-CIDR6,fd00::/8";
        let rules = parse_surge_ruleset(content).unwrap();
        assert_eq!(rules.len(), 2);
        assert!(matches!(&rules[0], ParsedRule::SrcIpCidr(_)));
        assert!(matches!(&rules[1], ParsedRule::SrcIpCidr(_)));
    }

    #[test]
    fn parse_mixed_with_new_types() {
        let content = r#"
DOMAIN,example.com
DST-PORT,443
SRC-IP-CIDR,192.168.0.0/16
IP-CIDR,10.0.0.0/8
"#;
        let rules = parse_surge_ruleset(content).unwrap();
        assert_eq!(rules.len(), 4);
        assert!(matches!(&rules[0], ParsedRule::Domain(d) if d == "example.com"));
        assert!(matches!(&rules[1], ParsedRule::DstPort(443)));
        assert!(matches!(&rules[2], ParsedRule::SrcIpCidr(_)));
        assert!(matches!(&rules[3], ParsedRule::IpCidr(_)));
    }

    #[test]
    fn parse_extra_fields_stripped() {
        // Real-world Surge/Clash rules often have trailing fields like
        // "no-resolve" or policy names that should be ignored.
        let content = r#"
DOMAIN-SUFFIX,google.com,Proxy
IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
DOMAIN,example.com,REJECT,extra,fields
DOMAIN-KEYWORD,ads,Proxy
"#;
        let rules = parse_surge_ruleset(content).unwrap();
        assert_eq!(rules.len(), 4);
        assert!(matches!(&rules[0], ParsedRule::DomainSuffix(d) if d == "google.com"));
        assert!(matches!(&rules[1], ParsedRule::IpCidr(_)));
        assert!(matches!(&rules[2], ParsedRule::Domain(d) if d == "example.com"));
        assert!(matches!(&rules[3], ParsedRule::DomainKeyword(d) if d == "ads"));
    }
}
