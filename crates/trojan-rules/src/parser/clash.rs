//! Clash rule-provider parser (YAML format).

use crate::error::RulesError;
use crate::parser::surge::parse_surge_ruleset;
use crate::rule::ParsedRule;

/// Parse a Clash rule-provider YAML file.
///
/// Supports three behaviors:
/// - `domain`: Each payload entry is a domain (`.` or `+.` prefix = suffix match)
/// - `ipcidr`: Each payload entry is a CIDR
/// - `classical`: Each payload entry is a Surge-format rule line
pub fn parse_clash_provider(content: &str, behavior: &str) -> Result<Vec<ParsedRule>, RulesError> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(content)?;

    let payload = yaml
        .get("payload")
        .and_then(|v| v.as_sequence())
        .ok_or_else(|| RulesError::Parse("missing 'payload' sequence in YAML".into()))?;

    match behavior {
        "domain" => parse_domain_behavior(payload),
        "ipcidr" => parse_ipcidr_behavior(payload),
        "classical" => parse_classical_behavior(payload),
        _ => Err(RulesError::Parse(format!(
            "unsupported behavior: {behavior}"
        ))),
    }
}

fn parse_domain_behavior(payload: &serde_yaml::Sequence) -> Result<Vec<ParsedRule>, RulesError> {
    let mut rules = Vec::with_capacity(payload.len());

    for item in payload {
        let s = item
            .as_str()
            .ok_or_else(|| RulesError::Parse("domain entry must be a string".into()))?;

        // Clash domain behavior: `+.` or `.` prefix means suffix match
        if let Some(suffix) = s.strip_prefix("+.").or_else(|| s.strip_prefix('.')) {
            rules.push(ParsedRule::DomainSuffix(suffix.to_string()));
        } else {
            rules.push(ParsedRule::Domain(s.to_string()));
        }
    }

    Ok(rules)
}

fn parse_ipcidr_behavior(payload: &serde_yaml::Sequence) -> Result<Vec<ParsedRule>, RulesError> {
    let mut rules = Vec::with_capacity(payload.len());

    for item in payload {
        let s = item
            .as_str()
            .ok_or_else(|| RulesError::Parse("ipcidr entry must be a string".into()))?;

        let net = s
            .parse()
            .map_err(|e| RulesError::InvalidCidr(format!("{s}: {e}")))?;
        rules.push(ParsedRule::IpCidr(net));
    }

    Ok(rules)
}

fn parse_classical_behavior(payload: &serde_yaml::Sequence) -> Result<Vec<ParsedRule>, RulesError> {
    let mut rules = Vec::new();

    for item in payload {
        let s = item
            .as_str()
            .ok_or_else(|| RulesError::Parse("classical entry must be a string".into()))?;

        // Each entry is a Surge-format line: "DOMAIN-SUFFIX,google.com"
        let mut parsed = parse_surge_ruleset(s)?;
        rules.append(&mut parsed);
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_domain_provider() {
        let yaml = r#"
payload:
  - '.apple.com'
  - 'google.com'
  - '+.netflix.com'
"#;
        let rules = parse_clash_provider(yaml, "domain").unwrap();
        assert_eq!(rules.len(), 3);
        assert!(matches!(&rules[0], ParsedRule::DomainSuffix(d) if d == "apple.com"));
        assert!(matches!(&rules[1], ParsedRule::Domain(d) if d == "google.com"));
        assert!(matches!(&rules[2], ParsedRule::DomainSuffix(d) if d == "netflix.com"));
    }

    #[test]
    fn parse_ipcidr_provider() {
        let yaml = r#"
payload:
  - '192.168.1.0/24'
  - '10.0.0.0/8'
  - '2001:db8::/32'
"#;
        let rules = parse_clash_provider(yaml, "ipcidr").unwrap();
        assert_eq!(rules.len(), 3);
        assert!(matches!(&rules[0], ParsedRule::IpCidr(_)));
        assert!(matches!(&rules[1], ParsedRule::IpCidr(_)));
        assert!(matches!(&rules[2], ParsedRule::IpCidr(_)));
    }

    #[test]
    fn parse_classical_provider() {
        let yaml = r#"
payload:
  - DOMAIN-SUFFIX,google.com
  - DOMAIN-KEYWORD,ads
  - IP-CIDR,127.0.0.0/8
"#;
        let rules = parse_clash_provider(yaml, "classical").unwrap();
        assert_eq!(rules.len(), 3);
        assert!(matches!(&rules[0], ParsedRule::DomainSuffix(d) if d == "google.com"));
        assert!(matches!(&rules[1], ParsedRule::DomainKeyword(d) if d == "ads"));
        assert!(matches!(&rules[2], ParsedRule::IpCidr(_)));
    }

    #[test]
    fn parse_missing_payload() {
        let yaml = "something_else: true";
        let result = parse_clash_provider(yaml, "domain");
        result.unwrap_err();
    }

    #[test]
    fn parse_unknown_behavior() {
        let yaml = "payload: []";
        let result = parse_clash_provider(yaml, "unknown");
        result.unwrap_err();
    }

    #[test]
    fn parse_classical_with_extra_fields() {
        let yaml = r#"
payload:
  - DOMAIN-SUFFIX,google.com,Proxy
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
"#;
        let rules = parse_clash_provider(yaml, "classical").unwrap();
        assert_eq!(rules.len(), 2);
        assert!(matches!(&rules[0], ParsedRule::DomainSuffix(d) if d == "google.com"));
        assert!(matches!(&rules[1], ParsedRule::IpCidr(_)));
    }
}
