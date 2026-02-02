//! File-based rule-set provider.

use std::path::Path;

use crate::error::RulesError;
use crate::parser;
use crate::rule::ParsedRule;

/// Provider that loads rule-sets from local files.
pub struct FileProvider;

impl FileProvider {
    /// Load and parse a rule-set from a local file.
    ///
    /// - `format`: "surge" or "clash"
    /// - `behavior`: Required for clash format ("domain", "ipcidr", "classical").
    ///   For surge, use "classical" or "domain-set".
    pub fn load(
        path: &Path,
        format: &str,
        behavior: Option<&str>,
    ) -> Result<Vec<ParsedRule>, RulesError> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content, format, behavior)
    }

    /// Parse rule-set content from a string.
    pub fn parse(
        content: &str,
        format: &str,
        behavior: Option<&str>,
    ) -> Result<Vec<ParsedRule>, RulesError> {
        match format {
            "surge" => match behavior {
                Some("domain-set") | Some("domain") => parser::parse_surge_domain_set(content),
                _ => parser::parse_surge_ruleset(content),
            },
            "clash" => {
                let behavior = behavior.ok_or_else(|| {
                    RulesError::Provider("behavior is required for clash format".into())
                })?;
                parser::parse_clash_provider(content, behavior)
            }
            _ => Err(RulesError::Provider(format!(
                "unsupported format: {format}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_surge_classical() {
        let content = "DOMAIN,example.com\nDOMAIN-SUFFIX,test.com";
        let rules = FileProvider::parse(content, "surge", Some("classical")).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn parse_surge_domain_set() {
        let content = "example.com\n.test.com";
        let rules = FileProvider::parse(content, "surge", Some("domain-set")).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn parse_clash_domain() {
        let content = "payload:\n  - 'example.com'\n  - '+.test.com'";
        let rules = FileProvider::parse(content, "clash", Some("domain")).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn unsupported_format() {
        let result = FileProvider::parse("", "unknown", None);
        assert!(result.is_err());
    }

    #[test]
    fn clash_missing_behavior() {
        let result = FileProvider::parse("payload: []", "clash", None);
        assert!(result.is_err());
    }

    #[test]
    fn parse_surge_domain_behavior() {
        // format="surge" with behavior="domain" should use domain-set parser
        let content = "example.com\n.test.com";
        let rules = FileProvider::parse(content, "surge", Some("domain")).unwrap();
        assert_eq!(rules.len(), 2);
        assert!(matches!(&rules[0], ParsedRule::Domain(d) if d == "example.com"));
        assert!(matches!(&rules[1], ParsedRule::DomainSuffix(d) if d == "test.com"));
    }
}
