//! Domain name matchers.
//!
//! - `DomainMatcher`: FxHashSet for exact + suffix matching (O(1) + O(k))
//! - `KeywordMatcher`: Aho-Corasick automaton for keyword matching (O(m))

use aho_corasick::AhoCorasick;
use rustc_hash::FxHashSet;

/// Matcher for DOMAIN and DOMAIN-SUFFIX rules.
///
/// Exact matches are stored as-is. Suffix matches are stored with a leading
/// dot (e.g., ".apple.com"). Lookup tries exact match first, then strips
/// labels left-to-right to find a suffix match.
#[derive(Debug)]
pub struct DomainMatcher {
    set: FxHashSet<String>,
}

impl DomainMatcher {
    /// Create a new empty domain matcher.
    pub fn new() -> Self {
        Self {
            set: FxHashSet::default(),
        }
    }

    /// Add an exact domain match.
    pub fn add_exact(&mut self, domain: &str) {
        self.set.insert(domain.to_ascii_lowercase());
    }

    /// Add a domain suffix match (matches the domain itself and all subdomains).
    ///
    /// A leading dot (e.g., `.example.com`) is stripped before storing, so both
    /// `.example.com` and `example.com` produce the same entries.
    pub fn add_suffix(&mut self, suffix: &str) {
        let stripped = suffix.strip_prefix('.').unwrap_or(suffix);
        let lower = stripped.to_ascii_lowercase();
        // Store as ".suffix" for suffix matching
        self.set.insert(format!(".{lower}"));
        // Also match the suffix itself as an exact match
        self.set.insert(lower);
    }

    /// Check if a domain matches any exact or suffix rule.
    pub fn matches(&self, domain: &str) -> bool {
        let lower = domain.to_ascii_lowercase();

        // 1. Exact match
        if self.set.contains(lower.as_str()) {
            return true;
        }

        // 2. Suffix match: strip labels left-to-right
        let mut pos = 0;
        while let Some(dot) = lower[pos..].find('.') {
            let suffix = &lower[pos + dot..]; // e.g., ".netflix.com"
            if self.set.contains(suffix) {
                return true;
            }
            pos += dot + 1;
        }

        false
    }

    /// Returns true if the matcher has no rules.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Number of entries in the set.
    pub fn len(&self) -> usize {
        self.set.len()
    }
}

impl Default for DomainMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Matcher for DOMAIN-KEYWORD rules using Aho-Corasick automaton.
///
/// Matches if the domain contains any of the registered keywords.
/// Complexity: O(m) where m is the domain length, independent of keyword count.
pub struct KeywordMatcher {
    ac: AhoCorasick,
    keywords: Vec<String>,
}

impl KeywordMatcher {
    /// Build a keyword matcher from a list of keywords.
    ///
    /// Returns `None` if the keyword list is empty.
    pub fn new(keywords: Vec<String>) -> Option<Self> {
        if keywords.is_empty() {
            return None;
        }
        let lower: Vec<String> = keywords.iter().map(|k| k.to_ascii_lowercase()).collect();
        let ac = AhoCorasick::new(&lower).expect("valid patterns");
        Some(Self {
            ac,
            keywords: lower,
        })
    }

    /// Check if the domain contains any keyword.
    pub fn matches(&self, domain: &str) -> bool {
        let lower = domain.to_ascii_lowercase();
        self.ac.is_match(&lower)
    }

    /// Number of keywords.
    pub fn len(&self) -> usize {
        self.keywords.len()
    }

    /// Returns true if there are no keywords.
    pub fn is_empty(&self) -> bool {
        self.keywords.is_empty()
    }
}

impl std::fmt::Debug for KeywordMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeywordMatcher")
            .field("keywords", &self.keywords)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_exact_match() {
        let mut m = DomainMatcher::new();
        m.add_exact("api.example.com");
        assert!(m.matches("api.example.com"));
        assert!(m.matches("API.EXAMPLE.COM")); // case insensitive
        assert!(!m.matches("example.com"));
        assert!(!m.matches("other.api.example.com"));
    }

    #[test]
    fn domain_suffix_match() {
        let mut m = DomainMatcher::new();
        m.add_suffix("apple.com");
        assert!(m.matches("apple.com")); // exact
        assert!(m.matches("store.apple.com")); // subdomain
        assert!(m.matches("cdn.store.apple.com")); // deep subdomain
        assert!(!m.matches("notapple.com")); // not a suffix
        assert!(!m.matches("com")); // partial
    }

    #[test]
    fn domain_mixed() {
        let mut m = DomainMatcher::new();
        m.add_exact("specific.example.com");
        m.add_suffix("google.com");
        assert!(m.matches("specific.example.com"));
        assert!(!m.matches("other.example.com"));
        assert!(m.matches("google.com"));
        assert!(m.matches("mail.google.com"));
    }

    #[test]
    fn domain_empty() {
        let m = DomainMatcher::new();
        assert!(!m.matches("anything.com"));
        assert!(m.is_empty());
    }

    #[test]
    fn keyword_match() {
        let m = KeywordMatcher::new(vec!["google".into(), "facebook".into()]).unwrap();
        assert!(m.matches("www.google.com"));
        assert!(m.matches("api.facebook.com"));
        assert!(m.matches("GOOGLE.co.jp")); // case insensitive
        assert!(!m.matches("www.apple.com"));
    }

    #[test]
    fn keyword_empty() {
        assert!(KeywordMatcher::new(vec![]).is_none());
    }

    #[test]
    fn keyword_single() {
        let m = KeywordMatcher::new(vec!["ads".into()]).unwrap();
        assert!(m.matches("ads.example.com"));
        assert!(m.matches("example-ads.com"));
        assert!(!m.matches("example.com"));
    }

    #[test]
    fn domain_suffix_leading_dot_normalized() {
        let mut m = DomainMatcher::new();
        m.add_suffix(".example.com"); // leading dot should be stripped
        assert!(m.matches("example.com")); // exact
        assert!(m.matches("sub.example.com")); // subdomain
        assert!(!m.matches("notexample.com")); // not a suffix
    }

    #[test]
    fn domain_suffix_with_and_without_dot_equivalent() {
        let mut m1 = DomainMatcher::new();
        m1.add_suffix("apple.com");
        let mut m2 = DomainMatcher::new();
        m2.add_suffix(".apple.com");

        // Both should match the same domains
        for domain in &["apple.com", "store.apple.com", "cdn.store.apple.com"] {
            assert_eq!(
                m1.matches(domain),
                m2.matches(domain),
                "mismatch for {domain}"
            );
        }
        for domain in &["notapple.com", "com"] {
            assert_eq!(
                m1.matches(domain),
                m2.matches(domain),
                "mismatch for {domain}"
            );
        }
    }
}
