//! Rule engine: compiles rule-sets and matches requests.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tracing::debug;

use crate::error::RulesError;
use crate::matcher::{CidrMatcher, DomainMatcher, KeywordMatcher};
#[cfg(feature = "geoip")]
use crate::matcher::GeoipMatcher;
use crate::rule::{Action, EngineRule, MatchContext, ParsedRule};

/// Result of a lazy match attempt that may require DNS resolution.
pub enum MatchDecision<'a> {
    /// A rule matched without needing an IP address.
    Matched(&'a Action),
    /// An IP-based rule appeared before any match; resolve and retry.
    NeedIp,
}

/// A compiled rule-set ready for matching.
#[derive(Debug)]
struct CompiledRuleSet {
    domain_matcher: DomainMatcher,
    keyword_matcher: Option<KeywordMatcher>,
    cidr_matcher: CidrMatcher,
    /// Destination ports to match.
    dst_ports: Vec<u16>,
    /// Source IP CIDR matcher.
    src_cidr_matcher: CidrMatcher,
}

impl CompiledRuleSet {
    /// Compile a list of parsed rules into optimized matchers.
    fn compile(rules: Vec<ParsedRule>) -> Self {
        let mut domain_matcher = DomainMatcher::new();
        let mut keywords = Vec::new();
        let mut v4_cidrs = Vec::new();
        let mut v6_cidrs = Vec::new();
        let mut dst_ports = Vec::new();
        let mut src_v4_cidrs = Vec::new();
        let mut src_v6_cidrs = Vec::new();

        for rule in rules {
            match rule {
                ParsedRule::Domain(d) => domain_matcher.add_exact(&d),
                ParsedRule::DomainSuffix(d) => domain_matcher.add_suffix(&d),
                ParsedRule::DomainKeyword(k) => keywords.push(k),
                ParsedRule::IpCidr(net) => match net {
                    ipnet::IpNet::V4(v4) => v4_cidrs.push(v4),
                    ipnet::IpNet::V6(v6) => v6_cidrs.push(v6),
                },
                ParsedRule::DstPort(port) => dst_ports.push(port),
                ParsedRule::SrcIpCidr(net) => match net {
                    ipnet::IpNet::V4(v4) => src_v4_cidrs.push(v4),
                    ipnet::IpNet::V6(v6) => src_v6_cidrs.push(v6),
                },
            }
        }

        Self {
            domain_matcher,
            keyword_matcher: KeywordMatcher::new(keywords),
            cidr_matcher: CidrMatcher::new(v4_cidrs, v6_cidrs),
            dst_ports,
            src_cidr_matcher: CidrMatcher::new(src_v4_cidrs, src_v6_cidrs),
        }
    }

    /// Check if a request context matches this rule-set.
    fn matches(&self, ctx: &MatchContext) -> bool {
        // Try domain matches first
        if let Some(domain) = ctx.domain {
            if self.domain_matcher.matches(domain) {
                return true;
            }
            if let Some(ref kw) = self.keyword_matcher {
                if kw.matches(domain) {
                    return true;
                }
            }
        }

        // Try IP matches
        if let Some(ip) = ctx.dest_ip {
            if self.cidr_matcher.contains(ip) {
                return true;
            }
        }

        // Try port matches
        if !self.dst_ports.is_empty() && self.dst_ports.contains(&ctx.dest_port) {
            return true;
        }

        // Try source IP matches
        if self.src_cidr_matcher.contains(ctx.src_ip) {
            return true;
        }

        false
    }
}

/// The rule engine: holds compiled rule-sets and an ordered list of rules.
///
/// Send + Sync, designed to be shared via `Arc<RuleEngine>`.
pub struct RuleEngine {
    compiled_sets: HashMap<String, CompiledRuleSet>,
    rules: Vec<EngineRule>,
    final_action: Action,
    #[cfg(feature = "geoip")]
    geoip: Option<Arc<GeoipMatcher>>,
}

impl RuleEngine {
    /// Match a request against the rules and return the action to take.
    ///
    /// Rules are evaluated in order; the first match wins.
    /// If no rule matches, the FINAL action is returned.
    pub fn match_request(&self, ctx: &MatchContext) -> &Action {
        for rule in &self.rules {
            match rule {
                EngineRule::RuleSet { name, action } => {
                    if let Some(compiled) = self.compiled_sets.get(name) {
                        if compiled.matches(ctx) {
                            return action;
                        }
                    }
                }
                EngineRule::GeoIp { code, action } => {
                    #[cfg(feature = "geoip")]
                    if let Some(ref geoip) = self.geoip {
                        // Only match on dest_ip; skip when no resolved IP is
                        // available.  Falling back to src_ip would mis-route
                        // domain requests based on the *client's* country.
                        if let Some(ip) = ctx.dest_ip {
                            if geoip.matches(ip, code) {
                                return action;
                            }
                        }
                    }
                    #[cfg(not(feature = "geoip"))]
                    {
                        let _ = (code, action);
                        // GEOIP matching requires the "geoip" feature. Skip.
                    }
                }
                EngineRule::Inline { rule, action } => {
                    if inline_matches(rule, ctx) {
                        return action;
                    }
                }
                EngineRule::Final { action } => {
                    return action;
                }
            }
        }
        &self.final_action
    }

    /// Try to match without an IP; if an IP-based rule appears before any
    /// match, returns `NeedIp` so callers can resolve and retry.
    pub fn match_request_lazy_ip(&self, ctx: &MatchContext) -> MatchDecision<'_> {
        for rule in &self.rules {
            match rule {
                EngineRule::RuleSet { name, action } => {
                    if let Some(compiled) = self.compiled_sets.get(name) {
                        // Domain matchers don't need IP.
                        if let Some(domain) = ctx.domain {
                            if compiled.domain_matcher.matches(domain)
                                || compiled
                                    .keyword_matcher
                                    .as_ref()
                                    .is_some_and(|kw| kw.matches(domain))
                            {
                                return MatchDecision::Matched(action);
                            }
                        }

                        // DST-PORT and SRC-IP-CIDR don't need DNS.
                        if !compiled.dst_ports.is_empty()
                            && compiled.dst_ports.contains(&ctx.dest_port)
                        {
                            return MatchDecision::Matched(action);
                        }
                        if compiled.src_cidr_matcher.contains(ctx.src_ip) {
                            return MatchDecision::Matched(action);
                        }

                        // Dest-IP CIDR requires resolved IP.
                        if ctx.dest_ip.is_none() && !compiled.cidr_matcher.is_empty() {
                            return MatchDecision::NeedIp;
                        }
                        if let Some(ip) = ctx.dest_ip {
                            if compiled.cidr_matcher.contains(ip) {
                                return MatchDecision::Matched(action);
                            }
                        }
                    }
                }
                EngineRule::GeoIp { code, action } => {
                    #[cfg(feature = "geoip")]
                    if let Some(ref geoip) = self.geoip {
                        if ctx.dest_ip.is_none() {
                            return MatchDecision::NeedIp;
                        }
                        if let Some(ip) = ctx.dest_ip {
                            if geoip.matches(ip, code) {
                                return MatchDecision::Matched(action);
                            }
                        }
                    }
                    #[cfg(not(feature = "geoip"))]
                    {
                        let _ = (code, action);
                        // GEOIP matching requires the "geoip" feature. Skip.
                    }
                }
                EngineRule::Inline { rule, action } => match rule {
                    ParsedRule::Domain(d) => {
                        if ctx.domain.is_some_and(|domain| domain.eq_ignore_ascii_case(d)) {
                            return MatchDecision::Matched(action);
                        }
                    }
                    ParsedRule::DomainSuffix(s) => {
                        if ctx.domain.is_some_and(|domain| {
                            let lower = domain.to_ascii_lowercase();
                            let suffix_lower = s.to_ascii_lowercase();
                            lower == suffix_lower || lower.ends_with(&format!(".{suffix_lower}"))
                        }) {
                            return MatchDecision::Matched(action);
                        }
                    }
                    ParsedRule::DomainKeyword(k) => {
                        if ctx.domain.is_some_and(|domain| {
                            domain
                                .to_ascii_lowercase()
                                .contains(&k.to_ascii_lowercase())
                        }) {
                            return MatchDecision::Matched(action);
                        }
                    }
                    ParsedRule::IpCidr(net) => {
                        if ctx.dest_ip.is_none() {
                            return MatchDecision::NeedIp;
                        }
                        if ctx.dest_ip.is_some_and(|ip| net.contains(&ip)) {
                            return MatchDecision::Matched(action);
                        }
                    }
                    ParsedRule::DstPort(port) => {
                        if ctx.dest_port == *port {
                            return MatchDecision::Matched(action);
                        }
                    }
                    ParsedRule::SrcIpCidr(net) => {
                        if net.contains(&ctx.src_ip) {
                            return MatchDecision::Matched(action);
                        }
                    }
                },
                EngineRule::Final { action } => {
                    return MatchDecision::Matched(action);
                }
            }
        }
        MatchDecision::Matched(&self.final_action)
    }

    /// Returns true if this engine has IP-based rules that may require DNS resolution.
    pub fn has_ip_rules(&self) -> bool {
        let has_cidr = self
            .compiled_sets
            .values()
            .any(|cs| !cs.cidr_matcher.is_empty());
        let has_geoip = {
            #[cfg(feature = "geoip")]
            {
                self.geoip.is_some()
                    && self
                        .rules
                        .iter()
                        .any(|r| matches!(r, EngineRule::GeoIp { .. }))
            }
            #[cfg(not(feature = "geoip"))]
            {
                false
            }
        };
        has_cidr || has_geoip
    }

    /// Number of compiled rule-sets.
    pub fn rule_set_count(&self) -> usize {
        self.compiled_sets.len()
    }

    /// Number of engine rules (including FINAL).
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// Check if a single inline rule matches the context.
fn inline_matches(rule: &ParsedRule, ctx: &MatchContext) -> bool {
    match rule {
        ParsedRule::Domain(d) => ctx
            .domain
            .is_some_and(|domain| domain.eq_ignore_ascii_case(d)),
        ParsedRule::DomainSuffix(s) => ctx.domain.is_some_and(|domain| {
            let lower = domain.to_ascii_lowercase();
            let suffix_lower = s.to_ascii_lowercase();
            lower == suffix_lower || lower.ends_with(&format!(".{suffix_lower}"))
        }),
        ParsedRule::DomainKeyword(k) => ctx.domain.is_some_and(|domain| {
            domain
                .to_ascii_lowercase()
                .contains(&k.to_ascii_lowercase())
        }),
        ParsedRule::IpCidr(net) => ctx.dest_ip.is_some_and(|ip| net.contains(&ip)),
        ParsedRule::DstPort(port) => ctx.dest_port == *port,
        ParsedRule::SrcIpCidr(net) => net.contains(&ctx.src_ip),
    }
}

impl std::fmt::Debug for RuleEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleEngine")
            .field("rule_sets", &self.compiled_sets.len())
            .field("rules", &self.rules.len())
            .field("final_action", &self.final_action)
            .finish()
    }
}

// ── Builder ──

/// Builder for constructing a `RuleEngine`.
pub struct RuleEngineBuilder {
    rule_sets: HashMap<String, Vec<ParsedRule>>,
    rules: Vec<EngineRule>,
    final_action: Option<Action>,
    #[cfg(feature = "geoip")]
    geoip: Option<Arc<GeoipMatcher>>,
}

impl RuleEngineBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            rule_sets: HashMap::new(),
            rules: Vec::new(),
            final_action: None,
            #[cfg(feature = "geoip")]
            geoip: None,
        }
    }

    /// Set the GeoIP matcher for GEOIP rule matching.
    #[cfg(feature = "geoip")]
    pub fn set_geoip(&mut self, matcher: Arc<GeoipMatcher>) -> &mut Self {
        self.geoip = Some(matcher);
        self
    }

    /// Add a named rule-set (parsed rules).
    pub fn add_rule_set(&mut self, name: impl Into<String>, rules: Vec<ParsedRule>) -> &mut Self {
        self.rule_sets.insert(name.into(), rules);
        self
    }

    /// Add a rule that references a named rule-set.
    pub fn add_rule_set_rule(
        &mut self,
        rule_set_name: impl Into<String>,
        action: Action,
    ) -> &mut Self {
        self.rules.push(EngineRule::RuleSet {
            name: rule_set_name.into(),
            action,
        });
        self
    }

    /// Add a GEOIP rule.
    pub fn add_geoip_rule(&mut self, code: impl Into<String>, action: Action) -> &mut Self {
        self.rules.push(EngineRule::GeoIp {
            code: code.into(),
            action,
        });
        self
    }

    /// Add an inline rule (single rule type + value).
    pub fn add_inline_rule(&mut self, rule: ParsedRule, action: Action) -> &mut Self {
        self.rules.push(EngineRule::Inline { rule, action });
        self
    }

    /// Set the FINAL (catch-all) action.
    pub fn set_final(&mut self, action: Action) -> &mut Self {
        self.final_action = Some(action.clone());
        self.rules.push(EngineRule::Final { action });
        self
    }

    /// Build the rule engine.
    pub fn build(self) -> Result<RuleEngine, RulesError> {
        let final_action = self.final_action.ok_or(RulesError::NoFinalRule)?;

        // Validate that all rule-set references exist
        for rule in &self.rules {
            if let EngineRule::RuleSet { name, .. } = rule {
                if !self.rule_sets.contains_key(name) {
                    return Err(RulesError::UnknownRuleSet(name.clone()));
                }
            }
        }

        // Warn when GEOIP rules are present but cannot be evaluated
        {
            let has_geoip_rules = self.rules.iter().any(|r| matches!(r, EngineRule::GeoIp { .. }));
            if has_geoip_rules {
                #[cfg(feature = "geoip")]
                if self.geoip.is_none() {
                    tracing::warn!("GEOIP rules are configured but no GeoIP database is loaded; they will never match");
                }
                #[cfg(not(feature = "geoip"))]
                tracing::warn!("GEOIP rules are configured but the 'geoip' feature is not enabled; they will never match");
            }
        }

        // Compile rule-sets
        let compiled_sets: HashMap<String, CompiledRuleSet> = self
            .rule_sets
            .into_iter()
            .map(|(name, rules)| {
                let count = rules.len();
                let compiled = CompiledRuleSet::compile(rules);
                debug!(
                    name = %name,
                    rules = count,
                    domains = compiled.domain_matcher.len(),
                    keywords = compiled.keyword_matcher.as_ref().map_or(0, |k| k.len()),
                    cidrs = compiled.cidr_matcher.len(),
                    "compiled rule-set"
                );
                (name, compiled)
            })
            .collect();

        Ok(RuleEngine {
            compiled_sets,
            rules: self.rules,
            final_action,
            #[cfg(feature = "geoip")]
            geoip: self.geoip,
        })
    }
}

impl Default for RuleEngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Hot-reloadable engine ──

/// A hot-reloadable wrapper around `RuleEngine`.
///
/// Uses `ArcSwap` for lock-free reads and atomic replacement.
/// All reads go through `arc_swap::Guard` which is wait-free.
pub struct HotRuleEngine {
    inner: ArcSwap<RuleEngine>,
}

impl HotRuleEngine {
    /// Create a new hot-reloadable engine with the given initial engine.
    pub fn new(engine: RuleEngine) -> Self {
        Self {
            inner: ArcSwap::new(Arc::new(engine)),
        }
    }

    /// Match a request against the current rules.
    ///
    /// Returns an owned `Action` (cloned from the engine) so the caller
    /// does not hold a borrow on the engine across await points.
    pub fn match_request(&self, ctx: &MatchContext) -> Action {
        let engine = self.inner.load();
        engine.match_request(ctx).clone()
    }

    /// Returns true if the current engine has IP-based rules.
    pub fn has_ip_rules(&self) -> bool {
        self.inner.load().has_ip_rules()
    }

    /// Atomically replace the engine with a new one.
    pub fn update(&self, engine: RuleEngine) {
        self.inner.store(Arc::new(engine));
    }

    /// Lazy IP matching: returns `Some(action)` if a rule matched without DNS,
    /// `None` if an IP-based rule appeared first and DNS resolution is needed.
    ///
    /// The caller should resolve DNS and then call `match_request()` with the
    /// resolved IP when `None` is returned.
    pub fn match_request_lazy_ip(&self, ctx: &MatchContext) -> Option<Action> {
        let engine = self.inner.load();
        match engine.match_request_lazy_ip(ctx) {
            MatchDecision::Matched(action) => Some(action.clone()),
            MatchDecision::NeedIp => None,
        }
    }

    /// Number of compiled rule-sets in the current engine.
    pub fn rule_set_count(&self) -> usize {
        self.inner.load().rule_set_count()
    }

    /// Number of engine rules in the current engine.
    pub fn rule_count(&self) -> usize {
        self.inner.load().rule_count()
    }
}

impl std::fmt::Debug for HotRuleEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HotRuleEngine")
            .field("inner", &*self.inner.load())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ctx_domain(domain: &str) -> MatchContext<'_> {
        MatchContext {
            domain: Some(domain),
            dest_ip: None,
            dest_port: 443,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }

    fn ctx_ip(ip: IpAddr) -> MatchContext<'static> {
        MatchContext {
            domain: None,
            dest_ip: Some(ip),
            dest_port: 443,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }

    #[test]
    fn rule_set_domain_match() {
        let mut builder = RuleEngineBuilder::new();
        builder.add_rule_set(
            "ads",
            vec![
                ParsedRule::DomainSuffix("ad.example.com".into()),
                ParsedRule::DomainKeyword("ads".into()),
            ],
        );
        builder.add_rule_set_rule("ads", Action::Reject);
        builder.set_final(Action::Direct);

        let engine = builder.build().unwrap();

        assert_eq!(
            engine.match_request(&ctx_domain("tracker.ad.example.com")),
            &Action::Reject
        );
        assert_eq!(
            engine.match_request(&ctx_domain("someads.com")),
            &Action::Reject
        );
        assert_eq!(
            engine.match_request(&ctx_domain("clean.example.com")),
            &Action::Direct
        );
    }

    #[test]
    fn rule_set_ip_match() {
        let mut builder = RuleEngineBuilder::new();
        builder.add_rule_set(
            "private",
            vec![ParsedRule::IpCidr("192.168.0.0/16".parse().unwrap())],
        );
        builder.add_rule_set_rule("private", Action::Outbound("vpn".into()));
        builder.set_final(Action::Direct);

        let engine = builder.build().unwrap();

        assert_eq!(
            engine.match_request(&ctx_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))),
            &Action::Outbound("vpn".into())
        );
        assert_eq!(
            engine.match_request(&ctx_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))),
            &Action::Direct
        );
    }

    #[test]
    fn rule_order_matters() {
        let mut builder = RuleEngineBuilder::new();
        builder.add_rule_set("block", vec![ParsedRule::Domain("example.com".into())]);
        builder.add_rule_set("allow", vec![ParsedRule::DomainSuffix("example.com".into())]);
        builder.add_rule_set_rule("block", Action::Reject);
        builder.add_rule_set_rule("allow", Action::Direct);
        builder.set_final(Action::Outbound("proxy".into()));

        let engine = builder.build().unwrap();

        // "example.com" matches "block" first → REJECT
        assert_eq!(
            engine.match_request(&ctx_domain("example.com")),
            &Action::Reject
        );
        // "sub.example.com" doesn't match "block" (exact), matches "allow" (suffix) → DIRECT
        assert_eq!(
            engine.match_request(&ctx_domain("sub.example.com")),
            &Action::Direct
        );
    }

    #[test]
    fn final_action_catch_all() {
        let mut builder = RuleEngineBuilder::new();
        builder.set_final(Action::Direct);
        let engine = builder.build().unwrap();

        assert_eq!(
            engine.match_request(&ctx_domain("anything.com")),
            &Action::Direct
        );
    }

    #[test]
    fn no_final_rule_error() {
        let builder = RuleEngineBuilder::new();
        assert!(builder.build().is_err());
    }

    #[test]
    fn unknown_rule_set_error() {
        let mut builder = RuleEngineBuilder::new();
        builder.add_rule_set_rule("nonexistent", Action::Reject);
        builder.set_final(Action::Direct);
        assert!(builder.build().is_err());
    }

    #[test]
    fn inline_rule_match() {
        let mut builder = RuleEngineBuilder::new();
        builder.add_inline_rule(ParsedRule::Domain("blocked.com".into()), Action::Reject);
        builder.add_inline_rule(
            ParsedRule::IpCidr("10.0.0.0/8".parse().unwrap()),
            Action::Outbound("internal".into()),
        );
        builder.set_final(Action::Direct);

        let engine = builder.build().unwrap();

        assert_eq!(
            engine.match_request(&ctx_domain("blocked.com")),
            &Action::Reject
        );
        assert_eq!(
            engine.match_request(&ctx_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))),
            &Action::Outbound("internal".into())
        );
        assert_eq!(
            engine.match_request(&ctx_domain("allowed.com")),
            &Action::Direct
        );
    }

    #[test]
    fn engine_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RuleEngine>();
    }

    #[test]
    fn lazy_match_domain_before_ip_rule() {
        let mut builder = RuleEngineBuilder::new();
        builder.add_inline_rule(ParsedRule::Domain("example.com".into()), Action::Reject);
        builder.add_inline_rule(
            ParsedRule::IpCidr("10.0.0.0/8".parse().unwrap()),
            Action::Direct,
        );
        builder.set_final(Action::Direct);
        let engine = builder.build().unwrap();

        let ctx = ctx_domain("example.com");
        match engine.match_request_lazy_ip(&ctx) {
            MatchDecision::Matched(action) => assert_eq!(action, &Action::Reject),
            MatchDecision::NeedIp => panic!("should not require IP for domain match"),
        }
    }

    #[test]
    fn lazy_match_needs_ip_when_ip_rule_first() {
        let mut builder = RuleEngineBuilder::new();
        builder.add_inline_rule(
            ParsedRule::IpCidr("10.0.0.0/8".parse().unwrap()),
            Action::Reject,
        );
        builder.add_inline_rule(ParsedRule::Domain("example.com".into()), Action::Direct);
        builder.set_final(Action::Direct);
        let engine = builder.build().unwrap();

        let ctx = ctx_domain("example.com");
        match engine.match_request_lazy_ip(&ctx) {
            MatchDecision::Matched(_) => panic!("should require IP before evaluating later rules"),
            MatchDecision::NeedIp => {}
        }
    }

    #[test]
    fn geoip_skipped_when_dest_ip_none() {
        // GEOIP rule should not match when dest_ip is None (domain-only request)
        let mut builder = RuleEngineBuilder::new();
        builder.add_geoip_rule("CN", Action::Reject);
        builder.set_final(Action::Direct);
        let engine = builder.build().unwrap();

        // domain-only context: dest_ip is None
        let ctx = ctx_domain("example.cn");
        assert_eq!(engine.match_request(&ctx), &Action::Direct);
    }

    #[test]
    fn inline_dst_port_match() {
        let mut builder = RuleEngineBuilder::new();
        builder.add_inline_rule(ParsedRule::DstPort(80), Action::Reject);
        builder.set_final(Action::Direct);
        let engine = builder.build().unwrap();

        let ctx = MatchContext {
            domain: Some("example.com"),
            dest_ip: None,
            dest_port: 80,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        assert_eq!(engine.match_request(&ctx), &Action::Reject);

        let ctx_miss = MatchContext {
            domain: Some("example.com"),
            dest_ip: None,
            dest_port: 443,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        assert_eq!(engine.match_request(&ctx_miss), &Action::Direct);
    }

    #[test]
    fn inline_src_ip_cidr_match() {
        let mut builder = RuleEngineBuilder::new();
        builder.add_inline_rule(
            ParsedRule::SrcIpCidr("10.0.0.0/8".parse().unwrap()),
            Action::Reject,
        );
        builder.set_final(Action::Direct);
        let engine = builder.build().unwrap();

        let ctx_match = MatchContext {
            domain: Some("example.com"),
            dest_ip: None,
            dest_port: 443,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        };
        assert_eq!(engine.match_request(&ctx_match), &Action::Reject);

        let ctx_miss = MatchContext {
            domain: Some("example.com"),
            dest_ip: None,
            dest_port: 443,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };
        assert_eq!(engine.match_request(&ctx_miss), &Action::Direct);
    }

    #[test]
    fn rule_set_with_dst_port_and_src_cidr() {
        let mut builder = RuleEngineBuilder::new();
        builder.add_rule_set(
            "mixed",
            vec![
                ParsedRule::DomainSuffix("example.com".into()),
                ParsedRule::DstPort(8080),
                ParsedRule::SrcIpCidr("172.16.0.0/12".parse().unwrap()),
            ],
        );
        builder.add_rule_set_rule("mixed", Action::Outbound("proxy".into()));
        builder.set_final(Action::Direct);
        let engine = builder.build().unwrap();

        // Match via dst port
        let ctx_port = MatchContext {
            domain: Some("other.com"),
            dest_ip: None,
            dest_port: 8080,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        assert_eq!(
            engine.match_request(&ctx_port),
            &Action::Outbound("proxy".into())
        );

        // Match via src ip
        let ctx_src = MatchContext {
            domain: Some("other.com"),
            dest_ip: None,
            dest_port: 443,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 5, 1)),
        };
        assert_eq!(
            engine.match_request(&ctx_src),
            &Action::Outbound("proxy".into())
        );

        // No match
        let ctx_miss = MatchContext {
            domain: Some("other.com"),
            dest_ip: None,
            dest_port: 443,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        assert_eq!(engine.match_request(&ctx_miss), &Action::Direct);
    }

    #[test]
    fn lazy_match_dst_port_no_dns_needed() {
        // DST-PORT rules should not require DNS resolution
        let mut builder = RuleEngineBuilder::new();
        builder.add_inline_rule(ParsedRule::DstPort(80), Action::Reject);
        builder.set_final(Action::Direct);
        let engine = builder.build().unwrap();

        let ctx = MatchContext {
            domain: Some("example.com"),
            dest_ip: None,
            dest_port: 80,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        match engine.match_request_lazy_ip(&ctx) {
            MatchDecision::Matched(action) => assert_eq!(action, &Action::Reject),
            MatchDecision::NeedIp => panic!("DST-PORT should not require IP resolution"),
        }
    }

    #[test]
    fn lazy_match_src_ip_cidr_no_dns_needed() {
        // SRC-IP-CIDR rules should not require DNS resolution
        let mut builder = RuleEngineBuilder::new();
        builder.add_inline_rule(
            ParsedRule::SrcIpCidr("10.0.0.0/8".parse().unwrap()),
            Action::Reject,
        );
        builder.set_final(Action::Direct);
        let engine = builder.build().unwrap();

        let ctx = MatchContext {
            domain: Some("example.com"),
            dest_ip: None,
            dest_port: 443,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        };
        match engine.match_request_lazy_ip(&ctx) {
            MatchDecision::Matched(action) => assert_eq!(action, &Action::Reject),
            MatchDecision::NeedIp => panic!("SRC-IP-CIDR should not require IP resolution"),
        }
    }

    #[test]
    fn lazy_match_rule_set_port_before_cidr() {
        // A rule-set containing both DST-PORT and IP-CIDR should match on
        // port without returning NeedIp, even when dest_ip is None.
        let mut builder = RuleEngineBuilder::new();
        builder.add_rule_set(
            "mixed",
            vec![
                ParsedRule::IpCidr("10.0.0.0/8".parse().unwrap()),
                ParsedRule::DstPort(8080),
            ],
        );
        builder.add_rule_set_rule("mixed", Action::Reject);
        builder.set_final(Action::Direct);
        let engine = builder.build().unwrap();

        // Port 8080, no dest_ip → should match on port, not return NeedIp
        let ctx = MatchContext {
            domain: Some("example.com"),
            dest_ip: None,
            dest_port: 8080,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        match engine.match_request_lazy_ip(&ctx) {
            MatchDecision::Matched(action) => assert_eq!(action, &Action::Reject),
            MatchDecision::NeedIp => {
                panic!("DST-PORT in rule-set should match before CIDR triggers NeedIp")
            }
        }

        // Port 443 (no match), no dest_ip, cidr exists → should return NeedIp
        let ctx_miss = MatchContext {
            domain: Some("other.com"),
            dest_ip: None,
            dest_port: 443,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        match engine.match_request_lazy_ip(&ctx_miss) {
            MatchDecision::Matched(_) => panic!("should return NeedIp for unmatched port with CIDR"),
            MatchDecision::NeedIp => {}
        }
    }

    #[test]
    fn domain_suffix_leading_dot_in_rule_set() {
        // Rule-sets compiled from parsers that produce leading-dot suffixes
        // should still match correctly after normalization.
        let mut builder = RuleEngineBuilder::new();
        builder.add_rule_set(
            "test",
            vec![ParsedRule::DomainSuffix(".example.com".into())],
        );
        builder.add_rule_set_rule("test", Action::Reject);
        builder.set_final(Action::Direct);
        let engine = builder.build().unwrap();

        assert_eq!(
            engine.match_request(&ctx_domain("example.com")),
            &Action::Reject
        );
        assert_eq!(
            engine.match_request(&ctx_domain("sub.example.com")),
            &Action::Reject
        );
        assert_eq!(
            engine.match_request(&ctx_domain("other.com")),
            &Action::Direct
        );
    }
}
