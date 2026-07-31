//! Compiled, order-preserving rule indexes.
//!
//! Rule semantics: rules are matched in order and the first match wins. All
//! single-matcher rules are grouped into per-matcher-type indexes (domain
//! suffix trie, IP radix, keyword list, regex bucket, protocol bucket); every
//! index entry keeps its original rule order, and a lookup returns the
//! smallest-order hit. Multi-matcher OR rules (rare) stay in a linear list
//! scanned on every lookup; their order is included in the global ordering.

use std::collections::HashMap;
use std::net::IpAddr;

use regex::Regex;

use crate::address::AddressMask;
use crate::client_proxy_selector::{ConnectMatcher, SniffedProtocol};

use super::rules::{ExternalRuleSet, ParsedRule};

/// Compiled, immutable rule set. Replaced atomically on reload (`Arc` swap).
#[derive(Debug, Default)]
pub struct CompiledRules {
    inner: Option<CompiledRulesInner>,
}

/// Reversed-domain trie for `DOMAIN-SUFFIX` rules. Each terminal node carries
/// the suffix entries; a lookup walks the hostname from its end and accepts
/// terminal hits only at a `.` boundary (same anchoring as the legacy
/// `matches_domain`: equal hostname, or preceding char is `.`).
#[derive(Debug, Default)]
struct SuffixTrie {
    root: SuffixNode,
}

#[derive(Debug, Default)]
struct SuffixNode {
    children: HashMap<char, Box<SuffixNode>>,
    /// Entries in rule order: (order, outbound).
    entries: Vec<(usize, String)>,
}

impl SuffixTrie {
    fn insert(&mut self, suffix: &str, order: usize, outbound: &str) {
        let mut node = &mut self.root;
        for ch in suffix.chars().rev() {
            node = node
                .children
                .entry(ch)
                .or_insert_with(|| Box::new(SuffixNode::default()));
        }
        node.entries.push((order, outbound.to_string()));
    }

    /// Collects terminal hits for `hostname` (already lowercased) into `best`,
    /// keeping the global smallest order.
    fn query<'a>(&'a self, hostname: &str, best: &mut Option<(usize, &'a str)>) {
        let bytes = hostname.as_bytes();
        let mut node = &self.root;
        for (index, &byte) in bytes.iter().enumerate().rev() {
            let Some(child) = node.children.get(&(byte as char)) else {
                return;
            };
            node = child;
            if node.entries.is_empty() {
                continue;
            }
            // Anchored: the hostname either is exactly the suffix (index 0)
            // or the char right before the suffix is '.'.
            if index > 0 && bytes[index - 1] != b'.' {
                continue;
            }
            for (order, outbound) in &node.entries {
                if best.is_none_or(|(best_order, _)| *order < best_order) {
                    *best = Some((*order, outbound));
                }
            }
        }
    }
}

/// Binary radix for IP/CIDR rules. Entries are kept per node in rule order.
/// IPv4 addresses are stored at the top 32 bits of the 128-bit key so the
/// bit walk matches the legacy `AddressMask` IPv4 `96 + bits` encoding.
#[derive(Debug, Default)]
struct IpRadix {
    root: IpNode,
}

#[derive(Debug, Default)]
struct IpNode {
    children: [Option<Box<IpNode>>; 2],
    /// Entries in rule order: (order, outbound, port; 0 = any port).
    entries: Vec<(usize, String, u16)>,
}

impl IpRadix {
    fn insert(&mut self, ip_bits: u128, prefix_len: u8, order: usize, outbound: &str, port: u16) {
        let mut node = &mut self.root;
        for shift in (0..prefix_len).map(|i| 127 - i) {
            let bit = ((ip_bits >> shift) & 1) as usize;
            node = node.children[bit].get_or_insert_with(|| Box::new(IpNode::default()));
        }
        node.entries.push((order, outbound.to_string(), port));
    }

    /// Collects hits for `ip_bits` into `best`, keeping the global smallest
    /// order; entries with a non-zero port only match that exact port.
    fn query<'a>(&'a self, ip_bits: u128, port: u16, best: &mut Option<(usize, &'a str)>) {
        let mut node = &self.root;
        for shift in (0..128).map(|i| 127 - i) {
            for (order, outbound, rule_port) in &node.entries {
                if *rule_port != 0 && *rule_port != port {
                    continue;
                }
                if best.is_none_or(|(best_order, _)| *order < best_order) {
                    *best = Some((*order, outbound));
                }
            }
            let bit = ((ip_bits >> shift) & 1) as usize;
            let Some(child) = &node.children[bit] else {
                return;
            };
            node = child;
        }
        for (order, outbound, rule_port) in &node.entries {
            if *rule_port != 0 && *rule_port != port {
                continue;
            }
            if best.is_none_or(|(best_order, _)| *order < best_order) {
                *best = Some((*order, outbound));
            }
        }
    }
}

/// Number of leading netmask bits of an `AddressMask` (see `AddressMask::from`
/// for the IPv4 `96 + bits` encoding; `0` netmask matches everything).
fn prefix_len(mask: &AddressMask) -> u8 {
    if mask.netmask == 0 {
        return 0;
    }
    let bits = 128 - mask.netmask.trailing_zeros() as u8;
    match mask.address {
        crate::address::Address::Ipv4(_) => bits.saturating_sub(96),
        _ => bits,
    }
}

#[derive(Debug)]
struct CompiledRulesInner {
    /// True when any rule needs IP matching (triggers DNS resolution for
    /// hostname targets).
    has_ip_rules: bool,
    /// Catch-all rule order/outbound (`MATCH`); `None` when absent.
    catch_all: Option<(usize, String)>,
    /// `DOMAIN-SUFFIX` trie.
    suffix_trie: SuffixTrie,
    /// `DOMAIN` exact entries keyed by lowercase domain: (order, outbound).
    full: HashMap<String, (usize, String)>,
    /// `DOMAIN-KEYWORD` entries: (order, lowercase keyword, outbound).
    keywords: Vec<(usize, String, String)>,
    /// `DOMAIN-REGEX` entries: (order, outbound, compiled regex).
    regexes: Vec<(usize, String, Regex)>,
    /// `IP-CIDR`/`IP-CIDR6` entries.
    ipv4: IpRadix,
    ipv6: IpRadix,
    /// `PROTOCOL` entries: (order, outbound, protocol).
    protocols: Vec<(usize, String, SniffedProtocol)>,
}

impl CompiledRules {
    pub fn empty() -> Self {
        Self { inner: None }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_none()
    }

    /// True when any compiled rule matches on IP/CIDR and hostname targets
    /// must be resolved before matching.
    pub fn has_ip_rules(&self) -> bool {
        self.inner.as_ref().is_some_and(|inner| inner.has_ip_rules)
    }

    /// True when any compiled rule matches on a sniffed protocol.
    pub fn has_protocol_rules(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|inner| !inner.protocols.is_empty())
    }

    /// Returns the outbound tag of the first-matching domain rule, if any.
    pub fn match_domain(&self, domain: &str) -> Option<&str> {
        let inner = self.inner.as_ref()?;
        let hostname = domain.to_ascii_lowercase();
        let mut best: Option<(usize, &str)> = None;

        inner.suffix_trie.query(&hostname, &mut best);

        if let Some((order, outbound)) = inner.full.get(&hostname)
            && best.is_none_or(|(best_order, _)| *order < best_order)
        {
            best = Some((*order, outbound));
        }
        for (order, keyword, outbound) in &inner.keywords {
            if hostname.contains(keyword) && best.is_none_or(|(best_order, _)| *order < best_order)
            {
                best = Some((*order, outbound));
            }
        }
        for (order, outbound, regex) in &inner.regexes {
            if regex.is_match(&hostname) && best.is_none_or(|(best_order, _)| *order < best_order) {
                best = Some((*order, outbound));
            }
        }
        best.map(|(_, outbound)| outbound)
    }

    /// Returns the outbound tag of the first-matching IP/CIDR rule, if any.
    pub fn match_ip(&self, ip: IpAddr, port: u16) -> Option<&str> {
        let inner = self.inner.as_ref()?;
        let mut best: Option<(usize, &str)> = None;
        match ip {
            IpAddr::V4(v4) => {
                inner
                    .ipv4
                    .query(u128::from(u32::from(v4)) << 96, port, &mut best);
            }
            IpAddr::V6(v6) => inner.ipv6.query(u128::from(v6), port, &mut best),
        }
        best.map(|(_, outbound)| outbound)
    }

    /// Returns the outbound tag of the first-matching protocol rule, if any.
    pub fn match_protocol(&self, protocol: SniffedProtocol) -> Option<&str> {
        let inner = self.inner.as_ref()?;
        let mut best: Option<(usize, &str)> = None;
        for (order, outbound, rule_protocol) in &inner.protocols {
            if *rule_protocol == protocol && best.is_none_or(|(best_order, _)| *order < best_order)
            {
                best = Some((*order, outbound));
            }
        }
        best.map(|(_, outbound)| outbound)
    }

    /// Returns the `MATCH` catch-all outbound, if configured.
    pub fn match_catch_all(&self) -> Option<&str> {
        self.inner.as_ref().and_then(|inner| {
            inner
                .catch_all
                .as_ref()
                .map(|(_, outbound)| outbound.as_str())
        })
    }

    /// Builds the compiled indexes from parsed rules. `expand_geosite` and
    /// `expand_geoip` return the expanded rules of a referenced local rule
    /// set; their outbound is overwritten with the referencing rule's.
    pub fn compile(
        rules: Vec<ParsedRule>,
        expand_geosite: impl Fn(&str) -> std::io::Result<Vec<ParsedRule>>,
        expand_geoip: impl Fn(&str) -> std::io::Result<Vec<ParsedRule>>,
    ) -> std::io::Result<Self> {
        let mut flat: Vec<(usize, ConnectMatcher, String)> = Vec::new();
        let mut catch_all: Option<(usize, String)> = None;

        for (order, rule) in rules.into_iter().enumerate() {
            match rule.external {
                Some(ExternalRuleSet::Geosite(code)) => {
                    let expanded = expand_geosite(&code)?;
                    for expanded_rule in expanded {
                        let matcher = expanded_rule.matcher.ok_or_else(|| {
                            external_rule_set_error(&code, "expanded rule has no matcher")
                        })?;
                        flat.push((order, matcher, rule.outbound.clone()));
                    }
                }
                Some(ExternalRuleSet::Geoip(code)) => {
                    let expanded = expand_geoip(&code)?;
                    for expanded_rule in expanded {
                        let matcher = expanded_rule.matcher.ok_or_else(|| {
                            external_rule_set_error(&code, "expanded rule has no matcher")
                        })?;
                        flat.push((order, matcher, rule.outbound.clone()));
                    }
                }
                None => match rule.matcher {
                    Some(matcher) => flat.push((order, matcher, rule.outbound)),
                    None => catch_all = Some((order, rule.outbound)),
                },
            }
        }

        if flat.is_empty() && catch_all.is_none() {
            return Ok(Self::empty());
        }

        let mut inner = CompiledRulesInner {
            has_ip_rules: false,
            catch_all,
            suffix_trie: SuffixTrie::default(),
            full: HashMap::new(),
            keywords: Vec::new(),
            regexes: Vec::new(),
            ipv4: IpRadix::default(),
            ipv6: IpRadix::default(),
            protocols: Vec::new(),
        };

        for (order, matcher, outbound) in flat {
            match matcher {
                ConnectMatcher::DomainSuffix(suffix) => {
                    inner.suffix_trie.insert(&suffix, order, &outbound);
                }
                ConnectMatcher::DomainFull(domain) => {
                    let key = domain.to_ascii_lowercase();
                    inner.full.entry(key).or_insert_with(|| (order, outbound));
                }
                ConnectMatcher::DomainKeyword(keyword) => {
                    inner
                        .keywords
                        .push((order, keyword.to_ascii_lowercase(), outbound));
                }
                ConnectMatcher::DomainRegex(regex) => {
                    inner.regexes.push((order, outbound, regex));
                }
                ConnectMatcher::Location(mask) => {
                    inner.has_ip_rules = true;
                    let prefix = prefix_len(&mask.address_mask);
                    let port = mask.port;
                    match mask.address_mask.address {
                        crate::address::Address::Ipv4(v4) => {
                            inner.ipv4.insert(
                                u128::from(u32::from(v4)) << 96,
                                prefix,
                                order,
                                &outbound,
                                port,
                            );
                        }
                        crate::address::Address::Ipv6(v6) => {
                            inner
                                .ipv6
                                .insert(u128::from(v6), prefix, order, &outbound, port);
                        }
                        crate::address::Address::Hostname(hostname) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                format!(
                                    "IP/CIDR rule cannot use hostname `{hostname}`; use DOMAIN-SUFFIX/DOMAIN instead"
                                ),
                            ));
                        }
                    }
                }
                ConnectMatcher::Protocol(protocol) => {
                    inner.protocols.push((order, outbound, protocol));
                }
            }
        }

        Ok(Self { inner: Some(inner) })
    }
}

fn external_rule_set_error(code: &str, msg: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("rule set `{code}`: {msg}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, NetLocationMask};

    fn parse(line: &str) -> ParsedRule {
        super::super::rules::parse_crs_line(line, 1, "config")
            .unwrap()
            .unwrap()
    }

    fn compile_with(rules: Vec<ParsedRule>) -> CompiledRules {
        CompiledRules::compile(rules, |_| Ok(Vec::new()), |_| Ok(Vec::new()))
            .expect("compile failed")
    }

    fn location_rule(value: &str, outbound: &str) -> ParsedRule {
        ParsedRule {
            line: 1,
            source: "config".to_string(),
            matcher: Some(ConnectMatcher::Location(
                NetLocationMask::from(value).unwrap(),
            )),
            external: None,
            outbound: outbound.to_string(),
        }
    }

    #[test]
    fn first_match_wins_across_indexes() {
        let rules = compile_with(vec![
            parse("DOMAIN-KEYWORD,cdn,key"),
            parse("DOMAIN-SUFFIX,example.com,suffix"),
            parse("DOMAIN,cdn.example.com,exact"),
        ]);
        // Keyword at order 0 beats suffix at order 1 for a matching hostname.
        assert_eq!(rules.match_domain("cdn.example.com"), Some("key"));
        assert_eq!(rules.match_domain("a.example.com"), Some("suffix"));
        assert_eq!(rules.match_domain("example.com"), Some("suffix"));
        assert_eq!(rules.match_domain("other.com"), None);
    }

    #[test]
    fn suffix_matching_is_anchored() {
        let rules = compile_with(vec![parse("DOMAIN-SUFFIX,example.com,out")]);
        assert_eq!(rules.match_domain("example.com"), Some("out"));
        assert_eq!(rules.match_domain("a.example.com"), Some("out"));
        assert_eq!(rules.match_domain("a.b.example.com"), Some("out"));
        assert_eq!(rules.match_domain("notexample.com"), None);
        assert_eq!(rules.match_domain("xexample.com"), None);
        assert_eq!(rules.match_domain("example.com.evil.org"), None);
        // Hostname matching is case-insensitive (legacy behavior).
        assert_eq!(rules.match_domain("A.EXAMPLE.COM"), Some("out"));
    }

    #[test]
    fn ip_radix_matches_cidr() {
        let rules = compile_with(vec![
            parse("IP-CIDR,1.2.3.16/28,out28"),
            parse("IP-CIDR,1.2.3.0/24,out24"),
            parse("IP-CIDR6,2001:db8::/32,out6"),
        ]);
        // The more specific /28 rule comes first and wins for its range.
        assert_eq!(
            rules.match_ip("1.2.3.20".parse().unwrap(), 443),
            Some("out28")
        );
        assert_eq!(
            rules.match_ip("1.2.3.55".parse().unwrap(), 443),
            Some("out24")
        );
        assert_eq!(rules.match_ip("1.2.4.1".parse().unwrap(), 443), None);
        assert_eq!(
            rules.match_ip("2001:db8::1".parse().unwrap(), 443),
            Some("out6")
        );
        assert_eq!(rules.match_ip("2001:db9::1".parse().unwrap(), 443), None);
        assert!(rules.has_ip_rules());
    }

    #[test]
    fn ip_cidr_zero_prefix_matches_everything() {
        let rules = compile_with(vec![parse("IP-CIDR,0.0.0.0/0,out")]);
        assert_eq!(rules.match_ip("9.9.9.9".parse().unwrap(), 80), Some("out"));
        assert_eq!(rules.match_ip("10.0.0.1".parse().unwrap(), 0), Some("out"));
        assert!(rules.has_ip_rules());
    }

    #[test]
    fn port_restricted_location_matches_only_port() {
        let rules = compile_with(vec![location_rule("127.0.0.0/8:443", "out")]);
        assert_eq!(
            rules.match_ip("127.0.0.1".parse().unwrap(), 443),
            Some("out")
        );
        assert_eq!(rules.match_ip("127.0.0.1".parse().unwrap(), 80), None);
    }

    #[test]
    fn protocol_and_catch_all() {
        let rules = compile_with(vec![
            parse("PROTOCOL,http,out_http"),
            parse("MATCH,out_match"),
        ]);
        assert_eq!(
            rules.match_protocol(SniffedProtocol::Http),
            Some("out_http")
        );
        assert_eq!(rules.match_protocol(SniffedProtocol::Tls), None);
        assert_eq!(rules.match_catch_all(), Some("out_match"));

        let no_catch_all = compile_with(vec![parse("PROTOCOL,tls,out_tls")]);
        assert_eq!(no_catch_all.match_catch_all(), None);
    }

    #[test]
    fn expansion_of_geosite_rules() {
        let rules = CompiledRules::compile(
            vec![parse("GEOSITE,netflix,out")],
            |code| {
                assert_eq!(code, "netflix");
                Ok(vec![
                    ParsedRule {
                        line: 1,
                        source: format!("geosite:{code}"),
                        matcher: Some(ConnectMatcher::domain_suffix("netflix.com")),
                        external: None,
                        outbound: String::new(),
                    },
                    ParsedRule {
                        line: 1,
                        source: format!("geosite:{code}"),
                        matcher: Some(ConnectMatcher::domain_full("netflix.tv")),
                        external: None,
                        outbound: String::new(),
                    },
                ])
            },
            |_| Ok(Vec::new()),
        )
        .expect("compile failed");
        assert_eq!(rules.match_domain("www.netflix.com"), Some("out"));
        assert_eq!(rules.match_domain("netflix.tv"), Some("out"));
        assert!(!rules.has_ip_rules());
    }

    #[test]
    fn expansion_failure_propagates() {
        let error = CompiledRules::compile(
            vec![parse("GEOSITE,missing,out")],
            |_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no such set",
                ))
            },
            |_| Ok(Vec::new()),
        )
        .expect_err("expected error");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn empty_rules_are_empty() {
        let rules = compile_with(Vec::new());
        assert!(rules.is_empty());
        assert_eq!(rules.match_domain("example.com"), None);
        assert_eq!(rules.match_catch_all(), None);
        assert!(!rules.has_ip_rules());
    }

    #[test]
    fn hostname_location_is_rejected() {
        let error = CompiledRules::compile(
            vec![ParsedRule {
                line: 1,
                source: "config".to_string(),
                matcher: Some(ConnectMatcher::Location(NetLocationMask {
                    address_mask: AddressMask {
                        address: Address::Hostname("example.com".to_string()),
                        netmask: 0,
                    },
                    port: 0,
                })),
                external: None,
                outbound: "out".to_string(),
            }],
            |_| Ok(Vec::new()),
            |_| Ok(Vec::new()),
        )
        .expect_err("expected error");
        assert!(error.to_string().contains("hostname"));
    }

    #[test]
    fn order_beats_index_type_priority() {
        // An earlier keyword hit must win over a later exact-domain rule.
        let rules = compile_with(vec![
            parse("DOMAIN-KEYWORD,cdn,key"),
            parse("DOMAIN,cdn.example.com,exact"),
        ]);
        assert_eq!(rules.match_domain("cdn.example.com"), Some("key"));
        assert_eq!(rules.match_domain("cdn.other.com"), Some("key"));
    }

    #[test]
    fn regex_rules_match() {
        let rules = compile_with(vec![parse("DOMAIN-REGEX,^cdn-[0-9]+\\.example\\.com$,out")]);
        assert_eq!(rules.match_domain("cdn-42.example.com"), Some("out"));
        assert_eq!(rules.match_domain("cdn-42.example.com.evil.org"), None);
        assert_eq!(rules.match_domain("cdn-x.example.com"), None);
    }

    #[test]
    fn geoip_expansion_sets_has_ip_rules() {
        let rules = CompiledRules::compile(
            vec![parse("GEOIP,CN,out")],
            |_| Ok(Vec::new()),
            |code| {
                assert_eq!(code, "CN");
                Ok(vec![location_rule("223.0.0.0/8", "")])
            },
        )
        .expect("compile failed");
        assert!(rules.has_ip_rules());
        assert_eq!(
            rules.match_ip("223.5.5.5".parse().unwrap(), 443),
            Some("out")
        );
        assert_eq!(rules.match_ip("8.8.8.8".parse().unwrap(), 443), None);
    }
}
