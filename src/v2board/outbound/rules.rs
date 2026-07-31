//! CRS (Clash/sing-box style) rule line parsing.
//!
//! One line maps to at most one matcher plus the target outbound tag. Rules
//! are matched in order, first match wins (see `index` for the compiled
//! order-preserving indexes).

use crate::address::NetLocationMask;
use crate::client_proxy_selector::{ConnectMatcher, SniffedProtocol};

/// A reference to an external local rule set expanded at compile time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalRuleSet {
    Geosite(String),
    Geoip(String),
}

impl ExternalRuleSet {
    pub fn code(&self) -> &str {
        match self {
            Self::Geosite(code) | Self::Geoip(code) => code,
        }
    }
}

/// A parsed CRS rule line. `matcher` is `None` for `MATCH` (catch-all) and
/// for external rule-set references (`external` is then `Some`).
#[derive(Debug)]
pub struct ParsedRule {
    /// 1-based source line number for diagnostics.
    pub line: usize,
    /// Source name for diagnostics: `config` or a rule provider tag.
    pub source: String,
    pub matcher: Option<ConnectMatcher>,
    /// `GEOSITE`/`GEOIP` reference to be expanded at compile time.
    pub external: Option<ExternalRuleSet>,
    pub outbound: String,
}

/// Parses a single CRS line. Supported types:
/// `DOMAIN-SUFFIX`, `DOMAIN`, `DOMAIN-KEYWORD`, `DOMAIN-REGEX`, `IP-CIDR`,
/// `IP-CIDR6`, `GEOSITE`, `GEOIP`, `PROTOCOL`, `MATCH`.
///
/// Returns `Ok(None)` for blank lines and comment lines (starting with `#`).
pub fn parse_crs_line(
    line: &str,
    line_number: usize,
    source: &str,
) -> Result<Option<ParsedRule>, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }

    let error = |msg: String| -> Result<Option<ParsedRule>, String> {
        Err(format!("{source}:{line_number}: {msg}"))
    };

    let fields: Vec<&str> = trimmed.split(',').map(|field| field.trim()).collect();
    let type_upper = fields[0].to_ascii_uppercase();

    let outbound = |fields: &[&str]| -> Result<String, String> {
        if fields.len() < 3 {
            return Err(format!(
                "{source}:{line_number}: rule `{type_upper}` expects TYPE,VALUE,OUTBOUND, got `{trimmed}`"
            ));
        }
        if fields.len() > 3 {
            return Err(format!(
                "{source}:{line_number}: rule `{type_upper}` has {} fields, expected 3: `{trimmed}`",
                fields.len()
            ));
        }
        Ok(fields[2].to_string())
    };

    let matcher = match type_upper.as_str() {
        "MATCH" => {
            if fields.len() != 2 {
                return error(format!(
                    "rule `MATCH` expects MATCH,OUTBOUND, got `{trimmed}`"
                ));
            }
            if fields[1].is_empty() {
                return error("rule `MATCH` requires a non-empty OUTBOUND".to_string());
            }
            return Ok(Some(ParsedRule {
                line: line_number,
                source: source.to_string(),
                matcher: None,
                external: None,
                outbound: fields[1].to_string(),
            }));
        }
        "DOMAIN-SUFFIX" => {
            let value = fields[1].trim_start_matches('.');
            if value.is_empty() {
                return error(format!(
                    "rule `DOMAIN-SUFFIX` requires a non-empty domain, got `{trimmed}`"
                ));
            }
            ConnectMatcher::domain_suffix(value)
        }
        "DOMAIN" => {
            if fields[1].is_empty() {
                return error(format!(
                    "rule `DOMAIN` requires a non-empty domain, got `{trimmed}`"
                ));
            }
            ConnectMatcher::domain_full(fields[1])
        }
        "DOMAIN-KEYWORD" => {
            if fields[1].is_empty() {
                return error(format!(
                    "rule `DOMAIN-KEYWORD` requires a non-empty keyword, got `{trimmed}`"
                ));
            }
            ConnectMatcher::domain_keyword(fields[1])
        }
        "DOMAIN-REGEX" => {
            if fields[1].is_empty() {
                return error(format!(
                    "rule `DOMAIN-REGEX` requires a non-empty pattern, got `{trimmed}`"
                ));
            }
            ConnectMatcher::domain_regex(fields[1]).map_err(|e| {
                format!(
                    "{source}:{line_number}: rule `DOMAIN-REGEX` has invalid regexp `{}`: {e}",
                    fields[1]
                )
            })?
        }
        "IP-CIDR" | "IP-CIDR6" => {
            let mask = NetLocationMask::from(fields[1]).map_err(|e| {
                format!(
                    "{source}:{line_number}: rule `{type_upper}` has invalid IP/CIDR `{}`: {e}",
                    fields[1]
                )
            })?;
            match &mask.address_mask.address {
                crate::address::Address::Ipv4(_) | crate::address::Address::Ipv6(_) => {}
                crate::address::Address::Hostname(hostname) => {
                    return error(format!(
                        "rule `{type_upper}` expects an IP/CIDR, got hostname `{hostname}`"
                    ));
                }
            }
            ConnectMatcher::location(mask)
        }
        "GEOSITE" | "GEOIP" => {
            let outbound = outbound(&fields)?;
            let code = fields[1];
            if code.is_empty() {
                return error(format!(
                    "rule `{type_upper}` requires a non-empty code, got `{trimmed}`"
                ));
            }
            let external = if type_upper == "GEOSITE" {
                ExternalRuleSet::Geosite(code.to_string())
            } else {
                ExternalRuleSet::Geoip(code.to_string())
            };
            return Ok(Some(ParsedRule {
                line: line_number,
                source: source.to_string(),
                matcher: None,
                external: Some(external),
                outbound,
            }));
        }
        "PROTOCOL" => {
            let protocol = parse_protocol_label(fields[1])
                .map_err(|e| format!("{source}:{line_number}: {e}"))?;
            ConnectMatcher::protocol(protocol)
        }
        _ => {
            return error(format!("unknown rule type `{type_upper}`"));
        }
    };

    let outbound = outbound(&fields)?;
    Ok(Some(ParsedRule {
        line: line_number,
        source: source.to_string(),
        matcher: Some(matcher),
        external: None,
        outbound,
    }))
}

/// Parses every line of a rule source. Blank lines and lines starting with
/// `#` are ignored; errors carry source and line numbers.
pub fn parse_crs_lines(lines: &[String], source: &str) -> Result<Vec<ParsedRule>, String> {
    let mut rules = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if let Some(rule) = parse_crs_line(line, index + 1, source)? {
            rules.push(rule);
        }
    }
    Ok(rules)
}

/// Returns true when a parsed rule references an external geosite/geoip set
/// and must be expanded by the compiler.
pub fn requires_expansion(rule: &ParsedRule) -> bool {
    rule.external.is_some()
}

/// Parses a `PROTOCOL` value into a sniffed protocol.
pub fn parse_protocol_label(label: &str) -> Result<SniffedProtocol, String> {
    SniffedProtocol::from_route_label(label).ok_or_else(|| {
        format!(
            "unknown protocol `{}`, expected one of: {}",
            label.trim(),
            SniffedProtocol::SUPPORTED_LABELS.join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_proxy_selector::ConnectMatcher;

    fn rule(line: &str) -> ParsedRule {
        parse_crs_line(line, 3, "config")
            .unwrap()
            .expect("expected a parsed rule")
    }

    #[test]
    fn parses_domain_suffix() {
        let parsed = rule("DOMAIN-SUFFIX,example.com,upstream");
        assert_eq!(parsed.line, 3);
        assert_eq!(parsed.source, "config");
        assert_eq!(parsed.outbound, "upstream");
        assert!(parsed.external.is_none());
        assert!(matches!(
            parsed.matcher,
            Some(ConnectMatcher::DomainSuffix(ref domain)) if domain == "example.com"
        ));
    }

    #[test]
    fn strips_leading_dot_from_suffix() {
        let parsed = rule("DOMAIN-SUFFIX,.example.com,upstream");
        assert!(matches!(
            parsed.matcher,
            Some(ConnectMatcher::DomainSuffix(ref domain)) if domain == "example.com"
        ));
    }

    #[test]
    fn rejects_unknown_type() {
        let error = parse_crs_line("DOMAIN-LIST,example.com,upstream", 3, "config").unwrap_err();
        assert_eq!(error, "config:3: unknown rule type `DOMAIN-LIST`");
    }

    #[test]
    fn ignores_blank_and_comment_lines() {
        assert!(parse_crs_line("", 1, "config").unwrap().is_none());
        assert!(parse_crs_line("   \n", 2, "config").unwrap().is_none());
        assert!(parse_crs_line("# comment", 3, "config").unwrap().is_none());
        assert!(
            parse_crs_line("   # indented", 4, "config")
                .unwrap()
                .is_none()
        );

        let lines = vec![
            "# header".to_string(),
            "".to_string(),
            "MATCH,direct".to_string(),
        ];
        let rules = parse_crs_lines(&lines, "config").unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].matcher.is_none());
    }

    #[test]
    fn parses_ip_cidr_v4_and_v6() {
        let v4 = rule("IP-CIDR,1.2.3.0/24,upstream");
        assert!(matches!(
            v4.matcher,
            Some(ConnectMatcher::Location(ref mask))
                if matches!(mask.address_mask.address, crate::address::Address::Ipv4(_))
                    && mask.address_mask.netmask == (u128::MAX << 8)
        ));

        let v6 = rule("IP-CIDR6,2001:db8::/32,upstream");
        assert!(matches!(
            v6.matcher,
            Some(ConnectMatcher::Location(ref mask))
                if matches!(mask.address_mask.address, crate::address::Address::Ipv6(_))
                    && mask.address_mask.netmask == (u128::MAX << 96)
        ));
    }

    #[test]
    fn rejects_invalid_cidr() {
        let error = parse_crs_line("IP-CIDR,not-an-ip,upstream", 5, "config").unwrap_err();
        assert!(error.starts_with("config:5:"), "{error}");
        assert!(error.contains("not-an-ip"), "{error}");

        let error = parse_crs_line("IP-CIDR6,1.2.3.4/99,upstream", 6, "config").unwrap_err();
        assert!(error.starts_with("config:6:"), "{error}");
    }

    #[test]
    fn parses_protocol_labels() {
        assert!(matches!(
            rule("PROTOCOL,http,upstream").matcher,
            Some(ConnectMatcher::Protocol(SniffedProtocol::Http))
        ));
        assert!(matches!(
            rule("PROTOCOL,TLS,upstream").matcher,
            Some(ConnectMatcher::Protocol(SniffedProtocol::Tls))
        ));
        assert!(matches!(
            rule("PROTOCOL,bittorrent,upstream").matcher,
            Some(ConnectMatcher::Protocol(SniffedProtocol::Bittorrent))
        ));
        let error = parse_crs_line("PROTOCOL,ftp,upstream", 6, "config").unwrap_err();
        assert!(error.contains("unknown protocol `ftp`"));
    }

    #[test]
    fn parses_match_without_value() {
        let parsed = rule("MATCH,upstream");
        assert!(parsed.matcher.is_none());
        assert!(parsed.external.is_none());
        assert_eq!(parsed.outbound, "upstream");
    }

    #[test]
    fn parses_geosite_and_geoip_references() {
        let geosite = rule("GEOSITE,netflix,upstream");
        assert_eq!(
            geosite.external,
            Some(ExternalRuleSet::Geosite("netflix".into()))
        );
        assert!(geosite.matcher.is_none());
        assert_eq!(geosite.outbound, "upstream");
        assert!(requires_expansion(&geosite));

        let geoip = rule("GEOIP,CN,upstream");
        assert_eq!(geoip.external, Some(ExternalRuleSet::Geoip("CN".into())));
        assert!(requires_expansion(&geoip));

        let match_rule = rule("MATCH,upstream");
        assert!(!requires_expansion(&match_rule));
    }

    #[test]
    fn errors_carry_source_and_line() {
        let error = parse_crs_line("NOPE,1,2", 42, "prov-a").unwrap_err();
        assert_eq!(error, "prov-a:42: unknown rule type `NOPE`");

        let error = parse_crs_line("DOMAIN-SUFFIX,example.com", 7, "config").unwrap_err();
        assert!(error.starts_with("config:7:"));
        assert!(error.contains("expects TYPE,VALUE,OUTBOUND"));

        let error = parse_crs_line("MATCH,up,stream", 8, "config").unwrap_err();
        assert!(error.contains("expects MATCH,OUTBOUND"));
    }

    #[test]
    fn type_is_case_insensitive() {
        let parsed = rule("domain-suffix,example.com,upstream");
        assert!(matches!(
            parsed.matcher,
            Some(ConnectMatcher::DomainSuffix(ref domain)) if domain == "example.com"
        ));
    }
}
