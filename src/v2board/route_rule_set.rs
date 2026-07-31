use std::fs;
use std::path::Path;

use crate::address::{Address, NetLocationMask};
use crate::backend_config::RouteRuleSetsConfig;
use crate::client_proxy_selector::ConnectMatcher;

pub fn load_geosite_matchers(
    node_tag: &str,
    rule_sets: &RouteRuleSetsConfig,
    code: &str,
) -> std::io::Result<Vec<ConnectMatcher>> {
    let path = rule_sets.geosite_path(code).ok_or_else(|| {
        invalid_error(format!(
            "node `{node_tag}` route matcher `geosite:{code}` requires v2board.route_rule_sets.geosite.{code}"
        ))
    })?;
    let content = read_rule_set_file(node_tag, "geosite", code, path)?;
    parse_geosite_matchers(node_tag, code, &content)
}

pub fn load_geoip_matchers(
    node_tag: &str,
    rule_sets: &RouteRuleSetsConfig,
    code: &str,
) -> std::io::Result<Vec<ConnectMatcher>> {
    let path = rule_sets.geoip_path(code).ok_or_else(|| {
        invalid_error(format!(
            "node `{node_tag}` route matcher `geoip:{code}` requires v2board.route_rule_sets.geoip.{code}"
        ))
    })?;
    let content = read_rule_set_file(node_tag, "geoip", code, path)?;
    parse_geoip_matchers(node_tag, code, &content)
}

fn read_rule_set_file(
    node_tag: &str,
    kind: &str,
    code: &str,
    path: &Path,
) -> std::io::Result<String> {
    fs::read_to_string(path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "node `{node_tag}` failed to read {kind}:{code} route rule-set {}: {e}",
                path.display()
            ),
        )
    })
}

fn parse_geosite_matchers(
    node_tag: &str,
    code: &str,
    content: &str,
) -> std::io::Result<Vec<ConnectMatcher>> {
    let mut matchers = Vec::new();
    for (line_number, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(domain) = strip_route_prefix(line, &lower, "domain:") {
            require_non_empty_rule_set_token(node_tag, "geosite", code, line_number, domain)?;
            matchers.push(ConnectMatcher::domain_suffix(domain));
        } else if let Some(domain) = strip_route_prefix(line, &lower, "full:") {
            require_non_empty_rule_set_token(node_tag, "geosite", code, line_number, domain)?;
            matchers.push(ConnectMatcher::domain_full(domain));
        } else if let Some(keyword) = strip_route_prefix(line, &lower, "keyword:") {
            require_non_empty_rule_set_token(node_tag, "geosite", code, line_number, keyword)?;
            matchers.push(ConnectMatcher::domain_keyword(keyword));
        } else if let Some(pattern) = strip_route_prefix(line, &lower, "regexp:") {
            require_non_empty_rule_set_token(node_tag, "geosite", code, line_number, pattern)?;
            matchers.push(ConnectMatcher::domain_regex(pattern).map_err(|e| {
                invalid_error(format!(
                    "node `{node_tag}` geosite:{code} line {} has invalid regexp `{pattern}`: {e}",
                    line_number + 1
                ))
            })?);
        } else if lower.starts_with("geosite:") || lower.starts_with("geoip:") {
            return invalid(format!(
                "node `{node_tag}` geosite:{code} line {} cannot reference nested route rule-set `{line}`",
                line_number + 1
            ));
        } else {
            matchers.push(ConnectMatcher::domain_keyword(lower));
        }
    }
    if matchers.is_empty() {
        return invalid(format!(
            "node `{node_tag}` geosite:{code} route rule-set has no usable matchers"
        ));
    }
    Ok(matchers)
}

fn parse_geoip_matchers(
    node_tag: &str,
    code: &str,
    content: &str,
) -> std::io::Result<Vec<ConnectMatcher>> {
    let mut matchers = Vec::new();
    for (line_number, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.to_ascii_lowercase().starts_with("geoip:") {
            return invalid(format!(
                "node `{node_tag}` geoip:{code} line {} cannot reference nested geoip rule-set `{line}`",
                line_number + 1
            ));
        }
        let mask = NetLocationMask::from(line).map_err(|e| {
            invalid_error(format!(
                "node `{node_tag}` geoip:{code} line {} has invalid IP/CIDR matcher `{line}`: {e}",
                line_number + 1
            ))
        })?;
        if matches!(mask.address_mask.address, Address::Hostname(_)) {
            return invalid(format!(
                "node `{node_tag}` geoip:{code} line {} expects IP/CIDR matcher, got `{line}`",
                line_number + 1
            ));
        }
        matchers.push(ConnectMatcher::location(mask));
    }
    if matchers.is_empty() {
        return invalid(format!(
            "node `{node_tag}` geoip:{code} route rule-set has no usable matchers"
        ));
    }
    Ok(matchers)
}

fn strip_route_prefix<'a>(value: &'a str, lower: &str, prefix: &str) -> Option<&'a str> {
    lower
        .starts_with(prefix)
        .then(|| value[prefix.len()..].trim())
}

fn require_non_empty_rule_set_token(
    node_tag: &str,
    kind: &str,
    code: &str,
    line_number: usize,
    value: &str,
) -> std::io::Result<()> {
    if value.trim().is_empty() {
        return invalid(format!(
            "node `{node_tag}` {kind}:{code} line {} has an empty matcher value",
            line_number + 1
        ));
    }
    Ok(())
}

fn invalid<T>(msg: impl Into<String>) -> std::io::Result<T> {
    Err(invalid_error(msg))
}

fn invalid_error(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, NetLocation};
    use crate::client_proxy_selector::{
        ClientProxySelector, ConnectAction, ConnectDecision, ConnectRule,
    };
    use crate::resolver::Resolver;
    use std::collections::HashMap;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::Arc;

    #[derive(Debug)]
    struct NoopResolver;

    impl Resolver for NoopResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[tokio::test]
    async fn geosite_text_rule_set_builds_domain_matchers() {
        let matchers = parse_geosite_matchers(
            "node-a",
            "local",
            "\n# comment\ndomain:example.com\nfull:api.local\nkeyword:video\nregexp:^cdn-[0-9]+\\.local$\n",
        )
        .unwrap();
        let selector = ClientProxySelector::new(vec![
            ConnectRule::new_matchers(matchers, ConnectAction::new_block()),
            ConnectRule::new_matchers(
                vec![ConnectMatcher::location(NetLocationMask::ANY)],
                ConnectAction::new_allow(
                    None,
                    crate::tcp::chain_builder::build_direct_chain_group(Arc::new(NoopResolver)),
                ),
            ),
        ]);
        let resolver: Arc<dyn Resolver> = Arc::new(NoopResolver);

        let decision = selector
            .judge(
                NetLocation::new(Address::Hostname("cdn-42.local".to_string()), 443).into(),
                &resolver,
            )
            .await
            .unwrap();
        assert!(matches!(decision, ConnectDecision::Block));
    }

    #[test]
    fn geoip_text_rule_set_builds_ip_matchers() {
        let matchers =
            parse_geoip_matchers("node-a", "local", "127.0.0.0/8\n2001:db8::/32\n").unwrap();

        assert_eq!(matchers.len(), 2);
    }

    #[test]
    fn configured_rule_sets_are_case_insensitive() {
        let mut rule_sets = RouteRuleSetsConfig {
            geosite: HashMap::new(),
            geoip: HashMap::new(),
        };
        rule_sets.geosite.insert(
            "Netflix".to_string(),
            Path::new("/tmp/netflix.txt").to_path_buf(),
        );

        assert!(rule_sets.geosite_path("netflix").is_some());
        assert!(rule_sets.geosite_path("NETFLIX").is_some());
    }
}
