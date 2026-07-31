//! Rule compilation entry point: parses config lines and provider files,
//! expands GEOSITE/GEOIP references through the existing local rule sets, and
//! builds the compiled indexes.

use std::collections::HashMap;
use std::path::Path;

use crate::backend_config::{RouteRuleSetsConfig, RuleProviderConfig};
use crate::client_proxy_selector::ConnectMatcher;
use crate::v2board::route_rule_set::{load_geoip_matchers, load_geosite_matchers};

use super::index::CompiledRules;
use super::rules::{ParsedRule, parse_crs_lines};

/// Compiles `route_rules` config lines plus every rule provider file.
///
/// `node_tag` is used in errors that reference `v2board.route_rule_sets`.
/// `config_lines` is the `route_rules` list; providers are loaded from their
/// paths. Returns the compiled rule set.
pub fn compile_route_rules(
    node_tag: &str,
    config_lines: &[String],
    providers: &[RuleProviderConfig],
    rule_sets: &RouteRuleSetsConfig,
) -> std::io::Result<CompiledRules> {
    let mut all = Vec::new();
    all.extend(
        parse_crs_lines(config_lines, "config")
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
    );
    for provider in providers {
        let mut provider_rules = load_provider_file(&provider.path).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "rule provider `{}` ({}) failed: {e}",
                    provider.tag,
                    provider.path.display()
                ),
            )
        })?;
        for rule in &mut provider_rules {
            rule.source = provider.tag.clone();
        }
        all.extend(provider_rules);
    }

    let expand_geosite = |code: &str| -> std::io::Result<Vec<ParsedRule>> {
        Ok(matchers_to_rules(load_geosite_matchers(
            node_tag, rule_sets, code,
        )?))
    };
    let expand_geoip = |code: &str| -> std::io::Result<Vec<ParsedRule>> {
        Ok(matchers_to_rules(load_geoip_matchers(
            node_tag, rule_sets, code,
        )?))
    };
    CompiledRules::compile(all, expand_geosite, expand_geoip)
}

/// Wraps expanded matchers as placeholder rules; `CompiledRules::compile`
/// overwrites their outbound with the referencing rule's.
fn matchers_to_rules(matchers: Vec<ConnectMatcher>) -> Vec<ParsedRule> {
    matchers
        .into_iter()
        .map(|matcher| ParsedRule {
            line: 0,
            source: String::new(),
            matcher: Some(matcher),
            external: None,
            outbound: String::new(),
        })
        .collect()
}

/// Loads a rule provider file and parses it. Errors carry the path.
pub fn load_provider_file(path: &Path) -> std::io::Result<Vec<ParsedRule>> {
    let content = std::fs::read_to_string(path)?;
    let lines: Vec<String> = content.lines().map(str::to_string).collect();
    parse_crs_lines(&lines, &path.display().to_string()).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{}: {e}", path.display()),
        )
    })
}

/// Checks provider files: existence and parseability (used by `validate`).
pub fn check_provider_files(providers: &[RuleProviderConfig]) -> std::io::Result<()> {
    for provider in providers {
        load_provider_file(&provider.path).map_err(|e| {
            std::io::Error::new(e.kind(), format!("rule provider `{}`: {e}", provider.tag))
        })?;
    }
    Ok(())
}

/// Returns the loaded provider tags, or `None` when a file could not be read
/// (mtime-based reload treats unreadable files as a transient error).
pub fn provider_mtimes(providers: &[RuleProviderConfig]) -> std::io::Result<HashMap<String, u64>> {
    let mut mtimes = HashMap::new();
    for provider in providers {
        let modified = std::fs::metadata(&provider.path)?.modified()?;
        mtimes.insert(
            provider.tag.clone(),
            modified
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "rule provider `{}` has invalid file mtime: {e}",
                            provider.tag
                        ),
                    )
                })?
                .as_secs(),
        );
    }
    Ok(mtimes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_provider(content: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "shoes-rule-provider-{}-{}.txt",
            std::process::id(),
            content.len()
        ));
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        path
    }

    fn temp_rule_sets(geosite_files: &[(&str, &str)]) -> RouteRuleSetsConfig {
        let mut rule_sets = RouteRuleSetsConfig {
            geosite: HashMap::new(),
            geoip: HashMap::new(),
        };
        for (code, content) in geosite_files {
            let path = temp_provider(content);
            rule_sets.geosite.insert(code.to_string(), path);
        }
        rule_sets
    }

    #[test]
    fn compiles_config_lines_with_providers() {
        let provider_path = temp_provider("DOMAIN-SUFFIX,provider.com,prov_out\n");
        let providers = vec![RuleProviderConfig {
            tag: "prov-a".to_string(),
            path: provider_path.clone(),
            reload_interval_secs: 0,
        }];
        let rule_sets = RouteRuleSetsConfig {
            geosite: HashMap::new(),
            geoip: HashMap::new(),
        };
        let config_lines = vec!["DOMAIN-SUFFIX,config.com,cfg_out".to_string()];
        let rules = compile_route_rules("node-a", &config_lines, &providers, &rule_sets).unwrap();
        assert_eq!(rules.match_domain("www.config.com"), Some("cfg_out"));
        assert_eq!(rules.match_domain("www.provider.com"), Some("prov_out"));
        assert_eq!(rules.match_domain("www.other.com"), None);
        let _ = std::fs::remove_file(&provider_path);
    }

    #[test]
    fn expands_geosite_references() {
        let geosite_path =
            temp_provider("# netflix domains\ndomain:netflix.com\nfull:netflix.tv\nkeyword:nflx\n");
        let mut rule_sets = RouteRuleSetsConfig {
            geosite: HashMap::new(),
            geoip: HashMap::new(),
        };
        rule_sets
            .geosite
            .insert("netflix".to_string(), geosite_path);
        let config_lines = vec![
            "GEOSITE,netflix,out".to_string(),
            "MATCH,direct".to_string(),
        ];
        let rules = compile_route_rules("node-a", &config_lines, &[], &rule_sets).unwrap();
        assert_eq!(rules.match_domain("www.netflix.com"), Some("out"));
        assert_eq!(rules.match_domain("netflix.tv"), Some("out"));
        assert_eq!(rules.match_domain("nflxcdn.example.org"), Some("out"));
        assert_eq!(rules.match_catch_all(), Some("direct"));
    }

    #[test]
    fn missing_geosite_reference_fails() {
        let rule_sets = RouteRuleSetsConfig {
            geosite: HashMap::new(),
            geoip: HashMap::new(),
        };
        let config_lines = vec!["GEOSITE,missing,out".to_string()];
        let error = compile_route_rules("node-a", &config_lines, &[], &rule_sets).unwrap_err();
        assert!(error.to_string().contains("geosite:missing"), "{error}");
    }

    #[test]
    fn provider_file_missing_fails_check() {
        let providers = vec![RuleProviderConfig {
            tag: "prov-a".to_string(),
            path: Path::new("/nonexistent/shoes-rule-provider.txt").to_path_buf(),
            reload_interval_secs: 0,
        }];
        assert!(check_provider_files(&providers).is_err());
    }

    #[test]
    fn provider_error_line_number_is_reported() {
        let provider_path = temp_provider("DOMAIN-SUFFIX,ok.com,out\nUNKNOWN,type,out\n");
        let providers = vec![RuleProviderConfig {
            tag: "prov-a".to_string(),
            path: provider_path.clone(),
            reload_interval_secs: 0,
        }];
        let rule_sets = RouteRuleSetsConfig {
            geosite: HashMap::new(),
            geoip: HashMap::new(),
        };
        let error = compile_route_rules("node-a", &[], &providers, &rule_sets).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("prov-a"), "{message}");
        assert!(message.contains(":2:"), "{message}");
        let _ = std::fs::remove_file(&provider_path);
    }

    #[test]
    fn provider_mtimes_reports_seconds() {
        let provider_path = temp_provider("MATCH,direct\n");
        let providers = vec![RuleProviderConfig {
            tag: "prov-a".to_string(),
            path: provider_path.clone(),
            reload_interval_secs: 0,
        }];
        let mtimes = provider_mtimes(&providers).unwrap();
        assert!(mtimes.contains_key("prov-a"));
        let _ = std::fs::remove_file(&provider_path);
    }

    #[test]
    fn geoip_reference_sets_ip_rules() {
        let geoip_path = temp_provider("223.0.0.0/8\n2001:db8::/32\n");
        let mut rule_sets = RouteRuleSetsConfig {
            geosite: HashMap::new(),
            geoip: HashMap::new(),
        };
        rule_sets.geoip.insert("CN".to_string(), geoip_path);
        let config_lines = vec!["GEOIP,CN,out".to_string()];
        let rules = compile_route_rules("node-a", &config_lines, &[], &rule_sets).unwrap();
        assert!(rules.has_ip_rules());
        assert_eq!(
            rules.match_ip("223.5.5.5".parse().unwrap(), 443),
            Some("out")
        );
        assert_eq!(rules.match_ip("8.8.8.8".parse().unwrap(), 443), None);
    }
}
