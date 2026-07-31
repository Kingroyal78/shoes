use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Deserializer};

use crate::address::NetLocation;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub v2board: V2BoardConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2BoardConfig {
    pub api_host: String,
    pub api_key: String,
    #[serde(default = "default_api_timeout_secs")]
    pub api_timeout_secs: u64,
    #[serde(default = "default_error_body_limit_bytes")]
    pub error_body_limit_bytes: usize,
    #[serde(default = "default_user_list_body_limit_bytes")]
    pub user_list_body_limit_bytes: usize,
    #[serde(default)]
    pub route_rule_sets: RouteRuleSetsConfig,
    pub nodes: Vec<V2BoardNodeConfig>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RouteRuleSetsConfig {
    #[serde(default)]
    pub geosite: HashMap<String, PathBuf>,
    #[serde(default)]
    pub geoip: HashMap<String, PathBuf>,
}

impl RouteRuleSetsConfig {
    pub fn geosite_path(&self, code: &str) -> Option<&PathBuf> {
        lookup_rule_set_path(&self.geosite, code)
    }

    pub fn geoip_path(&self, code: &str) -> Option<&PathBuf> {
        lookup_rule_set_path(&self.geoip, code)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2BoardNodeConfig {
    pub tag: String,
    pub node_id: u64,
    pub node_type: NodeType,
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub api_host: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub pull_interval_secs: Option<u64>,
    #[serde(default)]
    pub push_interval_secs: Option<u64>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Local TLS-decoded fallback used for Trojan probe resistance.
    ///
    /// V2Board's current UniProxy Trojan response does not expose a fallback
    /// destination, so this remains an explicit node-local setting.
    #[serde(default)]
    pub trojan_fallback: Option<NetLocation>,
    /// Node-local static HTTP/3 response used to disguise unauthenticated
    /// Hysteria2 connections.
    #[serde(default)]
    pub hysteria2_masquerade: Option<Hysteria2MasqueradeConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2MasqueradeConfig {
    #[serde(default = "default_hysteria2_masquerade_status_code")]
    pub status_code: u16,
    #[serde(default = "default_hysteria2_masquerade_content_type")]
    pub content_type: String,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Shadowsocks,
    Vmess,
    Vless,
    Trojan,
    Anytls,
    Tuic,
    Hysteria,
    Naiveproxy,
    V2Node,
}

impl NodeType {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "shadowsocks" | "ss" => Some(NodeType::Shadowsocks),
            "vmess" | "v2ray" => Some(NodeType::Vmess),
            "vless" => Some(NodeType::Vless),
            "trojan" => Some(NodeType::Trojan),
            "anytls" => Some(NodeType::Anytls),
            "tuic" => Some(NodeType::Tuic),
            "hysteria" | "hysteria2" => Some(NodeType::Hysteria),
            "naive" | "naiveproxy" | "naive_proxy" | "naive-proxy" => Some(NodeType::Naiveproxy),
            "v2node" => Some(NodeType::V2Node),
            _ => None,
        }
    }

    pub fn as_uniproxy(self) -> &'static str {
        match self {
            NodeType::Shadowsocks => "shadowsocks",
            NodeType::Vmess => "vmess",
            NodeType::Vless => "vless",
            NodeType::Trojan => "trojan",
            NodeType::Anytls => "anytls",
            NodeType::Tuic => "tuic",
            NodeType::Hysteria => "hysteria",
            NodeType::Naiveproxy => "naiveproxy",
            NodeType::V2Node => "v2node",
        }
    }

    pub fn uses_v2_config_api(self) -> bool {
        self == NodeType::V2Node
    }
}

impl<'de> Deserialize<'de> for NodeType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unsupported node_type `{}`; expected shadowsocks/ss, vmess/v2ray, vless, trojan, anytls, tuic, hysteria/hysteria2, naive/naiveproxy, or v2node",
                value
            ))
        })
    }
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_uniproxy())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_pull_interval_secs")]
    pub pull_interval_secs: u64,
    #[serde(default = "default_push_interval_secs")]
    pub push_interval_secs: u64,
    #[serde(default)]
    pub node_report_min_traffic: u64,
    #[serde(default)]
    pub device_online_min_traffic: u64,
    #[serde(default = "default_max_legacy_shadowsocks_users")]
    pub max_legacy_shadowsocks_users: usize,
    #[serde(default)]
    pub tcp_fast_open: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            pull_interval_secs: default_pull_interval_secs(),
            push_interval_secs: default_push_interval_secs(),
            node_report_min_traffic: 0,
            device_online_min_traffic: 0,
            max_legacy_shadowsocks_users: default_max_legacy_shadowsocks_users(),
            tcp_fast_open: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub file: Option<String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file: None,
        }
    }
}

impl AppConfig {
    pub async fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        let raw = tokio::fs::read_to_string(path).await.map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("failed to read config {}: {e}", path.display()),
            )
        })?;
        serde_yaml::from_str(&raw).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("failed to parse config {}: {e}", path.display()),
            )
        })
    }

    pub async fn validate(&self) -> std::io::Result<()> {
        if self.v2board.api_host.trim().is_empty() {
            return invalid("v2board.api_host must not be empty");
        }
        if self.v2board.api_key.trim().is_empty() {
            return invalid("v2board.api_key must not be empty");
        }
        if self.v2board.nodes.is_empty() {
            return invalid("v2board.nodes must contain at least one node");
        }
        validate_route_rule_sets(&self.v2board.route_rule_sets).await?;

        let mut tags = HashSet::new();
        for node in &self.v2board.nodes {
            if node.tag.trim().is_empty() {
                return invalid("v2board.nodes[].tag must not be empty");
            }
            if !tags.insert(node.tag.as_str()) {
                return invalid(format!("duplicate node tag `{}`", node.tag));
            }
            if matches!(node.listen.as_deref(), Some("")) {
                return invalid(format!("node `{}` listen must not be empty", node.tag));
            }
            if let Some(fallback) = &node.trojan_fallback {
                if !matches!(node.node_type, NodeType::Trojan | NodeType::V2Node) {
                    return invalid(format!(
                        "node `{}` trojan_fallback is only valid for trojan or v2node nodes",
                        node.tag
                    ));
                }
                if fallback.port() == 0 {
                    return invalid(format!(
                        "node `{}` trojan_fallback must use a non-zero port",
                        node.tag
                    ));
                }
            }
            if let Some(masquerade) = &node.hysteria2_masquerade {
                if !matches!(node.node_type, NodeType::Hysteria | NodeType::V2Node) {
                    return invalid(format!(
                        "node `{}` hysteria2_masquerade is only valid for hysteria or v2node nodes",
                        node.tag
                    ));
                }
                validate_hysteria2_masquerade(&node.tag, masquerade)?;
            }
        }

        if self.runtime.pull_interval_secs == 0 {
            return invalid("runtime.pull_interval_secs must be greater than 0");
        }
        if self.runtime.push_interval_secs == 0 {
            return invalid("runtime.push_interval_secs must be greater than 0");
        }
        if self.runtime.max_legacy_shadowsocks_users == 0 {
            return invalid("runtime.max_legacy_shadowsocks_users must be greater than 0");
        }
        if self.runtime.tcp_fast_open {
            return invalid(
                "runtime.tcp_fast_open is not supported by the V2Board runtime; set it to false",
            );
        }

        if let Some(tls) = &self.tls {
            validate_file_exists("tls.cert_file", &tls.cert_file).await?;
            validate_file_exists("tls.key_file", &tls.key_file).await?;
        }
        for node in &self.v2board.nodes {
            if let Some(tls) = &node.tls {
                validate_file_exists("nodes[].tls.cert_file", &tls.cert_file).await?;
                validate_file_exists("nodes[].tls.key_file", &tls.key_file).await?;
            }
        }

        Ok(())
    }

    pub fn effective_api_host<'a>(&'a self, node: &'a V2BoardNodeConfig) -> &'a str {
        node.api_host
            .as_deref()
            .unwrap_or(self.v2board.api_host.as_str())
    }

    pub fn effective_api_key<'a>(&'a self, node: &'a V2BoardNodeConfig) -> &'a str {
        node.api_key
            .as_deref()
            .unwrap_or(self.v2board.api_key.as_str())
    }

    pub fn effective_tls<'a>(&'a self, node: &'a V2BoardNodeConfig) -> Option<&'a TlsConfig> {
        node.tls.as_ref().or(self.tls.as_ref())
    }

    pub fn api_timeout(&self) -> Duration {
        Duration::from_secs(self.v2board.api_timeout_secs)
    }
}

fn lookup_rule_set_path<'a>(
    paths: &'a HashMap<String, PathBuf>,
    code: &str,
) -> Option<&'a PathBuf> {
    let wanted = normalize_rule_set_code(code);
    paths
        .iter()
        .find(|(label, _)| normalize_rule_set_code(label) == wanted)
        .map(|(_, path)| path)
}

fn normalize_rule_set_code(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

async fn validate_route_rule_sets(rule_sets: &RouteRuleSetsConfig) -> std::io::Result<()> {
    for (label, path) in &rule_sets.geosite {
        validate_rule_set_entry("v2board.route_rule_sets.geosite", label, path).await?;
    }
    for (label, path) in &rule_sets.geoip {
        validate_rule_set_entry("v2board.route_rule_sets.geoip", label, path).await?;
    }
    Ok(())
}

async fn validate_rule_set_entry(prefix: &str, label: &str, path: &Path) -> std::io::Result<()> {
    if label.trim().is_empty() {
        return invalid(format!("{prefix} contains an empty label"));
    }
    validate_file_exists(&format!("{prefix}.{label}"), path).await
}

async fn validate_file_exists(label: &str, path: &Path) -> std::io::Result<()> {
    tokio::fs::metadata(path).await.map(|_| ()).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("{label} {} is not readable: {e}", path.display()),
        )
    })
}

fn invalid<T>(msg: impl Into<String>) -> std::io::Result<T> {
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        msg.into(),
    ))
}

fn default_api_timeout_secs() -> u64 {
    30
}

fn default_error_body_limit_bytes() -> usize {
    4096
}

fn default_user_list_body_limit_bytes() -> usize {
    10 * 1024 * 1024
}

fn default_hysteria2_masquerade_status_code() -> u16 {
    404
}

fn default_hysteria2_masquerade_content_type() -> String {
    "text/html; charset=utf-8".to_string()
}

const HYSTERIA2_MASQUERADE_MAX_BODY_BYTES: usize = 64 * 1024;
const HYSTERIA2_MASQUERADE_MAX_CONTENT_TYPE_BYTES: usize = 256;

fn validate_hysteria2_masquerade(
    node_tag: &str,
    masquerade: &Hysteria2MasqueradeConfig,
) -> std::io::Result<()> {
    let status = http::StatusCode::from_u16(masquerade.status_code).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "node `{node_tag}` hysteria2_masquerade status_code {} is invalid: {e}",
                masquerade.status_code
            ),
        )
    })?;
    if status.is_informational() {
        return invalid(format!(
            "node `{node_tag}` hysteria2_masquerade status_code must be a final HTTP status"
        ));
    }
    if matches!(
        status,
        http::StatusCode::NO_CONTENT
            | http::StatusCode::RESET_CONTENT
            | http::StatusCode::NOT_MODIFIED
    ) {
        return invalid(format!(
            "node `{node_tag}` hysteria2_masquerade status_code must permit a response body"
        ));
    }
    if masquerade.content_type.is_empty()
        || masquerade.content_type.len() > HYSTERIA2_MASQUERADE_MAX_CONTENT_TYPE_BYTES
        || masquerade
            .content_type
            .parse::<http::HeaderValue>()
            .is_err()
    {
        return invalid(format!(
            "node `{node_tag}` hysteria2_masquerade content_type must be a valid non-empty HTTP header value of at most {HYSTERIA2_MASQUERADE_MAX_CONTENT_TYPE_BYTES} bytes"
        ));
    }
    if masquerade.body.len() > HYSTERIA2_MASQUERADE_MAX_BODY_BYTES {
        return invalid(format!(
            "node `{node_tag}` hysteria2_masquerade body exceeds {HYSTERIA2_MASQUERADE_MAX_BODY_BYTES} bytes"
        ));
    }
    Ok(())
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/shoes")
}

fn default_pull_interval_secs() -> u64 {
    60
}

fn default_push_interval_secs() -> u64 {
    60
}

fn default_max_legacy_shadowsocks_users() -> usize {
    10_000
}

fn default_log_level() -> String {
    "info".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    struct NodeTypeFixture {
        node_type: NodeType,
    }

    #[test]
    fn node_type_accepts_v2board_aliases_and_normalizes_uniproxy_value() {
        let cases = [
            ("shadowsocks", NodeType::Shadowsocks, "shadowsocks"),
            ("ss", NodeType::Shadowsocks, "shadowsocks"),
            ("vmess", NodeType::Vmess, "vmess"),
            ("v2ray", NodeType::Vmess, "vmess"),
            ("vless", NodeType::Vless, "vless"),
            ("trojan", NodeType::Trojan, "trojan"),
            ("anytls", NodeType::Anytls, "anytls"),
            ("tuic", NodeType::Tuic, "tuic"),
            ("hysteria", NodeType::Hysteria, "hysteria"),
            ("hysteria2", NodeType::Hysteria, "hysteria"),
            ("naive", NodeType::Naiveproxy, "naiveproxy"),
            ("naiveproxy", NodeType::Naiveproxy, "naiveproxy"),
            ("naive_proxy", NodeType::Naiveproxy, "naiveproxy"),
            ("naive-proxy", NodeType::Naiveproxy, "naiveproxy"),
            ("v2node", NodeType::V2Node, "v2node"),
            (" VMESS ", NodeType::Vmess, "vmess"),
        ];

        for (raw, expected, uniproxy) in cases {
            let fixture: NodeTypeFixture =
                serde_yaml::from_str(&format!("node_type: {raw:?}")).unwrap();
            assert_eq!(fixture.node_type, expected);
            assert_eq!(fixture.node_type.as_uniproxy(), uniproxy);
        }
    }

    #[test]
    fn node_type_rejects_unsupported_v2board_models_until_implemented() {
        let err = serde_yaml::from_str::<NodeTypeFixture>("node_type: mieru").unwrap_err();
        assert!(err.to_string().contains("unsupported node_type `mieru`"));
    }

    #[tokio::test]
    async fn trojan_fallback_is_an_explicit_node_local_destination() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
v2board:
  api_host: "http://127.0.0.1"
  api_key: "token"
  nodes:
    - tag: "trojan-1"
      node_id: 1
      node_type: "trojan"
      trojan_fallback: "127.0.0.1:8443"
"#,
        )
        .unwrap();

        config.validate().await.unwrap();
        assert_eq!(
            config.v2board.nodes[0]
                .trojan_fallback
                .as_ref()
                .unwrap()
                .to_string(),
            "127.0.0.1:8443"
        );
    }

    #[tokio::test]
    async fn trojan_fallback_is_rejected_for_unrelated_node_types() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
v2board:
  api_host: "http://127.0.0.1"
  api_key: "token"
  nodes:
    - tag: "vmess-1"
      node_id: 1
      node_type: "vmess"
      trojan_fallback: "127.0.0.1:8443"
"#,
        )
        .unwrap();

        let error = config.validate().await.unwrap_err();
        assert!(error.to_string().contains("only valid for trojan"));
    }

    #[tokio::test]
    async fn hysteria2_masquerade_is_an_explicit_bounded_node_local_response() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
v2board:
  api_host: "http://127.0.0.1"
  api_key: "token"
  nodes:
    - tag: "hy2-1"
      node_id: 1
      node_type: "hysteria2"
      hysteria2_masquerade:
        status_code: 200
        content_type: "text/plain"
        body: "not a proxy"
"#,
        )
        .unwrap();

        config.validate().await.unwrap();
        assert_eq!(
            config.v2board.nodes[0]
                .hysteria2_masquerade
                .as_ref()
                .unwrap(),
            &Hysteria2MasqueradeConfig {
                status_code: 200,
                content_type: "text/plain".to_string(),
                body: "not a proxy".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn hysteria2_masquerade_rejects_oversized_body() {
        let mut config: AppConfig = serde_yaml::from_str(
            r#"
v2board:
  api_host: "http://127.0.0.1"
  api_key: "token"
  nodes:
    - tag: "hy2-1"
      node_id: 1
      node_type: "hysteria"
      hysteria2_masquerade:
        body: ""
"#,
        )
        .unwrap();
        config.v2board.nodes[0]
            .hysteria2_masquerade
            .as_mut()
            .unwrap()
            .body = "x".repeat(HYSTERIA2_MASQUERADE_MAX_BODY_BYTES + 1);

        let error = config.validate().await.unwrap_err();

        assert!(error.to_string().contains("body exceeds"));
    }

    #[tokio::test]
    async fn hysteria2_masquerade_is_rejected_for_unrelated_node_types() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
v2board:
  api_host: "http://127.0.0.1"
  api_key: "token"
  nodes:
    - tag: "vmess-1"
      node_id: 1
      node_type: "vmess"
      hysteria2_masquerade:
        body: "not found"
"#,
        )
        .unwrap();

        let error = config.validate().await.unwrap_err();

        assert!(
            error
                .to_string()
                .contains("only valid for hysteria or v2node")
        );
    }

    #[tokio::test]
    async fn validate_rejects_tcp_fast_open_until_runtime_wires_it() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
v2board:
  api_host: "http://127.0.0.1"
  api_key: "token"
  nodes:
    - tag: "vmess-1"
      node_id: 1
      node_type: "vmess"
runtime:
  tcp_fast_open: true
"#,
        )
        .unwrap();

        let err = config.validate().await.unwrap_err();
        assert!(
            err.to_string()
                .contains("runtime.tcp_fast_open is not supported")
        );
    }
}
