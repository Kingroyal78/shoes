use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Deserializer};

use crate::address::NetLocation;
use crate::config::{
    ClientConfig, ClientProxyConfig, DEFAULT_REALITY_SHORT_ID, ShadowsocksConfig, TlsClientConfig,
    Transport, WebsocketClientConfig, WebsocketPingType,
};
use crate::option_util::{NoneOrOne, NoneOrSome};

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
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub default_out: Option<String>,
    #[serde(default)]
    pub route_rules: Vec<String>,
    #[serde(default)]
    pub rule_providers: Vec<RuleProviderConfig>,
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
pub struct RuleProviderConfig {
    pub tag: String,
    pub path: PathBuf,
    #[serde(default)]
    pub reload_interval_secs: u64,
}

impl Default for RuleProviderConfig {
    fn default() -> Self {
        Self {
            tag: String::new(),
            path: PathBuf::new(),
            reload_interval_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OutboundConfig {
    pub tag: String,
    #[serde(default)]
    pub chain: Option<Vec<String>>,
    #[serde(flatten)]
    pub spec: OutboundSpec,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum OutboundSpec {
    Direct,
    Proxy(ProxyOutboundSpec),
}

impl<'de> Deserialize<'de> for OutboundSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mapping = serde_yaml::Mapping::deserialize(deserializer)?;
        if mapping.is_empty() {
            return Ok(OutboundSpec::Direct);
        }
        let proxy =
            serde_yaml::from_value::<ProxyOutboundSpec>(serde_yaml::Value::Mapping(mapping))
                .map_err(serde::de::Error::custom)?;
        Ok(OutboundSpec::Proxy(proxy))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyOutboundSpec {
    pub r#type: String,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub cipher: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default = "default_outbound_udp")]
    pub udp: bool,
    #[serde(default)]
    pub tls: Option<OutboundTlsConfig>,
    #[serde(default)]
    pub reality: Option<OutboundRealityConfig>,
    #[serde(default)]
    pub transport: Option<OutboundTransportConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundTlsConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default)]
    pub cert_file: Option<PathBuf>,
    #[serde(default)]
    pub alpn: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundRealityConfig {
    pub public_key: String,
    #[serde(default)]
    pub short_id: Option<String>,
    #[serde(default)]
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundTransportConfig {
    #[serde(rename = "type")]
    pub transport_type: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyKind {
    Direct,
    Http,
    Socks5,
    Shadowsocks,
    Snell,
    Vless,
    Trojan,
    Vmess,
    Anytls,
    Naiveproxy,
    ShadowTls,
    Websocket,
}

impl ProxyKind {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "direct" => Some(Self::Direct),
            "http" => Some(Self::Http),
            "socks" | "socks5" => Some(Self::Socks5),
            "shadowsocks" | "ss" => Some(Self::Shadowsocks),
            "snell" => Some(Self::Snell),
            "vless" => Some(Self::Vless),
            "trojan" => Some(Self::Trojan),
            "vmess" => Some(Self::Vmess),
            "anytls" => Some(Self::Anytls),
            "naiveproxy" | "naive" => Some(Self::Naiveproxy),
            "shadowtls" => Some(Self::ShadowTls),
            "websocket" | "ws" => Some(Self::Websocket),
            _ => None,
        }
    }

    fn implies_tls(self) -> bool {
        matches!(self, Self::Trojan | Self::Anytls | Self::Naiveproxy)
    }
}

fn default_outbound_udp() -> bool {
    true
}

fn direct_client_config() -> ClientConfig {
    ClientConfig {
        bind_interface: NoneOrOne::None,
        address: NetLocation::UNSPECIFIED,
        protocol: ClientProxyConfig::Direct,
        transport: Transport::default(),
        tcp_settings: None,
        quic_settings: None,
    }
}

fn missing_outbound_field(tag: &str, field: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("outbound `{tag}` requires {field}"),
    )
}

impl OutboundConfig {
    pub fn to_client_config(&self) -> std::io::Result<ClientConfig> {
        if self.chain.is_some() {
            return invalid(format!(
                "outbound `{}` is a chain outbound; chains are assembled by the runtime via ClientChainHop, not converted to a single ClientConfig",
                self.tag
            ));
        }
        let spec = match &self.spec {
            OutboundSpec::Direct => return Ok(direct_client_config()),
            OutboundSpec::Proxy(spec) => spec,
        };
        if ProxyKind::parse(&spec.r#type) == Some(ProxyKind::Direct) {
            return Ok(direct_client_config());
        }
        let server = spec
            .server
            .as_deref()
            .ok_or_else(|| missing_outbound_field(&self.tag, "server"))?;
        let port = spec
            .port
            .ok_or_else(|| missing_outbound_field(&self.tag, "port"))?;
        let address = NetLocation::from_str(&format!("{server}:{port}"), Some(port))?;
        Ok(ClientConfig {
            bind_interface: NoneOrOne::None,
            address,
            protocol: self.to_client_proxy_config()?,
            transport: Transport::default(),
            tcp_settings: None,
            quic_settings: None,
        })
    }

    fn to_client_proxy_config(&self) -> std::io::Result<ClientProxyConfig> {
        let spec = match &self.spec {
            OutboundSpec::Direct => return Ok(ClientProxyConfig::Direct),
            OutboundSpec::Proxy(spec) => spec,
        };
        let kind = ProxyKind::parse(&spec.r#type).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("outbound `{}`: unknown type `{}`", self.tag, spec.r#type),
            )
        })?;
        if kind == ProxyKind::Websocket {
            return invalid(format!(
                "outbound `{}`: type `{}` is a transport; use a proxy type with `transport: {{type: ws}}`",
                self.tag, spec.r#type
            ));
        }
        let inner = match kind {
            ProxyKind::Direct => ClientProxyConfig::Direct,
            ProxyKind::Http => ClientProxyConfig::Http {
                username: spec.username.clone(),
                password: spec.password.clone(),
                resolve_hostname: false,
            },
            ProxyKind::Socks5 => ClientProxyConfig::Socks {
                username: spec.username.clone(),
                password: spec.password.clone(),
            },
            ProxyKind::Shadowsocks => ClientProxyConfig::Shadowsocks {
                config: self.shadowsocks_config(spec)?,
                udp_enabled: spec.udp,
            },
            ProxyKind::Snell => ClientProxyConfig::Snell {
                config: self.shadowsocks_config(spec)?,
                udp_enabled: spec.udp,
            },
            ProxyKind::Vless => ClientProxyConfig::Vless {
                user_id: spec
                    .user_id
                    .clone()
                    .ok_or_else(|| missing_outbound_field(&self.tag, "user_id"))?,
                udp_enabled: spec.udp,
                h2mux: None,
            },
            ProxyKind::Trojan => ClientProxyConfig::Trojan {
                password: spec
                    .password
                    .clone()
                    .ok_or_else(|| missing_outbound_field(&self.tag, "password"))?,
                shadowsocks: None,
                h2mux: None,
            },
            ProxyKind::Vmess => ClientProxyConfig::Vmess {
                cipher: spec
                    .cipher
                    .clone()
                    .ok_or_else(|| missing_outbound_field(&self.tag, "cipher"))?,
                user_id: spec
                    .user_id
                    .clone()
                    .ok_or_else(|| missing_outbound_field(&self.tag, "user_id"))?,
                udp_enabled: spec.udp,
                h2mux: None,
            },
            ProxyKind::Anytls => ClientProxyConfig::Anytls {
                password: spec
                    .password
                    .clone()
                    .ok_or_else(|| missing_outbound_field(&self.tag, "password"))?,
                udp_enabled: spec.udp,
                padding_scheme: None,
            },
            ProxyKind::Naiveproxy => ClientProxyConfig::Naiveproxy {
                username: spec
                    .username
                    .clone()
                    .ok_or_else(|| missing_outbound_field(&self.tag, "username"))?,
                password: spec
                    .password
                    .clone()
                    .ok_or_else(|| missing_outbound_field(&self.tag, "password"))?,
                padding: true,
            },
            ProxyKind::ShadowTls => ClientProxyConfig::ShadowTls {
                password: spec
                    .password
                    .clone()
                    .ok_or_else(|| missing_outbound_field(&self.tag, "password"))?,
                sni_hostname: spec.tls.as_ref().and_then(|tls| tls.sni.clone()),
                protocol: Box::new(ClientProxyConfig::Shadowsocks {
                    config: self.shadowsocks_config(spec)?,
                    udp_enabled: spec.udp,
                }),
            },
            ProxyKind::Websocket => unreachable!("type ws is rejected by validate"),
        };
        let protocol = if let Some(reality) = &spec.reality {
            ClientProxyConfig::Reality {
                public_key: reality.public_key.clone(),
                short_id: reality
                    .short_id
                    .clone()
                    .unwrap_or_else(|| DEFAULT_REALITY_SHORT_ID.to_string()),
                sni_hostname: reality.server_name.clone(),
                cipher_suites: NoneOrSome::Unspecified,
                vision: false,
                protocol: Box::new(inner),
            }
        } else if kind != ProxyKind::ShadowTls
            && spec
                .tls
                .as_ref()
                .and_then(|tls| tls.enabled)
                .unwrap_or_else(|| kind.implies_tls())
        {
            let tls = spec.tls.as_ref();
            let cert = match tls.and_then(|tls| tls.cert_file.as_ref()) {
                Some(cert_file) => Some(std::fs::read_to_string(cert_file).map_err(|e| {
                    std::io::Error::new(
                        e.kind(),
                        format!(
                            "outbound `{}` tls.cert_file {} is not readable: {e}",
                            self.tag,
                            cert_file.display()
                        ),
                    )
                })?),
                None => None,
            };
            let (verify, sni, alpn) = match tls {
                Some(tls) => (!tls.allow_insecure, tls.sni.clone(), tls.alpn.clone()),
                None => (true, None, Vec::new()),
            };
            ClientProxyConfig::Tls(TlsClientConfig {
                verify,
                server_fingerprints: NoneOrSome::Unspecified,
                sni_hostname: match sni {
                    Some(sni) => NoneOrOne::One(sni),
                    None => NoneOrOne::None,
                },
                alpn_protocols: if alpn.is_empty() {
                    NoneOrSome::Unspecified
                } else {
                    NoneOrSome::Some(alpn)
                },
                tls_buffer_size: None,
                protocol: Box::new(inner),
                key: None,
                cert,
                vision: false,
            })
        } else {
            inner
        };
        Ok(match &spec.transport {
            Some(transport) => ClientProxyConfig::Websocket(WebsocketClientConfig {
                matching_path: transport.path.clone(),
                matching_headers: transport
                    .host
                    .clone()
                    .map(|host| HashMap::from([("Host".to_string(), host)])),
                ping_type: WebsocketPingType::default(),
                protocol: Box::new(protocol),
            }),
            None => protocol,
        })
    }

    fn shadowsocks_config(&self, spec: &ProxyOutboundSpec) -> std::io::Result<ShadowsocksConfig> {
        ShadowsocksConfig::from_fields(
            spec.cipher
                .as_deref()
                .ok_or_else(|| missing_outbound_field(&self.tag, "cipher"))?,
            spec.password
                .as_deref()
                .ok_or_else(|| missing_outbound_field(&self.tag, "password"))?,
        )
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

        validate_outbounds(&self.outbounds, &self.default_out).await?;
        validate_route_rules(&self.route_rules)?;
        validate_rule_providers(&self.rule_providers)?;

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

async fn validate_outbounds(
    outbounds: &[OutboundConfig],
    default_out: &Option<String>,
) -> std::io::Result<()> {
    let mut tags: HashSet<&str> = HashSet::new();
    let mut chain_map: HashMap<&str, &[String]> = HashMap::new();
    for outbound in outbounds {
        if outbound.tag.trim().is_empty() {
            return invalid("outbounds[].tag must not be empty");
        }
        if !tags.insert(outbound.tag.as_str()) {
            return invalid(format!("duplicate outbound tag `{}`", outbound.tag));
        }
        if let Some(chain) = &outbound.chain {
            if chain.is_empty() {
                return invalid(format!(
                    "outbounds.{}: chain must contain at least one outbound tag",
                    outbound.tag
                ));
            }
            chain_map.insert(outbound.tag.as_str(), chain.as_slice());
        }
    }
    let mut state: HashMap<&str, u8> = HashMap::new();
    for outbound in outbounds {
        validate_chain_dfs(&outbound.tag, &chain_map, &tags, &mut state)?;
    }
    if let Some(default_tag) = default_out {
        if default_tag.trim().is_empty() {
            return invalid("default_out must not be empty");
        }
        if !tags.contains(default_tag.as_str()) {
            return invalid(format!(
                "default_out `{default_tag}` is not a configured outbound tag"
            ));
        }
    }
    for outbound in outbounds {
        if outbound.chain.is_some() {
            continue;
        }
        validate_outbound_spec(outbound).await?;
    }
    Ok(())
}

fn validate_chain_dfs<'a>(
    tag: &'a str,
    chain_map: &HashMap<&'a str, &'a [String]>,
    tags: &HashSet<&str>,
    state: &mut HashMap<&'a str, u8>,
) -> std::io::Result<()> {
    match state.get(tag).copied() {
        Some(1) => return invalid(format!("outbounds.{tag}.chain contains a cycle")),
        Some(2) => return Ok(()),
        _ => {}
    }
    state.insert(tag, 1);
    if let Some(chain) = chain_map.get(tag).copied() {
        for hop in chain {
            if !tags.contains(hop.as_str()) {
                return invalid(format!(
                    "outbounds.{tag}.chain references unknown outbound `{hop}`"
                ));
            }
            validate_chain_dfs(hop, chain_map, tags, state)?;
        }
    }
    state.insert(tag, 2);
    Ok(())
}

async fn validate_outbound_spec(outbound: &OutboundConfig) -> std::io::Result<()> {
    let OutboundSpec::Proxy(spec) = &outbound.spec else {
        return Ok(());
    };
    let prefix = format!("outbounds.{}", outbound.tag);
    let kind = ProxyKind::parse(&spec.r#type).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{prefix}: unknown type `{}`", spec.r#type),
        )
    })?;
    match kind {
        ProxyKind::Direct => {
            if spec.server.is_some()
                || spec.port.is_some()
                || spec.user_id.is_some()
                || spec.password.is_some()
                || spec.cipher.is_some()
                || spec.username.is_some()
                || spec.tls.is_some()
                || spec.reality.is_some()
                || spec.transport.is_some()
            {
                return invalid(format!(
                    "{prefix}: type `direct` must not set server, port, credentials, tls, reality, or transport"
                ));
            }
            return Ok(());
        }
        ProxyKind::Websocket => {
            return invalid(format!(
                "{prefix}: type `{}` is a transport; use a proxy type with `transport: {{type: ws}}`",
                spec.r#type
            ));
        }
        _ => {}
    }
    validate_required_server_port(&prefix, &spec.r#type, spec)?;
    match kind {
        ProxyKind::Shadowsocks | ProxyKind::Snell => {
            require_outbound_field(&prefix, &spec.r#type, spec.cipher.as_deref(), "cipher")?;
            require_outbound_field(&prefix, &spec.r#type, spec.password.as_deref(), "password")?;
        }
        ProxyKind::Vless => {
            require_outbound_field(&prefix, &spec.r#type, spec.user_id.as_deref(), "user_id")?;
        }
        ProxyKind::Trojan => {
            require_outbound_field(&prefix, &spec.r#type, spec.password.as_deref(), "password")?;
        }
        ProxyKind::Vmess => {
            require_outbound_field(&prefix, &spec.r#type, spec.cipher.as_deref(), "cipher")?;
            require_outbound_field(&prefix, &spec.r#type, spec.user_id.as_deref(), "user_id")?;
        }
        ProxyKind::Anytls => {
            require_outbound_field(&prefix, &spec.r#type, spec.password.as_deref(), "password")?;
        }
        ProxyKind::Naiveproxy => {
            require_outbound_field(&prefix, &spec.r#type, spec.username.as_deref(), "username")?;
            require_outbound_field(&prefix, &spec.r#type, spec.password.as_deref(), "password")?;
        }
        ProxyKind::ShadowTls => {
            require_outbound_field(&prefix, &spec.r#type, spec.password.as_deref(), "password")?;
            require_outbound_field(&prefix, &spec.r#type, spec.cipher.as_deref(), "cipher")?;
        }
        ProxyKind::Http | ProxyKind::Socks5 | ProxyKind::Direct | ProxyKind::Websocket => {}
    }
    if kind == ProxyKind::Snell
        && spec
            .cipher
            .as_deref()
            .is_some_and(|cipher| cipher.starts_with("2022-blake3-"))
    {
        return invalid(format!(
            "{prefix}: type snell does not support 2022-blake3 ciphers"
        ));
    }
    if let Some(transport) = &spec.transport {
        match transport
            .transport_type
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "ws" | "websocket" => {}
            other => {
                return invalid(format!(
                    "{prefix}: transport type `{other}` is not supported yet (only ws)"
                ));
            }
        }
    }
    if let Some(reality) = &spec.reality {
        if kind != ProxyKind::Vless {
            return invalid(format!(
                "{prefix}: reality is only supported for vless outbounds"
            ));
        }
        if spec.transport.is_some() {
            return invalid(format!(
                "{prefix}: reality with transport is not supported yet"
            ));
        }
        if spec.tls.is_some() {
            return invalid(format!(
                "{prefix}: reality provides its own TLS layer; remove tls"
            ));
        }
        if reality.public_key.trim().is_empty() {
            return invalid(format!("{prefix}: reality requires public_key"));
        }
        crate::reality::decode_public_key(&reality.public_key).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{prefix}: reality public_key is invalid: {e}"),
            )
        })?;
        if reality
            .server_name
            .as_deref()
            .is_none_or(|s| s.trim().is_empty())
        {
            return invalid(format!("{prefix}: reality requires server_name"));
        }
        if let Some(short_id) = &reality.short_id {
            crate::reality::decode_short_id(short_id).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{prefix}: reality short_id is invalid: {e}"),
                )
            })?;
        }
    }
    if let Some(tls) = &spec.tls {
        if kind == ProxyKind::ShadowTls {
            if tls.enabled == Some(false) {
                return invalid(format!(
                    "{prefix}: type shadowtls cannot disable tls; shadowtls is its own TLS layer"
                ));
            }
            if tls.allow_insecure {
                return invalid(format!(
                    "{prefix}: type shadowtls cannot set tls.allow_insecure; shadowtls is its own TLS layer"
                ));
            }
            if tls.cert_file.is_some() {
                return invalid(format!(
                    "{prefix}: type shadowtls cannot set tls.cert_file; shadowtls is its own TLS layer"
                ));
            }
            if !tls.alpn.is_empty() {
                return invalid(format!(
                    "{prefix}: type shadowtls cannot set tls.alpn; shadowtls is its own TLS layer"
                ));
            }
        }
        if let Some(cert_file) = &tls.cert_file {
            validate_file_exists(&format!("{prefix}.tls.cert_file"), cert_file).await?;
        }
    }
    Ok(())
}

fn validate_required_server_port(
    prefix: &str,
    type_str: &str,
    spec: &ProxyOutboundSpec,
) -> std::io::Result<()> {
    require_outbound_field(prefix, type_str, spec.server.as_deref(), "server")?;
    if spec.port.is_none_or(|port| port == 0) {
        return invalid(format!("{prefix}: type {type_str} requires port"));
    }
    Ok(())
}

fn require_outbound_field(
    prefix: &str,
    type_str: &str,
    value: Option<&str>,
    field: &str,
) -> std::io::Result<()> {
    if value.is_some_and(|v| !v.trim().is_empty()) {
        Ok(())
    } else {
        invalid(format!("{prefix}: type {type_str} requires {field}"))
    }
}

fn validate_route_rules(route_rules: &[String]) -> std::io::Result<()> {
    for (index, line) in route_rules.iter().enumerate() {
        crate::v2board::outbound::rules::parse_crs_line(line, index + 1, "config").map_err(
            |e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("route_rules[{index}]: {e}"),
                )
            },
        )?;
    }
    Ok(())
}

fn validate_rule_providers(providers: &[RuleProviderConfig]) -> std::io::Result<()> {
    let mut tags = HashSet::new();
    for provider in providers {
        if provider.tag.trim().is_empty() {
            return invalid("rule_providers[].tag must not be empty");
        }
        if !tags.insert(provider.tag.as_str()) {
            return invalid(format!("duplicate rule provider tag `{}`", provider.tag));
        }
        if provider.path.as_os_str().is_empty() {
            return invalid(format!(
                "rule_providers.{}: path must not be empty",
                provider.tag
            ));
        }
    }
    if providers.is_empty() {
        return Ok(());
    }
    crate::v2board::outbound::compiler::check_provider_files(providers)
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

    fn base_v2board() -> String {
        r#"
v2board:
  api_host: "http://127.0.0.1"
  api_key: "token"
  nodes:
    - tag: "node-1"
      node_id: 1
      node_type: "vmess"
"#
        .to_string()
    }

    #[test]
    fn outbound_flat_vless_tls_ws_assembles_nested_client_config() {
        let outbound: OutboundConfig = serde_yaml::from_str(
            r#"
tag: unlock
type: vless
server: "203.0.113.10"
port: 443
user_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
tls:
  enabled: true
  sni: "unlock.example.com"
  alpn: ["h2", "http/1.1"]
transport:
  type: ws
  path: "/unlock"
  host: "unlock.example.com"
"#,
        )
        .unwrap();

        assert!(outbound.chain.is_none());
        let client = outbound.to_client_config().unwrap();
        assert_eq!(client.address.to_string(), "203.0.113.10:443");
        let ClientProxyConfig::Websocket(ws) = client.protocol else {
            panic!("expected websocket wrapper");
        };
        assert_eq!(ws.matching_path.as_deref(), Some("/unlock"));
        assert_eq!(
            ws.matching_headers.as_ref().unwrap().get("Host").unwrap(),
            "unlock.example.com"
        );
        let ClientProxyConfig::Tls(tls) = *ws.protocol else {
            panic!("expected tls wrapper");
        };
        assert!(tls.verify);
        assert_eq!(
            tls.sni_hostname.into_option().as_deref(),
            Some("unlock.example.com")
        );
        assert_eq!(tls.alpn_protocols.into_vec(), vec!["h2", "http/1.1"]);
        assert!(tls.cert.is_none());
        let ClientProxyConfig::Vless {
            user_id,
            udp_enabled,
            h2mux,
        } = *tls.protocol
        else {
            panic!("expected vless inner protocol");
        };
        assert_eq!(user_id, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        assert!(udp_enabled);
        assert!(h2mux.is_none());
    }

    #[test]
    fn outbound_direct_maps_to_direct_protocol() {
        let bare: OutboundConfig = serde_yaml::from_str("tag: direct").unwrap();
        assert!(matches!(bare.spec, OutboundSpec::Direct));
        let client = bare.to_client_config().unwrap();
        assert!(client.address.is_unspecified());
        assert!(client.protocol.is_direct());

        let typed: OutboundConfig = serde_yaml::from_str("tag: direct\ntype: direct").unwrap();
        assert!(matches!(typed.spec, OutboundSpec::Proxy(_)));
        let client = typed.to_client_config().unwrap();
        assert!(client.protocol.is_direct());
    }

    #[test]
    fn outbound_chain_deserializes_but_has_no_single_client_config() {
        let outbound: OutboundConfig =
            serde_yaml::from_str("tag: via-socks\nchain: [\"socks-hop\", \"unlock\"]").unwrap();
        assert_eq!(
            outbound.chain.as_deref(),
            Some(["socks-hop".to_string(), "unlock".to_string()].as_slice())
        );
        let err = outbound.to_client_config().unwrap_err();
        assert!(err.to_string().contains("chain outbound"));
    }

    #[test]
    fn outbound_rejects_unknown_fields() {
        let err = serde_yaml::from_str::<OutboundConfig>(
            r#"
tag: x
type: vless
server: "h"
port: 443
user_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
bogus: 1
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `bogus`"));

        let err = serde_yaml::from_str::<OutboundConfig>(
            r#"
tag: x
type: vless
server: "h"
port: 443
user_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
tls:
  enabled: true
  bogus: 1
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `bogus`"));
    }

    #[test]
    fn outbound_udp_defaults_true() {
        let outbound: OutboundConfig = serde_yaml::from_str(
            r#"
tag: s
type: ss
server: "h"
port: 443
cipher: aes-128-gcm
password: pw
"#,
        )
        .unwrap();
        let OutboundSpec::Proxy(spec) = outbound.spec else {
            panic!("expected proxy spec");
        };
        assert!(spec.udp);
    }

    #[test]
    fn outbound_trojan_implies_tls_wrapper_without_explicit_tls() {
        let outbound: OutboundConfig = serde_yaml::from_str(
            r#"
tag: t
type: trojan
server: "h"
port: 443
password: pw
"#,
        )
        .unwrap();
        let client = outbound.to_client_config().unwrap();
        let ClientProxyConfig::Tls(tls) = client.protocol else {
            panic!("expected tls wrapper");
        };
        assert!(tls.verify);
        assert!(matches!(*tls.protocol, ClientProxyConfig::Trojan { .. }));
    }

    #[test]
    fn outbound_vless_without_tls_stays_plain() {
        let outbound: OutboundConfig = serde_yaml::from_str(
            r#"
tag: v
type: vless
server: "h"
port: 443
user_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
"#,
        )
        .unwrap();
        let client = outbound.to_client_config().unwrap();
        assert!(matches!(client.protocol, ClientProxyConfig::Vless { .. }));
    }

    #[test]
    fn outbound_reality_wraps_vless() {
        let outbound: OutboundConfig = serde_yaml::from_str(
            r#"
tag: r
type: vless
server: "h"
port: 443
user_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
reality:
  public_key: "c2hvZXMtcmVhbGl0eS1wdWJsaWMta2V5ISEhISE="
  server_name: "www.microsoft.com"
"#,
        )
        .unwrap();
        let client = outbound.to_client_config().unwrap();
        let ClientProxyConfig::Reality {
            public_key,
            short_id,
            sni_hostname,
            protocol,
            ..
        } = client.protocol
        else {
            panic!("expected reality wrapper");
        };
        assert_eq!(public_key, "c2hvZXMtcmVhbGl0eS1wdWJsaWMta2V5ISEhISE=");
        assert_eq!(short_id, DEFAULT_REALITY_SHORT_ID);
        assert_eq!(sni_hostname.as_deref(), Some("www.microsoft.com"));
        assert!(matches!(*protocol, ClientProxyConfig::Vless { .. }));
    }

    #[test]
    fn outbound_shadowtls_wraps_shadowsocks_with_shared_password() {
        let outbound: OutboundConfig = serde_yaml::from_str(
            r#"
tag: st
type: shadowtls
server: "h"
port: 443
password: "secret"
cipher: aes-128-gcm
tls:
  sni: "shadow.example.com"
"#,
        )
        .unwrap();
        let client = outbound.to_client_config().unwrap();
        let ClientProxyConfig::ShadowTls {
            password,
            sni_hostname,
            protocol,
        } = client.protocol
        else {
            panic!("expected shadowtls");
        };
        assert_eq!(password, "secret");
        assert_eq!(sni_hostname.as_deref(), Some("shadow.example.com"));
        assert!(matches!(*protocol, ClientProxyConfig::Shadowsocks { .. }));
    }

    #[test]
    fn outbound_ss_supports_2022_blake3_cipher() {
        let outbound: OutboundConfig = serde_yaml::from_str(
            r#"
tag: s
type: ss
server: "h"
port: 443
cipher: 2022-blake3-aes-128-gcm
password: "c2hvZXMtMjAyMi1rZXk="
"#,
        )
        .unwrap();
        let client = outbound.to_client_config().unwrap();
        let ClientProxyConfig::Shadowsocks {
            config,
            udp_enabled,
        } = client.protocol
        else {
            panic!("expected shadowsocks");
        };
        assert!(matches!(config, ShadowsocksConfig::Aead2022 { .. }));
        assert!(udp_enabled);
    }

    #[tokio::test]
    async fn validate_rejects_duplicate_outbound_tags() {
        let config: AppConfig = serde_yaml::from_str(&format!(
            "{}outbounds:\n  - tag: dup\n    type: vless\n    server: \"h\"\n    port: 443\n    user_id: \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\"\n  - tag: dup\n    type: direct\n",
            base_v2board()
        ))
        .unwrap();
        let err = config.validate().await.unwrap_err();
        assert!(err.to_string().contains("duplicate outbound tag `dup`"));
    }

    #[tokio::test]
    async fn validate_rejects_chain_cycles() {
        let config: AppConfig = serde_yaml::from_str(&format!(
            "{}outbounds:\n  - tag: a\n    chain: [\"b\"]\n  - tag: b\n    chain: [\"a\"]\n",
            base_v2board()
        ))
        .unwrap();
        let err = config.validate().await.unwrap_err();
        assert!(err.to_string().contains("contains a cycle"));
    }

    #[tokio::test]
    async fn validate_rejects_chain_with_unknown_hop() {
        let config: AppConfig = serde_yaml::from_str(&format!(
            "{}outbounds:\n  - tag: a\n    chain: [\"missing\"]\n",
            base_v2board()
        ))
        .unwrap();
        let err = config.validate().await.unwrap_err();
        assert!(err.to_string().contains("unknown outbound `missing`"));
    }

    #[tokio::test]
    async fn validate_rejects_empty_chain() {
        let config: AppConfig = serde_yaml::from_str(&format!(
            "{}outbounds:\n  - tag: a\n    chain: []\n",
            base_v2board()
        ))
        .unwrap();
        let err = config.validate().await.unwrap_err();
        assert!(err.to_string().contains("at least one outbound tag"));
    }

    #[tokio::test]
    async fn validate_rejects_missing_vless_user_id() {
        let config: AppConfig = serde_yaml::from_str(&format!(
            "{}outbounds:\n  - tag: unlock\n    type: vless\n    server: \"h\"\n    port: 443\n",
            base_v2board()
        ))
        .unwrap();
        let err = config.validate().await.unwrap_err();
        assert!(err.to_string().contains("type vless requires user_id"));
    }

    #[tokio::test]
    async fn validate_rejects_unknown_outbound_type() {
        let config: AppConfig = serde_yaml::from_str(&format!(
            "{}outbounds:\n  - tag: x\n    type: tuic\n    server: \"h\"\n    port: 443\n",
            base_v2board()
        ))
        .unwrap();
        let err = config.validate().await.unwrap_err();
        assert!(err.to_string().contains("unknown type `tuic`"));
    }

    #[tokio::test]
    async fn validate_rejects_unreadable_outbound_tls_cert_file() {
        let config: AppConfig = serde_yaml::from_str(&format!(
            "{}outbounds:\n  - tag: v\n    type: vless\n    server: \"h\"\n    port: 443\n    user_id: \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\"\n    tls:\n      enabled: true\n      cert_file: \"/nonexistent/shoes-test.pem\"\n",
            base_v2board()
        ))
        .unwrap();
        let err = config.validate().await.unwrap_err();
        assert!(err.to_string().contains("is not readable"));
    }

    #[tokio::test]
    async fn validate_accepts_readable_outbound_tls_cert_file() {
        let cert_path =
            std::env::temp_dir().join(format!("shoes-outbound-test-{}.pem", std::process::id()));
        std::fs::write(
            &cert_path,
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let config: AppConfig = serde_yaml::from_str(&format!(
            "{}outbounds:\n  - tag: v\n    type: vless\n    server: \"h\"\n    port: 443\n    user_id: \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\"\n    tls:\n      enabled: true\n      cert_file: \"{}\"\n",
            base_v2board(),
            cert_path.display()
        ))
        .unwrap();
        config.validate().await.unwrap();
        std::fs::remove_file(&cert_path).unwrap();
    }

    #[tokio::test]
    async fn validate_rejects_default_out_not_configured() {
        let config: AppConfig =
            serde_yaml::from_str(&format!("{}default_out: \"missing\"\n", base_v2board())).unwrap();
        let err = config.validate().await.unwrap_err();
        assert!(err.to_string().contains("default_out `missing`"));
    }

    #[tokio::test]
    async fn validate_rejects_reality_for_non_vless() {
        let config: AppConfig = serde_yaml::from_str(&format!(
            "{}outbounds:\n  - tag: t\n    type: trojan\n    server: \"h\"\n    port: 443\n    password: pw\n    reality:\n      public_key: \"c2hvZXMtcmVhbGl0eS1wdWJsaWMta2V5ISEhISE=\"\n      server_name: \"www.microsoft.com\"\n",
            base_v2board()
        ))
        .unwrap();
        let err = config.validate().await.unwrap_err();
        assert!(err.to_string().contains("only supported for vless"));
    }

    #[tokio::test]
    async fn validate_rejects_transport_type_not_supported() {
        let config: AppConfig = serde_yaml::from_str(&format!(
            "{}outbounds:\n  - tag: v\n    type: vless\n    server: \"h\"\n    port: 443\n    user_id: \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\"\n    transport:\n      type: grpc\n      path: \"/x\"\n",
            base_v2board()
        ))
        .unwrap();
        let err = config.validate().await.unwrap_err();
        assert!(err.to_string().contains("not supported yet"));
    }

    #[tokio::test]
    async fn validate_rejects_snell_2022_cipher() {
        let config: AppConfig = serde_yaml::from_str(&format!(
            "{}outbounds:\n  - tag: sn\n    type: snell\n    server: \"h\"\n    port: 443\n    cipher: 2022-blake3-aes-128-gcm\n    password: \"c2hvZXMtMjAyMi1rZXk=\"\n",
            base_v2board()
        ))
        .unwrap();
        let err = config.validate().await.unwrap_err();
        assert!(
            err.to_string()
                .contains("snell does not support 2022-blake3")
        );
    }

    #[tokio::test]
    async fn validate_rejects_shadowtls_tls_cert_file() {
        let config: AppConfig = serde_yaml::from_str(&format!(
            "{}outbounds:\n  - tag: st\n    type: shadowtls\n    server: \"h\"\n    port: 443\n    password: pw\n    cipher: aes-128-gcm\n    tls:\n      cert_file: \"/etc/ssl/certs/ca-certificates.crt\"\n",
            base_v2board()
        ))
        .unwrap();
        let err = config.validate().await.unwrap_err();
        assert!(
            err.to_string()
                .contains("shadowtls cannot set tls.cert_file")
        );
    }

    #[tokio::test]
    async fn validate_accepts_full_outbound_block() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
v2board:
  api_host: "http://127.0.0.1"
  api_key: "token"
  nodes:
    - tag: "node-1"
      node_id: 1
      node_type: "vmess"
outbounds:
  - tag: "unlock"
    type: "vless"
    server: "203.0.113.10"
    port: 443
    user_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    udp: true
    tls:
      enabled: true
      sni: "unlock.example.com"
      alpn: ["h2", "http/1.1"]
    transport:
      type: "ws"
      path: "/unlock"
      host: "unlock.example.com"
  - tag: "direct"
    type: "direct"
  - tag: "socks-hop"
    type: "socks5"
    server: "127.0.0.1"
    port: 1080
  - tag: "via-socks"
    chain: ["socks-hop", "unlock"]
default_out: "direct"
"#,
        )
        .unwrap();
        config.validate().await.unwrap();
        assert_eq!(config.default_out.as_deref(), Some("direct"));
        assert_eq!(config.outbounds.len(), 4);
    }

    #[tokio::test]
    async fn route_rules_and_rule_providers_default_to_empty() {
        let config: AppConfig = serde_yaml::from_str(&base_v2board()).unwrap();
        assert!(config.route_rules.is_empty());
        assert!(config.rule_providers.is_empty());
        assert!(config.outbounds.is_empty());
        assert!(config.default_out.is_none());
        config.validate().await.unwrap();
    }

    #[tokio::test]
    async fn validate_rejects_empty_rule_provider_tag() {
        let config: AppConfig = serde_yaml::from_str(&format!(
            "{}rule_providers:\n  - tag: \"\"\n    path: \"/tmp/shoes-test.yaml\"\n",
            base_v2board()
        ))
        .unwrap();
        let err = config.validate().await.unwrap_err();
        assert!(
            err.to_string()
                .contains("rule_providers[].tag must not be empty")
        );
    }

    #[tokio::test]
    async fn validate_rejects_duplicate_rule_provider_tags() {
        let config: AppConfig = serde_yaml::from_str(&format!(
            "{}rule_providers:\n  - tag: netflix\n    path: \"/tmp/a.yaml\"\n  - tag: netflix\n    path: \"/tmp/b.yaml\"\n",
            base_v2board()
        ))
        .unwrap();
        let err = config.validate().await.unwrap_err();
        assert!(
            err.to_string()
                .contains("duplicate rule provider tag `netflix`")
        );
    }

    #[tokio::test]
    async fn validate_rejects_direct_with_fields() {
        let config: AppConfig = serde_yaml::from_str(&format!(
            "{}outbounds:\n  - tag: d\n    type: direct\n    server: \"h\"\n    port: 443\n",
            base_v2board()
        ))
        .unwrap();
        let err = config.validate().await.unwrap_err();
        assert!(err.to_string().contains("type `direct` must not set"));
    }
}
