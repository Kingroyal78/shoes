use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use serde_json::Value;

use crate::backend_config::{
    AppConfig, Hysteria2MasqueradeConfig, NodeType, RouteRuleSetsConfig, V2BoardNodeConfig,
};

use super::types::{ServerConfig, UserInfo};
use super::xhttp::{XHttpConfig, XHttpConfigParts, XHttpDataPlacement, XHttpMode, XHttpPlacement};

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeNodeSpec {
    pub tag: String,
    pub node_id: u64,
    pub config_node_type: NodeType,
    pub node_type: NodeType,
    pub bind: RuntimeBind,
    pub accept_proxy_protocol: bool,
    pub protocol: RuntimeProtocol,
    pub transport: RuntimeTransport,
    pub security: RuntimeSecurity,
    pub users: Vec<RuntimeUser>,
    pub base: RuntimeBaseConfig,
    pub routes: Vec<RuntimeRoute>,
    pub route_rule_sets: RouteRuleSetsConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBind {
    pub listen: String,
    pub port: u16,
}

impl RuntimeBind {
    pub fn address(&self) -> String {
        format!("{}:{}", self.listen, self.port)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeProtocol {
    Shadowsocks {
        cipher: String,
        server_key: Option<String>,
        obfs: ShadowsocksObfs,
        encryption_settings: Option<Value>,
    },
    Vmess {
        security: String,
    },
    Vless {
        encryption: String,
        flow: Option<String>,
    },
    Trojan {
        server_name: Option<String>,
        fallback: Option<crate::address::NetLocation>,
    },
    Anytls {
        padding_scheme: Vec<String>,
    },
    Tuic {
        zero_rtt_handshake: bool,
        congestion_control: Option<String>,
        udp_relay_mode: Option<String>,
        disable_sni: bool,
    },
    Hysteria2 {
        up_mbps: u64,
        down_mbps: u64,
        ignore_client_bandwidth: bool,
        obfs: Option<String>,
        obfs_password: Option<String>,
        masquerade: Option<Hysteria2MasqueradeConfig>,
    },
    Naiveproxy {
        quic_congestion_control: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ShadowsocksObfs {
    Plain,
    Plugin {
        name: String,
        settings: Option<Value>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeTransport {
    Tcp {
        header: Option<TcpHeader>,
    },
    Http {
        hosts: Vec<String>,
        paths: Vec<String>,
        method: Option<String>,
        response_headers: HashMap<String, String>,
    },
    Websocket {
        path: String,
        headers: HashMap<String, String>,
        max_early_data: Option<u32>,
        early_data_header_name: Option<String>,
    },
    Grpc {
        service_name: Option<String>,
        authority: Option<String>,
        multi_mode: bool,
    },
    HttpUpgrade {
        path: String,
        host: Option<String>,
        headers: HashMap<String, String>,
    },
    XHttp(XHttpConfig),
    Quic,
    TcpAndQuic,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TcpHeader {
    Http {
        hosts: Vec<String>,
        paths: Vec<String>,
        method: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeSecurity {
    None,
    Tls(RuntimeTls),
    Reality(RuntimeReality),
}

impl RuntimeSecurity {
    pub fn label(&self) -> &'static str {
        match self {
            RuntimeSecurity::None => "none",
            RuntimeSecurity::Tls(_) => "tls",
            RuntimeSecurity::Reality(_) => "reality",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeTls {
    pub server_name: Option<String>,
    pub server_names: Vec<String>,
    pub alpn: Vec<String>,
    pub allow_insecure: bool,
    pub certificate: Option<RuntimeTlsCertificate>,
    pub cert_mode: Option<String>,
    pub ech: Option<String>,
    pub ech_server_name: Option<String>,
    pub ech_key: Option<String>,
    pub ech_config: Option<String>,
    pub raw_settings: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTlsCertificate {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeReality {
    pub server_name: Option<String>,
    pub server_names: Vec<String>,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub short_ids: Vec<String>,
    pub dest: Option<String>,
    pub server_port: Option<String>,
    pub max_time_diff_millis: Option<u64>,
    pub xver: u64,
    pub cert_mode: Option<String>,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub ech: Option<String>,
    pub ech_server_name: Option<String>,
    pub ech_key: Option<String>,
    pub ech_config: Option<String>,
    pub fingerprint: Option<String>,
    pub raw_settings: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeUser {
    pub uid: u64,
    pub credential: String,
    pub secret: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub user_key: String,
    pub policy: UserPolicy,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPolicy {
    pub speed_limit_mbps: Option<u64>,
    pub device_limit: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBaseConfig {
    pub pull_interval_secs: u64,
    pub push_interval_secs: u64,
    pub node_report_min_traffic: u64,
    pub device_online_min_traffic: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeRoute {
    pub raw: Value,
}

pub fn normalize_node(
    app_config: &AppConfig,
    node: &V2BoardNodeConfig,
    server: &ServerConfig,
    users: &[UserInfo],
) -> std::io::Result<RuntimeNodeSpec> {
    let node_type = runtime_node_type(node, server)?;
    validate_local_protocol_overrides(node, node_type, server)?;
    let users = normalize_users(node, users)?;

    let protocol = normalize_protocol(node, node_type, server)?;
    let transport = normalize_transport(node, node_type, server)?;
    let security = normalize_security(app_config, node, node_type, &transport, server)?;

    Ok(RuntimeNodeSpec {
        tag: node.tag.clone(),
        node_id: node.node_id,
        config_node_type: node.node_type,
        node_type,
        bind: RuntimeBind {
            listen: node
                .listen
                .clone()
                .or_else(|| non_empty(server.listen_ip.as_deref()))
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            port: server.server_port,
        },
        accept_proxy_protocol: normalize_accept_proxy_protocol(server),
        protocol,
        transport,
        security,
        users,
        base: RuntimeBaseConfig {
            pull_interval_secs: server.base_config.pull_interval,
            push_interval_secs: server.base_config.push_interval,
            node_report_min_traffic: server.base_config.node_report_min_traffic,
            device_online_min_traffic: server.base_config.device_online_min_traffic,
        },
        routes: server
            .routes
            .iter()
            .cloned()
            .map(|raw| RuntimeRoute { raw })
            .collect(),
        route_rule_sets: app_config.v2board.route_rule_sets.clone(),
    })
}

fn validate_local_protocol_overrides(
    node: &V2BoardNodeConfig,
    node_type: NodeType,
    server: &ServerConfig,
) -> std::io::Result<()> {
    if node.hysteria2_masquerade.is_some() && node_type != NodeType::Hysteria {
        return invalid(format!(
            "node `{}` sets hysteria2_masquerade but resolves to protocol `{node_type}`",
            node.tag
        ));
    }

    let Some(fallback) = node.trojan_fallback.as_ref() else {
        return Ok(());
    };
    if node_type != NodeType::Trojan {
        return invalid(format!(
            "node `{}` sets trojan_fallback but resolves to protocol `{node_type}`",
            node.tag
        ));
    }

    // A hostname or public address can resolve back to this listener. Requiring
    // a different port makes the loop check independent of DNS and bind style.
    if fallback.port() == server.server_port {
        return invalid(format!(
            "node `{}` trojan_fallback `{fallback}` must use a different port from its listener",
            node.tag
        ));
    }
    Ok(())
}

fn runtime_node_type(node: &V2BoardNodeConfig, server: &ServerConfig) -> std::io::Result<NodeType> {
    if node.node_type != NodeType::V2Node {
        return Ok(node.node_type);
    }
    let protocol = server.protocol.as_deref().ok_or_else(|| {
        invalid_error(format!(
            "node `{}` v2node config missing protocol",
            node.tag
        ))
    })?;
    let protocol_type = NodeType::parse(protocol).ok_or_else(|| {
        invalid_error(format!(
            "node `{}` v2node protocol `{protocol}` is not supported by this runtime",
            node.tag
        ))
    })?;
    if protocol_type == NodeType::V2Node {
        return invalid(format!(
            "node `{}` v2node protocol cannot be v2node",
            node.tag
        ));
    }
    Ok(protocol_type)
}

fn normalize_protocol(
    node: &V2BoardNodeConfig,
    node_type: NodeType,
    server: &ServerConfig,
) -> std::io::Result<RuntimeProtocol> {
    match node_type {
        NodeType::Shadowsocks => {
            let cipher = server
                .cipher
                .clone()
                .ok_or_else(|| invalid_error("shadowsocks server config missing cipher"))?;
            if server
                .encryption_settings
                .as_ref()
                .is_some_and(|value| !v2board_value_is_empty(value))
            {
                return invalid(
                    "shadowsocks encryption_settings is not supported; remove the V2Node encryption settings for Shadowsocks nodes",
                );
            }
            let obfs = match server.obfs.as_deref().unwrap_or("").trim() {
                "" | "none" | "plain" => ShadowsocksObfs::Plain,
                name => ShadowsocksObfs::Plugin {
                    name: name.to_string(),
                    settings: server.obfs_settings.clone(),
                },
            };
            Ok(RuntimeProtocol::Shadowsocks {
                cipher,
                server_key: server.server_key.clone(),
                obfs,
                encryption_settings: None,
            })
        }
        NodeType::Vmess => {
            reject_non_empty_encryption_settings("vmess", server)?;
            Ok(RuntimeProtocol::Vmess {
                security: vmess_security(server),
            })
        }
        NodeType::Vless => {
            reject_non_empty_encryption_settings("vless", server)?;
            Ok(RuntimeProtocol::Vless {
                encryption: server
                    .encryption
                    .clone()
                    .unwrap_or_else(|| "none".to_string()),
                flow: non_empty(server.flow.as_deref()),
            })
        }
        NodeType::Trojan => {
            reject_non_empty_encryption_settings("trojan", server)?;
            Ok(RuntimeProtocol::Trojan {
                server_name: non_empty(server.server_name.as_deref()),
                fallback: node.trojan_fallback.clone(),
            })
        }
        NodeType::Anytls => {
            reject_non_empty_encryption_settings("anytls", server)?;
            Ok(RuntimeProtocol::Anytls {
                padding_scheme: anytls_padding_scheme(server.padding_scheme.as_ref())?,
            })
        }
        NodeType::Tuic => {
            reject_non_empty_encryption_settings("tuic", server)?;
            Ok(RuntimeProtocol::Tuic {
                zero_rtt_handshake: bool_value(server.zero_rtt_handshake.as_ref()).unwrap_or(false),
                congestion_control: non_empty(server.congestion_control.as_deref()),
                udp_relay_mode: non_empty(server.udp_relay_mode.as_deref()),
                disable_sni: bool_value(server.disable_sni.as_ref()).unwrap_or(false),
            })
        }
        NodeType::Hysteria => {
            reject_non_empty_encryption_settings("hysteria2", server)?;
            if !is_hysteria2_config(server) {
                return invalid(
                    "hysteria v1 is not supported; configure V2Board Hysteria version=2 or V2Node protocol=hysteria2",
                );
            }
            let up_mbps = server.up_mbps.unwrap_or(0);
            let down_mbps = server.down_mbps.unwrap_or(0);
            Ok(RuntimeProtocol::Hysteria2 {
                up_mbps,
                down_mbps,
                ignore_client_bandwidth: server
                    .ignore_client_bandwidth
                    .unwrap_or(up_mbps == 0 && down_mbps == 0),
                obfs: non_empty(server.obfs.as_deref()),
                obfs_password: non_empty(server.obfs_password.as_deref()),
                masquerade: node.hysteria2_masquerade.clone(),
            })
        }
        NodeType::Naiveproxy => {
            reject_non_empty_encryption_settings("naiveproxy", server)?;
            if let Some(protocol) = non_empty(server.protocol.as_deref())
                && !matches!(
                    protocol.trim().to_ascii_lowercase().as_str(),
                    "naive" | "naiveproxy" | "naive_proxy" | "naive-proxy"
                )
            {
                return invalid(format!(
                    "naiveproxy server config protocol `{protocol}` is not supported"
                ));
            }
            let quic_congestion_control = non_empty(server.quic_congestion_control.as_deref())
                .or_else(|| non_empty(server.congestion_control.as_deref()));
            Ok(RuntimeProtocol::Naiveproxy {
                quic_congestion_control,
            })
        }
        NodeType::V2Node => invalid("v2node must be resolved to an inbound protocol"),
    }
}

fn reject_non_empty_encryption_settings(
    protocol: &str,
    server: &ServerConfig,
) -> std::io::Result<()> {
    if server
        .encryption_settings
        .as_ref()
        .is_some_and(|value| !v2board_value_is_empty(value))
    {
        return invalid(format!("{protocol} encryption_settings is not supported"));
    }
    Ok(())
}

fn is_hysteria2_config(server: &ServerConfig) -> bool {
    let protocol_is_hysteria2 = server
        .protocol
        .as_deref()
        .map(|protocol| protocol.trim().eq_ignore_ascii_case("hysteria2"))
        .unwrap_or(false);
    protocol_is_hysteria2 || server.version == Some(2)
}

fn vmess_security(server: &ServerConfig) -> String {
    string_setting(server.network_settings.as_ref(), &["security"])
        .or_else(|| server.encryption.clone())
        .or_else(|| server.cipher.clone())
        .unwrap_or_else(|| "auto".to_string())
}

fn normalize_accept_proxy_protocol(server: &ServerConfig) -> bool {
    bool_setting(
        server.network_settings.as_ref(),
        &["acceptProxyProtocol", "accept_proxy_protocol"],
    )
    .unwrap_or(false)
}

fn normalize_transport(
    node: &V2BoardNodeConfig,
    node_type: NodeType,
    server: &ServerConfig,
) -> std::io::Result<RuntimeTransport> {
    if matches!(node_type, NodeType::Tuic | NodeType::Hysteria) {
        return Ok(RuntimeTransport::Quic);
    }

    if node_type == NodeType::Naiveproxy {
        let network = server.network.as_deref().map(str::trim);
        return match network {
            Some(value) if value.eq_ignore_ascii_case("tcp") => {
                Ok(RuntimeTransport::Tcp { header: None })
            }
            None | Some("") => Ok(RuntimeTransport::TcpAndQuic),
            Some(value) if value.eq_ignore_ascii_case("udp") => Ok(RuntimeTransport::Quic),
            Some(value) => invalid(format!(
                "node `{}` naiveproxy network `{value}` is not supported",
                node.tag
            )),
        };
    }

    let network = server
        .network
        .as_deref()
        .unwrap_or("tcp")
        .trim()
        .to_ascii_lowercase();
    let settings = server.network_settings.as_ref();

    match network.as_str() {
        "" | "tcp" => Ok(RuntimeTransport::Tcp {
            header: normalize_tcp_header(settings),
        }),
        "ws" | "websocket" => {
            let (path, path_early_data) = normalize_websocket_path(
                node,
                string_setting(settings, &["path"]).unwrap_or_else(|| "/".to_string()),
            )?;
            let max_early_data = u64_setting(settings, &["maxEarlyData", "max_early_data"])
                .and_then(|v| u32::try_from(v).ok())
                .or(path_early_data)
                .or(Some(2048));
            let early_data_header_name =
                string_setting(settings, &["earlyDataHeaderName", "early_data_header_name"])
                    .or_else(|| {
                        if max_early_data.unwrap_or(0) > 0 {
                            Some("Sec-WebSocket-Protocol".to_string())
                        } else {
                            None
                        }
                    });
            Ok(RuntimeTransport::Websocket {
                path,
                headers: headers_setting(settings, &["headers"]),
                max_early_data,
                early_data_header_name,
            })
        }
        "http" => Ok(RuntimeTransport::Http {
            hosts: string_vec_setting(settings, &["host", "Host"]),
            paths: first_non_empty_string_vec_setting(settings, &["path"])
                .unwrap_or_else(|| vec!["/".to_string()]),
            method: string_setting(settings, &["method"]),
            response_headers: headers_list_setting(settings, &["headers"]),
        }),
        "grpc" => Ok(RuntimeTransport::Grpc {
            service_name: string_setting(settings, &["serviceName", "service_name"]),
            authority: string_setting(settings, &["authority", "host", "Host"]),
            multi_mode: bool_setting(settings, &["multiMode", "multi_mode"]).unwrap_or(false),
        }),
        "httpupgrade" | "http-upgrade" | "http_upgrade" => Ok(RuntimeTransport::HttpUpgrade {
            path: string_setting(settings, &["path"]).unwrap_or_else(|| "/".to_string()),
            host: string_setting(settings, &["host", "Host"]),
            headers: headers_setting(settings, &["headers"]),
        }),
        "xhttp" | "splithttp" | "split-http" | "split_http" => Ok(RuntimeTransport::XHttp(
            normalize_xhttp_transport(node, settings)?,
        )),
        _ => invalid(format!(
            "node `{}` {} network `{network}` is not supported by V2Board runtime model",
            node.tag, node_type
        )),
    }
}

fn normalize_xhttp_transport(
    node: &V2BoardNodeConfig,
    settings: Option<&Value>,
) -> std::io::Result<XHttpConfig> {
    let extra = xhttp_extra_settings(settings)?;
    let extra = extra.as_ref();
    reject_unsupported_xhttp_settings(node, settings, extra)?;

    Ok(XHttpConfig::new(XHttpConfigParts {
        host: xhttp_string_setting(settings, extra, &["host", "Host"]),
        path: xhttp_string_setting(settings, extra, &["path"]).unwrap_or_else(|| "/".to_string()),
        mode: xhttp_mode(
            node,
            xhttp_string_setting(settings, extra, &["mode"]).as_deref(),
        )?,
        no_grpc_header: xhttp_bool_setting(settings, extra, &["noGRPCHeader", "no_grpc_header"])
            .unwrap_or(false),
        no_sse_header: xhttp_bool_setting(settings, extra, &["noSSEHeader", "no_sse_header"])
            .unwrap_or(false),
        max_each_post_bytes: xhttp_usize_setting(
            settings,
            extra,
            &["scMaxEachPostBytes", "sc_max_each_post_bytes"],
        )?,
        max_buffered_posts: xhttp_usize_setting(
            settings,
            extra,
            &["scMaxBufferedPosts", "sc_max_buffered_posts"],
        )?,
        session_id_placement: xhttp_placement(
            node,
            "sessionIDPlacement",
            xhttp_string_setting(
                settings,
                extra,
                &[
                    "sessionIDPlacement",
                    "sessionIdPlacement",
                    "session_id_placement",
                ],
            )
            .as_deref(),
        )?,
        session_id_key: xhttp_string_setting(
            settings,
            extra,
            &["sessionIDKey", "sessionIdKey", "session_id_key"],
        ),
        seq_placement: xhttp_placement(
            node,
            "seqPlacement",
            xhttp_string_setting(settings, extra, &["seqPlacement", "seq_placement"]).as_deref(),
        )?,
        seq_key: xhttp_string_setting(settings, extra, &["seqKey", "seq_key"]),
        uplink_data_placement: xhttp_data_placement(
            node,
            xhttp_string_setting(
                settings,
                extra,
                &["uplinkDataPlacement", "uplink_data_placement"],
            )
            .as_deref(),
        )?,
        uplink_data_key: xhttp_string_setting(
            settings,
            extra,
            &["uplinkDataKey", "uplink_data_key"],
        ),
    }))
}

fn reject_unsupported_xhttp_settings(
    node: &V2BoardNodeConfig,
    settings: Option<&Value>,
    extra: Option<&Value>,
) -> std::io::Result<()> {
    reject_non_empty_xhttp_setting(
        node,
        settings,
        extra,
        &["downloadSettings", "download_settings"],
        "xhttp downloadSettings is not supported",
    )?;
    reject_non_empty_xhttp_setting(
        node,
        settings,
        extra,
        &["xmux", "xmuxSettings", "xmux_settings"],
        "xhttp xmux is not supported",
    )?;
    reject_non_empty_xhttp_setting(
        node,
        settings,
        extra,
        &["xPaddingBytes", "x_padding_bytes"],
        "xhttp xPaddingBytes is not supported",
    )?;
    reject_non_empty_xhttp_setting(
        node,
        settings,
        extra,
        &["xPaddingKey", "x_padding_key"],
        "xhttp xPaddingKey is not supported",
    )?;
    reject_non_empty_xhttp_setting(
        node,
        settings,
        extra,
        &["xPaddingHeader", "x_padding_header"],
        "xhttp xPaddingHeader is not supported",
    )?;
    reject_non_empty_xhttp_setting(
        node,
        settings,
        extra,
        &["xPaddingPlacement", "x_padding_placement"],
        "xhttp xPaddingPlacement is not supported",
    )?;
    reject_non_empty_xhttp_setting(
        node,
        settings,
        extra,
        &["xPaddingMethod", "x_padding_method"],
        "xhttp xPaddingMethod is not supported",
    )?;
    reject_non_empty_xhttp_setting(
        node,
        settings,
        extra,
        &["scStreamUpServerSecs", "sc_stream_up_server_secs"],
        "xhttp scStreamUpServerSecs is not supported",
    )?;
    reject_non_empty_xhttp_setting(
        node,
        settings,
        extra,
        &["serverMaxHeaderBytes", "server_max_header_bytes"],
        "xhttp serverMaxHeaderBytes is not supported",
    )?;
    reject_enabled_xhttp_setting(
        node,
        settings,
        extra,
        &["xPaddingObfsMode", "x_padding_obfs_mode"],
        "xPaddingObfsMode",
    )?;
    Ok(())
}

fn reject_non_empty_xhttp_setting(
    node: &V2BoardNodeConfig,
    settings: Option<&Value>,
    extra: Option<&Value>,
    keys: &[&str],
    message: &str,
) -> std::io::Result<()> {
    let Some(value) = xhttp_raw_setting(settings, extra, keys) else {
        return Ok(());
    };
    if v2board_value_is_empty(value) {
        return Ok(());
    }
    invalid(format!("node `{}` {message}", node.tag))
}

fn reject_enabled_xhttp_setting(
    node: &V2BoardNodeConfig,
    settings: Option<&Value>,
    extra: Option<&Value>,
    keys: &[&str],
    label: &str,
) -> std::io::Result<()> {
    let Some(value) = xhttp_raw_setting(settings, extra, keys) else {
        return Ok(());
    };
    match value {
        Value::Null => Ok(()),
        Value::Bool(false) => Ok(()),
        Value::Bool(true) => invalid(format!(
            "node `{}` xhttp {label} is not supported",
            node.tag
        )),
        Value::Number(number) if number.as_i64() == Some(0) => Ok(()),
        Value::Number(_) => invalid(format!(
            "node `{}` xhttp {label} is not supported",
            node.tag
        )),
        Value::String(text) => match text.trim().to_ascii_lowercase().as_str() {
            "" | "0" | "false" | "no" | "off" | "null" => Ok(()),
            "1" | "true" | "yes" | "on" => invalid(format!(
                "node `{}` xhttp {label} is not supported",
                node.tag
            )),
            _ => invalid(format!(
                "node `{}` xhttp {label} must be boolean when set",
                node.tag
            )),
        },
        _ => invalid(format!(
            "node `{}` xhttp {label} must be boolean when set",
            node.tag
        )),
    }
}

fn v2board_value_is_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => matches!(text.trim(), "" | "null" | "{}" | "[]"),
        Value::Array(values) => values.is_empty(),
        Value::Object(object) => object.is_empty(),
        _ => false,
    }
}

fn xhttp_extra_settings(settings: Option<&Value>) -> std::io::Result<Option<Value>> {
    let Some(object) = settings.and_then(Value::as_object) else {
        return Ok(None);
    };
    let Some(extra) = object.get("extra") else {
        return Ok(None);
    };
    match extra {
        Value::Null => Ok(None),
        Value::Object(_) => Ok(Some(extra.clone())),
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            let parsed = serde_json::from_str::<Value>(trimmed)
                .map_err(|e| invalid_error(format!("xhttp extra JSON is invalid: {e}")))?;
            match parsed {
                Value::Null => Ok(None),
                value @ Value::Object(_) => Ok(Some(value)),
                _ => invalid(format!(
                    "xhttp extra JSON `{trimmed}` must decode to an object"
                )),
            }
        }
        _ => invalid(format!(
            "xhttp extra `{extra}` must be an object or JSON string"
        )),
    }
}

fn xhttp_mode(node: &V2BoardNodeConfig, value: Option<&str>) -> std::io::Result<XHttpMode> {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("auto")
        .to_ascii_lowercase()
        .as_str()
    {
        "auto" => Ok(XHttpMode::Auto),
        "packet-up" | "packet_up" | "packetup" => Ok(XHttpMode::PacketUp),
        "stream-up" | "stream_up" | "streamup" => Ok(XHttpMode::StreamUp),
        "stream-one" | "stream_one" | "streamone" => Ok(XHttpMode::StreamOne),
        value => invalid(format!(
            "node `{}` xhttp mode `{value}` is not supported",
            node.tag
        )),
    }
}

fn xhttp_placement(
    node: &V2BoardNodeConfig,
    field: &str,
    value: Option<&str>,
) -> std::io::Result<XHttpPlacement> {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("path")
        .to_ascii_lowercase()
        .as_str()
    {
        "path" => Ok(XHttpPlacement::Path),
        "query" => Ok(XHttpPlacement::Query),
        "header" => Ok(XHttpPlacement::Header),
        "cookie" => Ok(XHttpPlacement::Cookie),
        value => invalid(format!(
            "node `{}` xhttp {field} `{value}` is not supported",
            node.tag
        )),
    }
}

fn xhttp_data_placement(
    node: &V2BoardNodeConfig,
    value: Option<&str>,
) -> std::io::Result<XHttpDataPlacement> {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("auto")
        .to_ascii_lowercase()
        .as_str()
    {
        "auto" => Ok(XHttpDataPlacement::Auto),
        "body" => Ok(XHttpDataPlacement::Body),
        "header" => Ok(XHttpDataPlacement::Header),
        "cookie" => Ok(XHttpDataPlacement::Cookie),
        value => invalid(format!(
            "node `{}` xhttp uplinkDataPlacement `{value}` is not supported",
            node.tag
        )),
    }
}

fn xhttp_string_setting(
    settings: Option<&Value>,
    extra: Option<&Value>,
    keys: &[&str],
) -> Option<String> {
    string_setting(settings, keys).or_else(|| string_setting(extra, keys))
}

fn xhttp_bool_setting(
    settings: Option<&Value>,
    extra: Option<&Value>,
    keys: &[&str],
) -> Option<bool> {
    bool_setting(settings, keys).or_else(|| bool_setting(extra, keys))
}

fn xhttp_usize_setting(
    settings: Option<&Value>,
    extra: Option<&Value>,
    keys: &[&str],
) -> std::io::Result<Option<usize>> {
    let Some(value) = xhttp_raw_setting(settings, extra, keys) else {
        return Ok(None);
    };
    value_to_usize_range_max(value)
}

fn xhttp_raw_setting<'a>(
    settings: Option<&'a Value>,
    extra: Option<&'a Value>,
    keys: &[&str],
) -> Option<&'a Value> {
    for source in [settings, extra].into_iter().flatten() {
        let Some(object) = source.as_object() else {
            continue;
        };
        for key in keys {
            if let Some(value) = object.get(*key) {
                return Some(value);
            }
        }
    }
    None
}

fn value_to_usize_range_max(value: &Value) -> std::io::Result<Option<usize>> {
    match value {
        Value::Null => Ok(None),
        Value::Number(number) => number
            .as_u64()
            .map(usize::try_from)
            .transpose()
            .map_err(|_| invalid_error(format!("xhttp numeric setting `{value}` is too large"))),
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                trimmed.parse::<usize>().map(Some).map_err(|e| {
                    invalid_error(format!("xhttp numeric setting `{text}` is invalid: {e}"))
                })
            }
        }
        Value::Object(object) => {
            let mut values = Vec::new();
            for key in ["to", "To", "max", "Max", "from", "From", "min", "Min"] {
                if let Some(value) = object.get(key)
                    && let Some(parsed) = value_to_usize_range_max(value)?
                {
                    values.push(parsed);
                }
            }
            Ok(values.into_iter().max())
        }
        _ => invalid(format!(
            "xhttp numeric setting `{value}` must be a number, string, or range object"
        )),
    }
}

fn normalize_security(
    app_config: &AppConfig,
    node: &V2BoardNodeConfig,
    node_type: NodeType,
    transport: &RuntimeTransport,
    server: &ServerConfig,
) -> std::io::Result<RuntimeSecurity> {
    let raw_mode = tls_mode(server.tls.as_ref());
    if node_type == crate::backend_config::NodeType::Naiveproxy
        && raw_mode == TlsMode::None
        && server.tls.is_some()
    {
        return invalid(format!(
            "node `{}` naiveproxy requires TLS; panel tls=0/false is not supported",
            node.tag
        ));
    }
    let mode = match raw_mode {
        TlsMode::None if node_type == crate::backend_config::NodeType::Trojan => TlsMode::Tls,
        TlsMode::None if node_type == crate::backend_config::NodeType::Anytls => TlsMode::Tls,
        TlsMode::None if node_type == crate::backend_config::NodeType::Tuic => TlsMode::Tls,
        TlsMode::None if node_type == crate::backend_config::NodeType::Hysteria => TlsMode::Tls,
        TlsMode::None if node_type == crate::backend_config::NodeType::Naiveproxy => TlsMode::Tls,
        TlsMode::Reality if node_type == crate::backend_config::NodeType::Tuic => {
            return invalid(format!(
                "node `{}` tuic requires QUIC TLS and does not support Reality",
                node.tag
            ));
        }
        TlsMode::Reality if node_type == crate::backend_config::NodeType::Hysteria => {
            return invalid(format!(
                "node `{}` hysteria2 requires QUIC TLS and does not support Reality",
                node.tag
            ));
        }
        TlsMode::Reality if node_type == crate::backend_config::NodeType::Naiveproxy => {
            return invalid(format!(
                "node `{}` naiveproxy requires TLS and does not support Reality in V2Board runtime",
                node.tag
            ));
        }
        mode => mode,
    };
    match mode {
        TlsMode::None => Ok(RuntimeSecurity::None),
        TlsMode::Tls => Ok(RuntimeSecurity::Tls(RuntimeTls {
            server_name: string_setting(
                server.tls_settings.as_ref(),
                &["server_name", "serverName", "serverName"],
            )
            .or_else(|| non_empty(server.server_name.as_deref())),
            server_names: string_vec_setting(
                server.tls_settings.as_ref(),
                &["server_names", "serverNames"],
            ),
            alpn: normalized_tls_alpn(node_type, transport, server.tls_settings.as_ref()),
            allow_insecure: bool_setting(
                server.tls_settings.as_ref(),
                &["allow_insecure", "allowInsecure"],
            )
            .unwrap_or(false),
            certificate: panel_tls_certificate(server.tls_settings.as_ref()).or_else(|| {
                app_config
                    .effective_tls(node)
                    .map(|tls| RuntimeTlsCertificate {
                        cert_file: tls.cert_file.clone(),
                        key_file: tls.key_file.clone(),
                    })
            }),
            cert_mode: string_setting(server.tls_settings.as_ref(), &["cert_mode", "certMode"]),
            ech: string_setting(server.tls_settings.as_ref(), &["ech"]),
            ech_server_name: string_setting(
                server.tls_settings.as_ref(),
                &["ech_server_name", "echServerName"],
            ),
            ech_key: string_setting(server.tls_settings.as_ref(), &["ech_key", "echKey"]),
            ech_config: string_setting(server.tls_settings.as_ref(), &["ech_config", "echConfig"]),
            raw_settings: server.tls_settings.clone(),
        })),
        TlsMode::Reality => Ok(RuntimeSecurity::Reality(RuntimeReality {
            server_name: string_setting(
                server.tls_settings.as_ref(),
                &["server_name", "serverName"],
            )
            .or_else(|| non_empty(server.server_name.as_deref())),
            server_names: string_vec_setting(
                server.tls_settings.as_ref(),
                &["server_names", "serverNames"],
            ),
            private_key: string_setting(
                server.tls_settings.as_ref(),
                &["private_key", "privateKey"],
            ),
            public_key: string_setting(server.tls_settings.as_ref(), &["public_key", "publicKey"]),
            short_ids: string_vec_setting(
                server.tls_settings.as_ref(),
                &["short_ids", "shortIds", "short_id", "shortId"],
            ),
            dest: string_setting(server.tls_settings.as_ref(), &["dest", "server", "target"]),
            server_port: string_setting(
                server.tls_settings.as_ref(),
                &["server_port", "serverPort"],
            ),
            max_time_diff_millis: reality_max_time_diff_millis(server.reality_config.as_ref())?,
            xver: u64_setting(server.tls_settings.as_ref(), &["xver", "Xver"]).unwrap_or(0),
            cert_mode: string_setting(server.tls_settings.as_ref(), &["cert_mode", "certMode"]),
            cert_file: string_setting(server.tls_settings.as_ref(), &["cert_file", "certFile"])
                .map(PathBuf::from),
            key_file: string_setting(server.tls_settings.as_ref(), &["key_file", "keyFile"])
                .map(PathBuf::from),
            ech: string_setting(server.tls_settings.as_ref(), &["ech"]),
            ech_server_name: string_setting(
                server.tls_settings.as_ref(),
                &["ech_server_name", "echServerName"],
            ),
            ech_key: string_setting(server.tls_settings.as_ref(), &["ech_key", "echKey"]),
            ech_config: string_setting(server.tls_settings.as_ref(), &["ech_config", "echConfig"]),
            fingerprint: string_setting(server.tls_settings.as_ref(), &["fingerprint"]),
            raw_settings: server.tls_settings.clone(),
        })),
    }
}

fn anytls_padding_scheme(value: Option<&Value>) -> std::io::Result<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    if let Some(array) = value.as_array() {
        let mut lines = Vec::new();
        for item in array {
            let line = item
                .as_str()
                .ok_or_else(|| invalid_error("anytls padding_scheme entries must be strings"))?
                .trim();
            if !line.is_empty() {
                lines.push(line.to_string());
            }
        }
        return Ok(lines);
    }
    if let Some(text) = value.as_str() {
        let text = text.trim();
        if text.is_empty() {
            return Ok(Vec::new());
        }
        if text.starts_with('[') {
            let parsed: Vec<String> = serde_json::from_str(text).map_err(|e| {
                invalid_error(format!("anytls padding_scheme JSON array is invalid: {e}"))
            })?;
            return Ok(parsed
                .into_iter()
                .filter(|line| !line.trim().is_empty())
                .collect());
        }
        return Ok(text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect());
    }
    invalid("anytls padding_scheme must be a string array, JSON array string, or multiline string")
}

fn normalize_users(
    node: &V2BoardNodeConfig,
    users: &[UserInfo],
) -> std::io::Result<Vec<RuntimeUser>> {
    let now = Utc::now();
    users
        .iter()
        .filter(|user| panel_user_active(user, now))
        .map(|user| {
            let credential = user.credential().ok_or_else(|| {
                invalid_error(format!(
                    "node `{}` user {} has no uuid/password/username credential",
                    node.tag, user.id
                ))
            })?;
            Ok(RuntimeUser {
                uid: user.id,
                credential: credential.to_string(),
                secret: user.secret().map(ToOwned::to_owned),
                username: non_empty(user.username.as_deref()),
                password: non_empty(user.password.as_deref()),
                user_key: user.key(),
                policy: UserPolicy {
                    speed_limit_mbps: user.speed_limit,
                    device_limit: user.device_limit,
                },
                label: user.label.clone(),
            })
        })
        .collect()
}

fn panel_user_active(user: &UserInfo, now: DateTime<Utc>) -> bool {
    if user.enabled_flag() == Some(false) {
        return false;
    }
    if let Some(expires_at) = user.expires_at_unix()
        && expires_at > 0
        && expires_at <= now.timestamp()
    {
        return false;
    }
    if expires_on_expired(user.expires_on.as_deref(), now) {
        return false;
    }
    true
}

fn expires_on_expired(value: Option<&str>, now: DateTime<Utc>) -> bool {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };
    for format in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(expires_at) = NaiveDateTime::parse_from_str(value, format) {
            return DateTime::<Utc>::from_naive_utc_and_offset(expires_at, Utc) <= now;
        }
    }
    if let Ok(expires_at) = DateTime::parse_from_rfc3339(value) {
        return expires_at.with_timezone(&Utc) <= now;
    }
    if let Ok(expires_on) = NaiveDate::parse_from_str(value, "%Y-%m-%d")
        && let Some(next_day) = expires_on.succ_opt()
        && let Some(end) = next_day.and_hms_opt(0, 0, 0)
    {
        return DateTime::<Utc>::from_naive_utc_and_offset(end, Utc) <= now;
    }
    false
}

fn normalize_websocket_path(
    node: &V2BoardNodeConfig,
    path: String,
) -> std::io::Result<(String, Option<u32>)> {
    let Some((path, query)) = path.split_once('?') else {
        return Ok((path, None));
    };
    let mut early_data = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if key == "ed" {
            early_data = Some(value.parse::<u32>().map_err(|e| {
                invalid_error(format!(
                    "node `{}` websocket path has invalid early data query `ed={value}`: {e}",
                    node.tag
                ))
            })?);
        }
    }
    Ok((path.to_string(), early_data))
}

fn normalize_tcp_header(settings: Option<&Value>) -> Option<TcpHeader> {
    let header = settings?.get("header")?;
    let header_type = header.get("type")?.as_str()?;
    if !header_type.eq_ignore_ascii_case("http") {
        return None;
    }
    let request = header.get("request");
    let hosts = request
        .and_then(|v| v.get("headers"))
        .and_then(|v| v.get("Host").or_else(|| v.get("host")))
        .map(value_to_string_vec)
        .unwrap_or_default();
    let paths = request
        .and_then(|v| v.get("path"))
        .map(value_to_string_vec)
        .unwrap_or_default();
    let method = request
        .and_then(|v| v.get("method"))
        .and_then(value_to_string);
    Some(TcpHeader::Http {
        hosts,
        paths,
        method,
    })
}

fn panel_tls_certificate(settings: Option<&Value>) -> Option<RuntimeTlsCertificate> {
    let cert_file = string_setting(settings, &["cert_file", "certFile"]).map(PathBuf::from)?;
    let key_file = string_setting(settings, &["key_file", "keyFile"]).map(PathBuf::from)?;
    Some(RuntimeTlsCertificate {
        cert_file,
        key_file,
    })
}

fn normalized_tls_alpn(
    node_type: NodeType,
    transport: &RuntimeTransport,
    settings: Option<&Value>,
) -> Vec<String> {
    let mut alpn = string_vec_setting(settings, &["alpn", "alpn_protocols"]);
    if matches!(node_type, NodeType::Tuic | NodeType::Hysteria)
        && !alpn.iter().any(|item| item.eq_ignore_ascii_case("h3"))
    {
        alpn.insert(0, "h3".to_string());
    }
    if node_type == NodeType::Naiveproxy {
        if matches!(
            transport,
            RuntimeTransport::Quic | RuntimeTransport::TcpAndQuic
        ) && !alpn.iter().any(|item| item.eq_ignore_ascii_case("h3"))
        {
            alpn.insert(0, "h3".to_string());
        }
        if !matches!(transport, RuntimeTransport::Quic) {
            if !alpn
                .iter()
                .any(|item| item.eq_ignore_ascii_case("http/1.1"))
            {
                alpn.push("http/1.1".to_string());
            }
            if !alpn.iter().any(|item| item.eq_ignore_ascii_case("h2")) {
                let h2_position = if matches!(transport, RuntimeTransport::TcpAndQuic)
                    && alpn.iter().any(|item| item.eq_ignore_ascii_case("h3"))
                {
                    1
                } else {
                    0
                };
                alpn.insert(h2_position, "h2".to_string());
            }
        }
    }
    alpn
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsMode {
    None,
    Tls,
    Reality,
}

fn tls_mode(value: Option<&Value>) -> TlsMode {
    match value {
        None | Some(Value::Null) => TlsMode::None,
        Some(Value::Bool(false)) => TlsMode::None,
        Some(Value::Bool(true)) => TlsMode::Tls,
        Some(Value::Number(n)) => match n.as_i64() {
            Some(0) => TlsMode::None,
            Some(2) => TlsMode::Reality,
            _ => TlsMode::Tls,
        },
        Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "" | "0" | "false" | "none" | "off" => TlsMode::None,
            "2" | "reality" => TlsMode::Reality,
            _ => TlsMode::Tls,
        },
        Some(_) => TlsMode::Tls,
    }
}

fn string_setting(settings: Option<&Value>, keys: &[&str]) -> Option<String> {
    let object = settings?.as_object()?;
    for key in keys {
        if let Some(value) = object.get(*key)
            && let Some(s) = value_to_string(value)
            && !s.is_empty()
        {
            return Some(s);
        }
    }
    None
}

fn bool_setting(settings: Option<&Value>, keys: &[&str]) -> Option<bool> {
    let object = settings?.as_object()?;
    for key in keys {
        if let Some(value) = object.get(*key) {
            return match value {
                Value::Bool(v) => Some(*v),
                Value::Number(n) => n.as_i64().map(|v| v != 0),
                Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
                    "1" | "true" | "yes" | "on" => Some(true),
                    "0" | "false" | "no" | "off" | "" => Some(false),
                    _ => None,
                },
                _ => None,
            };
        }
    }
    None
}

fn u64_setting(settings: Option<&Value>, keys: &[&str]) -> Option<u64> {
    let object = settings?.as_object()?;
    for key in keys {
        if let Some(value) = object.get(*key) {
            return match value {
                Value::Number(n) => n.as_u64(),
                Value::String(s) => s.parse::<u64>().ok(),
                _ => None,
            };
        }
    }
    None
}

fn reality_max_time_diff_millis(settings: Option<&Value>) -> std::io::Result<Option<u64>> {
    let Some(object) = settings.and_then(Value::as_object) else {
        return Ok(None);
    };
    let Some(value) = object
        .get("MaxTimeDiff")
        .or_else(|| object.get("max_time_diff"))
        .or_else(|| object.get("maxTimeDiff"))
        .or_else(|| object.get("max_time_difference"))
        .or_else(|| object.get("maxTimeDifference"))
    else {
        return Ok(None);
    };

    match value {
        Value::Null => Ok(None),
        Value::Number(number) => number.as_u64().map(Some).ok_or_else(|| {
            invalid_error(format!(
                "reality MaxTimeDiff `{value}` must be a non-negative integer"
            ))
        }),
        Value::String(text) => parse_reality_duration_millis(text.trim()).map(Some),
        _ => invalid(format!(
            "reality MaxTimeDiff `{value}` must be a number or duration string"
        )),
    }
}

fn parse_reality_duration_millis(value: &str) -> std::io::Result<u64> {
    if value.is_empty() {
        return invalid("reality MaxTimeDiff cannot be empty");
    }
    if value.bytes().all(|b| b.is_ascii_digit()) {
        return value.parse::<u64>().map_err(|e| {
            invalid_error(format!(
                "reality MaxTimeDiff `{value}` is not a valid millisecond value: {e}"
            ))
        });
    }

    let bytes = value.as_bytes();
    let mut index = 0;
    let mut total = 0u64;
    while index < bytes.len() {
        let number_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index < bytes.len() && bytes[index] == b'.' {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
        }
        if number_start == index {
            return invalid(format!(
                "reality MaxTimeDiff `{value}` has invalid duration segment"
            ));
        }
        let amount = value[number_start..index].parse::<f64>().map_err(|e| {
            invalid_error(format!(
                "reality MaxTimeDiff `{value}` has invalid duration amount: {e}"
            ))
        })?;
        if !amount.is_finite() || amount < 0.0 {
            return invalid(format!(
                "reality MaxTimeDiff `{value}` has invalid duration amount"
            ));
        }

        let unit_start = index;
        while index < bytes.len() && bytes[index].is_ascii_alphabetic() {
            index += 1;
        }
        let unit = &value[unit_start..index];
        let factor = match unit {
            "ns" => 0.000_001,
            "us" => 0.001,
            "ms" => 1.0,
            "s" => 1_000.0,
            "m" => 60_000.0,
            "h" => 3_600_000.0,
            _ => {
                return invalid(format!(
                    "reality MaxTimeDiff `{value}` has unsupported duration unit `{unit}`"
                ));
            }
        };
        let millis = (amount * factor).ceil();
        if !millis.is_finite() || millis > u64::MAX as f64 {
            return invalid(format!(
                "reality MaxTimeDiff `{value}` overflows milliseconds"
            ));
        }
        let millis = millis as u64;
        total = total.checked_add(millis).ok_or_else(|| {
            invalid_error(format!(
                "reality MaxTimeDiff `{value}` overflows milliseconds"
            ))
        })?;
    }
    Ok(total)
}

fn string_vec_setting(settings: Option<&Value>, keys: &[&str]) -> Vec<String> {
    let object = match settings.and_then(Value::as_object) {
        Some(object) => object,
        None => return Vec::new(),
    };
    for key in keys {
        if let Some(value) = object.get(*key) {
            let values = value_to_string_vec(value);
            if !values.is_empty() {
                return values;
            }
        }
    }
    Vec::new()
}

fn headers_setting(settings: Option<&Value>, keys: &[&str]) -> HashMap<String, String> {
    let object = match settings.and_then(Value::as_object) {
        Some(object) => object,
        None => return HashMap::new(),
    };
    for key in keys {
        if let Some(Value::Object(headers)) = object.get(*key) {
            return headers
                .iter()
                .filter_map(|(k, v)| value_to_string(v).map(|s| (k.clone(), s)))
                .collect();
        }
    }
    HashMap::new()
}

fn headers_list_setting(settings: Option<&Value>, keys: &[&str]) -> HashMap<String, String> {
    let object = match settings.and_then(Value::as_object) {
        Some(object) => object,
        None => return HashMap::new(),
    };
    for key in keys {
        if let Some(Value::Object(headers)) = object.get(*key) {
            return headers
                .iter()
                .filter_map(|(k, v)| {
                    let values = value_to_string_vec(v);
                    if values.is_empty() {
                        None
                    } else {
                        Some((k.clone(), values.join(", ")))
                    }
                })
                .collect();
        }
    }
    HashMap::new()
}

fn first_non_empty_string_vec_setting(
    settings: Option<&Value>,
    keys: &[&str],
) -> Option<Vec<String>> {
    let values = string_vec_setting(settings, keys);
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

fn value_to_string_vec(value: &Value) -> Vec<String> {
    match value {
        Value::Array(values) => values.iter().filter_map(value_to_string).collect(),
        _ => value_to_string(value).into_iter().collect(),
    }
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => non_empty(Some(s)),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(v) => Some(v.to_string()),
        _ => None,
    }
}

fn bool_value(value: Option<&Value>) -> Option<bool> {
    match value? {
        Value::Bool(value) => Some(*value),
        Value::Number(value) => value.as_i64().map(|value| value != 0),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" | "" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value.and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn invalid<T>(msg: impl Into<String>) -> std::io::Result<T> {
    Err(invalid_error(msg))
}

fn invalid_error(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.into())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::backend_config::{RuntimeConfig, V2BoardConfig};
    use crate::v2board::types::BaseConfig;

    fn app_config(node_type: NodeType) -> (AppConfig, V2BoardNodeConfig) {
        let node = V2BoardNodeConfig {
            tag: "node-a".to_string(),
            node_id: 7,
            node_type,
            listen: None,
            api_host: None,
            api_key: None,
            pull_interval_secs: None,
            push_interval_secs: None,
            tls: None,
            trojan_fallback: None,
            hysteria2_masquerade: None,
        };
        (
            AppConfig {
                v2board: V2BoardConfig {
                    api_host: "https://panel.example".to_string(),
                    api_key: "secret".to_string(),
                    api_timeout_secs: 30,
                    error_body_limit_bytes: 4096,
                    user_list_body_limit_bytes: 1024,
                    route_rule_sets: RouteRuleSetsConfig::default(),
                    nodes: vec![node.clone()],
                },
                runtime: RuntimeConfig::default(),
                tls: None,
                log: Default::default(),
            },
            node,
        )
    }

    fn server(network: &str) -> ServerConfig {
        ServerConfig {
            server_port: 443,
            protocol: None,
            version: None,
            listen_ip: None,
            cipher: Some("auto".to_string()),
            server_key: None,
            obfs: None,
            obfs_password: None,
            obfs_settings: None,
            host: None,
            server_name: None,
            network: Some(network.to_string()),
            network_settings: None,
            tls: None,
            tls_settings: None,
            reality_config: None,
            insecure: None,
            disable_sni: None,
            udp_relay_mode: None,
            zero_rtt_handshake: None,
            congestion_control: None,
            quic_congestion_control: None,
            up_mbps: None,
            down_mbps: None,
            ignore_client_bandwidth: None,
            padding_scheme: None,
            flow: None,
            encryption: None,
            encryption_settings: None,
            base_config: BaseConfig::default(),
            routes: Vec::new(),
            config_revision: None,
        }
    }

    fn users() -> Vec<UserInfo> {
        vec![UserInfo {
            id: 10,
            uuid: Some("00000000-0000-0000-0000-000000000001".to_string()),
            secret: None,
            password: None,
            username: None,
            speed_limit: Some(100),
            device_limit: Some(3),
            label: Some("alice".to_string()),
            enabled: None,
            expires_at: None,
            expires_on: None,
            max_connections: None,
            max_ips: None,
            quota_bytes: None,
        }]
    }

    #[test]
    fn normalizes_websocket_transport_and_user_policy() {
        let (app, node) = app_config(NodeType::Vmess);
        let mut server = server("ws");
        server.network_settings = Some(json!({
            "path": "/edge",
            "headers": {"Host": "edge.example"},
            "maxEarlyData": 2048,
            "earlyDataHeaderName": "Sec-WebSocket-Protocol"
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(spec.bind.address(), "0.0.0.0:443");
        assert_eq!(
            spec.transport,
            RuntimeTransport::Websocket {
                path: "/edge".to_string(),
                headers: HashMap::from([("Host".to_string(), "edge.example".to_string())]),
                max_early_data: Some(2048),
                early_data_header_name: Some("Sec-WebSocket-Protocol".to_string()),
            }
        );
        assert_eq!(spec.users[0].policy.speed_limit_mbps, Some(100));
        assert_eq!(spec.users[0].policy.device_limit, Some(3));
    }

    #[test]
    fn normalizes_vmess_security_from_network_settings() {
        let (app, node) = app_config(NodeType::Vmess);
        let mut server = server("ws");
        server.cipher = None;
        server.network_settings = Some(json!({
            "path": "/edge",
            "security": "none"
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(
            spec.protocol,
            RuntimeProtocol::Vmess {
                security: "none".to_string(),
            }
        );
    }

    #[test]
    fn normalizes_websocket_defaults_to_v2board_singbox_early_data() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("ws");
        server.network_settings = Some(json!({
            "path": "/vless-ws"
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(
            spec.transport,
            RuntimeTransport::Websocket {
                path: "/vless-ws".to_string(),
                headers: HashMap::new(),
                max_early_data: Some(2048),
                early_data_header_name: Some("Sec-WebSocket-Protocol".to_string()),
            }
        );
    }

    #[test]
    fn normalizes_websocket_path_ed_query() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("ws");
        server.network_settings = Some(json!({
            "path": "/vless-ws?ed=4096"
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(
            spec.transport,
            RuntimeTransport::Websocket {
                path: "/vless-ws".to_string(),
                headers: HashMap::new(),
                max_early_data: Some(4096),
                early_data_header_name: Some("Sec-WebSocket-Protocol".to_string()),
            }
        );
    }

    #[test]
    fn rejects_invalid_websocket_path_ed_query() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("ws");
        server.network_settings = Some(json!({
            "path": "/vless-ws?ed=bad"
        }));

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(
            err.to_string()
                .contains("websocket path has invalid early data query")
        );
    }

    #[test]
    fn rejects_domainsocket_network_when_payload_reaches_runtime() {
        let (app, node) = app_config(NodeType::Vmess);
        let server = server("domainsocket");

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(err.to_string().contains("network `domainsocket`"));
    }

    #[test]
    fn filters_inactive_panel_users() {
        let (app, node) = app_config(NodeType::Vmess);
        let mut users = users();
        users.push(UserInfo {
            id: 11,
            uuid: Some("00000000-0000-0000-0000-000000000011".to_string()),
            secret: None,
            password: None,
            username: None,
            speed_limit: None,
            device_limit: None,
            label: Some("disabled".to_string()),
            enabled: Some(json!(false)),
            expires_at: None,
            expires_on: None,
            max_connections: None,
            max_ips: None,
            quota_bytes: None,
        });
        users.push(UserInfo {
            id: 12,
            uuid: Some("00000000-0000-0000-0000-000000000012".to_string()),
            secret: None,
            password: None,
            username: None,
            speed_limit: None,
            device_limit: None,
            label: Some("expired".to_string()),
            enabled: Some(json!(true)),
            expires_at: Some(json!(1)),
            expires_on: None,
            max_connections: None,
            max_ips: None,
            quota_bytes: None,
        });

        let spec = normalize_node(&app, &node, &server("tcp"), &users).unwrap();

        assert_eq!(spec.users.len(), 1);
        assert_eq!(spec.users[0].uid, 10);
    }

    #[test]
    fn keeps_a_fail_closed_runtime_when_all_panel_users_are_inactive() {
        let (app, node) = app_config(NodeType::Vmess);
        let mut users = users();
        users[0].expires_on = Some("1970-01-01".to_string());

        let spec = normalize_node(&app, &node, &server("tcp"), &users).unwrap();

        assert!(spec.users.is_empty());
    }

    #[test]
    fn normalizes_accept_proxy_protocol_network_setting() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("ws");
        server.network_settings = Some(json!({
            "path": "/vless-ws",
            "acceptProxyProtocol": true
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert!(spec.accept_proxy_protocol);
        assert!(matches!(spec.transport, RuntimeTransport::Websocket { .. }));
    }

    #[test]
    fn normalizes_v2ray_http_transport() {
        let (app, node) = app_config(NodeType::Vmess);
        let mut server = server("http");
        server.network_settings = Some(json!({
            "host": ["edge.example", "backup.example"],
            "path": ["/ray"],
            "method": "PUT",
            "headers": {"X-Edge": ["ok", "fallback"]}
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(
            spec.transport,
            RuntimeTransport::Http {
                hosts: vec!["edge.example".to_string(), "backup.example".to_string()],
                paths: vec!["/ray".to_string()],
                method: Some("PUT".to_string()),
                response_headers: HashMap::from([(
                    "X-Edge".to_string(),
                    "ok, fallback".to_string()
                )]),
            }
        );
    }

    #[test]
    fn normalizes_xhttp_transport_defaults() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("xhttp");
        server.network_settings = Some(json!({
            "path": "/edge",
            "host": "xtls.github.io",
            "mode": "auto"
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(
            spec.transport,
            RuntimeTransport::XHttp(XHttpConfig::new(XHttpConfigParts {
                host: Some("xtls.github.io".to_string()),
                path: "/edge".to_string(),
                mode: XHttpMode::Auto,
                no_grpc_header: false,
                no_sse_header: false,
                max_each_post_bytes: None,
                max_buffered_posts: None,
                session_id_placement: XHttpPlacement::Path,
                session_id_key: None,
                seq_placement: XHttpPlacement::Path,
                seq_key: None,
                uplink_data_placement: XHttpDataPlacement::Auto,
                uplink_data_key: None,
            }))
        );
    }

    #[test]
    fn normalizes_xhttp_extra_from_v2board_json_string() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("xhttp");
        server.network_settings = Some(json!({
            "path": "/edge",
            "host": "edge.example",
            "mode": "packet-up",
            "extra": r#"{
                "noGRPCHeader": true,
                "noSSEHeader": true,
                "scMaxEachPostBytes": {"from": 2048, "to": 4096},
                "scMaxBufferedPosts": 64,
                "sessionIDPlacement": "query",
                "sessionIDKey": "sid",
                "seqPlacement": "header",
                "seqKey": "X-Seq",
                "uplinkDataPlacement": "header",
                "uplinkDataKey": "X-Data"
            }"#
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(
            spec.transport,
            RuntimeTransport::XHttp(XHttpConfig::new(XHttpConfigParts {
                host: Some("edge.example".to_string()),
                path: "/edge".to_string(),
                mode: XHttpMode::PacketUp,
                no_grpc_header: true,
                no_sse_header: true,
                max_each_post_bytes: Some(4096),
                max_buffered_posts: Some(64),
                session_id_placement: XHttpPlacement::Query,
                session_id_key: Some("sid".to_string()),
                seq_placement: XHttpPlacement::Header,
                seq_key: Some("X-Seq".to_string()),
                uplink_data_placement: XHttpDataPlacement::Header,
                uplink_data_key: Some("X-Data".to_string()),
            }))
        );
    }

    #[test]
    fn rejects_invalid_xhttp_mode() {
        let (app, node) = app_config(NodeType::Vmess);
        let mut server = server("xhttp");
        server.network_settings = Some(json!({
            "mode": "sideways"
        }));

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(err.to_string().contains("xhttp mode `sideways`"));
    }

    #[test]
    fn rejects_xhttp_extra_json_string_that_is_not_object() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("xhttp");
        server.network_settings = Some(json!({
            "extra": "[]"
        }));

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(
            err.to_string()
                .contains("xhttp extra JSON `[]` must decode to an object")
        );
    }

    #[test]
    fn rejects_xhttp_unsupported_download_settings() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("xhttp");
        server.network_settings = Some(json!({
            "extra": {
                "downloadSettings": {
                    "address": "127.0.0.1",
                    "port": 8443
                }
            }
        }));

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(
            err.to_string()
                .contains("xhttp downloadSettings is not supported")
        );
    }

    #[test]
    fn rejects_xhttp_unsupported_xmux() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("xhttp");
        server.network_settings = Some(json!({
            "extra": {
                "xmux": {
                    "maxConcurrency": 8,
                    "hKeepAlivePeriod": 30
                }
            }
        }));

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(err.to_string().contains("xhttp xmux is not supported"));
    }

    #[test]
    fn accepts_xhttp_client_only_extra_headers() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("xhttp");
        server.network_settings = Some(json!({
            "extra": {
                "headers": {
                    "X-Edge": "on"
                }
            }
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert!(matches!(spec.transport, RuntimeTransport::XHttp(_)));
    }

    #[test]
    fn rejects_xhttp_unsupported_padding_bytes() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("xhttp");
        server.network_settings = Some(json!({
            "extra": {
                "xPaddingBytes": {
                    "from": 100,
                    "to": 1000
                }
            }
        }));

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(
            err.to_string()
                .contains("xhttp xPaddingBytes is not supported")
        );
    }

    #[test]
    fn rejects_xhttp_unsupported_stream_up_server_keepalive() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("xhttp");
        server.network_settings = Some(json!({
            "extra": {
                "scStreamUpServerSecs": {
                    "from": 20,
                    "to": 80
                }
            }
        }));

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(
            err.to_string()
                .contains("xhttp scStreamUpServerSecs is not supported")
        );
    }

    #[test]
    fn rejects_xhttp_unsupported_server_max_header_bytes() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("xhttp");
        server.network_settings = Some(json!({
            "serverMaxHeaderBytes": 16384
        }));

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(
            err.to_string()
                .contains("xhttp serverMaxHeaderBytes is not supported")
        );
    }

    #[test]
    fn rejects_enabled_xhttp_padding_obfs_mode() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("xhttp");
        server.network_settings = Some(json!({
            "extra": {
                "xPaddingObfsMode": true
            }
        }));

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(
            err.to_string()
                .contains("xhttp xPaddingObfsMode is not supported")
        );
    }

    #[test]
    fn allows_empty_xhttp_advanced_extra_defaults() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("xhttp");
        server.network_settings = Some(json!({
            "path": "/edge",
            "extra": {
                "downloadSettings": {},
                "xmux": {},
                "headers": {},
                "xPaddingBytes": {},
                "scStreamUpServerSecs": {},
                "xPaddingObfsMode": false
            }
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert!(matches!(spec.transport, RuntimeTransport::XHttp(_)));
    }

    #[test]
    fn rejects_shadowsocks_non_empty_encryption_settings() {
        let (app, node) = app_config(NodeType::Shadowsocks);
        let mut server = server("tcp");
        server.cipher = Some("aes-128-gcm".to_string());
        server.encryption_settings = Some(json!({
            "mode": "native"
        }));

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(
            err.to_string()
                .contains("shadowsocks encryption_settings is not supported")
        );
    }

    #[test]
    fn allows_empty_shadowsocks_encryption_settings() {
        let (app, node) = app_config(NodeType::Shadowsocks);
        let mut server = server("tcp");
        server.cipher = Some("aes-128-gcm".to_string());
        server.encryption_settings = Some(json!({}));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert!(matches!(
            spec.protocol,
            RuntimeProtocol::Shadowsocks {
                encryption_settings: None,
                ..
            }
        ));
    }

    #[test]
    fn rejects_vless_non_empty_encryption_settings() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("tcp");
        server.encryption_settings = Some(json!({
            "mode": "mlkem"
        }));

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(
            err.to_string()
                .contains("vless encryption_settings is not supported")
        );
    }

    #[test]
    fn rejects_v2node_vmess_non_empty_encryption_settings() {
        let (app, node) = app_config(NodeType::V2Node);
        let mut server = server("tcp");
        server.protocol = Some("vmess".to_string());
        server.encryption_settings = Some(json!({
            "mode": "native"
        }));

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(
            err.to_string()
                .contains("vmess encryption_settings is not supported")
        );
    }

    #[test]
    fn allows_empty_vless_encryption_settings() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("tcp");
        server.encryption_settings = Some(json!({}));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert!(matches!(spec.protocol, RuntimeProtocol::Vless { .. }));
    }

    #[test]
    fn normalizes_tcp_http_header_obfuscation() {
        let (app, node) = app_config(NodeType::Vmess);
        let mut server = server("tcp");
        server.network_settings = Some(json!({
            "header": {
                "type": "http",
                "request": {
                    "method": "GET",
                    "path": ["/front"],
                    "headers": {"Host": ["front.example"]}
                }
            }
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(
            spec.transport,
            RuntimeTransport::Tcp {
                header: Some(TcpHeader::Http {
                    hosts: vec!["front.example".to_string()],
                    paths: vec!["/front".to_string()],
                    method: Some("GET".to_string()),
                }),
            }
        );
    }

    #[test]
    fn normalizes_reality_security_without_tls_certificate() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("tcp");
        server.tls = Some(json!(2));
        server.tls_settings = Some(json!({
            "server_name": "www.example.com",
            "private_key": "priv",
            "public_key": "pub",
            "short_ids": ["abcd", "ef01"],
            "dest": "www.example.com:443",
            "fingerprint": "chrome"
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(
            spec.security,
            RuntimeSecurity::Reality(RuntimeReality {
                server_name: Some("www.example.com".to_string()),
                server_names: Vec::new(),
                private_key: Some("priv".to_string()),
                public_key: Some("pub".to_string()),
                short_ids: vec!["abcd".to_string(), "ef01".to_string()],
                dest: Some("www.example.com:443".to_string()),
                server_port: None,
                max_time_diff_millis: None,
                xver: 0,
                cert_mode: None,
                cert_file: None,
                key_file: None,
                ech: None,
                ech_server_name: None,
                ech_key: None,
                ech_config: None,
                fingerprint: Some("chrome".to_string()),
                raw_settings: server.tls_settings.clone(),
            })
        );
    }

    #[test]
    fn normalizes_reality_max_time_diff_from_reality_config() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("tcp");
        server.tls = Some(json!(2));
        server.tls_settings = Some(json!({
            "server_name": "www.example.com",
            "private_key": "priv",
            "short_id": "abcd",
            "dest": "www.example.com:443"
        }));
        server.reality_config = Some(json!({
            "MaxTimeDiff": "1m30s"
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        match spec.security {
            RuntimeSecurity::Reality(reality) => {
                assert_eq!(reality.max_time_diff_millis, Some(90_000));
            }
            other => panic!("expected reality security, got {other:?}"),
        }

        server.reality_config = Some(json!({
            "MaxTimeDiff": "1.5s"
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        match spec.security {
            RuntimeSecurity::Reality(reality) => {
                assert_eq!(reality.max_time_diff_millis, Some(1_500));
            }
            other => panic!("expected reality security, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_reality_max_time_diff() {
        let (app, node) = app_config(NodeType::Vless);
        let mut server = server("tcp");
        server.tls = Some(json!(2));
        server.tls_settings = Some(json!({
            "server_name": "www.example.com",
            "private_key": "priv",
            "short_id": "abcd",
            "dest": "www.example.com:443"
        }));
        server.reality_config = Some(json!({
            "MaxTimeDiff": "1fortnight"
        }));

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(err.to_string().contains("unsupported duration unit"));
    }

    #[test]
    fn normalizes_trojan_as_tls_without_panel_tls_flag() {
        let (app, node) = app_config(NodeType::Trojan);
        let mut server = server("tcp");
        server.server_name = Some("trojan.example.com".to_string());

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        match spec.security {
            RuntimeSecurity::Tls(tls) => {
                assert_eq!(tls.server_name.as_deref(), Some("trojan.example.com"));
            }
            other => panic!("expected TLS security, got {other:?}"),
        }
    }

    #[test]
    fn normalizes_node_local_trojan_fallback() {
        let (app, mut node) = app_config(NodeType::Trojan);
        node.trojan_fallback =
            Some(crate::address::NetLocation::from_str("127.0.0.1:8443", None).unwrap());
        let server = server("tcp");

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();
        match spec.protocol {
            RuntimeProtocol::Trojan { fallback, .. } => {
                assert_eq!(fallback.unwrap().to_string(), "127.0.0.1:8443");
            }
            other => panic!("expected Trojan protocol, got {other:?}"),
        }
    }

    #[test]
    fn rejects_trojan_fallback_pointing_to_wildcard_listener() {
        let (app, mut node) = app_config(NodeType::Trojan);
        node.listen = Some("0.0.0.0".to_string());
        node.trojan_fallback =
            Some(crate::address::NetLocation::from_str("127.0.0.1:443", None).unwrap());
        let server = server("tcp");

        let error = normalize_node(&app, &node, &server, &users()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must use a different port from its listener")
        );
    }

    #[test]
    fn normalizes_anytls_as_tls_with_padding_scheme() {
        let (app, node) = app_config(NodeType::Anytls);
        let mut server = server("tcp");
        server.server_name = Some("anytls.example.com".to_string());
        server.padding_scheme = Some(json!(["stop=2", "0=30-30", "1=100-100"]));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(
            spec.protocol,
            RuntimeProtocol::Anytls {
                padding_scheme: vec![
                    "stop=2".to_string(),
                    "0=30-30".to_string(),
                    "1=100-100".to_string(),
                ],
            }
        );
        match spec.security {
            RuntimeSecurity::Tls(tls) => {
                assert_eq!(tls.server_name.as_deref(), Some("anytls.example.com"));
            }
            other => panic!("expected TLS security, got {other:?}"),
        }
    }

    #[test]
    fn normalizes_anytls_padding_scheme_from_json_string() {
        let (app, node) = app_config(NodeType::Anytls);
        let mut server = server("tcp");
        server.padding_scheme = Some(json!(r#"["stop=1","0=50-50"]"#));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(
            spec.protocol,
            RuntimeProtocol::Anytls {
                padding_scheme: vec!["stop=1".to_string(), "0=50-50".to_string()],
            }
        );
    }

    #[test]
    fn normalizes_tuic_as_quic_tls_with_v2board_fields() {
        let (app, node) = app_config(NodeType::Tuic);
        let mut server = server("ws");
        server.server_name = Some("tuic.example.com".to_string());
        server.zero_rtt_handshake = Some(json!("1"));
        server.congestion_control = Some("bbr".to_string());
        server.udp_relay_mode = Some("native".to_string());
        server.disable_sni = Some(json!(true));
        server.tls_settings = Some(json!({
            "alpn": ["custom"],
            "serverName": "tuic.example.com"
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(spec.node_type, NodeType::Tuic);
        assert_eq!(spec.transport, RuntimeTransport::Quic);
        assert_eq!(
            spec.protocol,
            RuntimeProtocol::Tuic {
                zero_rtt_handshake: true,
                congestion_control: Some("bbr".to_string()),
                udp_relay_mode: Some("native".to_string()),
                disable_sni: true,
            }
        );
        match spec.security {
            RuntimeSecurity::Tls(tls) => {
                assert_eq!(tls.server_name.as_deref(), Some("tuic.example.com"));
                assert_eq!(tls.alpn, vec!["h3".to_string(), "custom".to_string()]);
            }
            other => panic!("expected TLS security, got {other:?}"),
        }
    }

    #[test]
    fn normalizes_hysteria_version2_as_quic_tls() {
        let (app, node) = app_config(NodeType::Hysteria);
        let mut server = server("tcp");
        server.version = Some(2);
        server.server_name = Some("hy2.example.com".to_string());
        server.tls_settings = Some(json!({
            "alpn": ["custom"],
            "serverName": "hy2.example.com"
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(spec.config_node_type, NodeType::Hysteria);
        assert_eq!(spec.node_type, NodeType::Hysteria);
        assert_eq!(spec.transport, RuntimeTransport::Quic);
        assert_eq!(
            spec.protocol,
            RuntimeProtocol::Hysteria2 {
                up_mbps: 0,
                down_mbps: 0,
                ignore_client_bandwidth: true,
                obfs: None,
                obfs_password: None,
                masquerade: None,
            }
        );
        match spec.security {
            RuntimeSecurity::Tls(tls) => {
                assert_eq!(tls.server_name.as_deref(), Some("hy2.example.com"));
                assert_eq!(tls.alpn, vec!["h3".to_string(), "custom".to_string()]);
            }
            other => panic!("expected TLS security, got {other:?}"),
        }
    }

    #[test]
    fn normalizes_node_local_hysteria2_static_masquerade() {
        let (app, mut node) = app_config(NodeType::Hysteria);
        node.hysteria2_masquerade = Some(Hysteria2MasqueradeConfig {
            status_code: 200,
            content_type: "text/plain".to_string(),
            body: "not a proxy".to_string(),
        });
        let mut server = server("quic");
        server.version = Some(2);

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        match spec.protocol {
            RuntimeProtocol::Hysteria2 {
                masquerade: Some(masquerade),
                ..
            } => assert_eq!(masquerade.body, "not a proxy"),
            other => panic!("expected Hysteria2 protocol with masquerade, got {other:?}"),
        }
    }

    #[test]
    fn rejects_hysteria2_masquerade_when_v2node_resolves_to_another_protocol() {
        let (app, mut node) = app_config(NodeType::V2Node);
        node.hysteria2_masquerade = Some(Hysteria2MasqueradeConfig {
            status_code: 404,
            content_type: "text/plain".to_string(),
            body: "not found".to_string(),
        });
        let mut server = server("tcp");
        server.protocol = Some("vless".to_string());

        let error = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("sets hysteria2_masquerade but resolves to protocol")
        );
    }

    #[test]
    fn normalizes_naiveproxy_as_plain_tcp_tls() {
        let (app, node) = app_config(NodeType::Naiveproxy);
        let mut server = server("tcp");
        server.protocol = Some("naive".to_string());
        server.server_name = Some("naive.example.com".to_string());
        let mut users = users();
        users[0].username = Some("user-10".to_string());
        users[0].password = Some("00000000-0000-0000-0000-000000000001".to_string());

        let spec = normalize_node(&app, &node, &server, &users).unwrap();

        assert_eq!(spec.node_type, NodeType::Naiveproxy);
        assert_eq!(spec.transport, RuntimeTransport::Tcp { header: None });
        assert_eq!(
            spec.protocol,
            RuntimeProtocol::Naiveproxy {
                quic_congestion_control: None,
            }
        );
        assert_eq!(spec.users[0].username.as_deref(), Some("user-10"));
        assert_eq!(
            spec.users[0].password.as_deref(),
            Some("00000000-0000-0000-0000-000000000001")
        );
        match spec.security {
            RuntimeSecurity::Tls(tls) => {
                assert_eq!(tls.server_name.as_deref(), Some("naive.example.com"));
                assert_eq!(tls.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
            }
            other => panic!("expected TLS security, got {other:?}"),
        }
    }

    #[test]
    fn normalizes_naiveproxy_empty_network_as_dual_tcp_h3() {
        let (app, node) = app_config(NodeType::Naiveproxy);
        let mut server = server("tcp");
        server.network = None;
        server.quic_congestion_control = Some("bbr2".to_string());

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(spec.transport, RuntimeTransport::TcpAndQuic);
        assert_eq!(
            spec.protocol,
            RuntimeProtocol::Naiveproxy {
                quic_congestion_control: Some("bbr2".to_string()),
            }
        );
        match spec.security {
            RuntimeSecurity::Tls(tls) => assert_eq!(
                tls.alpn,
                vec!["h3".to_string(), "h2".to_string(), "http/1.1".to_string()]
            ),
            other => panic!("expected TLS security, got {other:?}"),
        }
    }

    #[test]
    fn rejects_naiveproxy_tls_disabled() {
        let (app, node) = app_config(NodeType::Naiveproxy);
        let mut server = server("tcp");
        server.tls = Some(json!(0));

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(err.to_string().contains("naiveproxy requires TLS"));
    }

    #[test]
    fn rejects_hysteria_v1() {
        let (app, node) = app_config(NodeType::Hysteria);
        let mut server = server("tcp");
        server.version = Some(1);

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(err.to_string().contains("hysteria v1 is not supported"));
    }

    #[test]
    fn rejects_hysteria2_reality() {
        let (app, node) = app_config(NodeType::Hysteria);
        let mut server = server("tcp");
        server.version = Some(2);
        server.tls = Some(json!(2));

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(err.to_string().contains("hysteria2 requires QUIC TLS"));
    }

    #[test]
    fn normalizes_v2node_protocol_and_listen_ip() {
        let (app, node) = app_config(NodeType::V2Node);
        let mut server = server("ws");
        server.protocol = Some("vmess".to_string());
        server.listen_ip = Some("127.0.0.2".to_string());
        server.network_settings = Some(json!({
            "path": "/v2node-vmess"
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(spec.config_node_type, NodeType::V2Node);
        assert_eq!(spec.node_type, NodeType::Vmess);
        assert_eq!(spec.bind.address(), "127.0.0.2:443");
        assert!(matches!(spec.protocol, RuntimeProtocol::Vmess { .. }));
    }

    #[test]
    fn normalizes_v2node_anytls_reality() {
        let (app, node) = app_config(NodeType::V2Node);
        let mut server = server("tcp");
        server.protocol = Some("anytls".to_string());
        server.tls = Some(json!(2));
        server.tls_settings = Some(json!({
            "server_name": "www.example.com",
            "private_key": "priv",
            "public_key": "pub",
            "short_id": "abcd",
            "dest": "www.example.com:443",
            "fingerprint": "chrome"
        }));
        server.padding_scheme = Some(json!(["stop=1", "0=30-30"]));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(spec.config_node_type, NodeType::V2Node);
        assert_eq!(spec.node_type, NodeType::Anytls);
        assert_eq!(
            spec.protocol,
            RuntimeProtocol::Anytls {
                padding_scheme: vec!["stop=1".to_string(), "0=30-30".to_string()],
            }
        );
        assert!(matches!(spec.security, RuntimeSecurity::Reality(_)));
    }

    #[test]
    fn normalizes_v2node_tuic_protocol() {
        let (app, node) = app_config(NodeType::V2Node);
        let mut server = server("tcp");
        server.protocol = Some("tuic".to_string());
        server.zero_rtt_handshake = Some(json!(1));
        server.congestion_control = Some("cubic".to_string());

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(spec.config_node_type, NodeType::V2Node);
        assert_eq!(spec.node_type, NodeType::Tuic);
        assert_eq!(spec.transport, RuntimeTransport::Quic);
        assert_eq!(
            spec.protocol,
            RuntimeProtocol::Tuic {
                zero_rtt_handshake: true,
                congestion_control: Some("cubic".to_string()),
                udp_relay_mode: None,
                disable_sni: false,
            }
        );
        assert!(matches!(spec.security, RuntimeSecurity::Tls(_)));
    }

    #[test]
    fn normalizes_v2node_hysteria2_protocol() {
        let (app, node) = app_config(NodeType::V2Node);
        let mut server = server("tcp");
        server.protocol = Some("hysteria2".to_string());
        server.up_mbps = Some(10);
        server.down_mbps = Some(20);
        server.ignore_client_bandwidth = Some(false);
        server.obfs = Some("salamander".to_string());
        server.obfs_password = Some("secret".to_string());

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(spec.config_node_type, NodeType::V2Node);
        assert_eq!(spec.node_type, NodeType::Hysteria);
        assert_eq!(spec.transport, RuntimeTransport::Quic);
        assert_eq!(
            spec.protocol,
            RuntimeProtocol::Hysteria2 {
                up_mbps: 10,
                down_mbps: 20,
                ignore_client_bandwidth: false,
                obfs: Some("salamander".to_string()),
                obfs_password: Some("secret".to_string()),
                masquerade: None,
            }
        );
        assert!(matches!(spec.security, RuntimeSecurity::Tls(_)));
    }

    #[test]
    fn normalizes_v2node_naive_protocol() {
        let (app, node) = app_config(NodeType::V2Node);
        let mut server = server("tcp");
        server.protocol = Some("naive".to_string());
        let mut users = users();
        users[0].username = Some("user-10".to_string());
        users[0].password = Some("00000000-0000-0000-0000-000000000001".to_string());

        let spec = normalize_node(&app, &node, &server, &users).unwrap();

        assert_eq!(spec.config_node_type, NodeType::V2Node);
        assert_eq!(spec.node_type, NodeType::Naiveproxy);
        assert_eq!(spec.transport, RuntimeTransport::Tcp { header: None });
        assert_eq!(
            spec.protocol,
            RuntimeProtocol::Naiveproxy {
                quic_congestion_control: None,
            }
        );
        assert!(matches!(spec.security, RuntimeSecurity::Tls(_)));
    }

    #[test]
    fn normalizes_v2node_naive_udp_as_quic_h3() {
        let (app, node) = app_config(NodeType::V2Node);
        let mut server = server("udp");
        server.protocol = Some("naive".to_string());
        server.congestion_control = Some("bbr_standard".to_string());
        server.tls_settings = Some(json!({
            "serverName": "naive.example.com",
            "alpn": ["h3"]
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        assert_eq!(spec.config_node_type, NodeType::V2Node);
        assert_eq!(spec.node_type, NodeType::Naiveproxy);
        assert_eq!(spec.transport, RuntimeTransport::Quic);
        match spec.security {
            RuntimeSecurity::Tls(tls) => {
                assert_eq!(tls.server_name.as_deref(), Some("naive.example.com"));
                assert_eq!(tls.alpn, vec!["h3".to_string()]);
            }
            other => panic!("expected TLS security, got {other:?}"),
        }
        assert_eq!(
            spec.protocol,
            RuntimeProtocol::Naiveproxy {
                quic_congestion_control: Some("bbr_standard".to_string()),
            }
        );
    }

    #[test]
    fn rejects_tuic_reality() {
        let (app, node) = app_config(NodeType::Tuic);
        let mut server = server("tcp");
        server.tls = Some(json!(2));

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(err.to_string().contains("tuic requires QUIC TLS"));
    }

    #[test]
    fn rejects_v2node_missing_protocol() {
        let (app, node) = app_config(NodeType::V2Node);
        let server = server("tcp");

        let err = normalize_node(&app, &node, &server, &users()).unwrap_err();

        assert!(err.to_string().contains("v2node config missing protocol"));
    }

    #[test]
    fn normalizes_tls_ech_fields_for_explicit_rejection() {
        let (app, node) = app_config(NodeType::Vmess);
        let mut server = server("tcp");
        server.tls = Some(json!(1));
        server.tls_settings = Some(json!({
            "serverName": "tls.example.com",
            "ech": "enabled",
            "echServerName": "ech.example.com",
            "echKey": "key",
            "echConfig": "config"
        }));

        let spec = normalize_node(&app, &node, &server, &users()).unwrap();

        match spec.security {
            RuntimeSecurity::Tls(tls) => {
                assert_eq!(tls.ech.as_deref(), Some("enabled"));
                assert_eq!(tls.ech_server_name.as_deref(), Some("ech.example.com"));
                assert_eq!(tls.ech_key.as_deref(), Some("key"));
                assert_eq!(tls.ech_config.as_deref(), Some("config"));
            }
            other => panic!("expected TLS security, got {other:?}"),
        }
    }
}
