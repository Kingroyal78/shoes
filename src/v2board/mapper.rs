use std::collections::HashMap;
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use rustc_hash::FxHashMap;
use serde_json::Value;
use tokio::task::JoinHandle;

use crate::address::{Address, AddressMask, NetLocation, NetLocationMask};
use crate::anytls::{AnyTlsServerHandler, PaddingFactory};
use crate::async_stream::AsyncStream;
use crate::backend_config::{AppConfig, NodeType, OutboundConfig, OutboundSpec, V2BoardNodeConfig};
use crate::client_proxy_chain::ClientChainGroup;
use crate::client_proxy_selector::{
    ClientProxySelector, ConnectAction, ConnectMatcher, ConnectRule, SniffedProtocol,
};
use crate::config::{
    BindLocation, ClientChain, ClientChainHop, ClientConfig, ConfigSelection, TcpConfig,
    WebsocketPingType,
};
use crate::hysteria2_obfs::Hysteria2Obfs;
use crate::hysteria2_server::{
    Hysteria2Masquerade, Hysteria2ServerUser, Hysteria2ServerUsers, Hysteria2StartConfig,
    start_hysteria2_server,
};
use crate::naiveproxy::UserLookup;
use crate::naiveproxy::naive_h3_service::{
    start_naive_h3_server, validate_naive_quic_congestion_control,
};
use crate::option_util::{NoneOrSome, OneOrSome};
use crate::reality::{RealityServerTarget, decode_private_key, decode_short_id};
use crate::resolver::Resolver;
use crate::rustls_config_util::create_server_config;
use crate::shadow_tls::{ShadowTlsServerTarget, ShadowTlsServerTargetHandshake};
use crate::shadowsocks::{ShadowsocksTcpHandler, shadowsocks_obfs::ShadowsocksHttpObfs};
use crate::ss_plugins::gost::{GostPluginServerConfig, GostPluginServerHandler};
use crate::ss_plugins::kcptun::config::{
    KcptunConfig, KcptunCrypt as RuntimeKcptunCrypt, KcptunMode as RuntimeKcptunMode,
};
use crate::ss_plugins::kcptun::server::{KcptunServer, KcptunServerLimits};
use crate::ss_plugins::obfs::{
    ObfsHttpConfig, ObfsHttpServerHandler, ObfsTlsConfig, ObfsTlsServerHandler,
};
use crate::ss_plugins::restls::{
    ClientChainRestlsConnector, RestlsPluginServerHandler, RestlsRuntimeLimits, RestlsScript,
};
use crate::ss_plugins::shadow_tls::{ClientChainShadowTlsConnector, ShadowTlsPluginServerHandler};
use crate::ss_plugins::v2ray::{
    V2rayPluginServerConfig, V2rayPluginServerHandler, V2rayTransportMode,
};
use crate::tcp::chain_builder::{
    build_client_chain_group, build_client_proxy_chain, build_direct_chain_group,
};
use crate::tcp::tcp_handler::{
    AuthenticatedUser, ServerUser, TcpServerHandler, TcpServerSetupResult,
};
use crate::tcp::tcp_server::start_tcp_handler_servers;
use crate::thread_util::get_num_threads;
use crate::tls_server_handler::{
    InnerProtocol, NaiveConfig, TlsServerHandler, TlsServerTarget, VisionVlessConfig,
};
use crate::trojan_handler::TrojanTcpHandler;
use crate::tuic_server::{TuicServerUser, TuicServerUsers, start_tuic_server};
use crate::v2board::grpc::GrpcServerHandler;
use crate::v2board::http::{V2RayHttp2ServerHandler, V2RayHttpServerHandler};
use crate::v2board::httpupgrade::HttpUpgradeServerHandler;
use crate::v2board::outbound::compiler::compile_route_rules;
use crate::v2board::outbound::dispatcher::OutboundDispatcher;
use crate::v2board::proxy_protocol::ProxyProtocolServerHandler;
use crate::v2board::route_rule_set::{load_geoip_matchers, load_geosite_matchers};
use crate::v2board::runtime_model::{
    RuntimeNodeSpec, RuntimeProtocol, RuntimeSecurity, RuntimeTls, RuntimeTransport,
    ShadowsocksObfs, TcpHeader, normalize_node,
};
use crate::v2board::tracker::TrafficTracker;
use crate::v2board::xhttp::XHttpServerHandler;
use crate::vless::vless_server_handler::VlessTcpServerHandler;
use crate::vmess::VmessTcpServerHandler;
use crate::websocket::{WebsocketServerTarget, WebsocketTcpServerHandler};

use super::plugin_api::{
    GostPluginOptions, KcptunCrypt, KcptunMode, KcptunOptions, ObfsMode, ObfsOptions,
    PluginRuntimeManifest, RuntimePlugin,
};
use super::types::{ServerConfig, UserInfo};

const VLESS_XTLS_VISION_FLOW: &str = "xtls-rprx-vision";

type VlessVisionUser = (Box<[u8]>, Option<AuthenticatedUser>);

#[derive(Clone)]
pub struct RuntimeNode {
    pub tag: String,
    pub bind_location: BindLocation,
    kind: RuntimeNodeKind,
}

#[derive(Clone)]
enum RuntimeNodeKind {
    Tcp {
        handler: Arc<dyn TcpServerHandler>,
        tcp_config: TcpConfig,
    },
    Tuic {
        quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
        users: TuicServerUsers,
        proxy_selector: Arc<ClientProxySelector>,
        zero_rtt_handshake: bool,
        congestion_control: Option<String>,
        num_endpoints: usize,
    },
    Hysteria2 {
        quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
        users: Hysteria2ServerUsers,
        proxy_selector: Arc<ClientProxySelector>,
        num_endpoints: usize,
        udp_enabled: bool,
        up_mbps: u64,
        down_mbps: u64,
        ignore_client_bandwidth: bool,
        obfs: Option<Hysteria2Obfs>,
        masquerade: Option<Hysteria2Masquerade>,
    },
    NaiveH3 {
        quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
        naive_cfg: NaiveConfig,
        proxy_selector: Arc<ClientProxySelector>,
        congestion_control: Option<String>,
        num_endpoints: usize,
    },
    NaiveCombined {
        handler: Arc<dyn TcpServerHandler>,
        tcp_config: TcpConfig,
        quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
        naive_cfg: NaiveConfig,
        proxy_selector: Arc<ClientProxySelector>,
        congestion_control: Option<String>,
        num_endpoints: usize,
    },
    Kcptun {
        config: KcptunConfig,
        limits: KcptunServerLimits,
        raw_handler: Arc<dyn TcpServerHandler>,
    },
}

impl RuntimeNode {
    pub fn new_tcp(
        tag: String,
        bind_location: BindLocation,
        handler: Arc<dyn TcpServerHandler>,
        tcp_config: TcpConfig,
    ) -> Self {
        Self {
            tag,
            bind_location,
            kind: RuntimeNodeKind::Tcp {
                handler,
                tcp_config,
            },
        }
    }

    pub fn tcp_parts(&self) -> std::io::Result<(Arc<dyn TcpServerHandler>, TcpConfig)> {
        match &self.kind {
            RuntimeNodeKind::Tcp {
                handler,
                tcp_config,
            } => Ok((handler.clone(), tcp_config.clone())),
            _ => invalid(format!(
                "node `{}` cannot be used as a TCP plugin upstream",
                self.tag
            )),
        }
    }

    pub fn new_kcptun(
        tag: String,
        bind_location: BindLocation,
        config: KcptunConfig,
        limits: KcptunServerLimits,
        raw_handler: Arc<dyn TcpServerHandler>,
    ) -> Self {
        Self {
            tag,
            bind_location,
            kind: RuntimeNodeKind::Kcptun {
                config,
                limits,
                raw_handler,
            },
        }
    }

    pub async fn start(self, resolver: Arc<dyn Resolver>) -> std::io::Result<Vec<JoinHandle<()>>> {
        log::info!(
            "Starting V2Board node `{}` at {}",
            self.tag,
            self.bind_location
        );
        match self.kind {
            RuntimeNodeKind::Tcp {
                handler,
                tcp_config,
            } => start_tcp_handler_servers(self.bind_location, tcp_config, handler, resolver).await,
            RuntimeNodeKind::Tuic {
                quic_server_config,
                users,
                proxy_selector,
                zero_rtt_handshake,
                congestion_control,
                num_endpoints,
            } => {
                let bind_addresses = match self.bind_location {
                    BindLocation::Address(address) => address.to_socket_addrs()?,
                    BindLocation::Path(path) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "node `{}` tuic cannot listen on unix socket {}",
                                self.tag,
                                path.display()
                            ),
                        ));
                    }
                };
                let mut handles = Vec::new();
                for bind_address in bind_addresses {
                    handles.extend(
                        start_tuic_server(
                            bind_address,
                            quic_server_config.clone(),
                            users.clone(),
                            proxy_selector.clone(),
                            resolver.clone(),
                            num_endpoints,
                            zero_rtt_handshake,
                            congestion_control.clone(),
                        )
                        .await?,
                    );
                }
                Ok(handles)
            }
            RuntimeNodeKind::Hysteria2 {
                quic_server_config,
                users,
                proxy_selector,
                num_endpoints,
                udp_enabled,
                up_mbps,
                down_mbps,
                ignore_client_bandwidth,
                obfs,
                masquerade,
            } => {
                let bind_addresses = match self.bind_location {
                    BindLocation::Address(address) => address.to_socket_addrs()?,
                    BindLocation::Path(path) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "node `{}` hysteria2 cannot listen on unix socket {}",
                                self.tag,
                                path.display()
                            ),
                        ));
                    }
                };
                let mut handles = Vec::new();
                for bind_address in bind_addresses {
                    handles.extend(
                        start_hysteria2_server(Hysteria2StartConfig {
                            bind_address,
                            quic_server_config: quic_server_config.clone(),
                            users: users.clone(),
                            client_proxy_selector: proxy_selector.clone(),
                            resolver: resolver.clone(),
                            num_endpoints,
                            udp_enabled,
                            up_mbps,
                            down_mbps,
                            ignore_client_bandwidth,
                            obfs: obfs.clone(),
                            masquerade: masquerade.clone(),
                        })
                        .await?,
                    );
                }
                Ok(handles)
            }
            RuntimeNodeKind::NaiveH3 {
                quic_server_config,
                naive_cfg,
                proxy_selector,
                congestion_control,
                num_endpoints,
            } => {
                let bind_addresses = match self.bind_location {
                    BindLocation::Address(address) => address.to_socket_addrs()?,
                    BindLocation::Path(path) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "node `{}` naiveproxy H3 cannot listen on unix socket {}",
                                self.tag,
                                path.display()
                            ),
                        ));
                    }
                };
                let mut handles = Vec::new();
                for bind_address in bind_addresses {
                    handles.extend(
                        start_naive_h3_server(
                            bind_address,
                            quic_server_config.clone(),
                            naive_cfg.clone(),
                            proxy_selector.clone(),
                            resolver.clone(),
                            num_endpoints,
                            congestion_control.clone(),
                        )
                        .await?,
                    );
                }
                Ok(handles)
            }
            RuntimeNodeKind::NaiveCombined {
                handler,
                tcp_config,
                quic_server_config,
                naive_cfg,
                proxy_selector,
                congestion_control,
                num_endpoints,
            } => {
                let bind_addresses = match self.bind_location.clone() {
                    BindLocation::Address(address) => address.to_socket_addrs()?,
                    BindLocation::Path(path) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "node `{}` naiveproxy dual TCP/H3 cannot listen on unix socket {}",
                                self.tag,
                                path.display()
                            ),
                        ));
                    }
                };
                let mut handles = start_tcp_handler_servers(
                    self.bind_location,
                    tcp_config,
                    handler,
                    resolver.clone(),
                )
                .await?;
                for bind_address in bind_addresses {
                    handles.extend(
                        start_naive_h3_server(
                            bind_address,
                            quic_server_config.clone(),
                            naive_cfg.clone(),
                            proxy_selector.clone(),
                            resolver.clone(),
                            num_endpoints,
                            congestion_control.clone(),
                        )
                        .await?,
                    );
                }
                Ok(handles)
            }
            RuntimeNodeKind::Kcptun {
                config,
                limits,
                raw_handler,
            } => {
                let bind_addresses = match self.bind_location {
                    BindLocation::Address(address) => address.to_socket_addrs()?,
                    BindLocation::Path(path) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "node `{}` kcptun cannot listen on unix socket {}",
                                self.tag,
                                path.display()
                            ),
                        ));
                    }
                };
                let mut handles = Vec::new();
                for bind_address in bind_addresses {
                    let server = KcptunServer::bind_with_tcp_handler(
                        bind_address,
                        config.clone(),
                        limits.clone(),
                        raw_handler.clone(),
                        resolver.clone(),
                    )
                    .await?;
                    let tag = self.tag.clone();
                    handles.push(tokio::spawn(async move {
                        if let Err(error) = server.wait().await {
                            log::error!("node `{tag}` Kcptun server stopped: {error}");
                        }
                    }));
                }
                Ok(handles)
            }
        }
    }

    pub async fn readiness_probe(&self) -> std::io::Result<()> {
        if !matches!(&self.kind, RuntimeNodeKind::Tcp { .. }) {
            return Ok(());
        }
        match &self.bind_location {
            BindLocation::Address(address) => {
                let addresses = address.to_socket_addrs()?;
                let mut last_error = None;
                for mut address in addresses {
                    if address.ip().is_unspecified() {
                        address.set_ip(if address.is_ipv4() {
                            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                        } else {
                            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                        });
                    }
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        tokio::net::TcpStream::connect(address),
                    )
                    .await
                    {
                        Ok(Ok(_)) => return Ok(()),
                        Ok(Err(error)) => last_error = Some(error),
                        Err(_) => {
                            last_error = Some(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                format!("TCP readiness probe to {address} timed out"),
                            ));
                        }
                    }
                }
                Err(last_error.unwrap_or_else(|| {
                    invalid_error(format!(
                        "node `{}` TCP readiness address resolved empty",
                        self.tag
                    ))
                }))
            }
            #[cfg(unix)]
            BindLocation::Path(path) => {
                tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    tokio::net::UnixStream::connect(path),
                )
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("unix readiness probe to {} timed out", path.display()),
                    )
                })??;
                Ok(())
            }
            #[cfg(not(unix))]
            BindLocation::Path(path) => Err(invalid_error(format!(
                "unix readiness probe is unavailable for {}",
                path.display()
            ))),
        }
    }
}

pub fn map_node(
    app_config: &AppConfig,
    node: &V2BoardNodeConfig,
    server: &ServerConfig,
    users: &[UserInfo],
    tracker: Arc<TrafficTracker>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<RuntimeNode> {
    if app_config.runtime.tcp_fast_open {
        return invalid(
            "runtime.tcp_fast_open is not supported by the V2Board runtime; set it to false",
        );
    }
    let spec = normalize_node(app_config, node, server, users)?;
    let outbound_dispatcher = build_outbound_dispatcher(app_config, &node.tag, &resolver)?;
    build_runtime_node(
        spec,
        tracker,
        resolver,
        app_config.runtime.max_legacy_shadowsocks_users,
        outbound_dispatcher,
    )
}

/// Builds the complete raw-SS plus public-plugin listener set for one manifest.
///
/// The returned nodes are intentionally not started here; `RuntimeGraph`
/// health-gates the whole set before committing the generation.
pub fn map_shadowsocks_plugin_nodes(
    app_config: &AppConfig,
    node: &V2BoardNodeConfig,
    server: &ServerConfig,
    users: &[UserInfo],
    manifest: &PluginRuntimeManifest,
    tracker: Arc<TrafficTracker>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<RuntimeNode>> {
    if node.node_type != NodeType::Shadowsocks {
        return invalid("plugin runtime can only be built for a Shadowsocks node");
    }
    if server.server_port != manifest.server_port
        || server.cipher.as_deref() != Some(manifest.cipher.as_str())
        || server.server_key.as_deref()
            != manifest
                .server_key
                .as_ref()
                .map(|secret| secret.expose_secret())
        || server.routes != manifest.routes
    {
        return invalid(format!(
            "node `{}` /config and /plugin-config raw Shadowsocks settings disagree",
            node.tag
        ));
    }
    if server.config_revision.as_ref() != Some(&manifest.config_revision) {
        return invalid(format!(
            "node `{}` /config and /plugin-config revisions are not coherent",
            node.tag
        ));
    }

    let spec = normalize_node(app_config, node, server, users)?;
    let public_host = spec.bind.listen.clone();
    let multiplex = manifest.multiplex.as_ref().filter(|mux| mux.enabled);
    if multiplex.is_some_and(|mux| mux.brutal.enabled) {
        return invalid(format!(
            "node `{}` requests TCP Brutal, which is not implemented by the server mux runtime",
            node.tag
        ));
    }
    let outbound_dispatcher = build_outbound_dispatcher(app_config, &node.tag, &resolver)?;
    let raw_public = build_runtime_node_with_shadowsocks_mux(
        spec,
        tracker,
        resolver.clone(),
        app_config.runtime.max_legacy_shadowsocks_users,
        multiplex.map(|mux| mux.padding),
        outbound_dispatcher,
    )?;
    let Some(plugin) = manifest.plugin.as_ref() else {
        return Ok(vec![raw_public]);
    };
    let (raw_handler, tcp_config) = raw_public.tcp_parts()?;
    let raw_loopback = RuntimeNode::new_tcp(
        node.tag.clone(),
        plugin_bind_location("127.0.0.1", manifest.server_port, &node.tag)?,
        raw_handler.clone(),
        tcp_config.clone(),
    );
    let public_bind = plugin_bind_location(&public_host, plugin.listen_port(), &node.tag)?;
    let public_edge = match plugin {
        RuntimePlugin::Kcptun { options, .. } => RuntimeNode::new_kcptun(
            node.tag.clone(),
            public_bind,
            build_kcptun_config(options)?,
            KcptunServerLimits::default(),
            raw_handler,
        ),
        _ => {
            let edge_handler =
                build_shadowsocks_plugin_handler(app_config, node, plugin, raw_handler, resolver)?;
            RuntimeNode::new_tcp(node.tag.clone(), public_bind, edge_handler, tcp_config)
        }
    };
    Ok(vec![raw_loopback, public_edge])
}

fn build_shadowsocks_plugin_handler(
    app_config: &AppConfig,
    node: &V2BoardNodeConfig,
    plugin: &RuntimePlugin,
    raw_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Arc<dyn TcpServerHandler>> {
    match plugin {
        RuntimePlugin::Obfs { options, .. } => build_obfs_plugin_handler(options, raw_handler),
        RuntimePlugin::V2ray { options, .. } => {
            let tls = if options.tls {
                Some(build_plugin_tls_config(app_config, node)?)
            } else {
                None
            };
            let config = V2rayPluginServerConfig {
                mode: if options.v2ray_http_upgrade {
                    V2rayTransportMode::HttpUpgrade
                } else {
                    V2rayTransportMode::Websocket
                },
                tls,
                host: Some(options.host.clone()),
                path: options.path.clone(),
                mux: options.mux,
                ..Default::default()
            };
            V2rayPluginServerHandler::new(config, raw_handler, resolver)
                .map(|handler| Arc::new(handler) as Arc<dyn TcpServerHandler>)
        }
        RuntimePlugin::Gost { options, .. } => {
            build_gost_plugin_handler(app_config, node, options, raw_handler, resolver)
        }
        RuntimePlugin::ShadowTls { options, .. } => {
            build_shadow_tls_plugin_handler(options, raw_handler, resolver)
        }
        RuntimePlugin::Restls { options, .. } => {
            build_restls_plugin_handler(options, raw_handler, resolver)
        }
        RuntimePlugin::Kcptun { .. } => invalid(format!(
            "node `{}` Kcptun requires the UDP runtime graph",
            node.tag
        )),
    }
}

fn build_shadow_tls_plugin_handler(
    options: &super::plugin_api::ShadowTlsOptions,
    raw_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Arc<dyn TcpServerHandler>> {
    let handler = match options.version {
        1 => {
            let connector = Arc::new(ClientChainShadowTlsConnector::new(
                &options.host,
                direct_client_chain(resolver.clone()),
                resolver,
            )?);
            ShadowTlsPluginServerHandler::new_v1(connector, raw_handler)
        }
        2 => {
            let password = options.password.as_ref().ok_or_else(|| {
                invalid_error("ShadowTLS v2 manifest is missing its required password")
            })?;
            let connector = Arc::new(ClientChainShadowTlsConnector::new(
                &options.host,
                direct_client_chain(resolver.clone()),
                resolver,
            )?);
            ShadowTlsPluginServerHandler::new_v2(password.expose_secret(), connector, raw_handler)?
        }
        3 => {
            let password = options.password.as_ref().ok_or_else(|| {
                invalid_error("ShadowTLS v3 manifest is missing its required password")
            })?;
            let location = NetLocation::new(Address::from(options.host.as_str())?, 443);
            let target = Arc::new(ShadowTlsServerTarget::new(
                password.expose_secret().to_string(),
                ShadowTlsServerTargetHandshake::new_remote(
                    location,
                    direct_client_chain(resolver.clone()),
                ),
                Box::new(ArcTcpServerHandler(raw_handler)),
            ));
            let fallback_connector = Arc::new(ClientChainShadowTlsConnector::new(
                &options.host,
                direct_client_chain(resolver.clone()),
                resolver.clone(),
            )?);
            ShadowTlsPluginServerHandler::new_v3_with_fallback(target, resolver, fallback_connector)
        }
        version => {
            return invalid(format!("unsupported ShadowTLS plugin version {version}"));
        }
    };
    Ok(Arc::new(handler))
}

fn build_restls_plugin_handler(
    options: &super::plugin_api::RestlsOptions,
    raw_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Arc<dyn TcpServerHandler>> {
    let script = options
        .restls_script
        .parse::<RestlsScript>()
        .map_err(|error| invalid_error(format!("invalid Restls script: {error}")))?;
    let connector = Arc::new(ClientChainRestlsConnector::new(
        &options.host,
        direct_client_chain(resolver.clone()),
        resolver,
    )?);
    RestlsPluginServerHandler::new(
        options.password.expose_secret(),
        script,
        connector,
        raw_handler,
        RestlsRuntimeLimits::default(),
    )
    .map(|handler| Arc::new(handler) as Arc<dyn TcpServerHandler>)
}

fn direct_client_chain(resolver: Arc<dyn Resolver>) -> crate::client_proxy_chain::ClientProxyChain {
    build_client_proxy_chain(
        OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
            ClientConfig::default(),
        ))),
        resolver,
    )
}

fn build_kcptun_config(options: &KcptunOptions) -> std::io::Result<KcptunConfig> {
    Ok(KcptunConfig {
        key: options.key.expose_secret().to_string(),
        crypt: match options.crypt {
            KcptunCrypt::Aes => RuntimeKcptunCrypt::Aes,
            KcptunCrypt::Aes128 => RuntimeKcptunCrypt::Aes128,
            KcptunCrypt::Aes128Gcm => RuntimeKcptunCrypt::Aes128Gcm,
            KcptunCrypt::Aes192 => RuntimeKcptunCrypt::Aes192,
            KcptunCrypt::Salsa20 => RuntimeKcptunCrypt::Salsa20,
            KcptunCrypt::Blowfish => RuntimeKcptunCrypt::Blowfish,
            KcptunCrypt::Twofish => RuntimeKcptunCrypt::Twofish,
            KcptunCrypt::Cast5 => RuntimeKcptunCrypt::Cast5,
            KcptunCrypt::TripleDes => RuntimeKcptunCrypt::TripleDes,
            KcptunCrypt::Tea => RuntimeKcptunCrypt::Tea,
            KcptunCrypt::Xtea => RuntimeKcptunCrypt::Xtea,
            KcptunCrypt::Xor => RuntimeKcptunCrypt::Xor,
            KcptunCrypt::None => RuntimeKcptunCrypt::None,
            KcptunCrypt::Null => RuntimeKcptunCrypt::Null,
        },
        mode: match options.mode {
            KcptunMode::Fast3 => RuntimeKcptunMode::Fast3,
            KcptunMode::Fast2 => RuntimeKcptunMode::Fast2,
            KcptunMode::Fast => RuntimeKcptunMode::Fast,
            KcptunMode::Normal => RuntimeKcptunMode::Normal,
            KcptunMode::Manual => RuntimeKcptunMode::Manual,
        },
        mtu: options.mtu,
        rate_limit: options.ratelimit,
        send_window: options.sndwnd,
        receive_window: options.rcvwnd,
        data_shards: options.datashard,
        parity_shards: options.parityshard,
        dscp: options.dscp,
        no_compression: options.nocomp,
        ack_no_delay: options.acknodelay,
        no_delay: options.nodelay != 0,
        interval_ms: u32::from(options.interval),
        resend: options.resend,
        no_congestion: options.nc != 0,
        socket_buffer: options.sockbuf,
        smux_version: options.smuxver,
        smux_buffer: options.smuxbuf,
        frame_size: u16::try_from(options.framesize)
            .map_err(|_| invalid_error("Kcptun framesize exceeds u16"))?,
        stream_buffer: options.streambuf,
        keepalive_secs: options.keepalive,
    })
}

fn build_obfs_plugin_handler(
    options: &ObfsOptions,
    raw_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<Arc<dyn TcpServerHandler>> {
    let expected_hosts = vec![options.host.clone()];
    Ok(match options.mode {
        ObfsMode::Http => Arc::new(ObfsHttpServerHandler::new(
            ObfsHttpConfig {
                expected_hosts,
                ..Default::default()
            },
            raw_handler,
        )),
        ObfsMode::Tls => Arc::new(ObfsTlsServerHandler::new(
            ObfsTlsConfig {
                expected_hosts,
                ..Default::default()
            },
            raw_handler,
        )),
    })
}

fn build_gost_plugin_handler(
    app_config: &AppConfig,
    node: &V2BoardNodeConfig,
    options: &GostPluginOptions,
    raw_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Arc<dyn TcpServerHandler>> {
    let tls = if options.tls {
        Some(build_plugin_tls_config(app_config, node)?)
    } else {
        None
    };
    let config = GostPluginServerConfig {
        tls,
        host: Some(options.host.clone()),
        path: options.path.clone(),
        mux: options.mux,
        ..Default::default()
    };
    GostPluginServerHandler::new(config, raw_handler, resolver)
        .map(|handler| Arc::new(handler) as Arc<dyn TcpServerHandler>)
}

fn build_plugin_tls_config(
    app_config: &AppConfig,
    node: &V2BoardNodeConfig,
) -> std::io::Result<Arc<rustls::ServerConfig>> {
    let tls = app_config.effective_tls(node).ok_or_else(|| {
        invalid_error(format!(
            "node `{}` plugin TLS requires a local cert_file/key_file",
            node.tag
        ))
    })?;
    let cert = std::fs::read(&tls.cert_file).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "node `{}` failed to read plugin TLS certificate {}: {error}",
                node.tag,
                tls.cert_file.display()
            ),
        )
    })?;
    let key = std::fs::read(&tls.key_file).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "node `{}` failed to read plugin TLS key {}: {error}",
                node.tag,
                tls.key_file.display()
            ),
        )
    })?;
    Ok(Arc::new(create_server_config(
        &cert,
        &key,
        Vec::new(),
        &["http/1.1".to_string()],
        &[],
    )))
}

fn plugin_bind_location(host: &str, port: u16, tag: &str) -> std::io::Result<BindLocation> {
    let location = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    NetLocation::from_str(&location, None)
        .map(BindLocation::from)
        .map_err(|error| {
            invalid_error(format!(
                "invalid plugin bind address for node `{tag}`: {error}"
            ))
        })
}

/// Builds the node-side outbound dispatcher from local routing config.
///
/// Returns `None` when no routing is configured (outbounds, route rules,
/// rule providers, or `default_out` all absent), preserving the legacy
/// direct-only dial path.
fn build_outbound_dispatcher(
    app_config: &AppConfig,
    node_tag: &str,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<Option<Arc<OutboundDispatcher>>> {
    if app_config.outbounds.is_empty()
        && app_config.route_rules.is_empty()
        && app_config.rule_providers.is_empty()
        && app_config.default_out.is_none()
    {
        return Ok(None);
    }
    let rules = Arc::new(compile_route_rules(
        node_tag,
        &app_config.route_rules,
        &app_config.rule_providers,
        &app_config.v2board.route_rule_sets,
    )?);
    let direct = Arc::new(build_direct_chain_group(resolver.clone()));
    let by_tag: HashMap<&str, &OutboundConfig> = app_config
        .outbounds
        .iter()
        .map(|outbound| (outbound.tag.as_str(), outbound))
        .collect();
    let mut resolved: HashMap<&str, Vec<ClientConfig>> = HashMap::new();
    let mut chains: HashMap<String, Arc<ClientChainGroup>> = HashMap::new();
    for outbound in &app_config.outbounds {
        let hops = resolve_outbound_hops(&outbound.tag, &by_tag, &mut resolved)?;
        let group = if matches!(outbound.spec, OutboundSpec::Direct) {
            direct.clone()
        } else {
            Arc::new(build_client_chain_group(
                NoneOrSome::One(ClientChain {
                    hops: OneOrSome::Some(
                        hops.into_iter()
                            .map(|config| ClientChainHop::Single(ConfigSelection::Config(config)))
                            .collect(),
                    ),
                }),
                resolver.clone(),
            ))
        };
        chains.insert(outbound.tag.clone(), group);
    }
    Ok(Some(Arc::new(OutboundDispatcher::new(
        Some(rules),
        chains,
        app_config.default_out.clone(),
        direct,
    ))))
}

/// Resolves the full hop `ClientConfig` list for an outbound tag, expanding
/// `chain` references (nested chains are flattened depth-first). The
/// memoization key is the outbound tag; `validate_outbounds` has already
/// rejected cycles and unknown references.
fn resolve_outbound_hops<'a>(
    tag: &'a str,
    by_tag: &HashMap<&'a str, &'a OutboundConfig>,
    resolved: &mut HashMap<&'a str, Vec<ClientConfig>>,
) -> std::io::Result<Vec<ClientConfig>> {
    if let Some(hops) = resolved.get(tag) {
        return Ok(hops.clone());
    }
    let outbound = by_tag.get(tag).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("outbound `{tag}` is referenced but not configured"),
        )
    })?;
    let hops = if let Some(chain) = &outbound.chain {
        let mut hops = Vec::new();
        for hop in chain {
            hops.extend(resolve_outbound_hops(hop, by_tag, resolved)?);
        }
        hops
    } else {
        vec![outbound.to_client_config()?]
    };
    resolved.insert(tag, hops.clone());
    Ok(hops)
}

fn build_runtime_node(
    spec: RuntimeNodeSpec,
    tracker: Arc<TrafficTracker>,
    resolver: Arc<dyn Resolver>,
    max_legacy_shadowsocks_users: usize,
    outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
) -> std::io::Result<RuntimeNode> {
    build_runtime_node_with_shadowsocks_mux(
        spec,
        tracker,
        resolver,
        max_legacy_shadowsocks_users,
        None,
        outbound_dispatcher,
    )
}

fn build_runtime_node_with_shadowsocks_mux(
    spec: RuntimeNodeSpec,
    tracker: Arc<TrafficTracker>,
    resolver: Arc<dyn Resolver>,
    max_legacy_shadowsocks_users: usize,
    shadowsocks_mux_padding: Option<bool>,
    outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
) -> std::io::Result<RuntimeNode> {
    let bind_location = bind_location(&spec)?;
    let proxy_selector = Arc::new(build_v2board_proxy_selector(&spec, resolver.clone())?);
    match spec.node_type {
        // UDP-only listeners do not use the outbound dispatcher yet; the
        // legacy selector dial path applies.
        NodeType::Tuic => return build_tuic_runtime_node(spec, tracker, proxy_selector),
        NodeType::Hysteria => {
            return build_hysteria2_runtime_node(spec, tracker, proxy_selector);
        }
        NodeType::Naiveproxy => {
            return build_naiveproxy_runtime_node(spec, tracker, proxy_selector, resolver);
        }
        _ => {}
    }
    let protocol = build_protocol_handler(
        &spec,
        tracker.clone(),
        proxy_selector.clone(),
        resolver.clone(),
        max_legacy_shadowsocks_users,
        shadowsocks_mux_padding,
        outbound_dispatcher,
    )?;
    let transport = build_transport_handler(&spec, protocol, resolver.clone())?;
    let mut handler = build_security_handler(&spec, transport, tracker, proxy_selector, resolver)?;
    if spec.accept_proxy_protocol {
        handler = Arc::new(ProxyProtocolServerHandler::new(handler));
    }

    Ok(RuntimeNode {
        tag: spec.tag,
        bind_location,
        kind: RuntimeNodeKind::Tcp {
            handler,
            tcp_config: TcpConfig { no_delay: true },
        },
    })
}

fn build_tuic_runtime_node(
    spec: RuntimeNodeSpec,
    tracker: Arc<TrafficTracker>,
    proxy_selector: Arc<ClientProxySelector>,
) -> std::io::Result<RuntimeNode> {
    let bind_location = bind_location(&spec)?;
    let (zero_rtt_handshake, congestion_control, udp_relay_mode, disable_sni) = match &spec.protocol
    {
        RuntimeProtocol::Tuic {
            zero_rtt_handshake,
            congestion_control,
            udp_relay_mode,
            disable_sni,
        } => (
            *zero_rtt_handshake,
            congestion_control.clone(),
            udp_relay_mode.clone(),
            *disable_sni,
        ),
        _ => {
            return invalid(format!(
                "node `{}` type/protocol mismatch in V2Board runtime model",
                spec.tag
            ));
        }
    };
    if !matches!(spec.transport, RuntimeTransport::Quic) {
        return invalid(format!(
            "node `{}` tuic requires QUIC transport in V2Board runtime model",
            spec.tag
        ));
    }
    if spec.accept_proxy_protocol {
        return invalid(format!(
            "node `{}` tuic does not support network_settings.acceptProxyProtocol; QUIC cannot use the TCP PROXY protocol parser",
            spec.tag
        ));
    }
    if let Some(mode) = &udp_relay_mode
        && !matches!(
            mode.trim().to_ascii_lowercase().as_str(),
            "native" | "quic" | "packetaddr" | "packet_addr"
        )
    {
        return invalid(format!(
            "node `{}` tuic udp_relay_mode `{mode}` is not supported",
            spec.tag
        ));
    }
    if disable_sni {
        log::debug!(
            "node `{}` tuic disable_sni is a client-side panel option and is ignored inbound",
            spec.tag
        );
    }

    let tls = match &spec.security {
        RuntimeSecurity::Tls(tls) => tls,
        RuntimeSecurity::None => {
            return invalid(format!(
                "node `{}` tuic requires TLS in production V2Board runtime",
                spec.tag
            ));
        }
        RuntimeSecurity::Reality(_) => {
            return invalid(format!("node `{}` tuic does not support Reality", spec.tag));
        }
    };
    let quic_server_config = build_quic_server_config(&spec, tls, "tuic")?;
    let users = tuic_server_users(&spec, tracker)?;

    Ok(RuntimeNode {
        tag: spec.tag,
        bind_location,
        kind: RuntimeNodeKind::Tuic {
            quic_server_config,
            users,
            proxy_selector,
            zero_rtt_handshake,
            congestion_control,
            num_endpoints: get_num_threads().max(1),
        },
    })
}

fn build_hysteria2_runtime_node(
    spec: RuntimeNodeSpec,
    tracker: Arc<TrafficTracker>,
    proxy_selector: Arc<ClientProxySelector>,
) -> std::io::Result<RuntimeNode> {
    let bind_location = bind_location(&spec)?;
    let (up_mbps, down_mbps, ignore_client_bandwidth, obfs, obfs_password, masquerade) =
        match &spec.protocol {
            RuntimeProtocol::Hysteria2 {
                up_mbps,
                down_mbps,
                ignore_client_bandwidth,
                obfs,
                obfs_password,
                masquerade,
            } => (
                *up_mbps,
                *down_mbps,
                *ignore_client_bandwidth,
                obfs.clone(),
                obfs_password.clone(),
                masquerade.clone(),
            ),
            _ => {
                return invalid(format!(
                    "node `{}` type/protocol mismatch in V2Board runtime model",
                    spec.tag
                ));
            }
        };
    if !matches!(spec.transport, RuntimeTransport::Quic) {
        return invalid(format!(
            "node `{}` hysteria2 requires QUIC transport in V2Board runtime model",
            spec.tag
        ));
    }
    if spec.accept_proxy_protocol {
        return invalid(format!(
            "node `{}` hysteria2 does not support network_settings.acceptProxyProtocol; QUIC cannot use the TCP PROXY protocol parser",
            spec.tag
        ));
    }
    let obfs = hysteria2_obfs_for_node(&spec.tag, obfs.as_deref(), obfs_password.as_deref())?;
    let masquerade = masquerade
        .map(|masquerade| {
            Hysteria2Masquerade::try_new(
                masquerade.status_code,
                masquerade.content_type,
                Bytes::from(masquerade.body),
            )
        })
        .transpose()?;

    let tls = match &spec.security {
        RuntimeSecurity::Tls(tls) => tls,
        RuntimeSecurity::None => {
            return invalid(format!(
                "node `{}` hysteria2 requires TLS in production V2Board runtime",
                spec.tag
            ));
        }
        RuntimeSecurity::Reality(_) => {
            return invalid(format!(
                "node `{}` hysteria2 does not support Reality",
                spec.tag
            ));
        }
    };
    let quic_server_config = build_quic_server_config(&spec, tls, "hysteria2")?;
    let users = hysteria2_server_users(&spec, tracker)?;

    Ok(RuntimeNode {
        tag: spec.tag,
        bind_location,
        kind: RuntimeNodeKind::Hysteria2 {
            quic_server_config,
            users,
            proxy_selector,
            num_endpoints: get_num_threads().max(1),
            udp_enabled: true,
            up_mbps,
            down_mbps,
            ignore_client_bandwidth,
            obfs,
            masquerade,
        },
    })
}

fn build_naiveproxy_runtime_node(
    spec: RuntimeNodeSpec,
    tracker: Arc<TrafficTracker>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<RuntimeNode> {
    let bind_location = bind_location(&spec)?;
    let quic_congestion_control = match &spec.protocol {
        RuntimeProtocol::Naiveproxy {
            quic_congestion_control,
        } => quic_congestion_control.clone(),
        _ => {
            return invalid(format!(
                "node `{}` type/protocol mismatch in V2Board runtime model",
                spec.tag
            ));
        }
    };
    let tls = match &spec.security {
        RuntimeSecurity::Tls(tls) => tls,
        RuntimeSecurity::None => {
            return invalid(format!(
                "node `{}` naiveproxy requires TLS in production V2Board runtime",
                spec.tag
            ));
        }
        RuntimeSecurity::Reality(_) => {
            return invalid(format!(
                "node `{}` naiveproxy does not support Reality in V2Board runtime",
                spec.tag
            ));
        }
    };

    let naive_cfg = NaiveConfig {
        users: Arc::new(naiveproxy_user_lookup(&spec, tracker)?),
        fallback_path: None,
        udp_enabled: true,
        padding_enabled: true,
    };

    match &spec.transport {
        RuntimeTransport::Tcp { header: None } => {
            validate_naiveproxy_tls_options(&spec, tls, NaiveProxyTransportMode::Tcp)?;
            if quic_congestion_control.is_some() {
                return invalid(format!(
                    "node `{}` naiveproxy quic_congestion_control requires QUIC/H3 transport",
                    spec.tag
                ));
            }
            let handler = build_tls_handler(
                &spec,
                tls,
                InnerProtocol::Naive(naive_cfg),
                proxy_selector,
                resolver,
            )?;
            let handler = if spec.accept_proxy_protocol {
                Arc::new(ProxyProtocolServerHandler::new(handler)) as Arc<dyn TcpServerHandler>
            } else {
                handler
            };

            Ok(RuntimeNode {
                tag: spec.tag,
                bind_location,
                kind: RuntimeNodeKind::Tcp {
                    handler,
                    tcp_config: TcpConfig { no_delay: true },
                },
            })
        }
        RuntimeTransport::Quic => {
            if spec.accept_proxy_protocol {
                return invalid(format!(
                    "node `{}` naiveproxy H3 does not support network_settings.acceptProxyProtocol; QUIC cannot use the TCP PROXY protocol parser",
                    spec.tag
                ));
            }
            validate_naiveproxy_tls_options(&spec, tls, NaiveProxyTransportMode::Quic)?;
            validate_naive_quic_congestion_control(quic_congestion_control.as_deref())
                .map_err(|e| std::io::Error::new(e.kind(), format!("node `{}` {e}", spec.tag)))?;
            let quic_server_config = build_quic_server_config(&spec, tls, "naiveproxy")?;
            Ok(RuntimeNode {
                tag: spec.tag,
                bind_location,
                kind: RuntimeNodeKind::NaiveH3 {
                    quic_server_config,
                    naive_cfg,
                    proxy_selector,
                    congestion_control: quic_congestion_control,
                    num_endpoints: get_num_threads().max(1),
                },
            })
        }
        RuntimeTransport::TcpAndQuic => {
            if spec.accept_proxy_protocol {
                return invalid(format!(
                    "node `{}` naiveproxy dual TCP/H3 does not support network_settings.acceptProxyProtocol; QUIC cannot use the TCP PROXY protocol parser",
                    spec.tag
                ));
            }
            validate_naiveproxy_tls_options(&spec, tls, NaiveProxyTransportMode::TcpAndQuic)?;
            validate_naive_quic_congestion_control(quic_congestion_control.as_deref())
                .map_err(|e| std::io::Error::new(e.kind(), format!("node `{}` {e}", spec.tag)))?;
            let tcp_handler = build_tls_handler(
                &spec,
                tls,
                InnerProtocol::Naive(naive_cfg.clone()),
                proxy_selector.clone(),
                resolver,
            )?;
            let quic_server_config = build_quic_server_config(&spec, tls, "naiveproxy")?;
            Ok(RuntimeNode {
                tag: spec.tag,
                bind_location,
                kind: RuntimeNodeKind::NaiveCombined {
                    handler: tcp_handler,
                    tcp_config: TcpConfig { no_delay: true },
                    quic_server_config,
                    naive_cfg,
                    proxy_selector,
                    congestion_control: quic_congestion_control,
                    num_endpoints: get_num_threads().max(1),
                },
            })
        }
        _ => invalid(format!(
            "node `{}` naiveproxy requires plain tcp or QUIC/H3 transport",
            spec.tag
        )),
    }
}

#[derive(Clone, Copy)]
enum NaiveProxyTransportMode {
    Tcp,
    Quic,
    TcpAndQuic,
}

fn validate_naiveproxy_tls_options(
    spec: &RuntimeNodeSpec,
    tls: &RuntimeTls,
    mode: NaiveProxyTransportMode,
) -> std::io::Result<()> {
    for protocol in &tls.alpn {
        let lower = protocol.trim().to_ascii_lowercase();
        let supported = match mode {
            NaiveProxyTransportMode::Tcp => matches!(lower.as_str(), "h2" | "http/1.1"),
            NaiveProxyTransportMode::Quic => lower == "h3",
            NaiveProxyTransportMode::TcpAndQuic => {
                matches!(lower.as_str(), "h2" | "http/1.1" | "h3")
            }
        };
        if !supported {
            let (transport_label, allowed) = match mode {
                NaiveProxyTransportMode::Tcp => ("TCP/H2", "h2/http/1.1"),
                NaiveProxyTransportMode::Quic => ("QUIC/H3", "h3"),
                NaiveProxyTransportMode::TcpAndQuic => ("dual TCP/H3", "h2/http/1.1/h3"),
            };
            return invalid(format!(
                "node `{}` naiveproxy custom TLS ALPN `{protocol}` is not supported for {}; use {allowed}",
                spec.tag, transport_label
            ));
        }
    }
    Ok(())
}

fn hysteria2_obfs_for_node(
    tag: &str,
    obfs: Option<&str>,
    obfs_password: Option<&str>,
) -> std::io::Result<Option<Hysteria2Obfs>> {
    let obfs = obfs
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    let obfs_password = obfs_password
        .map(str::trim)
        .filter(|value| !value.is_empty());

    match (obfs.as_deref(), obfs_password) {
        (None, None) => Ok(None),
        (None, Some(_)) => invalid(format!(
            "node `{tag}` hysteria2 obfs_password is set but obfs is empty"
        )),
        (Some("salamander"), Some(password)) => Hysteria2Obfs::salamander(password.to_string())
            .map(Some)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("node `{tag}` {e}"),
                )
            }),
        (Some("salamander"), None) => invalid(format!(
            "node `{tag}` hysteria2 salamander obfs requires obfs_password"
        )),
        (Some("gecko"), Some(password)) => Hysteria2Obfs::gecko(password.to_string(), None, None)
            .map(Some)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("node `{tag}` {e}"),
                )
            }),
        (Some("gecko"), None) => invalid(format!(
            "node `{tag}` hysteria2 gecko obfs requires obfs_password"
        )),
        (Some(other), _) => invalid(format!("node `{tag}` unsupported hysteria2 obfs `{other}`")),
    }
}

fn build_v2board_proxy_selector(
    spec: &RuntimeNodeSpec,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<ClientProxySelector> {
    let mut rules = Vec::new();
    for route in &spec.routes {
        rules.extend(v2board_route_to_rules(spec, route)?);
    }

    rules.push(ConnectRule::new(
        vec![NetLocationMask::ANY],
        ConnectAction::new_allow(None, build_direct_chain_group(resolver)),
    ));
    Ok(ClientProxySelector::new(rules))
}

fn v2board_route_to_rules(
    spec: &RuntimeNodeSpec,
    route: &crate::v2board::runtime_model::RuntimeRoute,
) -> std::io::Result<Vec<ConnectRule>> {
    let action = route_string_field(&route.raw, "action").ok_or_else(|| {
        invalid_error(format!(
            "node `{}` route missing required action: {}",
            spec.tag, route.raw
        ))
    })?;

    match action.as_str() {
        "block" => block_domain_route_rules(spec, route),
        "block_ip" => block_ip_route_rules(spec, route),
        "block_port" => block_port_route_rules(spec, route),
        "protocol" => protocol_route_rules(spec, route),
        "dns" | "route" | "route_ip" | "default_out" => invalid(format!(
            "node `{}` route action `{}` is not supported; V2Board Xray outbound/DNS routes have no equivalent local outbound model",
            spec.tag, action
        )),
        other => invalid(format!(
            "node `{}` route action `{other}` is not supported",
            spec.tag
        )),
    }
}

fn block_domain_route_rules(
    spec: &RuntimeNodeSpec,
    route: &crate::v2board::runtime_model::RuntimeRoute,
) -> std::io::Result<Vec<ConnectRule>> {
    let mut matchers = Vec::new();
    let mut protocols = Vec::new();

    for raw in route_match_values(spec, route)? {
        let value = raw.trim();
        let lower = value.to_ascii_lowercase();
        if lower.is_empty() {
            continue;
        }
        if let Some(domain) = strip_route_prefix(value, &lower, "domain:") {
            require_non_empty_route_token(spec, "domain", domain)?;
            matchers.push(ConnectMatcher::domain_suffix(domain));
        } else if let Some(domain) = strip_route_prefix(value, &lower, "full:") {
            require_non_empty_route_token(spec, "full", domain)?;
            matchers.push(ConnectMatcher::domain_full(domain));
        } else if let Some(keyword) = strip_route_prefix(value, &lower, "keyword:") {
            require_non_empty_route_token(spec, "keyword", keyword)?;
            matchers.push(ConnectMatcher::domain_keyword(keyword));
        } else if let Some(pattern) = strip_route_prefix(value, &lower, "regexp:") {
            require_non_empty_route_token(spec, "regexp", pattern)?;
            matchers.push(ConnectMatcher::domain_regex(pattern).map_err(|e| {
                invalid_error(format!(
                    "node `{}` route matcher `regexp:{pattern}` is invalid: {e}",
                    spec.tag
                ))
            })?);
        } else if let Some(code) = strip_route_prefix(value, &lower, "geosite:") {
            require_non_empty_route_token(spec, "geosite", code)?;
            matchers.extend(load_geosite_matchers(
                &spec.tag,
                &spec.route_rule_sets,
                code,
            )?);
        } else if let Some(protocol) = strip_route_prefix(value, &lower, "protocol:") {
            require_non_empty_route_token(spec, "protocol", protocol)?;
            push_route_protocol(spec, "block", protocol, &mut protocols)?;
        } else {
            matchers.push(ConnectMatcher::domain_keyword(lower));
        }
    }

    if matchers.is_empty() && protocols.is_empty() {
        return invalid(format!(
            "node `{}` route action `block` has no usable domain or protocol matchers",
            spec.tag
        ));
    }

    let mut rules = Vec::new();
    if !matchers.is_empty() {
        rules.push(ConnectRule::new_matchers(
            matchers,
            ConnectAction::new_block(),
        ));
    }
    if !protocols.is_empty() {
        rules.push(protocol_block_rule(protocols));
    }
    Ok(rules)
}

fn strip_route_prefix<'a>(value: &'a str, lower: &str, prefix: &str) -> Option<&'a str> {
    lower
        .starts_with(prefix)
        .then(|| value[prefix.len()..].trim())
}

fn block_ip_route_rules(
    spec: &RuntimeNodeSpec,
    route: &crate::v2board::runtime_model::RuntimeRoute,
) -> std::io::Result<Vec<ConnectRule>> {
    let mut matchers = Vec::new();

    for raw in route_match_values(spec, route)? {
        let value = raw.trim();
        if value.is_empty() {
            continue;
        }
        if let Some(code) = value
            .to_ascii_lowercase()
            .strip_prefix("geoip:")
            .map(|_| value["geoip:".len()..].trim())
        {
            require_non_empty_route_token(spec, "geoip", code)?;
            matchers.extend(load_geoip_matchers(&spec.tag, &spec.route_rule_sets, code)?);
            continue;
        }
        let mask = NetLocationMask::from(value).map_err(|e| {
            invalid_error(format!(
                "node `{}` route action `block_ip` has invalid matcher `{value}`: {e}",
                spec.tag
            ))
        })?;
        if matches!(mask.address_mask.address, Address::Hostname(_)) {
            return invalid(format!(
                "node `{}` route action `block_ip` expects IP/CIDR matcher, got `{value}`",
                spec.tag
            ));
        }
        matchers.push(ConnectMatcher::location(mask));
    }

    if matchers.is_empty() {
        return invalid(format!(
            "node `{}` route action `block_ip` has no usable IP matchers",
            spec.tag
        ));
    }

    Ok(vec![ConnectRule::new_matchers(
        matchers,
        ConnectAction::new_block(),
    )])
}

fn block_port_route_rules(
    spec: &RuntimeNodeSpec,
    route: &crate::v2board::runtime_model::RuntimeRoute,
) -> std::io::Result<Vec<ConnectRule>> {
    let mut matchers = Vec::new();

    for raw in route_match_values(spec, route)? {
        for port in parse_route_ports(spec, raw.trim())? {
            matchers.push(ConnectMatcher::location(NetLocationMask {
                address_mask: AddressMask::ANY,
                port,
            }));
        }
    }

    if matchers.is_empty() {
        return invalid(format!(
            "node `{}` route action `block_port` has no usable port matchers",
            spec.tag
        ));
    }

    Ok(vec![ConnectRule::new_matchers(
        matchers,
        ConnectAction::new_block(),
    )])
}

fn protocol_route_rules(
    spec: &RuntimeNodeSpec,
    route: &crate::v2board::runtime_model::RuntimeRoute,
) -> std::io::Result<Vec<ConnectRule>> {
    let mut protocols = Vec::new();
    for raw in route_match_values(spec, route)? {
        let value = raw.trim();
        if value.is_empty() {
            continue;
        }
        push_route_protocol(spec, "protocol", value, &mut protocols)?;
    }

    if protocols.is_empty() {
        return invalid(format!(
            "node `{}` route action `protocol` has no usable protocol matchers",
            spec.tag
        ));
    }

    Ok(vec![protocol_block_rule(protocols)])
}

fn push_route_protocol(
    spec: &RuntimeNodeSpec,
    action: &str,
    value: &str,
    protocols: &mut Vec<SniffedProtocol>,
) -> std::io::Result<()> {
    let Some(protocol) = SniffedProtocol::from_route_label(value) else {
        return invalid(format!(
            "node `{}` route action `{action}` has unsupported protocol matcher `{value}`; supported matchers: {}",
            spec.tag,
            SniffedProtocol::SUPPORTED_LABELS.join(", ")
        ));
    };
    if !protocols.contains(&protocol) {
        protocols.push(protocol);
    }
    Ok(())
}

fn protocol_block_rule(protocols: Vec<SniffedProtocol>) -> ConnectRule {
    ConnectRule::new_matchers(
        protocols
            .into_iter()
            .map(ConnectMatcher::protocol)
            .collect(),
        ConnectAction::new_block(),
    )
}

fn parse_route_ports(spec: &RuntimeNodeSpec, value: &str) -> std::io::Result<Vec<u16>> {
    let mut ports = Vec::new();
    if value.is_empty() {
        return Ok(ports);
    }

    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-').or_else(|| part.split_once(':')) {
            let start = parse_route_port(spec, start.trim())?;
            let end = parse_route_port(spec, end.trim())?;
            if start > end {
                return invalid(format!(
                    "node `{}` route action `block_port` has invalid descending range `{part}`",
                    spec.tag
                ));
            }
            ports.extend(start..=end);
        } else {
            ports.push(parse_route_port(spec, part)?);
        }
    }

    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn parse_route_port(spec: &RuntimeNodeSpec, value: &str) -> std::io::Result<u16> {
    let port = value.parse::<u16>().map_err(|e| {
        invalid_error(format!(
            "node `{}` route action `block_port` has invalid port `{value}`: {e}",
            spec.tag
        ))
    })?;
    if port == 0 {
        return invalid(format!(
            "node `{}` route action `block_port` cannot match port 0",
            spec.tag
        ));
    }
    Ok(port)
}

fn route_match_values(
    spec: &RuntimeNodeSpec,
    route: &crate::v2board::runtime_model::RuntimeRoute,
) -> std::io::Result<Vec<String>> {
    let Some(value) = route.raw.get("match") else {
        return invalid(format!(
            "node `{}` route action `{}` missing match array",
            spec.tag,
            route_string_field(&route.raw, "action").unwrap_or_else(|| "<unknown>".to_string())
        ));
    };

    let values = match value {
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| match item {
                serde_json::Value::String(value) => Some(value.clone()),
                serde_json::Value::Number(value) => Some(value.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>(),
        serde_json::Value::String(value) => value
            .split(',')
            .map(|item| item.trim().to_string())
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };

    if values.iter().all(|value| value.trim().is_empty()) {
        return invalid(format!(
            "node `{}` route action `{}` has empty match array",
            spec.tag,
            route_string_field(&route.raw, "action").unwrap_or_else(|| "<unknown>".to_string())
        ));
    }

    Ok(values)
}

fn route_string_field(value: &serde_json::Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(|value| value.as_str())
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

fn require_non_empty_route_token(
    spec: &RuntimeNodeSpec,
    kind: &str,
    value: &str,
) -> std::io::Result<()> {
    if value.trim().is_empty() {
        return invalid(format!(
            "node `{}` route matcher `{kind}:` has empty value",
            spec.tag
        ));
    }
    Ok(())
}

fn build_transport_handler(
    spec: &RuntimeNodeSpec,
    inner: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Arc<dyn TcpServerHandler>> {
    if spec.node_type == NodeType::Shadowsocks
        && !matches!(spec.transport, RuntimeTransport::Tcp { header: None })
    {
        return invalid(format!(
            "node `{}` shadowsocks requires plain tcp transport",
            spec.tag
        ));
    }
    if spec.node_type == NodeType::Anytls
        && !matches!(spec.transport, RuntimeTransport::Tcp { header: None })
    {
        return invalid(format!(
            "node `{}` anytls requires plain tcp transport",
            spec.tag
        ));
    }
    match &spec.transport {
        RuntimeTransport::Tcp { header: None } => Ok(inner),
        RuntimeTransport::Tcp {
            header:
                Some(TcpHeader::Http {
                    hosts,
                    paths,
                    method,
                }),
        } => build_http_transport_handler(
            spec,
            hosts.clone(),
            paths.clone(),
            method.clone(),
            HashMap::new(),
            inner,
            resolver,
        ),
        RuntimeTransport::Http {
            hosts,
            paths,
            method,
            response_headers,
        } => build_http_transport_handler(
            spec,
            hosts.clone(),
            paths.clone(),
            method.clone(),
            response_headers.clone(),
            inner,
            resolver,
        ),
        RuntimeTransport::Websocket {
            path,
            headers,
            max_early_data,
            early_data_header_name,
        } => Ok(Arc::new(WebsocketTcpServerHandler::new(vec![
            WebsocketServerTarget {
                matching_path: Some(path.clone()),
                matching_headers: websocket_headers(headers),
                max_early_data: *max_early_data,
                early_data_header_name: early_data_header_name.clone(),
                ping_type: WebsocketPingType::PingFrame,
                handler: boxed_handler(inner),
            },
        ]))),
        RuntimeTransport::Grpc {
            service_name,
            authority,
            multi_mode,
        } => {
            if *multi_mode {
                return invalid(format!(
                    "node `{}` grpc multi_mode is modeled but not implemented yet",
                    spec.tag
                ));
            }
            Ok(Arc::new(GrpcServerHandler::new(
                service_name.clone(),
                authority.clone(),
                boxed_handler(inner),
            )))
        }
        RuntimeTransport::HttpUpgrade {
            path,
            host,
            headers,
        } => Ok(Arc::new(HttpUpgradeServerHandler::new(
            path.clone(),
            host.clone(),
            headers.clone(),
            boxed_handler(inner),
        ))),
        RuntimeTransport::XHttp(config) => {
            build_xhttp_transport_handler(spec, config.clone(), inner, resolver)
        }
        RuntimeTransport::Quic | RuntimeTransport::TcpAndQuic => invalid(format!(
            "node `{}` QUIC transport is started by a dedicated runtime node",
            spec.tag
        )),
    }
}

fn build_xhttp_transport_handler(
    spec: &RuntimeNodeSpec,
    config: crate::v2board::xhttp::XHttpConfig,
    inner: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Arc<dyn TcpServerHandler>> {
    if !matches!(spec.node_type, NodeType::Vmess | NodeType::Vless) {
        return invalid(format!(
            "node `{}` xhttp transport is only supported for VMess/VLESS nodes",
            spec.tag
        ));
    }
    let http2 = matches!(
        spec.security,
        RuntimeSecurity::Tls(_) | RuntimeSecurity::Reality(_)
    );
    Ok(Arc::new(XHttpServerHandler::new(
        config, inner, resolver, http2,
    )))
}

fn build_http_transport_handler(
    spec: &RuntimeNodeSpec,
    hosts: Vec<String>,
    paths: Vec<String>,
    method: Option<String>,
    response_headers: HashMap<String, String>,
    inner: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Arc<dyn TcpServerHandler>> {
    if !matches!(spec.node_type, NodeType::Vmess | NodeType::Vless) {
        return invalid(format!(
            "node `{}` v2ray http transport is only supported for VMess/VLESS nodes",
            spec.tag
        ));
    }
    match &spec.security {
        RuntimeSecurity::None => Ok(Arc::new(V2RayHttpServerHandler::new(
            hosts,
            paths,
            method,
            response_headers,
            boxed_handler(inner),
        ))),
        RuntimeSecurity::Tls(_) => Ok(Arc::new(V2RayHttp2ServerHandler::new(
            hosts,
            paths,
            method,
            response_headers,
            inner,
            resolver,
        ))),
        RuntimeSecurity::Reality(_) => Ok(Arc::new(V2RayHttp2ServerHandler::new(
            hosts,
            paths,
            method,
            response_headers,
            inner,
            resolver,
        ))),
    }
}

fn build_security_handler(
    spec: &RuntimeNodeSpec,
    inner: Arc<dyn TcpServerHandler>,
    tracker: Arc<TrafficTracker>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Arc<dyn TcpServerHandler>> {
    match &spec.security {
        RuntimeSecurity::None => {
            if spec.node_type == NodeType::Anytls {
                return invalid(format!(
                    "node `{}` anytls requires TLS in production V2Board runtime",
                    spec.tag
                ));
            }
            if vless_vision_flow(spec).is_some() {
                return invalid(format!(
                    "node `{}` vless flow `{VLESS_XTLS_VISION_FLOW}` requires TLS or Reality",
                    spec.tag
                ));
            }
            Ok(inner)
        }
        RuntimeSecurity::Tls(tls) => {
            let inner_protocol = secured_inner_protocol(spec, inner, tracker)?;
            build_tls_handler(spec, tls, inner_protocol, proxy_selector, resolver)
        }
        RuntimeSecurity::Reality(reality) => {
            if spec.node_type == NodeType::Anytls && spec.config_node_type != NodeType::V2Node {
                return invalid(format!(
                    "node `{}` V1 anytls does not expose Reality settings; use node_type `v2node` for AnyTLS Reality",
                    spec.tag
                ));
            }
            let inner_protocol = secured_inner_protocol(spec, inner, tracker)?;
            build_reality_handler(spec, reality, inner_protocol, proxy_selector, resolver)
        }
    }
}

fn secured_inner_protocol(
    spec: &RuntimeNodeSpec,
    inner: Arc<dyn TcpServerHandler>,
    tracker: Arc<TrafficTracker>,
) -> std::io::Result<InnerProtocol> {
    if vless_vision_flow(spec).is_some() {
        return Ok(InnerProtocol::VisionVless(VisionVlessConfig {
            users: vless_vision_users(spec, tracker)?,
            udp_enabled: true,
            fallback: None,
        }));
    }
    Ok(InnerProtocol::Normal(boxed_handler(inner)))
}

fn build_reality_handler(
    spec: &RuntimeNodeSpec,
    reality: &crate::v2board::runtime_model::RuntimeReality,
    inner_protocol: InnerProtocol,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Arc<dyn TcpServerHandler>> {
    reject_unsupported_reality_options(spec, reality)?;
    let private_key = reality_private_key(spec, reality)?;
    let short_ids = reality_short_ids(spec, reality)?;
    let dest = reality_dest(spec, reality)?;
    let dest_client_chain = build_client_proxy_chain(
        OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
            ClientConfig::default(),
        ))),
        resolver.clone(),
    );

    let target = TlsServerTarget::Reality(RealityServerTarget {
        private_key,
        short_ids,
        dest,
        max_time_diff: reality.max_time_diff_millis.or(Some(60_000)),
        min_client_version: None,
        max_client_version: None,
        cipher_suites: crate::reality::DEFAULT_CIPHER_SUITES.to_vec(),
        selected_alpn: selected_reality_alpn(spec),
        effective_selector: proxy_selector,
        inner_protocol,
        dest_client_chain,
    });
    Ok(Arc::new(TlsServerHandler::new(
        FxHashMap::default(),
        Some(target),
        None,
        resolver,
    )))
}

fn selected_reality_alpn(spec: &RuntimeNodeSpec) -> Option<String> {
    if transport_requires_h2_alpn(spec) {
        Some("h2".to_string())
    } else {
        None
    }
}

fn reject_unsupported_reality_options(
    spec: &RuntimeNodeSpec,
    reality: &crate::v2board::runtime_model::RuntimeReality,
) -> std::io::Result<()> {
    if reality.xver != 0 {
        return invalid(format!(
            "node `{}` reality xver={} is not supported",
            spec.tag, reality.xver
        ));
    }
    if reality.ech.is_some()
        || reality.ech_server_name.is_some()
        || reality.ech_key.is_some()
        || reality.ech_config.is_some()
    {
        return invalid(format!("node `{}` reality ECH is not supported", spec.tag));
    }
    if let Some(cert_mode) = reality.cert_mode.as_deref() {
        let mode = cert_mode.trim().to_ascii_lowercase();
        if matches!(
            mode.as_str(),
            "http" | "dns" | "auto" | "acme" | "letsencrypt"
        ) {
            return invalid(format!(
                "node `{}` reality cert_mode `{cert_mode}` automatic certificate issuance is not supported",
                spec.tag
            ));
        }
    }
    Ok(())
}

fn reality_private_key(
    spec: &RuntimeNodeSpec,
    reality: &crate::v2board::runtime_model::RuntimeReality,
) -> std::io::Result<[u8; 32]> {
    let private_key = reality
        .private_key
        .as_deref()
        .ok_or_else(|| invalid_error(format!("node `{}` reality missing private_key", spec.tag)))?;
    decode_private_key(private_key).map_err(|e| {
        invalid_error(format!(
            "node `{}` reality private_key failed to decode: {e}",
            spec.tag
        ))
    })
}

fn reality_short_ids(
    spec: &RuntimeNodeSpec,
    reality: &crate::v2board::runtime_model::RuntimeReality,
) -> std::io::Result<Vec<[u8; 8]>> {
    if reality.short_ids.is_empty() {
        return invalid(format!("node `{}` reality missing short_id", spec.tag));
    }

    let short_ids: Vec<&str> = reality.short_ids.iter().map(String::as_str).collect();
    short_ids
        .into_iter()
        .map(|short_id| {
            decode_short_id(short_id).map_err(|e| {
                invalid_error(format!(
                    "node `{}` reality short_id `{short_id}` failed to decode: {e}",
                    spec.tag
                ))
            })
        })
        .collect()
}

fn reality_dest(
    spec: &RuntimeNodeSpec,
    reality: &crate::v2board::runtime_model::RuntimeReality,
) -> std::io::Result<NetLocation> {
    let default_port = match reality.server_port.as_deref() {
        Some(port) => Some(parse_reality_port(spec, port)?),
        None => None,
    };

    if let Some(dest) = reality.dest.as_deref() {
        return NetLocation::from_str(dest, default_port).map_err(|e| {
            invalid_error(format!(
                "node `{}` reality dest `{dest}` is invalid: {e}",
                spec.tag
            ))
        });
    }

    let server_name = reality.server_name.as_deref().ok_or_else(|| {
        invalid_error(format!(
            "node `{}` reality missing dest or server_name/server_port",
            spec.tag
        ))
    })?;
    NetLocation::from_str(server_name, default_port).map_err(|e| {
        invalid_error(format!(
            "node `{}` reality server_name/server_port `{server_name}` is invalid: {e}",
            spec.tag
        ))
    })
}

fn parse_reality_port(spec: &RuntimeNodeSpec, port: &str) -> std::io::Result<u16> {
    port.parse::<u16>().map_err(|e| {
        invalid_error(format!(
            "node `{}` reality server_port `{port}` is invalid: {e}",
            spec.tag
        ))
    })
}

fn build_tls_handler(
    spec: &RuntimeNodeSpec,
    tls: &RuntimeTls,
    inner_protocol: InnerProtocol,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Arc<dyn TcpServerHandler>> {
    validate_tls_options(spec, tls)?;
    let (cert, key) = read_tls_certificate_pair(spec, tls)?;

    if !tls.server_names.is_empty() {
        log::debug!(
            "node `{}` TLS server_names {:?} are accepted; default TLS target handles all SNI",
            spec.tag,
            tls.server_names
        );
    }
    if let Some(server_name) = &tls.server_name {
        log::debug!(
            "node `{}` TLS server_name `{server_name}` is accepted; default TLS target handles all SNI",
            spec.tag
        );
    }

    let alpn = tls_alpn_for_transport(spec, tls);
    let server_config = Arc::new(create_server_config(&cert, &key, Vec::new(), &alpn, &[]));
    let target = TlsServerTarget::Tls {
        server_config,
        effective_selector: proxy_selector,
        inner_protocol,
    };
    Ok(Arc::new(TlsServerHandler::new(
        FxHashMap::default(),
        Some(target),
        None,
        resolver,
    )))
}

fn validate_tls_options(spec: &RuntimeNodeSpec, tls: &RuntimeTls) -> std::io::Result<()> {
    if tls.ech.is_some()
        || tls.ech_server_name.is_some()
        || tls.ech_key.is_some()
        || tls.ech_config.is_some()
    {
        return invalid(format!("node `{}` tls ECH is not supported", spec.tag));
    }
    if let Some(cert_mode) = tls.cert_mode.as_deref() {
        let mode = cert_mode.trim().to_ascii_lowercase();
        if !mode.is_empty() && mode != "file" && mode != "local" {
            return invalid(format!(
                "node `{}` tls cert_mode `{cert_mode}` is not supported; provide cert_file/key_file",
                spec.tag
            ));
        }
    }
    if tls.allow_insecure {
        log::warn!(
            "node `{}` tls allow_insecure is a client-side panel option and is ignored inbound",
            spec.tag
        );
    }
    Ok(())
}

fn read_tls_certificate_pair(
    spec: &RuntimeNodeSpec,
    tls: &RuntimeTls,
) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let certificate = tls.certificate.as_ref().ok_or_else(|| {
        invalid_error(format!(
            "node `{}` enables TLS but no cert_file/key_file is configured",
            spec.tag
        ))
    })?;
    let cert = std::fs::read(&certificate.cert_file).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "node `{}` failed to read TLS certificate {}: {e}",
                spec.tag,
                certificate.cert_file.display()
            ),
        )
    })?;
    let key = std::fs::read(&certificate.key_file).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "node `{}` failed to read TLS key {}: {e}",
                spec.tag,
                certificate.key_file.display()
            ),
        )
    })?;
    Ok((cert, key))
}

fn build_quic_server_config(
    spec: &RuntimeNodeSpec,
    tls: &RuntimeTls,
    protocol: &str,
) -> std::io::Result<Arc<quinn::crypto::rustls::QuicServerConfig>> {
    validate_tls_options(spec, tls)?;
    let (cert, key) = read_tls_certificate_pair(spec, tls)?;
    let mut alpn = tls.alpn.clone();
    if !alpn.iter().any(|item| item.eq_ignore_ascii_case("h3")) {
        alpn.insert(0, "h3".to_string());
    }
    let server_config = Arc::new(create_server_config(&cert, &key, Vec::new(), &alpn, &[]));
    let quic_server_config: quinn::crypto::rustls::QuicServerConfig =
        server_config.try_into().map_err(|e| {
            std::io::Error::other(format!(
                "node `{}` invalid {protocol} QUIC server config: {e}",
                spec.tag,
            ))
        })?;
    Ok(Arc::new(quic_server_config))
}

fn tls_alpn_for_transport(spec: &RuntimeNodeSpec, tls: &RuntimeTls) -> Vec<String> {
    if spec.node_type == NodeType::Naiveproxy && !matches!(spec.transport, RuntimeTransport::Quic) {
        return vec!["h2".to_string(), "http/1.1".to_string()];
    }
    let mut alpn = tls.alpn.clone();
    if transport_requires_h2_alpn(spec) {
        alpn.retain(|protocol| !protocol.eq_ignore_ascii_case("h2"));
        alpn.insert(0, "h2".to_string());
    }
    alpn
}

fn transport_requires_h2_alpn(spec: &RuntimeNodeSpec) -> bool {
    matches!(
        spec.transport,
        RuntimeTransport::Grpc { .. }
            | RuntimeTransport::Http { .. }
            | RuntimeTransport::XHttp(_)
            | RuntimeTransport::Tcp {
                header: Some(TcpHeader::Http { .. })
            }
    )
}

fn build_protocol_handler(
    spec: &RuntimeNodeSpec,
    tracker: Arc<TrafficTracker>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    max_legacy_shadowsocks_users: usize,
    shadowsocks_mux_padding: Option<bool>,
    outbound_dispatcher: Option<Arc<OutboundDispatcher>>,
) -> std::io::Result<Arc<dyn TcpServerHandler>> {
    let server_users = server_users(spec, tracker.clone())?;

    let handler: Arc<dyn TcpServerHandler> = match (&spec.node_type, &spec.protocol) {
        (NodeType::Vless, RuntimeProtocol::Vless { encryption, flow }) => {
            if encryption != "none" {
                return invalid(format!(
                    "node `{}` vless encryption `{encryption}` is not supported",
                    spec.tag
                ));
            }
            if let Some(flow) = flow {
                if flow != VLESS_XTLS_VISION_FLOW {
                    return invalid(format!(
                        "node `{}` vless flow `{flow}` is not supported",
                        spec.tag
                    ));
                }
                if !matches!(spec.transport, RuntimeTransport::Tcp { header: None }) {
                    return invalid(format!(
                        "node `{}` vless flow `{VLESS_XTLS_VISION_FLOW}` requires plain tcp transport",
                        spec.tag
                    ));
                }
            }
            validate_vless_user_ids(spec)?;
            Arc::new(
                VlessTcpServerHandler::new_multi(
                    server_users,
                    true,
                    proxy_selector,
                    resolver,
                    None,
                )
                .with_outbound_dispatcher(outbound_dispatcher.clone()),
            )
        }
        (NodeType::Vmess, RuntimeProtocol::Vmess { security }) => Arc::new(
            VmessTcpServerHandler::new_multi(
                security,
                server_users,
                true,
                proxy_selector,
                resolver,
            )
            .with_outbound_dispatcher(outbound_dispatcher.clone()),
        ),
        (NodeType::Trojan, RuntimeProtocol::Trojan { fallback, .. }) => {
            if matches!(spec.security, RuntimeSecurity::None) {
                return invalid(format!(
                    "node `{}` trojan requires TLS in production V2Board runtime",
                    spec.tag
                ));
            }
            Arc::new(
                TrojanTcpHandler::new_multi_server(
                    server_users,
                    &None,
                    proxy_selector,
                    resolver,
                    fallback.clone(),
                )
                .with_outbound_dispatcher(outbound_dispatcher.clone()),
            )
        }
        (NodeType::Anytls, RuntimeProtocol::Anytls { padding_scheme }) => {
            if matches!(spec.security, RuntimeSecurity::None) {
                return invalid(format!(
                    "node `{}` anytls requires TLS in production V2Board runtime",
                    spec.tag
                ));
            }
            validate_duplicate_credentials(spec, "anytls")?;
            Arc::new(
                AnyTlsServerHandler::new_authenticated(
                    server_users,
                    anytls_padding_factory(spec, padding_scheme)?,
                    resolver,
                    proxy_selector,
                    true,
                    None,
                )
                .with_outbound_dispatcher(outbound_dispatcher.clone()),
            )
        }
        (
            NodeType::Shadowsocks,
            RuntimeProtocol::Shadowsocks {
                cipher,
                server_key,
                obfs,
                encryption_settings,
            },
        ) => {
            let http_obfs = shadowsocks_http_obfs_for_node(&spec.tag, obfs)?;
            let is_2022 = validate_shadowsocks_user_keys(
                spec,
                cipher,
                server_key.as_deref(),
                max_legacy_shadowsocks_users,
            )?;
            if is_2022 {
                let key_len = shadowsocks_2022_key_len(cipher)?.ok_or_else(|| {
                    invalid_error(format!(
                        "node `{}` shadowsocks cipher `{cipher}` was classified as 2022 without key length",
                        spec.tag
                    ))
                })?;
                let server_key = decode_shadowsocks_2022_psk(
                    server_key.as_deref().ok_or_else(|| {
                        invalid_error(format!(
                            "node `{}` shadowsocks 2022 cipher `{cipher}` requires server_key",
                            spec.tag
                        ))
                    })?,
                    key_len,
                    &format!("node `{}` shadowsocks server_key", spec.tag),
                )?;
                let users = shadowsocks_2022_server_users(spec, key_len, tracker.clone())?;
                let cipher = shadowsocks_2022_runtime_cipher(cipher)?;
                let mut handler = ShadowsocksTcpHandler::new_v2board_aead2022_multi_server(
                    cipher,
                    server_key,
                    users,
                    true,
                    proxy_selector,
                    resolver,
                )
                .with_outbound_dispatcher(outbound_dispatcher.clone());
                if let Some(http_obfs) = http_obfs {
                    handler = handler.with_http_obfs(http_obfs);
                }
                if let Some(padding) = shadowsocks_mux_padding {
                    handler = handler.with_h2mux_server(padding);
                }
                return Ok(Arc::new(handler));
            }
            if encryption_settings
                .as_ref()
                .is_some_and(|value| !v2board_value_is_empty(value))
            {
                return invalid(format!(
                    "node `{}` shadowsocks encryption_settings is not supported",
                    spec.tag
                ));
            }
            let cipher = cipher.as_str().try_into()?;
            let mut handler = ShadowsocksTcpHandler::new_v2board_multi_server(
                cipher,
                server_users,
                true,
                proxy_selector,
                resolver,
            )
            .with_outbound_dispatcher(outbound_dispatcher.clone());
            if let Some(http_obfs) = http_obfs {
                handler = handler.with_http_obfs(http_obfs);
            }
            if let Some(padding) = shadowsocks_mux_padding {
                handler = handler.with_h2mux_server(padding);
            }
            Arc::new(handler)
        }
        _ => {
            return invalid(format!(
                "node `{}` type/protocol mismatch in V2Board runtime model",
                spec.tag
            ));
        }
    };
    Ok(handler)
}

fn shadowsocks_http_obfs_for_node(
    tag: &str,
    obfs: &ShadowsocksObfs,
) -> std::io::Result<Option<ShadowsocksHttpObfs>> {
    let ShadowsocksObfs::Plugin { name, settings } = obfs else {
        return Ok(None);
    };
    let obfs_name = name.trim().to_ascii_lowercase();
    if obfs_name != "http" {
        return invalid(format!(
            "node `{tag}` shadowsocks obfs plugin `{name}` is not supported"
        ));
    }
    let hosts = shadowsocks_obfs_string_vec(settings.as_ref(), &["host", "Host", "obfs-host"]);
    let path = shadowsocks_obfs_string(settings.as_ref(), &["path", "obfs-path"]);
    Ok(Some(ShadowsocksHttpObfs::new(hosts, path)))
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

fn shadowsocks_obfs_string(settings: Option<&Value>, keys: &[&str]) -> Option<String> {
    let object = settings?.as_object()?;
    for key in keys {
        if let Some(value) = object.get(*key)
            && let Some(value) = shadowsocks_obfs_value_to_string(value)
            && !value.is_empty()
        {
            return Some(value);
        }
    }
    None
}

fn shadowsocks_obfs_string_vec(settings: Option<&Value>, keys: &[&str]) -> Vec<String> {
    let object = match settings.and_then(Value::as_object) {
        Some(object) => object,
        None => return Vec::new(),
    };
    for key in keys {
        if let Some(value) = object.get(*key) {
            let values = match value {
                Value::Array(values) => values
                    .iter()
                    .filter_map(shadowsocks_obfs_value_to_string)
                    .filter(|value| !value.is_empty())
                    .collect::<Vec<_>>(),
                Value::String(value) => value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
                    .collect(),
                _ => shadowsocks_obfs_value_to_string(value)
                    .into_iter()
                    .filter(|value| !value.is_empty())
                    .collect(),
            };
            if !values.is_empty() {
                return values;
            }
        }
    }
    Vec::new()
}

fn shadowsocks_obfs_value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.trim().to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn anytls_padding_factory(
    spec: &RuntimeNodeSpec,
    padding_scheme: &[String],
) -> std::io::Result<Arc<PaddingFactory>> {
    if padding_scheme.is_empty() {
        return Ok(PaddingFactory::default_factory());
    }
    let raw_scheme = padding_scheme.join("\n");
    PaddingFactory::new(raw_scheme.as_bytes())
        .map(Arc::new)
        .map_err(|e| {
            invalid_error(format!(
                "node `{}` invalid anytls padding_scheme: {e}",
                spec.tag
            ))
        })
}

fn validate_duplicate_credentials(spec: &RuntimeNodeSpec, protocol: &str) -> std::io::Result<()> {
    let mut seen = HashMap::with_capacity(spec.users.len());
    for user in &spec.users {
        if let Some(previous) = seen.insert(user.credential.as_str(), user.uid) {
            return invalid(format!(
                "node `{}` {protocol} user {} credential duplicates user {} credential",
                spec.tag, user.uid, previous
            ));
        }
    }
    Ok(())
}

fn validate_shadowsocks_user_keys(
    spec: &RuntimeNodeSpec,
    cipher: &str,
    server_key: Option<&str>,
    max_legacy_shadowsocks_users: usize,
) -> std::io::Result<bool> {
    let Some(key_len) = shadowsocks_2022_key_len(cipher)? else {
        if spec.users.len() > max_legacy_shadowsocks_users {
            return invalid(format!(
                "node `{}` shadowsocks legacy AEAD has {} users; max_legacy_shadowsocks_users={} because legacy multi-user authentication is O(n)",
                spec.tag,
                spec.users.len(),
                max_legacy_shadowsocks_users
            ));
        }
        validate_duplicate_credentials(spec, "shadowsocks")?;
        return Ok(false);
    };

    let server_key = server_key.ok_or_else(|| {
        invalid_error(format!(
            "node `{}` shadowsocks 2022 cipher `{cipher}` requires server_key",
            spec.tag
        ))
    })?;
    let _ = decode_shadowsocks_2022_psk(
        server_key,
        key_len,
        &format!("node `{}` shadowsocks server_key", spec.tag),
    )?;

    let mut seen = HashMap::with_capacity(spec.users.len());
    for user in &spec.users {
        let password = shadowsocks_2022_user_password(user, key_len, &spec.tag)?;
        let psk = decode_shadowsocks_2022_psk(
            &password,
            key_len,
            &format!("node `{}` user {} shadowsocks 2022 psk", spec.tag, user.uid),
        )?;
        if let Some(previous) = seen.insert(psk, user.uid) {
            return invalid(format!(
                "node `{}` shadowsocks user {} psk duplicates user {} psk",
                spec.tag, user.uid, previous
            ));
        }
    }

    Ok(true)
}

fn shadowsocks_2022_key_len(cipher: &str) -> std::io::Result<Option<usize>> {
    match cipher {
        "2022-blake3-aes-128-gcm" => Ok(Some(16)),
        "2022-blake3-aes-256-gcm" => Ok(Some(32)),
        "2022-blake3-chacha20-poly1305" => invalid(format!(
            "shadowsocks 2022 cipher `{cipher}` is not supported for V2Board multi-user"
        )),
        "aes-128-gcm" | "aes-192-gcm" | "aes-256-gcm" | "chacha20-ietf-poly1305" => Ok(None),
        _ => invalid(format!("unsupported shadowsocks cipher `{cipher}`")),
    }
}

fn shadowsocks_2022_user_password(
    user: &crate::v2board::runtime_model::RuntimeUser,
    key_len: usize,
    node_tag: &str,
) -> std::io::Result<String> {
    if let Some(secret) = &user.secret {
        return Ok(secret.clone());
    }
    if user.credential.len() < key_len {
        return invalid(format!(
            "node `{node_tag}` user {} credential is too short for shadowsocks 2022 key derivation",
            user.uid
        ));
    }
    Ok(BASE64.encode(&user.credential.as_bytes()[..key_len]))
}

fn decode_shadowsocks_2022_psk(
    value: &str,
    key_len: usize,
    name: &str,
) -> std::io::Result<Vec<u8>> {
    let mut key = BASE64.decode(value).map_err(|e| {
        invalid_error(format!(
            "{name} must be base64-encoded for shadowsocks 2022: {e}"
        ))
    })?;
    if key.len() < key_len {
        return invalid(format!(
            "{name} is too short for shadowsocks 2022 key length {key_len}"
        ));
    }
    if key.len() > key_len {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, key.as_slice());
        key = digest.as_ref()[..key_len].to_vec();
    }
    Ok(key)
}

fn shadowsocks_2022_runtime_cipher(
    cipher: &str,
) -> std::io::Result<crate::shadowsocks::ShadowsocksCipher> {
    match cipher {
        "2022-blake3-aes-128-gcm" => "aes-128-gcm".try_into(),
        "2022-blake3-aes-256-gcm" => "aes-256-gcm".try_into(),
        _ => invalid(format!("unsupported shadowsocks 2022 cipher `{cipher}`")),
    }
}

fn shadowsocks_2022_server_users(
    spec: &RuntimeNodeSpec,
    key_len: usize,
    tracker: Arc<TrafficTracker>,
) -> std::io::Result<Vec<(Vec<u8>, AuthenticatedUser)>> {
    spec.users
        .iter()
        .map(|user| {
            let password = shadowsocks_2022_user_password(user, key_len, &spec.tag)?;
            let psk = decode_shadowsocks_2022_psk(
                &password,
                key_len,
                &format!("node `{}` user {} shadowsocks 2022 psk", spec.tag, user.uid),
            )?;
            Ok((
                psk,
                AuthenticatedUser {
                    node_tag: spec.tag.clone(),
                    uid: user.uid,
                    user_key: user.user_key.clone(),
                    speed_limit: user.policy.speed_limit_mbps,
                    device_limit: user.policy.device_limit,
                    recorder: Some(tracker.clone()),
                },
            ))
        })
        .collect()
}

fn server_users(
    spec: &RuntimeNodeSpec,
    tracker: Arc<TrafficTracker>,
) -> std::io::Result<Vec<ServerUser>> {
    spec.users
        .iter()
        .map(|user| {
            Ok(ServerUser {
                credential: user.credential.clone(),
                authenticated_user: AuthenticatedUser {
                    node_tag: spec.tag.clone(),
                    uid: user.uid,
                    user_key: user.user_key.clone(),
                    speed_limit: user.policy.speed_limit_mbps,
                    device_limit: user.policy.device_limit,
                    recorder: Some(tracker.clone()),
                },
            })
        })
        .collect()
}

fn naiveproxy_user_lookup(
    spec: &RuntimeNodeSpec,
    tracker: Arc<TrafficTracker>,
) -> std::io::Result<UserLookup> {
    let mut seen = HashMap::with_capacity(spec.users.len());
    let users = spec
        .users
        .iter()
        .map(|user| {
            let username = user
                .username
                .clone()
                .unwrap_or_else(|| format!("user-{}", user.uid));
            if username.trim().is_empty() {
                return invalid(format!(
                    "node `{}` naiveproxy user {} has empty username",
                    spec.tag, user.uid
                ));
            }
            let password = user
                .password
                .clone()
                .unwrap_or_else(|| user.credential.clone());
            if password.trim().is_empty() {
                return invalid(format!(
                    "node `{}` naiveproxy user {} has empty password",
                    spec.tag, user.uid
                ));
            }
            let key = format!("{username}\0{password}");
            if let Some(previous) = seen.insert(key, user.uid) {
                return invalid(format!(
                    "node `{}` naiveproxy user {} username/password duplicates user {} credentials",
                    spec.tag, user.uid, previous
                ));
            }
            Ok((
                format!("user-{}", user.uid),
                username,
                password,
                Some(AuthenticatedUser {
                    node_tag: spec.tag.clone(),
                    uid: user.uid,
                    user_key: user.user_key.clone(),
                    speed_limit: user.policy.speed_limit_mbps,
                    device_limit: user.policy.device_limit,
                    recorder: Some(tracker.clone()),
                }),
            ))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    Ok(UserLookup::new_with_authenticated_users(users))
}

fn tuic_server_users(
    spec: &RuntimeNodeSpec,
    tracker: Arc<TrafficTracker>,
) -> std::io::Result<TuicServerUsers> {
    validate_duplicate_credentials(spec, "tuic")?;
    let users = spec
        .users
        .iter()
        .map(|user| {
            let uuid = crate::uuid_util::parse_uuid(&user.credential).map_err(|e| {
                invalid_error(format!(
                    "node `{}` user {} has invalid TUIC uuid `{}`: {e}",
                    spec.tag, user.uid, user.credential
                ))
            })?;
            let uuid: [u8; 16] = uuid.try_into().map_err(|_| {
                invalid_error(format!(
                    "node `{}` user {} has invalid TUIC uuid length",
                    spec.tag, user.uid
                ))
            })?;
            Ok(TuicServerUser::new(
                uuid,
                user.credential.clone(),
                Some(AuthenticatedUser {
                    node_tag: spec.tag.clone(),
                    uid: user.uid,
                    user_key: user.user_key.clone(),
                    speed_limit: user.policy.speed_limit_mbps,
                    device_limit: user.policy.device_limit,
                    recorder: Some(tracker.clone()),
                }),
            ))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    TuicServerUsers::new(users).map_err(|e| {
        invalid_error(format!(
            "node `{}` failed to build TUIC users: {e}",
            spec.tag
        ))
    })
}

fn hysteria2_server_users(
    spec: &RuntimeNodeSpec,
    tracker: Arc<TrafficTracker>,
) -> std::io::Result<Hysteria2ServerUsers> {
    validate_duplicate_credentials(spec, "hysteria2")?;
    let users = spec
        .users
        .iter()
        .map(|user| {
            Hysteria2ServerUser::new(
                user.credential.clone(),
                Some(AuthenticatedUser {
                    node_tag: spec.tag.clone(),
                    uid: user.uid,
                    user_key: user.user_key.clone(),
                    speed_limit: user.policy.speed_limit_mbps,
                    device_limit: user.policy.device_limit,
                    recorder: Some(tracker.clone()),
                }),
            )
        })
        .collect();
    Hysteria2ServerUsers::new(users).map_err(|e| {
        invalid_error(format!(
            "node `{}` failed to build hysteria2 users: {e}",
            spec.tag
        ))
    })
}

fn validate_vless_user_ids(spec: &RuntimeNodeSpec) -> std::io::Result<()> {
    for user in &spec.users {
        parse_vless_user_id(spec, user)?;
    }
    Ok(())
}

fn vless_vision_users(
    spec: &RuntimeNodeSpec,
    tracker: Arc<TrafficTracker>,
) -> std::io::Result<Vec<VlessVisionUser>> {
    spec.users
        .iter()
        .map(|user| {
            Ok((
                parse_vless_user_id(spec, user)?.into_boxed_slice(),
                Some(AuthenticatedUser {
                    node_tag: spec.tag.clone(),
                    uid: user.uid,
                    user_key: user.user_key.clone(),
                    speed_limit: user.policy.speed_limit_mbps,
                    device_limit: user.policy.device_limit,
                    recorder: Some(tracker.clone()),
                }),
            ))
        })
        .collect()
}

fn parse_vless_user_id(
    spec: &RuntimeNodeSpec,
    user: &crate::v2board::runtime_model::RuntimeUser,
) -> std::io::Result<Vec<u8>> {
    crate::uuid_util::parse_uuid(&user.credential).map_err(|e| {
        invalid_error(format!(
            "node `{}` user {} has invalid VLESS uuid `{}`: {e}",
            spec.tag, user.uid, user.credential
        ))
    })
}

fn vless_vision_flow(spec: &RuntimeNodeSpec) -> Option<&str> {
    match (&spec.node_type, &spec.protocol) {
        (
            NodeType::Vless,
            RuntimeProtocol::Vless {
                flow: Some(flow), ..
            },
        ) if flow == VLESS_XTLS_VISION_FLOW => Some(flow.as_str()),
        _ => None,
    }
}

fn bind_location(spec: &RuntimeNodeSpec) -> std::io::Result<BindLocation> {
    let bind = spec.bind.address();
    NetLocation::from_str(&bind, None)
        .map(BindLocation::from)
        .map_err(|e| {
            invalid_error(format!(
                "invalid bind address for node `{}`: {bind}: {e}",
                spec.tag
            ))
        })
}

fn websocket_headers(
    headers: &std::collections::HashMap<String, String>,
) -> Option<FxHashMap<String, String>> {
    if headers.is_empty() {
        return None;
    }
    Some(
        headers
            .iter()
            .map(|(key, value)| {
                let mut key = key.clone();
                key.make_ascii_lowercase();
                (key, value.clone())
            })
            .collect(),
    )
}

fn boxed_handler(handler: Arc<dyn TcpServerHandler>) -> Box<dyn TcpServerHandler> {
    Box::new(ArcTcpServerHandler(handler))
}

#[derive(Debug)]
struct ArcTcpServerHandler(Arc<dyn TcpServerHandler>);

#[async_trait::async_trait]
impl TcpServerHandler for ArcTcpServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.0.setup_server_stream(server_stream).await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        server_stream: Box<dyn AsyncStream>,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.0
            .setup_server_stream_with_peer_addr(server_stream, peer_addr)
            .await
    }
}

fn invalid<T>(msg: impl Into<String>) -> std::io::Result<T> {
    Err(invalid_error(msg))
}

fn invalid_error(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.into())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::backend_config::RouteRuleSetsConfig;
    use crate::resolver::NativeResolver;
    use crate::v2board::runtime_model::{
        RuntimeBaseConfig, RuntimeBind, RuntimeReality, RuntimeRoute, RuntimeTls, RuntimeUser,
        UserPolicy,
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;

    fn valid_reality_private_key() -> String {
        URL_SAFE_NO_PAD.encode([7u8; 32])
    }

    fn test_tracker() -> Arc<TrafficTracker> {
        let dir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        Arc::new(
            runtime
                .block_on(TrafficTracker::new(dir.path().to_path_buf()))
                .unwrap(),
        )
    }

    fn test_resolver() -> Arc<dyn Resolver> {
        Arc::new(NativeResolver::new())
    }

    fn expect_build_err(spec: RuntimeNodeSpec) -> std::io::Error {
        match build_runtime_node(spec, test_tracker(), test_resolver(), 10, None) {
            Ok(_) => panic!("expected runtime node build to fail"),
            Err(err) => err,
        }
    }

    fn shadowsocks_spec(
        cipher: &str,
        server_key: Option<String>,
        users: Vec<RuntimeUser>,
    ) -> RuntimeNodeSpec {
        RuntimeNodeSpec {
            tag: "ss-node".to_string(),
            node_id: 1,
            config_node_type: NodeType::Shadowsocks,
            node_type: NodeType::Shadowsocks,
            bind: RuntimeBind {
                listen: "127.0.0.1".to_string(),
                port: 8388,
            },
            accept_proxy_protocol: false,
            protocol: RuntimeProtocol::Shadowsocks {
                cipher: cipher.to_string(),
                server_key,
                obfs: ShadowsocksObfs::Plain,
                encryption_settings: None,
            },
            transport: RuntimeTransport::Tcp { header: None },
            security: RuntimeSecurity::None,
            users,
            base: RuntimeBaseConfig {
                pull_interval_secs: 60,
                push_interval_secs: 60,
                node_report_min_traffic: 0,
                device_online_min_traffic: 0,
            },
            routes: Vec::<RuntimeRoute>::new(),
            route_rule_sets: Default::default(),
        }
    }

    fn vless_reality_spec(reality: RuntimeReality) -> RuntimeNodeSpec {
        RuntimeNodeSpec {
            tag: "vless-reality".to_string(),
            node_id: 1,
            config_node_type: NodeType::Vless,
            node_type: NodeType::Vless,
            bind: RuntimeBind {
                listen: "127.0.0.1".to_string(),
                port: 8443,
            },
            accept_proxy_protocol: false,
            protocol: RuntimeProtocol::Vless {
                encryption: "none".to_string(),
                flow: None,
            },
            transport: RuntimeTransport::Tcp { header: None },
            security: RuntimeSecurity::Reality(reality),
            users: vec![runtime_user(
                1,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                None,
            )],
            base: RuntimeBaseConfig {
                pull_interval_secs: 60,
                push_interval_secs: 60,
                node_report_min_traffic: 0,
                device_online_min_traffic: 0,
            },
            routes: Vec::<RuntimeRoute>::new(),
            route_rule_sets: Default::default(),
        }
    }

    fn vmess_tls_spec(tls: RuntimeTls) -> RuntimeNodeSpec {
        RuntimeNodeSpec {
            tag: "vmess-tls".to_string(),
            node_id: 1,
            config_node_type: NodeType::Vmess,
            node_type: NodeType::Vmess,
            bind: RuntimeBind {
                listen: "127.0.0.1".to_string(),
                port: 8443,
            },
            accept_proxy_protocol: false,
            protocol: RuntimeProtocol::Vmess {
                security: "auto".to_string(),
            },
            transport: RuntimeTransport::Tcp { header: None },
            security: RuntimeSecurity::Tls(tls),
            users: vec![runtime_user(
                1,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                None,
            )],
            base: RuntimeBaseConfig {
                pull_interval_secs: 60,
                push_interval_secs: 60,
                node_report_min_traffic: 0,
                device_online_min_traffic: 0,
            },
            routes: Vec::<RuntimeRoute>::new(),
            route_rule_sets: Default::default(),
        }
    }

    fn anytls_tls_spec(tls: RuntimeTls) -> RuntimeNodeSpec {
        RuntimeNodeSpec {
            tag: "anytls-tls".to_string(),
            node_id: 1,
            config_node_type: NodeType::Anytls,
            node_type: NodeType::Anytls,
            bind: RuntimeBind {
                listen: "127.0.0.1".to_string(),
                port: 8444,
            },
            accept_proxy_protocol: false,
            protocol: RuntimeProtocol::Anytls {
                padding_scheme: vec![
                    "stop=2".to_string(),
                    "0=30-30".to_string(),
                    "1=100-100".to_string(),
                ],
            },
            transport: RuntimeTransport::Tcp { header: None },
            security: RuntimeSecurity::Tls(tls),
            users: vec![runtime_user(
                1,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                None,
            )],
            base: RuntimeBaseConfig {
                pull_interval_secs: 60,
                push_interval_secs: 60,
                node_report_min_traffic: 0,
                device_online_min_traffic: 0,
            },
            routes: Vec::<RuntimeRoute>::new(),
            route_rule_sets: Default::default(),
        }
    }

    fn tuic_tls_spec(tls: RuntimeTls) -> RuntimeNodeSpec {
        RuntimeNodeSpec {
            tag: "tuic-tls".to_string(),
            node_id: 1,
            config_node_type: NodeType::Tuic,
            node_type: NodeType::Tuic,
            bind: RuntimeBind {
                listen: "127.0.0.1".to_string(),
                port: 8445,
            },
            accept_proxy_protocol: false,
            protocol: RuntimeProtocol::Tuic {
                zero_rtt_handshake: true,
                congestion_control: Some("bbr".to_string()),
                udp_relay_mode: Some("native".to_string()),
                disable_sni: false,
            },
            transport: RuntimeTransport::Quic,
            security: RuntimeSecurity::Tls(tls),
            users: vec![runtime_user(
                1,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                None,
            )],
            base: RuntimeBaseConfig {
                pull_interval_secs: 60,
                push_interval_secs: 60,
                node_report_min_traffic: 0,
                device_online_min_traffic: 0,
            },
            routes: Vec::<RuntimeRoute>::new(),
            route_rule_sets: Default::default(),
        }
    }

    fn hysteria2_tls_spec(tls: RuntimeTls) -> RuntimeNodeSpec {
        RuntimeNodeSpec {
            tag: "hy2-tls".to_string(),
            node_id: 1,
            config_node_type: NodeType::Hysteria,
            node_type: NodeType::Hysteria,
            bind: RuntimeBind {
                listen: "127.0.0.1".to_string(),
                port: 8446,
            },
            accept_proxy_protocol: false,
            protocol: RuntimeProtocol::Hysteria2 {
                up_mbps: 0,
                down_mbps: 0,
                ignore_client_bandwidth: true,
                obfs: None,
                obfs_password: None,
                masquerade: None,
            },
            transport: RuntimeTransport::Quic,
            security: RuntimeSecurity::Tls(tls),
            users: vec![runtime_user(
                1,
                "b831381d-6324-4d53-ad4f-8cda48b30811",
                None,
            )],
            base: RuntimeBaseConfig {
                pull_interval_secs: 60,
                push_interval_secs: 60,
                node_report_min_traffic: 0,
                device_online_min_traffic: 0,
            },
            routes: Vec::<RuntimeRoute>::new(),
            route_rule_sets: Default::default(),
        }
    }

    fn naiveproxy_tls_spec(tls: RuntimeTls) -> RuntimeNodeSpec {
        let mut user = runtime_user(1, "00000000-0000-0000-0000-000000000001", None);
        user.username = Some("user-1".to_string());
        user.password = Some("00000000-0000-0000-0000-000000000001".to_string());
        RuntimeNodeSpec {
            tag: "naive-tls".to_string(),
            node_id: 1,
            config_node_type: NodeType::Naiveproxy,
            node_type: NodeType::Naiveproxy,
            bind: RuntimeBind {
                listen: "127.0.0.1".to_string(),
                port: 8447,
            },
            accept_proxy_protocol: false,
            protocol: RuntimeProtocol::Naiveproxy {
                quic_congestion_control: None,
            },
            transport: RuntimeTransport::Tcp { header: None },
            security: RuntimeSecurity::Tls(tls),
            users: vec![user],
            base: RuntimeBaseConfig {
                pull_interval_secs: 60,
                push_interval_secs: 60,
                node_report_min_traffic: 0,
                device_online_min_traffic: 0,
            },
            routes: Vec::<RuntimeRoute>::new(),
            route_rule_sets: Default::default(),
        }
    }

    fn runtime_tls() -> RuntimeTls {
        RuntimeTls {
            server_name: Some("tls.example.com".to_string()),
            server_names: Vec::new(),
            alpn: Vec::new(),
            allow_insecure: false,
            certificate: None,
            cert_mode: None,
            ech: None,
            ech_server_name: None,
            ech_key: None,
            ech_config: None,
            raw_settings: None,
        }
    }

    fn runtime_tls_with_certificate() -> (RuntimeTls, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let certified =
            rcgen::generate_simple_self_signed(vec!["tls.example.com".to_string()]).unwrap();
        let cert_file = dir.path().join("tls.crt");
        let key_file = dir.path().join("tls.key");
        std::fs::write(&cert_file, certified.cert.pem()).unwrap();
        std::fs::write(&key_file, certified.signing_key.serialize_pem()).unwrap();

        let mut tls = runtime_tls();
        tls.certificate = Some(crate::v2board::runtime_model::RuntimeTlsCertificate {
            cert_file,
            key_file,
        });
        (tls, dir)
    }

    fn runtime_reality() -> RuntimeReality {
        RuntimeReality {
            server_name: Some("www.example.com".to_string()),
            server_names: Vec::new(),
            private_key: Some(valid_reality_private_key()),
            public_key: None,
            short_ids: vec!["abcd".to_string()],
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
            fingerprint: None,
            raw_settings: None,
        }
    }

    fn runtime_user(uid: u64, credential: &str, secret: Option<String>) -> RuntimeUser {
        RuntimeUser {
            uid,
            credential: credential.to_string(),
            secret,
            username: None,
            password: None,
            user_key: credential.to_string(),
            policy: UserPolicy {
                speed_limit_mbps: None,
                device_limit: None,
            },
            label: None,
        }
    }

    #[test]
    fn builds_tuic_runtime_node_with_authenticated_users() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let spec = tuic_tls_spec(tls);

        let node = build_runtime_node(spec, test_tracker(), test_resolver(), 10, None).unwrap();

        match node.kind {
            RuntimeNodeKind::Tuic {
                zero_rtt_handshake,
                congestion_control,
                num_endpoints,
                ..
            } => {
                assert!(zero_rtt_handshake);
                assert_eq!(congestion_control.as_deref(), Some("bbr"));
                assert!(num_endpoints >= 1);
            }
            RuntimeNodeKind::Tcp { .. }
            | RuntimeNodeKind::Hysteria2 { .. }
            | RuntimeNodeKind::NaiveH3 { .. }
            | RuntimeNodeKind::NaiveCombined { .. }
            | RuntimeNodeKind::Kcptun { .. } => panic!("expected TUIC runtime node"),
        }
    }

    #[test]
    fn builds_hysteria2_runtime_node_with_authenticated_users() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = hysteria2_tls_spec(tls);
        spec.protocol = RuntimeProtocol::Hysteria2 {
            up_mbps: 50,
            down_mbps: 25,
            ignore_client_bandwidth: false,
            obfs: None,
            obfs_password: None,
            masquerade: None,
        };

        let node = build_runtime_node(spec, test_tracker(), test_resolver(), 10, None).unwrap();

        match node.kind {
            RuntimeNodeKind::Hysteria2 {
                num_endpoints,
                udp_enabled,
                up_mbps,
                down_mbps,
                ignore_client_bandwidth,
                ..
            } => {
                assert!(num_endpoints >= 1);
                assert!(udp_enabled);
                assert_eq!(up_mbps, 50);
                assert_eq!(down_mbps, 25);
                assert!(!ignore_client_bandwidth);
            }
            RuntimeNodeKind::Tcp { .. }
            | RuntimeNodeKind::Tuic { .. }
            | RuntimeNodeKind::NaiveH3 { .. }
            | RuntimeNodeKind::NaiveCombined { .. }
            | RuntimeNodeKind::Kcptun { .. } => {
                panic!("expected Hysteria2 runtime node")
            }
        }
    }

    #[test]
    fn builds_hysteria2_static_masquerade_from_node_local_config() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = hysteria2_tls_spec(tls);
        spec.protocol = RuntimeProtocol::Hysteria2 {
            up_mbps: 0,
            down_mbps: 0,
            ignore_client_bandwidth: true,
            obfs: None,
            obfs_password: None,
            masquerade: Some(crate::backend_config::Hysteria2MasqueradeConfig {
                status_code: 200,
                content_type: "text/plain".to_string(),
                body: "not a proxy".to_string(),
            }),
        };

        let node = build_runtime_node(spec, test_tracker(), test_resolver(), 10, None).unwrap();

        match node.kind {
            RuntimeNodeKind::Hysteria2 {
                masquerade: Some(_),
                ..
            } => {}
            _ => panic!("expected Hysteria2 runtime node with masquerade"),
        }
    }

    #[test]
    fn accepts_hysteria2_salamander_obfs() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = hysteria2_tls_spec(tls);
        spec.protocol = RuntimeProtocol::Hysteria2 {
            up_mbps: 0,
            down_mbps: 0,
            ignore_client_bandwidth: true,
            obfs: Some("salamander".to_string()),
            obfs_password: Some("secret".to_string()),
            masquerade: None,
        };

        let node = build_runtime_node(spec, test_tracker(), test_resolver(), 10, None).unwrap();

        match node.kind {
            RuntimeNodeKind::Hysteria2 { obfs, .. } => {
                assert_eq!(
                    obfs,
                    Some(Hysteria2Obfs::Salamander {
                        password: "secret".to_string(),
                    })
                );
            }
            RuntimeNodeKind::Tcp { .. }
            | RuntimeNodeKind::Tuic { .. }
            | RuntimeNodeKind::NaiveH3 { .. }
            | RuntimeNodeKind::NaiveCombined { .. }
            | RuntimeNodeKind::Kcptun { .. } => {
                panic!("expected Hysteria2 runtime node")
            }
        }
    }

    #[test]
    fn rejects_hysteria2_obfs_password_without_type() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = hysteria2_tls_spec(tls);
        spec.protocol = RuntimeProtocol::Hysteria2 {
            up_mbps: 0,
            down_mbps: 0,
            ignore_client_bandwidth: true,
            obfs: None,
            obfs_password: Some("secret".to_string()),
            masquerade: None,
        };

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("obfs_password is set"));
    }

    #[test]
    fn rejects_hysteria2_salamander_without_password() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = hysteria2_tls_spec(tls);
        spec.protocol = RuntimeProtocol::Hysteria2 {
            up_mbps: 0,
            down_mbps: 0,
            ignore_client_bandwidth: true,
            obfs: Some("salamander".to_string()),
            obfs_password: None,
            masquerade: None,
        };

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("requires obfs_password"));
    }

    #[test]
    fn accepts_hysteria2_gecko_obfs() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = hysteria2_tls_spec(tls);
        spec.protocol = RuntimeProtocol::Hysteria2 {
            up_mbps: 0,
            down_mbps: 0,
            ignore_client_bandwidth: true,
            obfs: Some("gecko".to_string()),
            obfs_password: Some("secret".to_string()),
            masquerade: None,
        };

        let node = build_runtime_node(spec, test_tracker(), test_resolver(), 10, None).unwrap();

        match node.kind {
            RuntimeNodeKind::Hysteria2 { obfs, .. } => {
                assert!(matches!(obfs, Some(Hysteria2Obfs::Gecko { .. })));
            }
            _ => panic!("expected hysteria2 node"),
        }
    }

    #[test]
    fn rejects_unknown_hysteria2_obfs() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = hysteria2_tls_spec(tls);
        spec.protocol = RuntimeProtocol::Hysteria2 {
            up_mbps: 0,
            down_mbps: 0,
            ignore_client_bandwidth: true,
            obfs: Some("xplus".to_string()),
            obfs_password: Some("secret".to_string()),
            masquerade: None,
        };

        let err = expect_build_err(spec);

        assert!(
            err.to_string()
                .contains("unsupported hysteria2 obfs `xplus`")
        );
    }

    #[test]
    fn accepts_hysteria2_panel_bandwidth_limits() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = hysteria2_tls_spec(tls);
        spec.protocol = RuntimeProtocol::Hysteria2 {
            up_mbps: 100,
            down_mbps: 100,
            ignore_client_bandwidth: false,
            obfs: None,
            obfs_password: None,
            masquerade: None,
        };

        let node = build_runtime_node(spec, test_tracker(), test_resolver(), 10, None).unwrap();

        match node.kind {
            RuntimeNodeKind::Hysteria2 {
                up_mbps,
                down_mbps,
                ignore_client_bandwidth,
                ..
            } => {
                assert_eq!(up_mbps, 100);
                assert_eq!(down_mbps, 100);
                assert!(!ignore_client_bandwidth);
            }
            RuntimeNodeKind::Tcp { .. }
            | RuntimeNodeKind::Tuic { .. }
            | RuntimeNodeKind::NaiveH3 { .. }
            | RuntimeNodeKind::NaiveCombined { .. }
            | RuntimeNodeKind::Kcptun { .. } => {
                panic!("expected Hysteria2 runtime node")
            }
        }
    }

    #[test]
    fn builds_naiveproxy_runtime_node_with_authenticated_users() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let spec = naiveproxy_tls_spec(tls);

        let lookup = naiveproxy_user_lookup(&spec, test_tracker()).unwrap();
        let auth_header = format!(
            "Basic {}",
            BASE64.encode("user-1:00000000-0000-0000-0000-000000000001")
        );
        let validated = lookup.validate(&auth_header).unwrap();
        assert_eq!(validated.name, "user-1");
        assert_eq!(validated.authenticated_user.unwrap().uid, 1);

        let node =
            build_runtime_node(spec.clone(), test_tracker(), test_resolver(), 10, None).unwrap();

        match node.kind {
            RuntimeNodeKind::Tcp { .. } => {}
            RuntimeNodeKind::Tuic { .. }
            | RuntimeNodeKind::Hysteria2 { .. }
            | RuntimeNodeKind::NaiveH3 { .. }
            | RuntimeNodeKind::NaiveCombined { .. }
            | RuntimeNodeKind::Kcptun { .. } => {
                panic!("expected NaiveProxy TCP runtime node")
            }
        }
        assert_eq!(
            tls_alpn_for_transport(&spec, &runtime_tls()),
            vec!["h2".to_string(), "http/1.1".to_string()]
        );
    }

    #[test]
    fn builds_naiveproxy_quic_h3_runtime_node() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = naiveproxy_tls_spec(tls);
        spec.protocol = RuntimeProtocol::Naiveproxy {
            quic_congestion_control: Some("bbr2".to_string()),
        };
        spec.transport = RuntimeTransport::Quic;

        let node = build_runtime_node(spec, test_tracker(), test_resolver(), 10, None).unwrap();

        match node.kind {
            RuntimeNodeKind::NaiveH3 {
                congestion_control,
                num_endpoints,
                ..
            } => {
                assert_eq!(congestion_control.as_deref(), Some("bbr2"));
                assert!(num_endpoints >= 1);
            }
            RuntimeNodeKind::Tcp { .. }
            | RuntimeNodeKind::Tuic { .. }
            | RuntimeNodeKind::Hysteria2 { .. }
            | RuntimeNodeKind::NaiveCombined { .. }
            | RuntimeNodeKind::Kcptun { .. } => {
                panic!("expected NaiveProxy H3 runtime node")
            }
        }
    }

    #[test]
    fn builds_naiveproxy_dual_tcp_h3_runtime_node() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = naiveproxy_tls_spec(tls);
        spec.protocol = RuntimeProtocol::Naiveproxy {
            quic_congestion_control: Some("bbr_standard".to_string()),
        };
        spec.transport = RuntimeTransport::TcpAndQuic;

        let node = build_runtime_node(spec, test_tracker(), test_resolver(), 10, None).unwrap();

        match node.kind {
            RuntimeNodeKind::NaiveCombined {
                congestion_control,
                num_endpoints,
                ..
            } => {
                assert_eq!(congestion_control.as_deref(), Some("bbr_standard"));
                assert!(num_endpoints >= 1);
            }
            RuntimeNodeKind::Tcp { .. }
            | RuntimeNodeKind::Tuic { .. }
            | RuntimeNodeKind::Hysteria2 { .. }
            | RuntimeNodeKind::NaiveH3 { .. }
            | RuntimeNodeKind::Kcptun { .. } => {
                panic!("expected NaiveProxy dual TCP/H3 runtime node")
            }
        }
    }

    #[test]
    fn rejects_naiveproxy_unknown_quic_congestion_control() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = naiveproxy_tls_spec(tls);
        spec.protocol = RuntimeProtocol::Naiveproxy {
            quic_congestion_control: Some("invalid-cc".to_string()),
        };
        spec.transport = RuntimeTransport::TcpAndQuic;

        let err = expect_build_err(spec);

        assert!(
            err.to_string()
                .contains("unsupported naiveproxy quic_congestion_control `invalid-cc`")
        );
    }

    #[test]
    fn rejects_naiveproxy_tcp_quic_congestion_control() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = naiveproxy_tls_spec(tls);
        spec.protocol = RuntimeProtocol::Naiveproxy {
            quic_congestion_control: Some("bbr".to_string()),
        };
        spec.transport = RuntimeTransport::Tcp { header: None };

        let err = expect_build_err(spec);

        assert!(
            err.to_string()
                .contains("naiveproxy quic_congestion_control requires QUIC/H3 transport")
        );
    }

    #[test]
    fn rejects_naiveproxy_plaintext_security() {
        let mut spec = naiveproxy_tls_spec(runtime_tls());
        spec.security = RuntimeSecurity::None;

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("naiveproxy requires TLS"));
    }

    #[test]
    fn rejects_naiveproxy_non_plain_tcp_transport() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = naiveproxy_tls_spec(tls);
        spec.transport = RuntimeTransport::Websocket {
            path: "/naive".to_string(),
            headers: HashMap::new(),
            max_early_data: None,
            early_data_header_name: None,
        };

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("plain tcp or QUIC/H3 transport"));
    }

    #[test]
    fn rejects_naiveproxy_custom_alpn() {
        let (mut tls, _dir) = runtime_tls_with_certificate();
        tls.alpn = vec!["h3".to_string()];
        let spec = naiveproxy_tls_spec(tls);

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("custom TLS ALPN"));
    }

    #[test]
    fn rejects_naiveproxy_duplicate_username_password() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = naiveproxy_tls_spec(tls);
        let mut second = runtime_user(2, "00000000-0000-0000-0000-000000000002", None);
        second.username = Some("user-1".to_string());
        second.password = Some("00000000-0000-0000-0000-000000000001".to_string());
        spec.users.push(second);

        let err = naiveproxy_user_lookup(&spec, test_tracker()).unwrap_err();

        assert!(err.to_string().contains("duplicates user"));
    }

    #[test]
    fn rejects_hysteria2_proxy_protocol() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = hysteria2_tls_spec(tls);
        spec.accept_proxy_protocol = true;

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("acceptProxyProtocol"));
    }

    #[test]
    fn rejects_tuic_user_with_invalid_uuid() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = tuic_tls_spec(tls);
        spec.users = vec![runtime_user(1, "not-a-uuid", None)];

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("invalid TUIC uuid"));
    }

    #[test]
    fn rejects_tuic_proxy_protocol() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = tuic_tls_spec(tls);
        spec.accept_proxy_protocol = true;

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("acceptProxyProtocol"));
    }

    #[test]
    fn accepts_tuic_supported_udp_relay_modes() {
        for mode in ["native", "quic", "packetaddr", "packet_addr"] {
            let (tls, _dir) = runtime_tls_with_certificate();
            let mut spec = tuic_tls_spec(tls);
            if let RuntimeProtocol::Tuic { udp_relay_mode, .. } = &mut spec.protocol {
                *udp_relay_mode = Some(mode.to_string());
            }

            build_runtime_node(spec, test_tracker(), test_resolver(), 10, None).unwrap();
        }
    }

    #[test]
    fn rejects_tuic_unsupported_udp_relay_mode() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = tuic_tls_spec(tls);
        if let RuntimeProtocol::Tuic { udp_relay_mode, .. } = &mut spec.protocol {
            *udp_relay_mode = Some("invalid-mode".to_string());
        }

        let err = expect_build_err(spec);

        assert!(
            err.to_string()
                .contains("tuic udp_relay_mode `invalid-mode` is not supported")
        );
    }

    fn route(action: &str, matches: Vec<&str>) -> RuntimeRoute {
        RuntimeRoute {
            raw: json!({
                "id": 1,
                "action": action,
                "match": matches,
                "action_value": null
            }),
        }
    }

    #[tokio::test]
    async fn v2board_block_route_supports_domain_match_modes() {
        let mut spec =
            shadowsocks_spec("aes-128-gcm", None, vec![runtime_user(1, "password", None)]);
        spec.routes = vec![route(
            "block",
            vec![
                "video",
                "domain:example.com",
                "full:api.internal.local",
                r"regexp:^cdn-[0-9]+\.regex-route\.local$",
            ],
        )];
        let selector = build_v2board_proxy_selector(&spec, test_resolver()).unwrap();

        let keyword = NetLocation::new(Address::Hostname("cdn-video.local".to_string()), 443);
        let decision = selector
            .judge(keyword.into(), &test_resolver())
            .await
            .unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Block
        ));

        let suffix = NetLocation::new(Address::Hostname("www.example.com".to_string()), 443);
        let decision = selector
            .judge(suffix.into(), &test_resolver())
            .await
            .unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Block
        ));

        let full = NetLocation::new(Address::Hostname("api.internal.local".to_string()), 443);
        let decision = selector.judge(full.into(), &test_resolver()).await.unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Block
        ));

        let regex = NetLocation::new(
            Address::Hostname("cdn-42.regex-route.local".to_string()),
            443,
        );
        let decision = selector
            .judge(regex.into(), &test_resolver())
            .await
            .unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Block
        ));

        let allowed = NetLocation::new(Address::Hostname("not-example.local".to_string()), 443);
        let decision = selector
            .judge(allowed.into(), &test_resolver())
            .await
            .unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn v2board_block_ip_and_port_routes_are_enforced() {
        let mut spec =
            shadowsocks_spec("aes-128-gcm", None, vec![runtime_user(1, "password", None)]);
        spec.routes = vec![
            route("block_ip", vec!["127.0.0.0/8"]),
            route("block_port", vec!["18080-18081", "18082:18083"]),
        ];
        let selector = build_v2board_proxy_selector(&spec, test_resolver()).unwrap();

        let blocked_ip =
            NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let decision = selector
            .judge(blocked_ip.into(), &test_resolver())
            .await
            .unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Block
        ));

        let blocked_port =
            NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 18081);
        let decision = selector
            .judge(blocked_port.into(), &test_resolver())
            .await
            .unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Block
        ));

        let blocked_colon_range_port =
            NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 18083);
        let decision = selector
            .judge(blocked_colon_range_port.into(), &test_resolver())
            .await
            .unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Block
        ));

        let allowed = NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 443);
        let decision = selector
            .judge(allowed.into(), &test_resolver())
            .await
            .unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn v2board_route_rule_sets_support_geosite_and_geoip_matchers() {
        let dir = tempfile::tempdir().unwrap();
        let geosite_path = dir.path().join("geosite-local.txt");
        let geoip_path = dir.path().join("geoip-local.txt");
        std::fs::write(
            &geosite_path,
            "domain:stream.example\nfull:api.rule.local\nregexp:^cdn-[0-9]+\\.rule\\.local$\n",
        )
        .unwrap();
        std::fs::write(&geoip_path, "127.0.0.0/8\n2001:db8::/32\n").unwrap();

        let mut spec =
            shadowsocks_spec("aes-128-gcm", None, vec![runtime_user(1, "password", None)]);
        spec.route_rule_sets = RouteRuleSetsConfig {
            geosite: HashMap::from([("local".to_string(), geosite_path)]),
            geoip: HashMap::from([("local".to_string(), geoip_path)]),
        };
        spec.routes = vec![
            route("block", vec!["geosite:local"]),
            route("block_ip", vec!["geoip:local"]),
        ];
        let selector = build_v2board_proxy_selector(&spec, test_resolver()).unwrap();

        let geosite = NetLocation::new(Address::Hostname("cdn-42.rule.local".to_string()), 443);
        let decision = selector
            .judge(geosite.into(), &test_resolver())
            .await
            .unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Block
        ));

        let geoip = NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let decision = selector
            .judge(geoip.into(), &test_resolver())
            .await
            .unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Block
        ));

        let allowed = NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 443);
        let decision = selector
            .judge(allowed.into(), &test_resolver())
            .await
            .unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn v2board_protocol_route_blocks_sniffed_protocols() {
        let mut spec =
            shadowsocks_spec("aes-128-gcm", None, vec![runtime_user(1, "password", None)]);
        spec.routes = vec![route("protocol", vec!["http", "tls", "bittorrent"])];
        let selector = build_v2board_proxy_selector(&spec, test_resolver()).unwrap();

        assert!(selector.requires_protocol_sniff());

        let target = NetLocation::new(Address::Hostname("payload.example".to_string()), 443);
        let decision = selector
            .judge_with_protocol(
                target.clone().into(),
                &test_resolver(),
                Some(SniffedProtocol::Http),
            )
            .await
            .unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Block
        ));

        let decision = selector
            .judge_with_protocol(
                target.clone().into(),
                &test_resolver(),
                Some(SniffedProtocol::Ssh),
            )
            .await
            .unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Allow { .. }
        ));

        let decision = selector
            .judge(target.into(), &test_resolver())
            .await
            .unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn v2board_block_route_accepts_protocol_prefixed_matchers() {
        let mut spec =
            shadowsocks_spec("aes-128-gcm", None, vec![runtime_user(1, "password", None)]);
        spec.routes = vec![route(
            "block",
            vec!["protocol:bittorrent", "domain:blocked.test"],
        )];
        let selector = build_v2board_proxy_selector(&spec, test_resolver()).unwrap();

        assert!(selector.requires_protocol_sniff());

        let bittorrent_target =
            NetLocation::new(Address::Hostname("allowed.test".to_string()), 443);
        let decision = selector
            .judge_with_protocol(
                bittorrent_target.into(),
                &test_resolver(),
                Some(SniffedProtocol::Bittorrent),
            )
            .await
            .unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Block
        ));

        let domain_target =
            NetLocation::new(Address::Hostname("api.blocked.test".to_string()), 443);
        let decision = selector
            .judge_with_protocol(
                domain_target.into(),
                &test_resolver(),
                Some(SniffedProtocol::Http),
            )
            .await
            .unwrap();
        assert!(matches!(
            decision,
            crate::client_proxy_selector::ConnectDecision::Block
        ));
    }

    #[test]
    fn v2board_v2ray_http_transport_builds_for_plaintext_nodes() {
        let mut spec = vmess_tls_spec(runtime_tls());
        spec.tag = "vmess-http".to_string();
        spec.security = RuntimeSecurity::None;
        spec.transport = RuntimeTransport::Http {
            hosts: vec!["edge.example".to_string()],
            paths: vec!["/ray".to_string()],
            method: Some("PUT".to_string()),
            response_headers: HashMap::from([("X-Edge".to_string(), "ok".to_string())]),
        };

        build_runtime_node(spec, test_tracker(), test_resolver(), 10, None).unwrap();
    }

    #[test]
    fn v2board_tcp_http_header_obfuscation_builds_for_plaintext_nodes() {
        let mut spec = vmess_tls_spec(runtime_tls());
        spec.tag = "vmess-tcp-http-header".to_string();
        spec.security = RuntimeSecurity::None;
        spec.transport = RuntimeTransport::Tcp {
            header: Some(TcpHeader::Http {
                hosts: vec!["front.example".to_string()],
                paths: vec!["/front".to_string()],
                method: Some("GET".to_string()),
            }),
        };

        build_runtime_node(spec, test_tracker(), test_resolver(), 10, None).unwrap();
    }

    #[test]
    fn v2board_v2ray_http_transport_builds_for_tls_nodes() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = vmess_tls_spec(tls);
        spec.transport = RuntimeTransport::Http {
            hosts: vec!["edge.example".to_string()],
            paths: vec!["/ray".to_string()],
            method: Some("PUT".to_string()),
            response_headers: HashMap::new(),
        };

        build_runtime_node(spec.clone(), test_tracker(), test_resolver(), 10, None).unwrap();
        assert_eq!(tls_alpn_for_transport(&spec, &runtime_tls()), vec!["h2"]);
    }

    #[test]
    fn v2board_tcp_http_header_obfuscation_builds_for_tls_nodes() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = vmess_tls_spec(tls);
        spec.transport = RuntimeTransport::Tcp {
            header: Some(TcpHeader::Http {
                hosts: vec!["front.example".to_string()],
                paths: vec!["/front".to_string()],
                method: Some("GET".to_string()),
            }),
        };

        build_runtime_node(spec, test_tracker(), test_resolver(), 10, None).unwrap();
    }

    #[test]
    fn v2board_anytls_builds_for_tls_nodes() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let spec = anytls_tls_spec(tls);

        let node = build_runtime_node(spec, test_tracker(), test_resolver(), 10, None).unwrap();

        assert_eq!(node.tag, "anytls-tls");
    }

    #[test]
    fn v2board_anytls_rejects_plaintext_security() {
        let mut spec = anytls_tls_spec(runtime_tls());
        spec.security = RuntimeSecurity::None;

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("anytls requires TLS"));
    }

    #[test]
    fn v2board_anytls_rejects_non_tcp_transport() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = anytls_tls_spec(tls);
        spec.transport = RuntimeTransport::Websocket {
            path: "/anytls".to_string(),
            headers: HashMap::new(),
            max_early_data: None,
            early_data_header_name: None,
        };

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("plain tcp transport"));
    }

    #[test]
    fn v2board_anytls_rejects_v1_reality() {
        let mut spec = anytls_tls_spec(runtime_tls());
        spec.security = RuntimeSecurity::Reality(runtime_reality());

        let err = expect_build_err(spec);

        assert!(
            err.to_string()
                .contains("V1 anytls does not expose Reality")
        );
    }

    #[test]
    fn v2board_v2node_anytls_reality_builds() {
        let mut spec = anytls_tls_spec(runtime_tls());
        spec.config_node_type = NodeType::V2Node;
        spec.security = RuntimeSecurity::Reality(runtime_reality());

        let node = build_runtime_node(spec, test_tracker(), test_resolver(), 10, None).unwrap();

        assert_eq!(node.tag, "anytls-tls");
    }

    #[test]
    fn v2board_anytls_rejects_duplicate_credentials() {
        let (tls, _dir) = runtime_tls_with_certificate();
        let mut spec = anytls_tls_spec(tls);
        spec.users = vec![
            runtime_user(1, "same-password", None),
            runtime_user(2, "same-password", None),
        ];

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("duplicates user"));
    }

    #[test]
    fn v2board_v2ray_http_transport_builds_for_reality_nodes() {
        let mut spec = vless_reality_spec(runtime_reality());
        spec.transport = RuntimeTransport::Http {
            hosts: vec!["edge.example".to_string()],
            paths: vec!["/ray".to_string()],
            method: Some("PUT".to_string()),
            response_headers: HashMap::new(),
        };

        build_runtime_node(spec.clone(), test_tracker(), test_resolver(), 10, None).unwrap();
        assert_eq!(selected_reality_alpn(&spec), Some("h2".to_string()));
    }

    #[test]
    fn v2board_routes_reject_unsupported_actions_and_matchers() {
        let mut spec =
            shadowsocks_spec("aes-128-gcm", None, vec![runtime_user(1, "password", None)]);
        spec.routes = vec![route("route", vec!["example.com"])];
        let err = build_v2board_proxy_selector(&spec, test_resolver()).unwrap_err();
        assert!(
            err.to_string()
                .contains("route action `route` is not supported")
        );

        spec.routes = vec![route("block", vec!["geosite:cn"])];
        let err = build_v2board_proxy_selector(&spec, test_resolver()).unwrap_err();
        assert!(
            err.to_string()
                .contains("requires v2board.route_rule_sets.geosite.cn")
        );

        spec.routes = vec![route("block_ip", vec!["geoip:cn"])];
        let err = build_v2board_proxy_selector(&spec, test_resolver()).unwrap_err();
        assert!(
            err.to_string()
                .contains("requires v2board.route_rule_sets.geoip.cn")
        );

        spec.routes = vec![route("block", vec!["regexp:*bad"])];
        let err = build_v2board_proxy_selector(&spec, test_resolver()).unwrap_err();
        assert!(
            err.to_string()
                .contains("route matcher `regexp:*bad` is invalid")
        );

        spec.routes = vec![route("protocol", vec!["smtp"])];
        let err = build_v2board_proxy_selector(&spec, test_resolver()).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported protocol matcher `smtp`")
        );
    }

    #[test]
    fn legacy_shadowsocks_enforces_user_threshold() {
        let spec = shadowsocks_spec(
            "aes-128-gcm",
            None,
            vec![
                runtime_user(1, "u1", None),
                runtime_user(2, "u2", None),
                runtime_user(3, "u3", None),
            ],
        );

        let err = validate_shadowsocks_user_keys(&spec, "aes-128-gcm", None, 2).unwrap_err();

        assert!(err.to_string().contains("legacy AEAD"));
        assert!(err.to_string().contains("O(n)"));
    }

    #[test]
    fn legacy_shadowsocks_rejects_duplicate_credentials() {
        let spec = shadowsocks_spec(
            "aes-128-gcm",
            None,
            vec![
                runtime_user(1, "same-password", None),
                runtime_user(2, "same-password", None),
            ],
        );

        let err = validate_shadowsocks_user_keys(&spec, "aes-128-gcm", None, 10).unwrap_err();

        assert!(err.to_string().contains("duplicates user"));
    }

    #[test]
    fn shadowsocks_rejects_non_plain_tcp_transport() {
        let mut spec =
            shadowsocks_spec("aes-128-gcm", None, vec![runtime_user(1, "password", None)]);
        spec.transport = RuntimeTransport::Websocket {
            path: "/ss".to_string(),
            headers: HashMap::new(),
            max_early_data: None,
            early_data_header_name: None,
        };

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("shadowsocks requires plain tcp"));
    }

    #[test]
    fn shadowsocks_accepts_v2board_http_obfs() {
        let mut spec =
            shadowsocks_spec("aes-128-gcm", None, vec![runtime_user(1, "password", None)]);
        spec.protocol = RuntimeProtocol::Shadowsocks {
            cipher: "aes-128-gcm".to_string(),
            server_key: None,
            obfs: ShadowsocksObfs::Plugin {
                name: "http".to_string(),
                settings: Some(json!({
                    "host": "example.com",
                    "path": "/obfs"
                })),
            },
            encryption_settings: None,
        };

        let node = build_runtime_node(spec, test_tracker(), test_resolver(), 10, None).unwrap();

        assert_eq!(node.tag, "ss-node");
    }

    #[test]
    fn shadowsocks_rejects_unknown_obfs_plugin() {
        let mut spec =
            shadowsocks_spec("aes-128-gcm", None, vec![runtime_user(1, "password", None)]);
        spec.protocol = RuntimeProtocol::Shadowsocks {
            cipher: "aes-128-gcm".to_string(),
            server_key: None,
            obfs: ShadowsocksObfs::Plugin {
                name: "tls".to_string(),
                settings: None,
            },
            encryption_settings: None,
        };

        let err = expect_build_err(spec);

        assert!(
            err.to_string()
                .contains("shadowsocks obfs plugin `tls` is not supported")
        );
    }

    #[test]
    fn shadowsocks_rejects_non_empty_encryption_settings_at_builder() {
        let mut spec =
            shadowsocks_spec("aes-128-gcm", None, vec![runtime_user(1, "password", None)]);
        spec.protocol = RuntimeProtocol::Shadowsocks {
            cipher: "aes-128-gcm".to_string(),
            server_key: None,
            obfs: ShadowsocksObfs::Plain,
            encryption_settings: Some(json!({
                "mode": "native"
            })),
        };

        let err = expect_build_err(spec);

        assert!(
            err.to_string()
                .contains("shadowsocks encryption_settings is not supported")
        );
    }

    #[test]
    fn shadowsocks_2022_accepts_uuid_fallback_psk() {
        let server_key = BASE64.encode([1u8; 16]);
        let spec = shadowsocks_spec(
            "2022-blake3-aes-128-gcm",
            Some(server_key.clone()),
            vec![runtime_user(
                1,
                "00000000-0000-0000-0000-000000000001",
                None,
            )],
        );

        let is_2022 =
            validate_shadowsocks_user_keys(&spec, "2022-blake3-aes-128-gcm", Some(&server_key), 10)
                .unwrap();

        assert!(is_2022);
    }

    #[test]
    fn shadowsocks_2022_builder_creates_multi_user_handler() {
        let server_key = BASE64.encode([1u8; 16]);
        let spec = shadowsocks_spec(
            "2022-blake3-aes-128-gcm",
            Some(server_key),
            vec![runtime_user(
                1,
                "00000000-0000-0000-0000-000000000001",
                None,
            )],
        );

        let node = build_runtime_node(spec, test_tracker(), test_resolver(), 10, None).unwrap();

        assert_eq!(node.tag, "ss-node");
    }

    #[test]
    fn shadowsocks_2022_rejects_duplicate_user_psk() {
        let server_key = BASE64.encode([1u8; 16]);
        let user_key = BASE64.encode([2u8; 16]);
        let spec = shadowsocks_spec(
            "2022-blake3-aes-128-gcm",
            Some(server_key.clone()),
            vec![
                runtime_user(1, "user-a", Some(user_key.clone())),
                runtime_user(2, "user-b", Some(user_key)),
            ],
        );

        let err =
            validate_shadowsocks_user_keys(&spec, "2022-blake3-aes-128-gcm", Some(&server_key), 10)
                .unwrap_err();

        assert!(err.to_string().contains("duplicates user"));
    }

    #[test]
    fn shadowsocks_2022_rejects_chacha_cipher() {
        let spec = shadowsocks_spec(
            "2022-blake3-chacha20-poly1305",
            Some(BASE64.encode([1u8; 32])),
            vec![runtime_user(1, "user-a", None)],
        );

        let err = validate_shadowsocks_user_keys(&spec, "2022-blake3-chacha20-poly1305", None, 10)
            .unwrap_err();

        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn legacy_shadowsocks_rejects_non_v2board_admin_ciphers() {
        for cipher in ["xchacha20-ietf-poly1305", "none"] {
            let spec = shadowsocks_spec(cipher, None, vec![runtime_user(1, "password", None)]);

            let err = validate_shadowsocks_user_keys(&spec, cipher, None, 10).unwrap_err();

            assert!(err.to_string().contains("unsupported shadowsocks cipher"));
        }
    }

    fn routing_app_config() -> AppConfig {
        serde_yaml::from_str::<AppConfig>(
            r#"
v2board:
  api_host: "https://panel.example.com"
  api_key: "server-token"
  nodes:
    - tag: "node-a"
      node_id: 7
      node_type: "vless"
outbounds:
  - tag: "unlock"
    type: "vless"
    server: "203.0.113.10"
    port: 443
    user_id: "00000000-0000-4000-8000-000000000001"
  - tag: "direct"
    type: "direct"
  - tag: "via-socks"
    chain: ["unlock"]
default_out: "direct"
route_rules:
  - "DOMAIN-SUFFIX,netflix.com,unlock"
  - "PROTOCOL,http,unlock"
"#,
        )
        .unwrap()
    }

    #[test]
    fn outbound_dispatcher_absent_without_routing_config() {
        let (mut app, _node) = {
            let config = routing_app_config();
            (config, ())
        };
        app.outbounds.clear();
        app.route_rules.clear();
        app.default_out = None;
        let resolver = test_resolver();
        assert!(
            build_outbound_dispatcher(&app, "node-a", &resolver)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn outbound_dispatcher_builds_chains_and_rules() {
        let app = routing_app_config();
        let resolver = test_resolver();
        let dispatcher = build_outbound_dispatcher(&app, "node-a", &resolver)
            .unwrap()
            .expect("routing config must produce a dispatcher");
        assert!(dispatcher.has_routing());
        let tags = app
            .outbounds
            .iter()
            .map(|o| o.tag.as_str())
            .collect::<Vec<_>>();
        assert_eq!(tags, vec!["unlock", "direct", "via-socks"]);
        let rules = compile_route_rules(
            "node-a",
            &app.route_rules,
            &app.rule_providers,
            &app.v2board.route_rule_sets,
        )
        .unwrap();
        assert_eq!(rules.match_domain("api.netflix.com"), Some("unlock"));
        assert_eq!(rules.match_domain("netflix.com"), Some("unlock"));
        assert_eq!(rules.match_domain("netflix.org"), None);
        assert!(rules.has_protocol_rules());
    }

    #[test]
    fn outbound_dispatcher_expands_chains_into_hop_configs() {
        let app = routing_app_config();
        let by_tag: HashMap<&str, &OutboundConfig> =
            app.outbounds.iter().map(|o| (o.tag.as_str(), o)).collect();
        let mut resolved = HashMap::new();
        let hops = resolve_outbound_hops("via-socks", &by_tag, &mut resolved).unwrap();
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].address.to_string(), "203.0.113.10:443");
        assert!(matches!(
            hops[0].protocol,
            crate::config::ClientProxyConfig::Vless { .. }
        ));
    }

    #[test]
    fn plugin_manifest_builds_every_in_process_server_adapter() {
        let app = serde_yaml::from_str::<AppConfig>(
            r#"
v2board:
  api_host: "https://panel.example.com"
  api_key: "server-token"
  nodes:
    - tag: "ss-plugin"
      node_id: 12
      node_type: "shadowsocks"
      listen: "127.0.0.1"
runtime:
  max_legacy_shadowsocks_users: 100
"#,
        )
        .unwrap();
        let node = app.v2board.nodes[0].clone();
        let revision = concat!(
            "sha256:",
            "0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef"
        );
        let server = serde_json::from_value::<ServerConfig>(json!({
            "server_port": 8388,
            "cipher": "aes-128-gcm",
            "routes": [],
            "config_revision": revision
        }))
        .unwrap();
        let users = vec![
            serde_json::from_value::<UserInfo>(json!({
                "id": 1,
                "uuid": "plugin-user-password"
            }))
            .unwrap(),
        ];
        let plugins = [
            json!({
                "type": "obfs",
                "listen_port": 9001,
                "upstream": {"host": "127.0.0.1", "port": 8388},
                "options": {"mode": "http", "host": "cover.example.com"}
            }),
            json!({
                "type": "v2ray-plugin",
                "listen_port": 9002,
                "upstream": {"host": "127.0.0.1", "port": 8388},
                "options": {
                    "mode": "websocket", "host": "cover.example.com",
                    "path": "/v2ray", "tls": false, "mux": true,
                    "v2ray_http_upgrade": false
                }
            }),
            json!({
                "type": "gost-plugin",
                "listen_port": 9003,
                "upstream": {"host": "127.0.0.1", "port": 8388},
                "options": {
                    "mode": "websocket", "host": "cover.example.com",
                    "path": "/gost", "tls": false, "mux": true
                }
            }),
            json!({
                "type": "shadow-tls",
                "listen_port": 9004,
                "upstream": {"host": "127.0.0.1", "port": 8388},
                "options": {
                    "host": "cover.example.com", "version": 3,
                    "password": "shadow-secret"
                }
            }),
            json!({
                "type": "restls",
                "listen_port": 9005,
                "upstream": {"host": "127.0.0.1", "port": 8388},
                "options": {
                    "host": "cover.example.com", "password": "restls-secret",
                    "restls_script": "300?100<1"
                }
            }),
            json!({
                "type": "kcptun",
                "listen_port": 9006,
                "upstream": {"host": "127.0.0.1", "port": 8388},
                "options": {
                    "key": "kcptun-secret", "crypt": "aes", "mode": "fast",
                    "mtu": 1350, "ratelimit": 0, "sndwnd": 128, "rcvwnd": 512,
                    "datashard": 10, "parityshard": 3, "dscp": 0,
                    "nocomp": false, "acknodelay": false, "nodelay": 0,
                    "interval": 30, "resend": 2, "nc": 1,
                    "sockbuf": 4194304, "smuxver": 2, "smuxbuf": 4194304,
                    "framesize": 8192, "streambuf": 2097152, "keepalive": 10
                }
            }),
        ];

        for plugin in plugins {
            let manifest = serde_json::from_value::<PluginRuntimeManifest>(json!({
                "schema_version": 1,
                "node_type": "shadowsocks",
                "node_id": 12,
                "server_port": 8388,
                "cipher": "aes-128-gcm",
                "server_key": null,
                "obfs": null,
                "obfs_settings": null,
                "multiplex": {
                    "enabled": true,
                    "padding": true,
                    "brutal": {"enabled": false, "up_mbps": 0, "down_mbps": 0}
                },
                "plugin": plugin,
                "routes": [],
                "config_revision": revision,
                "base_config": {
                    "push_interval": 60,
                    "pull_interval": 60,
                    "node_report_min_traffic": 0,
                    "device_online_min_traffic": 0
                }
            }))
            .unwrap();
            manifest.validate(node.node_id).unwrap();
            let nodes = map_shadowsocks_plugin_nodes(
                &app,
                &node,
                &server,
                &users,
                &manifest,
                test_tracker(),
                test_resolver(),
            )
            .unwrap();
            assert_eq!(nodes.len(), 2);
            assert!(matches!(&nodes[0].kind, RuntimeNodeKind::Tcp { .. }));
            if matches!(manifest.plugin, Some(RuntimePlugin::Kcptun { .. })) {
                assert!(matches!(&nodes[1].kind, RuntimeNodeKind::Kcptun { .. }));
            } else {
                assert!(matches!(&nodes[1].kind, RuntimeNodeKind::Tcp { .. }));
            }
        }
    }

    #[test]
    fn plugin_graph_rejects_tcp_brutal_without_disrupting_the_old_runtime() {
        let app = serde_yaml::from_str::<AppConfig>(
            r#"
v2board:
  api_host: "https://panel.example.com"
  api_key: "server-token"
  nodes:
    - tag: "ss-plugin"
      node_id: 12
      node_type: "shadowsocks"
"#,
        )
        .unwrap();
        let node = app.v2board.nodes[0].clone();
        let revision = concat!(
            "sha256:",
            "0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef"
        );
        let server = serde_json::from_value::<ServerConfig>(json!({
            "server_port": 8388,
            "cipher": "aes-128-gcm",
            "routes": [],
            "config_revision": revision
        }))
        .unwrap();
        let manifest = serde_json::from_value::<PluginRuntimeManifest>(json!({
            "schema_version": 1,
            "node_type": "shadowsocks",
            "node_id": 12,
            "server_port": 8388,
            "cipher": "aes-128-gcm",
            "server_key": null,
            "obfs": null,
            "obfs_settings": null,
            "multiplex": {
                "enabled": true,
                "padding": false,
                "brutal": {"enabled": true, "up_mbps": 100, "down_mbps": 100}
            },
            "plugin": null,
            "routes": [],
            "config_revision": revision,
            "base_config": {
                "push_interval": 60,
                "pull_interval": 60,
                "node_report_min_traffic": 0,
                "device_online_min_traffic": 0
            }
        }))
        .unwrap();
        let users = vec![
            serde_json::from_value::<UserInfo>(json!({
                "id": 1,
                "uuid": "plugin-user-password"
            }))
            .unwrap(),
        ];
        let error = match map_shadowsocks_plugin_nodes(
            &app,
            &node,
            &server,
            &users,
            &manifest,
            test_tracker(),
            test_resolver(),
        ) {
            Ok(_) => panic!("expected TCP Brutal plugin graph to fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("TCP Brutal"));
    }

    #[test]
    fn tls_builder_rejects_ech_before_certificate_lookup() {
        let mut tls = runtime_tls();
        tls.ech_config = Some("config".to_string());
        let spec = vmess_tls_spec(tls);

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("tls ECH is not supported"));
    }

    #[test]
    fn reality_builder_rejects_missing_private_key() {
        let mut reality = runtime_reality();
        reality.private_key = None;
        let spec = vless_reality_spec(reality);

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("private_key"));
    }

    #[test]
    fn reality_builder_rejects_missing_short_id() {
        let mut reality = runtime_reality();
        reality.short_ids = Vec::new();
        let spec = vless_reality_spec(reality);

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("missing short_id"));
    }

    #[test]
    fn reality_builder_rejects_xver_and_ech() {
        let mut reality = runtime_reality();
        reality.xver = 1;
        let spec = vless_reality_spec(reality);

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("xver=1"));

        let mut reality = runtime_reality();
        reality.ech = Some("custom".to_string());
        let spec = vless_reality_spec(reality);

        let err = expect_build_err(spec);

        assert!(err.to_string().contains("ECH"));
    }

    #[test]
    fn reality_dest_falls_back_to_server_name_and_server_port() {
        let mut reality = runtime_reality();
        reality.dest = None;
        reality.server_name = Some("fallback.example.com".to_string());
        reality.server_port = Some("9443".to_string());
        let spec = vless_reality_spec(reality.clone());

        let dest = reality_dest(&spec, &reality).unwrap();

        assert_eq!(dest.to_string(), "fallback.example.com:9443");
    }
}
