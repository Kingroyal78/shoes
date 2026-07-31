//! In-process, server-side v2ray-plugin compatible transport.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use rustc_hash::FxHashMap;

use crate::async_stream::AsyncStream;
use crate::config::WebsocketPingType;
use crate::resolver::Resolver;
use crate::ss_plugins::transport::{
    HttpUpgradeConfig, HttpUpgradeServerHandler, MuxCoolLimits, MuxCoolServerHandler,
    TlsTerminatingServerHandler, WebsocketServerConfig, normalize_path, websocket_server_handler,
};
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V2rayTransportMode {
    Websocket,
    HttpUpgrade,
}

#[derive(Clone)]
pub struct V2rayPluginServerConfig {
    pub mode: V2rayTransportMode,
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub host: Option<String>,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub max_early_data: Option<u32>,
    pub mux: bool,
    pub mux_limits: MuxCoolLimits,
    pub websocket_ping_type: WebsocketPingType,
}

impl fmt::Debug for V2rayPluginServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2rayPluginServerConfig")
            .field("mode", &self.mode)
            .field("tls", &self.tls.as_ref().map(|_| "<rustls ServerConfig>"))
            .field("host", &self.host)
            .field("path", &self.path)
            .field("headers", &self.headers)
            .field("max_early_data", &self.max_early_data)
            .field("mux", &self.mux)
            .field("mux_limits", &self.mux_limits)
            .field("websocket_ping_type", &self.websocket_ping_type)
            .finish()
    }
}

impl Default for V2rayPluginServerConfig {
    fn default() -> Self {
        Self {
            mode: V2rayTransportMode::Websocket,
            tls: None,
            host: None,
            path: "/".to_string(),
            headers: HashMap::new(),
            max_early_data: None,
            mux: false,
            mux_limits: MuxCoolLimits::default(),
            websocket_ping_type: WebsocketPingType::PingFrame,
        }
    }
}

pub struct V2rayPluginServerHandler {
    pipeline: Arc<dyn TcpServerHandler>,
    config: V2rayPluginServerConfig,
}

impl fmt::Debug for V2rayPluginServerHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2rayPluginServerHandler")
            .field("config", &self.config)
            .field("pipeline", &self.pipeline)
            .finish()
    }
}

impl V2rayPluginServerHandler {
    pub fn new(
        mut config: V2rayPluginServerConfig,
        inner: Arc<dyn TcpServerHandler>,
        resolver: Arc<dyn Resolver>,
    ) -> io::Result<Self> {
        let (path, query_early_data) = parse_path_options(&config.path)?;
        config.path = path;
        if let Some(query_limit) = query_early_data {
            if config
                .max_early_data
                .is_some_and(|configured| configured != query_limit)
            {
                return invalid_input(
                    "v2ray-plugin early-data limit conflicts with the path `ed` option",
                );
            }
            config.max_early_data = Some(query_limit);
        }
        if config.mode == V2rayTransportMode::HttpUpgrade && config.max_early_data.unwrap_or(0) != 0
        {
            return invalid_input("v2ray HTTP Upgrade mode cannot use WebSocket early data");
        }
        if config
            .headers
            .keys()
            .any(|name| name.trim().is_empty() || name.contains(['\r', '\n', ':']))
        {
            return invalid_input("v2ray-plugin custom header name is invalid");
        }
        if config
            .headers
            .values()
            .any(|value| value.contains(['\r', '\n']))
        {
            return invalid_input("v2ray-plugin custom header value contains CR/LF");
        }

        let payload_handler: Arc<dyn TcpServerHandler> = if config.mux {
            Arc::new(MuxCoolServerHandler::new(
                inner,
                resolver,
                config.mux_limits,
            ))
        } else {
            inner
        };
        let transport_handler: Arc<dyn TcpServerHandler> = match config.mode {
            V2rayTransportMode::Websocket => {
                let headers = config
                    .headers
                    .iter()
                    .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
                    .collect::<FxHashMap<_, _>>();
                Arc::new(websocket_server_handler(
                    WebsocketServerConfig {
                        path: config.path.clone(),
                        host: config.host.clone(),
                        headers,
                        max_early_data: config.max_early_data.filter(|limit| *limit > 0),
                        early_data_header_name: config
                            .max_early_data
                            .filter(|limit| *limit > 0)
                            .map(|_| "Sec-WebSocket-Protocol".to_string()),
                        ping_type: config.websocket_ping_type.clone(),
                        http_limits: Default::default(),
                    },
                    payload_handler,
                ))
            }
            V2rayTransportMode::HttpUpgrade => Arc::new(HttpUpgradeServerHandler::new(
                HttpUpgradeConfig {
                    path: config.path.clone(),
                    host: config.host.clone(),
                    headers: config.headers.clone(),
                    ..HttpUpgradeConfig::default()
                },
                payload_handler,
            )),
        };
        let pipeline: Arc<dyn TcpServerHandler> = if let Some(tls_config) = config.tls.clone() {
            Arc::new(TlsTerminatingServerHandler::new(
                tls_config,
                transport_handler,
            ))
        } else {
            transport_handler
        };
        Ok(Self { pipeline, config })
    }

    pub fn config(&self) -> &V2rayPluginServerConfig {
        &self.config
    }
}

#[async_trait]
impl TcpServerHandler for V2rayPluginServerHandler {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        self.pipeline.setup_server_stream(stream).await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        stream: Box<dyn AsyncStream>,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> io::Result<TcpServerSetupResult> {
        self.pipeline
            .setup_server_stream_with_peer_addr(stream, peer_addr)
            .await
    }
}

fn parse_path_options(path: &str) -> io::Result<(String, Option<u32>)> {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let mut early_data = None;
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if name == "ed" {
            let parsed = value.parse::<u32>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "v2ray-plugin path `ed` option is not a u32",
                )
            })?;
            if parsed == 0 {
                return invalid_input("v2ray-plugin path `ed` option cannot be zero");
            }
            if early_data.replace(parsed).is_some() {
                return invalid_input("v2ray-plugin path has duplicate `ed` options");
            }
        }
    }
    Ok((normalize_path(path), early_data))
}

fn invalid_input<T>(message: impl Into<String>) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_early_data_query_and_normalizes_path() {
        assert_eq!(
            parse_path_options("ws?ed=2048&x=1").unwrap(),
            ("/ws".to_string(), Some(2048))
        );
        assert_eq!(
            parse_path_options("/ws").unwrap(),
            ("/ws".to_string(), None)
        );
    }

    #[test]
    fn rejects_duplicate_zero_and_non_numeric_early_data() {
        assert!(parse_path_options("/?ed=0").is_err());
        assert!(parse_path_options("/?ed=x").is_err());
        assert!(parse_path_options("/?ed=1&ed=2").is_err());
    }
}
