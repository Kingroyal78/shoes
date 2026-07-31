//! In-process, server-side GOST SIP003 plugin transport.

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
    SmuxLimits, SmuxV1ServerHandler, TlsTerminatingServerHandler, WebsocketServerConfig,
    websocket_server_handler,
};
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

#[derive(Clone)]
pub struct GostPluginServerConfig {
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub host: Option<String>,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub mux: bool,
    pub smux_limits: SmuxLimits,
    pub websocket_ping_type: WebsocketPingType,
}

impl fmt::Debug for GostPluginServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GostPluginServerConfig")
            .field("tls", &self.tls.as_ref().map(|_| "<rustls ServerConfig>"))
            .field("host", &self.host)
            .field("path", &self.path)
            .field("headers", &self.headers)
            .field("mux", &self.mux)
            .field("smux_limits", &self.smux_limits)
            .field("websocket_ping_type", &self.websocket_ping_type)
            .finish()
    }
}

impl Default for GostPluginServerConfig {
    fn default() -> Self {
        Self {
            tls: None,
            host: None,
            path: "/".to_string(),
            headers: HashMap::new(),
            mux: false,
            smux_limits: SmuxLimits::default(),
            websocket_ping_type: WebsocketPingType::PingFrame,
        }
    }
}

pub struct GostPluginServerHandler {
    pipeline: Arc<dyn TcpServerHandler>,
    config: GostPluginServerConfig,
}

impl fmt::Debug for GostPluginServerHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GostPluginServerHandler")
            .field("config", &self.config)
            .field("pipeline", &self.pipeline)
            .finish()
    }
}

impl GostPluginServerHandler {
    pub fn new(
        config: GostPluginServerConfig,
        inner: Arc<dyn TcpServerHandler>,
        resolver: Arc<dyn Resolver>,
    ) -> io::Result<Self> {
        validate_config(&config)?;
        let payload_handler: Arc<dyn TcpServerHandler> = if config.mux {
            Arc::new(SmuxV1ServerHandler::new(
                inner,
                resolver,
                config.smux_limits,
            ))
        } else {
            inner
        };
        let headers = config
            .headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect::<FxHashMap<_, _>>();
        let websocket: Arc<dyn TcpServerHandler> = Arc::new(websocket_server_handler(
            WebsocketServerConfig {
                path: config.path.clone(),
                host: config.host.clone(),
                headers,
                max_early_data: None,
                early_data_header_name: None,
                ping_type: config.websocket_ping_type.clone(),
                http_limits: Default::default(),
            },
            payload_handler,
        ));
        let pipeline: Arc<dyn TcpServerHandler> = if let Some(tls_config) = config.tls.clone() {
            Arc::new(TlsTerminatingServerHandler::new(tls_config, websocket))
        } else {
            websocket
        };
        Ok(Self { pipeline, config })
    }

    pub fn config(&self) -> &GostPluginServerConfig {
        &self.config
    }
}

#[async_trait]
impl TcpServerHandler for GostPluginServerHandler {
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

fn validate_config(config: &GostPluginServerConfig) -> io::Result<()> {
    if config.path.contains(['\r', '\n']) {
        return invalid("GOST WebSocket path contains CR/LF");
    }
    if config
        .headers
        .keys()
        .any(|name| name.trim().is_empty() || name.contains(['\r', '\n', ':']))
    {
        return invalid("GOST custom header name is invalid");
    }
    if config
        .headers
        .values()
        .any(|value| value.contains(['\r', '\n']))
    {
        return invalid("GOST custom header value contains CR/LF");
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_header_and_path_injection() {
        let config = GostPluginServerConfig {
            path: "/ws\r\nX: injected".to_string(),
            ..GostPluginServerConfig::default()
        };
        assert!(validate_config(&config).is_err());

        let mut config = GostPluginServerConfig::default();
        config
            .headers
            .insert("X-Test".to_string(), "ok\r\nInjected: yes".to_string());
        assert!(validate_config(&config).is_err());
    }
}
