use std::fmt;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use rustc_hash::FxHashMap;

use super::ArcTcpServerHandler;
use super::http::{HttpLimits, HttpRequest, host_matches_optional_port};
use crate::async_stream::AsyncStream;
use crate::config::WebsocketPingType;
use crate::h2mux::PrependStream;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::websocket::{WebsocketServerTarget, WebsocketTcpServerHandler};

#[derive(Clone, Debug)]
pub struct WebsocketServerConfig {
    pub path: String,
    pub host: Option<String>,
    pub headers: FxHashMap<String, String>,
    pub max_early_data: Option<u32>,
    pub early_data_header_name: Option<String>,
    pub ping_type: WebsocketPingType,
    pub http_limits: HttpLimits,
}

impl Default for WebsocketServerConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: None,
            headers: FxHashMap::default(),
            max_early_data: None,
            early_data_header_name: None,
            ping_type: WebsocketPingType::PingFrame,
            http_limits: HttpLimits::default(),
        }
    }
}

pub struct StrictWebsocketServerHandler {
    inner: WebsocketTcpServerHandler,
    limits: HttpLimits,
    expected_host: Option<String>,
}

impl fmt::Debug for StrictWebsocketServerHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StrictWebsocketServerHandler")
            .field("inner", &self.inner)
            .field("limits", &self.limits)
            .field("expected_host", &self.expected_host)
            .finish()
    }
}

/// Builds the project's RFC6455 server around a shareable inner handler.
///
/// The existing WebSocket stream state machine enforces client masking,
/// continuation ordering, control-frame limits, UTF-8 text validation and
/// close/ping/pong behavior.  Keeping one implementation avoids subtly
/// different wire behavior between native transports and plugin transports.
pub fn websocket_server_handler(
    config: WebsocketServerConfig,
    inner: Arc<dyn TcpServerHandler>,
) -> StrictWebsocketServerHandler {
    let headers = (!config.headers.is_empty()).then_some(config.headers);
    let inner = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
        matching_path: Some(super::normalize_path(config.path)),
        matching_headers: headers,
        max_early_data: config.max_early_data,
        early_data_header_name: config.early_data_header_name,
        ping_type: config.ping_type,
        handler: Box::new(ArcTcpServerHandler(inner)),
    }]);
    StrictWebsocketServerHandler {
        inner,
        limits: config.http_limits,
        expected_host: config.host,
    }
}

#[async_trait]
impl TcpServerHandler for StrictWebsocketServerHandler {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_peer_addr(stream, None).await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        mut stream: Box<dyn AsyncStream>,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> io::Result<TcpServerSetupResult> {
        let request = HttpRequest::read(&mut stream, self.limits).await?;
        validate_websocket_request(&request, self.expected_host.as_deref())?;
        let mut replay = request.raw_header;
        replay.extend_from_slice(&request.unparsed_data);
        let replay: Box<dyn AsyncStream> =
            Box::new(PrependStream::new(stream, Some(replay.into_boxed_slice())));
        self.inner
            .setup_server_stream_with_peer_addr(replay, peer_addr)
            .await
    }
}

fn validate_websocket_request(
    request: &HttpRequest,
    expected_host: Option<&str>,
) -> io::Result<()> {
    if request.method != "GET" || request.version != "HTTP/1.1" {
        return invalid("WebSocket handshake must be an HTTP/1.1 GET");
    }
    if !request.header_contains_token("connection", "upgrade")
        || !request.header_contains_token("upgrade", "websocket")
    {
        return invalid("WebSocket Upgrade/Connection headers are incomplete");
    }
    if request.header("sec-websocket-version")? != Some("13") {
        return invalid("WebSocket version must be 13");
    }
    let key = request
        .header("sec-websocket-key")?
        .ok_or_else(|| invalid_error("WebSocket key is missing"))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(|_| invalid_error("WebSocket key is not valid base64"))?;
    if decoded.len() != 16 {
        return invalid("WebSocket key must decode to exactly 16 bytes");
    }
    if let Some(value) = request.header("content-length")? {
        let length = value
            .parse::<u64>()
            .map_err(|_| invalid_error("WebSocket Content-Length is malformed"))?;
        if length != 0 {
            return invalid("WebSocket handshake must not contain an HTTP body");
        }
    }
    if request.header("transfer-encoding")?.is_some() {
        return invalid("WebSocket handshake must not use Transfer-Encoding");
    }
    if let Some(expected_host) = expected_host {
        let actual = request
            .header("host")?
            .ok_or_else(|| invalid_error("WebSocket Host is missing"))?;
        if !host_matches_optional_port(actual, expected_host) {
            return invalid("WebSocket Host does not match configuration");
        }
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> io::Result<T> {
    Err(invalid_error(message))
}

fn invalid_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn request(headers: &[(&str, &str)]) -> HttpRequest {
        let headers = headers
            .iter()
            .fold(HashMap::new(), |mut map, (key, value)| {
                map.insert(key.to_string(), vec![value.to_string()]);
                map
            });
        HttpRequest {
            method: "GET".to_string(),
            target: "/".to_string(),
            version: "HTTP/1.1".to_string(),
            headers,
            raw_header: Vec::new(),
            unparsed_data: Vec::new(),
        }
    }

    #[test]
    fn validates_complete_rfc6455_handshake() {
        let request = request(&[
            ("connection", "keep-alive, Upgrade"),
            ("upgrade", "websocket"),
            ("sec-websocket-version", "13"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("host", "Example.COM:443"),
        ]);
        validate_websocket_request(&request, None).unwrap();
        validate_websocket_request(&request, Some("example.com")).unwrap();
    }

    #[test]
    fn rejects_bad_key_version_body_and_missing_upgrade() {
        let base = [
            ("connection", "Upgrade"),
            ("upgrade", "websocket"),
            ("sec-websocket-version", "13"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ];
        let mut bad = base;
        bad[3].1 = "short";
        assert!(validate_websocket_request(&request(&bad), None).is_err());
        let mut bad = base;
        bad[2].1 = "12";
        assert!(validate_websocket_request(&request(&bad), None).is_err());
        let mut with_body = base.to_vec();
        with_body.push(("content-length", "1"));
        assert!(validate_websocket_request(&request(&with_body), None).is_err());
        let missing_upgrade = &base[2..];
        assert!(validate_websocket_request(&request(missing_upgrade), None).is_err());
    }
}
