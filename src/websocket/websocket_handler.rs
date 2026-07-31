use std::collections::HashMap;

use async_trait::async_trait;
use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
};
use rustc_hash::FxHashMap;
use tokio::io::AsyncWriteExt;

use super::websocket_stream::WebsocketStream;
use crate::address::ResolvedLocation;
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::config::WebsocketPingType;
use crate::h2mux::PrependStream;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};

#[derive(Debug)]
pub struct WebsocketServerTarget {
    pub matching_path: Option<String>,
    pub matching_headers: Option<FxHashMap<String, String>>,
    pub max_early_data: Option<u32>,
    pub early_data_header_name: Option<String>,
    pub ping_type: WebsocketPingType,
    pub handler: Box<dyn TcpServerHandler>,
}

#[derive(Debug)]
pub struct WebsocketTcpServerHandler {
    server_targets: Vec<WebsocketServerTarget>,
}

impl WebsocketTcpServerHandler {
    pub fn new(server_targets: Vec<WebsocketServerTarget>) -> Self {
        Self { server_targets }
    }

    async fn run(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let ParsedHttpData {
            mut first_line,
            headers: mut request_headers,
            stream_reader,
        } = ParsedHttpData::parse(&mut server_stream).await?;
        let request_path = {
            if !first_line.ends_with(" HTTP/1.0") && !first_line.ends_with(" HTTP/1.1") {
                return Err(std::io::Error::other(format!(
                    "invalid http request version: {first_line}"
                )));
            }

            if !first_line.starts_with("GET ") {
                return Err(std::io::Error::other(format!(
                    "invalid http request: {first_line}"
                )));
            }

            // remove ' HTTP/1.x'
            first_line.truncate(first_line.len() - 9);

            // return the path after 'GET '
            first_line.split_off(4)
        };

        let websocket_key = request_headers
            .remove("sec-websocket-key")
            .ok_or_else(|| std::io::Error::other("missing websocket key header"))?;

        'outer: for server_target in self.server_targets.iter() {
            let WebsocketServerTarget {
                matching_path,
                matching_headers,
                max_early_data,
                early_data_header_name,
                ping_type,
                handler,
            } = server_target;

            let Some(early_data) = match_path_and_decode_early_data(
                &request_path,
                &request_headers,
                matching_path.as_deref(),
                *max_early_data,
                early_data_header_name.as_deref(),
            )?
            else {
                continue;
            };

            if let Some(headers) = matching_headers {
                for (header_key, header_val) in headers {
                    if request_headers.get(header_key) != Some(header_val) {
                        continue 'outer;
                    }
                }
            }

            let websocket_key_response = create_websocket_key_response(websocket_key);

            let host_response_header = match request_headers.get("host") {
                Some(v) => format!("Host: {v}\r\n"),
                None => "".to_string(),
            };

            let websocket_version_response_header =
                match request_headers.get("sec-websocket-version") {
                    Some(v) => format!("Sec-WebSocket-Version: {v}\r\n"),
                    None => "".to_string(),
                };

            let websocket_protocol_response_header =
                match request_headers.get("sec-websocket-protocol") {
                    Some(v) => format!("Sec-WebSocket-Protocol: {v}\r\n"),
                    None => "".to_string(),
                };

            let http_response = format!(
                concat!(
                    "HTTP/1.1 101 Switching Protocol\r\n",
                    "{}",
                    "Upgrade: websocket\r\n",
                    "Connection: Upgrade\r\n",
                    "{}",
                    "Sec-WebSocket-Accept: {}\r\n",
                    "{}",
                    "\r\n"
                ),
                host_response_header,
                websocket_version_response_header,
                websocket_key_response,
                websocket_protocol_response_header,
            );

            server_stream.write_all(http_response.as_bytes()).await?;
            server_stream.flush().await?;

            let websocket_stream = WebsocketStream::new(
                server_stream,
                false,
                ping_type.clone(),
                stream_reader.unparsed_data(),
            );
            let websocket_stream: Box<dyn AsyncStream> = match early_data {
                Some(data) => Box::new(PrependStream::new(websocket_stream, Some(data))),
                None => Box::new(websocket_stream),
            };

            let mut target_setup_result = handler
                .setup_server_stream_with_peer_addr(websocket_stream, peer_addr)
                .await;

            if let Ok(ref mut setup_result) = target_setup_result {
                if matches!(setup_result, TcpServerSetupResult::AlreadyHandled) {
                    return target_setup_result;
                }
                setup_result.set_need_initial_flush(true);
                // Inner handler already has effective_selector from construction
            }

            return target_setup_result;
        }

        Err(std::io::Error::other("No matching websocket targets"))
    }
}

#[async_trait]
impl TcpServerHandler for WebsocketTcpServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.run(server_stream, None).await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        server_stream: Box<dyn AsyncStream>,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.run(server_stream, peer_addr).await
    }
}

fn match_path_and_decode_early_data(
    request_path: &str,
    request_headers: &HashMap<String, String>,
    matching_path: Option<&str>,
    max_early_data: Option<u32>,
    early_data_header_name: Option<&str>,
) -> std::io::Result<Option<Option<Box<[u8]>>>> {
    let max_early_data = max_early_data.unwrap_or(0);
    let early_data_header_name = early_data_header_name
        .map(str::trim)
        .filter(|name| !name.is_empty());

    if (max_early_data == 0 || early_data_header_name.is_some())
        && let Some(path) = matching_path
        && request_path != path
    {
        return Ok(None);
    }

    if max_early_data == 0 {
        return Ok(Some(None));
    }

    let early_data = if let Some(header_name) = early_data_header_name {
        let header_name = header_name.to_ascii_lowercase();
        request_headers
            .get(&header_name)
            .filter(|value| !value.is_empty())
            .map(|value| decode_early_data(value, max_early_data))
            .transpose()?
    } else if let Some(path) = matching_path {
        let Some(encoded) = request_path.strip_prefix(path) else {
            return Ok(None);
        };
        if encoded.is_empty() {
            None
        } else {
            Some(decode_early_data(encoded, max_early_data)?)
        }
    } else {
        None
    };

    Ok(Some(early_data.map(Vec::into_boxed_slice)))
}

fn decode_early_data(encoded: &str, max_early_data: u32) -> std::io::Result<Vec<u8>> {
    let data = URL_SAFE_NO_PAD.decode(encoded).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("websocket early-data is not valid base64url: {e}"),
        )
    })?;
    if data.len() > max_early_data as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "websocket early-data length {} exceeds configured limit {}",
                data.len(),
                max_early_data
            ),
        ));
    }
    Ok(data)
}

#[derive(Debug)]
pub struct WebsocketTcpClientHandler {
    matching_path: Option<String>,
    matching_headers: Option<FxHashMap<String, String>>,
    ping_type: WebsocketPingType,
    handler: Box<dyn TcpClientHandler>,
}

impl WebsocketTcpClientHandler {
    pub fn new(
        matching_path: Option<String>,
        matching_headers: Option<FxHashMap<String, String>>,
        ping_type: WebsocketPingType,
        handler: Box<dyn TcpClientHandler>,
    ) -> Self {
        Self {
            matching_path,
            matching_headers,
            ping_type,
            handler,
        }
    }

    async fn setup_client_stream_common(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<WebsocketStream> {
        let request_path = self.matching_path.as_deref().unwrap_or("/");

        let websocket_key = create_websocket_key();
        let mut http_request = String::with_capacity(1024);
        http_request.push_str("GET ");
        http_request.push_str(request_path);
        http_request.push_str(" HTTP/1.1\r\n");
        http_request.push_str(concat!("Connection: Upgrade\r\n", "Upgrade: websocket\r\n",));

        if let Some(ref headers) = self.matching_headers {
            for (header_key, header_val) in headers {
                http_request.push_str(header_key);
                http_request.push_str(": ");
                http_request.push_str(header_val);
                http_request.push_str("\r\n");
            }
        }

        http_request.push_str(concat!(
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Key: "
        ));
        http_request.push_str(&websocket_key);
        http_request.push_str("\r\n\r\n");

        client_stream.write_all(&http_request.into_bytes()).await?;
        client_stream.flush().await?;

        let ParsedHttpData {
            first_line,
            headers: response_headers,
            stream_reader,
        } = ParsedHttpData::parse(&mut client_stream).await?;

        if !first_line.starts_with("HTTP/1.1 101") && !first_line.starts_with("HTTP/1.0 101") {
            return Err(std::io::Error::other(format!(
                "Bad websocket response: {first_line}"
            )));
        }

        let websocket_key_response = response_headers
            .get("sec-websocket-accept")
            .ok_or_else(|| std::io::Error::other("missing websocket key response header"))?;

        let expected_key_response = create_websocket_key_response(websocket_key);
        if websocket_key_response != &expected_key_response {
            return Err(std::io::Error::other(format!(
                "incorrect websocket key response, expected {expected_key_response}, got {websocket_key_response}"
            )));
        }

        Ok(WebsocketStream::new(
            client_stream,
            true,
            self.ping_type.clone(),
            stream_reader.unparsed_data(),
        ))
    }
}

#[async_trait]
impl TcpClientHandler for WebsocketTcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let websocket_stream = self.setup_client_stream_common(client_stream).await?;
        self.handler
            .setup_client_tcp_stream(Box::new(websocket_stream), remote_location)
            .await
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.handler.supports_udp_over_tcp()
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let websocket_stream = self.setup_client_stream_common(client_stream).await?;
        self.handler
            .setup_client_udp_bidirectional(Box::new(websocket_stream), target)
            .await
    }
}

struct ParsedHttpData {
    first_line: String,
    headers: HashMap<String, String>,
    stream_reader: StreamReader,
}

impl ParsedHttpData {
    async fn parse(stream: &mut Box<dyn AsyncStream>) -> std::io::Result<Self> {
        let mut stream_reader = StreamReader::new();
        let mut first_line: Option<String> = None;
        // don't use FxHashMap for unvalidated user data
        let mut headers: HashMap<String, String> = HashMap::new();

        let mut line_count = 0;
        loop {
            let line = stream_reader.read_line(stream).await?;
            if line.is_empty() {
                break;
            }

            if line.len() >= 4096 {
                return Err(std::io::Error::other("http request line is too long"));
            }

            if first_line.is_none() {
                first_line = Some(line.to_string());
            } else {
                let tokens: Vec<&str> = line.splitn(2, ':').collect();
                if tokens.len() != 2 {
                    return Err(std::io::Error::other(format!(
                        "invalid http request line: {line}"
                    )));
                }
                let header_key = tokens[0].trim().to_lowercase();
                let header_value = tokens[1].trim().to_string();
                headers.insert(header_key, header_value);
            }

            line_count += 1;
            if line_count >= 40 {
                return Err(std::io::Error::other("http request is too long"));
            }
        }

        let first_line = first_line.ok_or_else(|| std::io::Error::other("empty http request"))?;

        Ok(Self {
            first_line,
            headers,
            stream_reader,
        })
    }
}

fn create_websocket_key() -> String {
    let key: [u8; 16] = rand::random();
    BASE64.encode(key)
}

fn create_websocket_key_response(key: String) -> String {
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut input = key.into_bytes();
    input.extend_from_slice(WS_GUID);
    let hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, &input);
    BASE64.encode(hash.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_header_early_data_after_exact_path_match() {
        let mut headers = HashMap::new();
        headers.insert("sec-websocket-protocol".to_string(), "aGVsbG8".to_string());

        let data = match_path_and_decode_early_data(
            "/ws",
            &headers,
            Some("/ws"),
            Some(2048),
            Some("Sec-WebSocket-Protocol"),
        )
        .unwrap()
        .unwrap()
        .unwrap();

        assert_eq!(&*data, b"hello");
    }

    #[test]
    fn decodes_path_early_data_suffix() {
        let headers = HashMap::new();

        let data =
            match_path_and_decode_early_data("/wsaGk", &headers, Some("/ws"), Some(2048), None)
                .unwrap()
                .unwrap()
                .unwrap();

        assert_eq!(&*data, b"hi");
    }

    #[test]
    fn rejects_early_data_over_configured_limit() {
        let mut headers = HashMap::new();
        headers.insert("sec-websocket-protocol".to_string(), "aGVsbG8".to_string());

        let err = match_path_and_decode_early_data(
            "/ws",
            &headers,
            Some("/ws"),
            Some(4),
            Some("Sec-WebSocket-Protocol"),
        )
        .unwrap_err();

        assert!(err.to_string().contains("exceeds configured limit"));
    }
}
