use std::collections::HashMap;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use crate::async_stream::AsyncStream;
use crate::h2mux::PrependStream;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

#[derive(Debug)]
pub struct HttpUpgradeServerHandler {
    path: String,
    host: Option<String>,
    headers: HashMap<String, String>,
    handler: Box<dyn TcpServerHandler>,
}

impl HttpUpgradeServerHandler {
    pub fn new(
        path: String,
        host: Option<String>,
        headers: HashMap<String, String>,
        handler: Box<dyn TcpServerHandler>,
    ) -> Self {
        Self {
            path: normalize_path(path),
            host,
            headers: normalize_headers(headers),
            handler,
        }
    }
}

#[async_trait]
impl TcpServerHandler for HttpUpgradeServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_peer_addr(server_stream, None)
            .await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let parsed = ParsedHttpRequest::parse(&mut server_stream).await?;
        if parsed.method != "GET" {
            return invalid(format!("httpupgrade bad method `{}`", parsed.method));
        }
        if parsed.path != self.path {
            return invalid(format!(
                "httpupgrade bad path `{}` expected `{}`",
                parsed.path, self.path
            ));
        }
        if let Some(host) = &self.host
            && parsed.headers.get("host") != Some(host)
        {
            return invalid(format!("httpupgrade bad host, expected `{host}`"));
        }
        if !header_contains(
            parsed.headers.get("connection").map(String::as_str),
            "upgrade",
        ) {
            return invalid("httpupgrade missing Connection: upgrade");
        }
        if !matches!(
            parsed.headers.get("upgrade").map(String::as_str),
            Some(value) if value.eq_ignore_ascii_case("websocket")
        ) {
            return invalid("httpupgrade missing Upgrade: websocket");
        }
        if parsed.headers.contains_key("sec-websocket-key") {
            return invalid("httpupgrade received a real websocket request");
        }
        for (key, expected) in &self.headers {
            if parsed.headers.get(key) != Some(expected) {
                return invalid(format!("httpupgrade bad header `{key}`"));
            }
        }

        server_stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await?;
        server_stream.flush().await?;

        let initial_data = parsed.stream_reader.unparsed_data_owned();
        let stream: Box<dyn AsyncStream> = if initial_data.is_some() {
            Box::new(PrependStream::new(server_stream, initial_data))
        } else {
            server_stream
        };
        self.handler
            .setup_server_stream_with_peer_addr(stream, peer_addr)
            .await
    }
}

struct ParsedHttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    stream_reader: StreamReader,
}

impl ParsedHttpRequest {
    async fn parse(stream: &mut Box<dyn AsyncStream>) -> std::io::Result<Self> {
        let mut stream_reader = StreamReader::new();
        let first_line = stream_reader.read_line(stream).await?.to_string();
        let mut parts = first_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();
        let version = parts.next().unwrap_or("");
        if parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
            return invalid(format!("invalid httpupgrade request line `{first_line}`"));
        }

        let mut headers = HashMap::new();
        let mut line_count = 0usize;
        loop {
            let line = stream_reader.read_line(stream).await?;
            if line.is_empty() {
                break;
            }
            if line.len() >= 4096 {
                return invalid("httpupgrade request header line is too long");
            }
            let (key, value) = line.split_once(':').ok_or_else(|| {
                invalid_error(format!("invalid httpupgrade request header `{line}`"))
            })?;
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
            line_count += 1;
            if line_count >= 64 {
                return invalid("httpupgrade request has too many headers");
            }
        }

        Ok(Self {
            method,
            path,
            headers,
            stream_reader,
        })
    }
}

fn normalize_path(path: String) -> String {
    if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    }
}

fn normalize_headers(headers: HashMap<String, String>) -> HashMap<String, String> {
    headers
        .into_iter()
        .map(|(key, value)| (key.to_ascii_lowercase(), value))
        .collect()
}

fn header_contains(header: Option<&str>, expected: &str) -> bool {
    header
        .map(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(expected))
        })
        .unwrap_or(false)
}

fn invalid<T>(msg: impl Into<String>) -> std::io::Result<T> {
    Err(invalid_error(msg))
}

fn invalid_error(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.into())
}
