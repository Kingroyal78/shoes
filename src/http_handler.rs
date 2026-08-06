use std::borrow::Cow;
use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use log::debug;
use tokio::io::AsyncWriteExt;
use url::Url;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::resolver::{Resolver, resolve_single_address};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};

const PROXY_AUTH_HEADER_PREFIX: &str = "proxy-authorization: basic ";
const CONNECTION_HEADER_PREFIX: &str = "connection: ";
const PROXY_CONNECTION_HEADER_PREFIX: &str = "proxy-connection: ";
const MAX_HTTP_FORWARD_REQUEST_LEN: usize = 16_384;
const CONNECTION_CLOSE_HEADER: &[u8] = b"Connection: close\r\n\r\n";
const HTTP_FORWARD_REQUEST_INITIAL_EXTRA_CAPACITY: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpProxyHeaderKind {
    ProxyAuthorization,
    ConnectionControl,
    Other,
}

pub fn classify_http_proxy_header_line(line: &str) -> HttpProxyHeaderKind {
    if line.len() > PROXY_AUTH_HEADER_PREFIX.len() + 1
        && starts_with_ignore_ascii_case(line, PROXY_AUTH_HEADER_PREFIX)
    {
        HttpProxyHeaderKind::ProxyAuthorization
    } else if starts_with_ignore_ascii_case(line, CONNECTION_HEADER_PREFIX)
        || starts_with_ignore_ascii_case(line, PROXY_CONNECTION_HEADER_PREFIX)
    {
        HttpProxyHeaderKind::ConnectionControl
    } else {
        HttpProxyHeaderKind::Other
    }
}

fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn create_http_auth_token(username: &str, password: &str) -> String {
    BASE64.encode(format!("{username}:{password}"))
}

fn start_http_forward_request(directive: &str, location: &str, http_version: &str) -> Vec<u8> {
    let mut request = Vec::with_capacity(
        directive.len()
            + 1
            + location.len()
            + 1
            + http_version.len()
            + 2
            + HTTP_FORWARD_REQUEST_INITIAL_EXTRA_CAPACITY,
    );
    request.extend_from_slice(directive.as_bytes());
    request.push(b' ');
    request.extend_from_slice(location.as_bytes());
    request.push(b' ');
    request.extend_from_slice(http_version.as_bytes());
    request.extend_from_slice(b"\r\n");
    request
}

fn append_http_forward_header_line(request: &mut Vec<u8>, line: &str) -> std::io::Result<()> {
    request.extend_from_slice(line.as_bytes());
    request.extend_from_slice(b"\r\n");

    if request.len() > MAX_HTTP_FORWARD_REQUEST_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP GET request is too long",
        ));
    }

    Ok(())
}

fn finish_http_forward_initial_data(mut request: Vec<u8>, unparsed_data: &[u8]) -> Vec<u8> {
    request.reserve(CONNECTION_CLOSE_HEADER.len() + unparsed_data.len());
    request.extend_from_slice(CONNECTION_CLOSE_HEADER);
    request.extend_from_slice(unparsed_data);
    request
}

#[cfg(any(test, feature = "internal-bench"))]
pub fn build_http_forward_initial_data_for_bench(
    directive: &str,
    location: &str,
    http_version: &str,
    headers: &[&str],
    unparsed_data: &[u8],
) -> std::io::Result<Vec<u8>> {
    let mut request = start_http_forward_request(directive, location, http_version);
    for line in headers {
        append_http_forward_header_line(&mut request, line)?;
    }
    Ok(finish_http_forward_initial_data(request, unparsed_data))
}

fn parse_connect_authority(authority: &str) -> std::io::Result<NetLocation> {
    parse_authority(authority, None)
}

fn parse_authority(authority: &str, default_port: Option<u16>) -> std::io::Result<NetLocation> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']').ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid IPv6 authority")
        })?;
        let host = &rest[..end];
        let after_host = &rest[end + 1..];
        let port = if let Some(port_str) = after_host.strip_prefix(':') {
            if port_str.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid address format",
                ));
            }
            port_str
                .parse::<u16>()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        } else if after_host.is_empty() {
            default_port
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "No port"))?
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid IPv6 authority",
            ));
        };

        return Ok(NetLocation::new(Address::from(host)?, port));
    }

    let (host, port) = match authority.rfind(':') {
        Some(separator_index) => {
            let host = &authority[..separator_index];
            let port_str = &authority[separator_index + 1..];
            if host.is_empty() || port_str.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid address format",
                ));
            }
            let port = port_str
                .parse::<u16>()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            (host, port)
        }
        None => (
            authority,
            default_port
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "No port"))?,
        ),
    };

    Ok(NetLocation::new(Address::from(host)?, port))
}

pub fn parse_http_forward_url(raw_url: &str) -> std::io::Result<(NetLocation, Cow<'_, str>)> {
    if let Some(parsed) = parse_http_forward_url_fast(raw_url)? {
        return Ok(parsed);
    }
    parse_http_forward_url_slow(raw_url)
}

fn parse_http_forward_url_fast(
    raw_url: &str,
) -> std::io::Result<Option<(NetLocation, Cow<'_, str>)>> {
    let Some(rest) = raw_url.strip_prefix("http://") else {
        return Ok(None);
    };

    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return Ok(None);
    }

    let (host, port) = parse_http_fast_authority(authority)?;
    let location = http_fast_location(&rest[authority_end..]);
    Ok(Some((
        NetLocation::new(Address::from(host)?, port),
        location,
    )))
}

fn parse_http_fast_authority(authority: &str) -> std::io::Result<(&str, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']').ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid IPv6 authority")
        })?;
        let host = &rest[..end];
        let after_host = &rest[end + 1..];
        let port = if after_host.is_empty() {
            80
        } else if let Some(port_str) = after_host.strip_prefix(':') {
            parse_http_fast_port(port_str)?
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid IPv6 authority",
            ));
        };
        return Ok((host, port));
    }

    if authority.contains(['[', ']']) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid HTTP authority",
        ));
    }

    match authority.rfind(':') {
        Some(separator_index) => {
            let host = &authority[..separator_index];
            let port = parse_http_fast_port(&authority[separator_index + 1..])?;
            if host.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "HTTP URL missing host",
                ));
            }
            Ok((host, port))
        }
        None => Ok((authority, 80)),
    }
}

fn parse_http_fast_port(port: &str) -> std::io::Result<u16> {
    if port.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "HTTP URL missing port",
        ));
    }
    port.parse::<u16>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn http_fast_location(path_query_fragment: &str) -> Cow<'_, str> {
    let path_query = path_query_fragment
        .split_once('#')
        .map(|(path_query, _)| path_query)
        .unwrap_or(path_query_fragment);
    match path_query.as_bytes().first() {
        Some(b'/') => Cow::Borrowed(path_query),
        Some(b'?') => {
            let mut location = String::with_capacity(path_query.len() + 1);
            location.push('/');
            location.push_str(path_query);
            Cow::Owned(location)
        }
        _ => Cow::Borrowed("/"),
    }
}

fn parse_http_forward_url_slow(raw_url: &str) -> std::io::Result<(NetLocation, Cow<'_, str>)> {
    let url = Url::parse(raw_url)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    if url.scheme() != "http" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unsupported http forward url: {raw_url}"),
        ));
    }
    let host = url.host_str().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "HTTP URL missing host")
    })?;
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let port = url.port_or_known_default().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "HTTP URL missing port")
    })?;

    let mut location = url.path().to_string();
    if location.is_empty() {
        location.push('/');
    }
    if let Some(query) = url.query() {
        location.push('?');
        location.push_str(query);
    }

    Ok((
        NetLocation::new(Address::from(host)?, port),
        Cow::Owned(location),
    ))
}

#[derive(Debug)]
pub struct HttpTcpServerHandler {
    auth_token: Option<String>,
    proxy_selector: Arc<ClientProxySelector>,
}

unsafe impl Send for HttpTcpServerHandler {}
unsafe impl Sync for HttpTcpServerHandler {}

impl HttpTcpServerHandler {
    pub fn new(
        auth_credentials: Option<(String, String)>,
        proxy_selector: Arc<ClientProxySelector>,
    ) -> Self {
        let auth_token = auth_credentials
            .map(|(username, password)| create_http_auth_token(&username, &password));
        Self {
            auth_token,
            proxy_selector,
        }
    }
}

#[async_trait]
impl TcpServerHandler for HttpTcpServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let stream_reader = StreamReader::new();
        setup_http_server_stream_inner(
            self.auth_token.as_deref(),
            server_stream,
            stream_reader,
            self.proxy_selector.clone(),
        )
        .await
    }
}

/// Core HTTP proxy server setup logic.
/// Can be called from HttpTcpServerHandler or MixedTcpServerHandler.
///
/// Takes ownership of `server_stream` and returns it in the result.
pub async fn setup_http_server_stream_inner(
    auth_token: Option<&str>,
    mut server_stream: Box<dyn AsyncStream>,
    mut stream_reader: StreamReader,
    proxy_selector: Arc<ClientProxySelector>,
) -> std::io::Result<TcpServerSetupResult> {
    let line = stream_reader.read_line(&mut server_stream).await?;
    if !line.ends_with(" HTTP/1.0") && !line.ends_with(" HTTP/1.1") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unrecognized http request: {line}"),
        ));
    }

    // GET = 3 (smaller than CONNECT)
    // HTTP/1.1 = 8
    // min address a.ab = 4
    // port 1
    // 3 spaces
    // total = 19
    if line.len() < 19 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid http request: {line}"),
        ));
    }

    let http_version = line[line.len() - 8..].to_string();
    let (remote_location, connection_success_response, initial_remote_data, need_initial_flush) =
        if line.starts_with("CONNECT ") {
            let address = &line[8..line.len() - 9];
            let remote_location = parse_connect_authority(address)?;

            // wait for an empty \r\n before connecting, and check for auth header line if needed.
            let mut need_auth = auth_token.is_some();

            loop {
                let line = stream_reader.read_line(&mut server_stream).await?;
                if line.is_empty() {
                    break;
                }
                if need_auth
                    && line.len() > PROXY_AUTH_HEADER_PREFIX.len() + 1
                    && line[0..PROXY_AUTH_HEADER_PREFIX.len()].to_ascii_lowercase()
                        == PROXY_AUTH_HEADER_PREFIX
                {
                    if &line[PROXY_AUTH_HEADER_PREFIX.len()..] != auth_token.unwrap() {
                        debug!(
                            "Received incorrect HTTP CONNECT authentication: {}",
                            &line[PROXY_AUTH_HEADER_PREFIX.len()..]
                        );
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Incorrect HTTP CONNECT authentication",
                        ));
                    }
                    need_auth = false;
                    continue;
                }
                debug!("Ignored HTTP CONNECT request header: {line}");
            }

            if need_auth {
                // FoxyProxy and similar clients require Proxy-Authenticate header to send credentials
                server_stream.write_all(
                &format!("{http_version} 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
            ).await?;
                server_stream.flush().await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Missing HTTP CONNECT authentication",
                ));
            }

            // We need an initial flush for this line.
            let connection_success_response = Some(
                format!("{http_version} 200 Connection established\r\n\r\n")
                    .into_bytes()
                    .into_boxed_slice(),
            );

            (
                remote_location,
                connection_success_response,
                stream_reader.unparsed_data_owned(),
                true,
            )
        } else {
            // Request looks a normal HTTP request but with protocol and address:
            // GET http://ipinfo.io/ HTTP/1.1
            // <headers follow..>
            // <empty line>

            let line = &line[0..line.len() - 9];

            let space_index = line.find(' ').ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Unrecognized http request: {line} {http_version}"),
                )
            })?;

            let directive = &line[0..space_index];
            let url = &line[space_index + 1..];

            let (remote_location, location) = parse_http_forward_url(url)?;

            let mut request =
                start_http_forward_request(directive, location.as_ref(), &http_version);

            // wait for an empty \r\n before connecting, and check for auth header line if needed.
            let mut need_auth = auth_token.is_some();

            loop {
                let line = stream_reader.read_line(&mut server_stream).await?;
                if line.is_empty() {
                    break;
                }

                match classify_http_proxy_header_line(line) {
                    HttpProxyHeaderKind::ProxyAuthorization => {
                        if need_auth {
                            if &line[PROXY_AUTH_HEADER_PREFIX.len()..] != auth_token.unwrap() {
                                debug!(
                                    "Received incorrect HTTP GET authentication: {}",
                                    &line[PROXY_AUTH_HEADER_PREFIX.len()..]
                                );
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    "Incorrect HTTP GET authentication",
                                ));
                            }
                            need_auth = false;
                        }
                        // If some auth header was passed in and we don't have auth configured,
                        // simply ignore it.
                        continue;
                    }
                    HttpProxyHeaderKind::ConnectionControl => {
                        // We can't support 'Connection' or 'Proxy-Connection' for GET style proxy requests.
                        // Because then we'd have to parse the remote server's response to know when it ends,
                        // in order to handle subsequent GET requests.
                        // So filter them out, and then we make sure to add a 'Connection: close' header to prevent
                        // having to worry about that.
                        continue;
                    }
                    HttpProxyHeaderKind::Other => {}
                }

                append_http_forward_header_line(&mut request, line)?;
            }

            if need_auth {
                // FoxyProxy and similar clients require Proxy-Authenticate header to send credentials
                server_stream.write_all(
                &format!("{http_version} 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
            ).await?;
                server_stream.flush().await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Missing HTTP GET authentication",
                ));
            }

            // We don't write "HTTP/xxx 200 Connection established\r\n\r\n" for this type of
            // request, the server's response (eg. "HTTP/1.1 200 OK") is what the client
            // expects as a response.

            let unparsed_data = stream_reader.unparsed_data();
            let initial_remote_data = finish_http_forward_initial_data(request, unparsed_data);

            (
                remote_location,
                None,
                Some(initial_remote_data.into_boxed_slice()),
                false,
            )
        };

    Ok(TcpServerSetupResult::TcpForward {
        remote_location,
        stream: server_stream,
        need_initial_flush,
        connection_success_response,
        initial_remote_data,
        proxy_selector,
        outbound_dispatcher: None,
        authenticated_user: None,
    })
}

fn create_http_auth_header_line(username: &str, password: &str) -> String {
    format!(
        "Proxy-Authorization: Basic {}\r\n",
        create_http_auth_token(username, password)
    )
}

pub struct HttpTcpClientHandler {
    auth_header: Option<String>,
    resolver: Option<Arc<dyn Resolver>>,
}

impl std::fmt::Debug for HttpTcpClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTcpClientHandler")
            .field(
                "auth_header",
                &self.auth_header.as_ref().map(|_| "[redacted]"),
            )
            .field("resolver", &self.resolver.is_some())
            .finish()
    }
}

impl HttpTcpClientHandler {
    pub fn new(
        auth_credentials: Option<(String, String)>,
        resolver: Option<Arc<dyn Resolver>>,
    ) -> Self {
        let auth_header = auth_credentials
            .map(|(username, password)| create_http_auth_header_line(&username, &password));
        Self {
            auth_header,
            resolver,
        }
    }
}

#[async_trait]
impl TcpClientHandler for HttpTcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        // Resolve hostname to IP if resolver is configured.
        // Bypasses DNS issues when the upstream proxy has DNS problems.
        // Uses pre-resolved address if available, otherwise resolves here.
        let connect_location = if let Some(ref resolver) = self.resolver {
            if let Some(resolved_addr) = remote_location.resolved_addr() {
                // Use pre-resolved address
                debug!(
                    "HTTP CONNECT using pre-resolved {} -> {}",
                    remote_location.location(),
                    resolved_addr
                );
                let address = match resolved_addr.ip() {
                    std::net::IpAddr::V4(ip) => Address::Ipv4(ip),
                    std::net::IpAddr::V6(ip) => Address::Ipv6(ip),
                };
                NetLocation::new(address, resolved_addr.port())
            } else if remote_location.address().hostname().is_some() {
                let socket_addr =
                    resolve_single_address(resolver, remote_location.location()).await?;
                debug!(
                    "HTTP CONNECT resolved {} -> {}",
                    remote_location.location(),
                    socket_addr
                );
                let address = match socket_addr.ip() {
                    std::net::IpAddr::V4(ip) => Address::Ipv4(ip),
                    std::net::IpAddr::V6(ip) => Address::Ipv6(ip),
                };
                NetLocation::new(address, socket_addr.port())
            } else {
                remote_location.into_location()
            }
        } else {
            remote_location.into_location()
        };

        let mut connect_str = match connect_location.address() {
            Address::Ipv6(addr) => {
                format!(
                    "CONNECT [{}]:{} HTTP/1.1\r\n",
                    addr,
                    connect_location.port()
                )
            }
            Address::Ipv4(addr) => {
                format!("CONNECT {}:{} HTTP/1.1\r\n", addr, connect_location.port())
            }
            Address::Hostname(d) => {
                format!("CONNECT {}:{} HTTP/1.1\r\n", d, connect_location.port())
            }
        };

        if let Some(ref header) = self.auth_header {
            connect_str.push_str(header);
        }
        connect_str.push_str("\r\n");
        client_stream.write_all(&connect_str.into_bytes()).await?;
        client_stream.flush().await?;

        let mut stream_reader = StreamReader::new();
        let line = stream_reader.read_line(&mut client_stream).await?;

        // Expected response: HTTP/1.1 200 Connection established\r\n\r\n
        if !line.starts_with("HTTP/1.1 200") && !line.starts_with("HTTP/1.0 200") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("HTTP CONNECT request failed: {line}"),
            ));
        }

        loop {
            let line = stream_reader.read_line(&mut client_stream).await?;
            if line.is_empty() {
                break;
            }
        }

        let early_data = stream_reader.unparsed_data();
        let early_data = if early_data.is_empty() {
            None
        } else {
            Some(early_data.to_vec())
        };

        Ok(TcpClientSetupResult {
            client_stream,
            early_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn connect_authority_parses_bracketed_ipv6() {
        let location = parse_connect_authority("[::1]:443").unwrap();
        assert_eq!(
            location,
            NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 443)
        );
    }

    #[test]
    fn connect_authority_parses_hostname() {
        let location = parse_connect_authority("example.com:8443").unwrap();
        assert_eq!(
            location,
            NetLocation::new(Address::Hostname("example.com".to_string()), 8443)
        );
    }

    #[test]
    fn forward_url_parses_ipv6_host_and_query() {
        let (location, path) = parse_http_forward_url("http://[::1]:8080/path?q=1").unwrap();
        assert_eq!(
            location,
            NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 8080)
        );
        assert_eq!(path, "/path?q=1");
    }

    #[test]
    fn forward_url_defaults_to_port_80() {
        let (location, path) = parse_http_forward_url("http://127.0.0.1").unwrap();
        assert_eq!(
            location,
            NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 80)
        );
        assert_eq!(path, "/");
    }

    #[test]
    fn forward_url_parses_query_without_explicit_path() {
        let (location, path) = parse_http_forward_url("http://example.com?x=1").unwrap();
        assert_eq!(
            location,
            NetLocation::new(Address::Hostname("example.com".to_string()), 80)
        );
        assert_eq!(path, "/?x=1");
    }

    #[test]
    fn forward_url_ignores_fragment_like_previous_url_parser() {
        let (location, path) = parse_http_forward_url("http://example.com/a?b=1#frag").unwrap();
        assert_eq!(
            location,
            NetLocation::new(Address::Hostname("example.com".to_string()), 80)
        );
        assert_eq!(path, "/a?b=1");
    }

    #[test]
    fn forward_url_falls_back_for_userinfo() {
        let (location, path) = parse_http_forward_url("http://user@example.com/a").unwrap();
        assert_eq!(
            location,
            NetLocation::new(Address::Hostname("example.com".to_string()), 80)
        );
        assert_eq!(path, "/a");
    }

    #[test]
    fn forward_url_rejects_https() {
        let err = parse_http_forward_url("https://example.com/").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn forward_initial_data_builder_preserves_request_bytes() {
        let headers = [
            "Host: example.com",
            "User-Agent: shoes-test",
            "X-Test: value",
        ];
        let initial = build_http_forward_initial_data_for_bench(
            "GET",
            "/payload.bin?q=1",
            "HTTP/1.1",
            &headers,
            b"body-prefix",
        )
        .unwrap();

        assert_eq!(
            initial,
            b"GET /payload.bin?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: shoes-test\r\nX-Test: value\r\nConnection: close\r\n\r\nbody-prefix"
        );
    }
}
