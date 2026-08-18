use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ::http::{HeaderMap, Request, Response, StatusCode};
use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::async_stream::AsyncStream;
use crate::h2mux::PrependStream;
use crate::resolver::Resolver;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::tcp::tcp_server::handle_server_setup_result;

const MAX_H2_WRITE_PAYLOAD_LEN: usize = 16 * 1024;

#[derive(Debug)]
pub struct V2RayHttpServerHandler {
    hosts: Vec<String>,
    paths: Vec<String>,
    method: Option<String>,
    response_headers: HashMap<String, String>,
    handler: Box<dyn TcpServerHandler>,
}

impl V2RayHttpServerHandler {
    pub fn new(
        hosts: Vec<String>,
        paths: Vec<String>,
        method: Option<String>,
        response_headers: HashMap<String, String>,
        handler: Box<dyn TcpServerHandler>,
    ) -> Self {
        Self {
            hosts,
            paths: normalize_paths(paths),
            method: method.and_then(|value| non_empty(value.trim())),
            response_headers: normalize_headers(response_headers),
            handler,
        }
    }
}

#[async_trait]
impl TcpServerHandler for V2RayHttpServerHandler {
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
        peer_addr: Option<SocketAddr>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let parsed = ParsedHttpRequest::parse(&mut server_stream).await?;

        if let Some(method) = &self.method
            && !parsed.method.eq_ignore_ascii_case(method)
        {
            return invalid(format!(
                "v2ray http transport bad method `{}` expected `{method}`",
                parsed.method
            ));
        }

        if !self.paths.iter().any(|path| parsed.path.starts_with(path)) {
            return invalid(format!(
                "v2ray http transport bad path `{}` expected prefix in {:?}",
                parsed.path, self.paths
            ));
        }

        if !self.hosts.is_empty() {
            let host = parsed
                .headers
                .get("host")
                .ok_or_else(|| invalid_error("v2ray http transport missing Host header"))?;
            if !self
                .hosts
                .iter()
                .any(|expected| expected.eq_ignore_ascii_case(host))
            {
                return invalid(format!(
                    "v2ray http transport bad host `{host}` expected one of {:?}",
                    self.hosts
                ));
            }
        }

        let mut response = String::from("HTTP/1.1 200 OK\r\nCache-Control: no-store\r\n");
        for (key, value) in &self.response_headers {
            response.push_str(key);
            response.push_str(": ");
            response.push_str(value);
            response.push_str("\r\n");
        }
        response.push_str("\r\n");
        server_stream.write_all(response.as_bytes()).await?;
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

#[derive(Debug)]
pub struct V2RayHttp2ServerHandler {
    hosts: Vec<String>,
    paths: Vec<String>,
    method: Option<String>,
    response_headers: HashMap<String, String>,
    handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
}

impl V2RayHttp2ServerHandler {
    pub fn new(
        hosts: Vec<String>,
        paths: Vec<String>,
        method: Option<String>,
        response_headers: HashMap<String, String>,
        handler: Arc<dyn TcpServerHandler>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self {
            hosts,
            paths: normalize_paths(paths),
            method: method.and_then(|value| non_empty(value.trim())),
            response_headers: normalize_headers(response_headers),
            handler,
            resolver,
        }
    }

    async fn run(
        &self,
        server_stream: Box<dyn AsyncStream>,
        peer_addr: Option<SocketAddr>,
    ) -> io::Result<TcpServerSetupResult> {
        let connection = h2::server::handshake(server_stream)
            .await
            .map_err(h2_error)?;
        Ok(TcpServerSetupResult::connection_task(run_h2_accept_loop(
            connection,
            H2TransportSettings {
                hosts: self.hosts.clone(),
                paths: self.paths.clone(),
                method: self.method.clone(),
                response_headers: self.response_headers.clone(),
            },
            self.handler.clone(),
            self.resolver.clone(),
            peer_addr,
        )))
    }
}

#[async_trait]
impl TcpServerHandler for V2RayHttp2ServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        self.run(server_stream, None).await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        server_stream: Box<dyn AsyncStream>,
        peer_addr: Option<SocketAddr>,
    ) -> io::Result<TcpServerSetupResult> {
        self.run(server_stream, peer_addr).await
    }
}

#[derive(Clone)]
struct H2TransportSettings {
    hosts: Vec<String>,
    paths: Vec<String>,
    method: Option<String>,
    response_headers: HashMap<String, String>,
}

async fn run_h2_accept_loop<T>(
    mut connection: h2::server::Connection<T, Bytes>,
    settings: H2TransportSettings,
    handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    peer_addr: Option<SocketAddr>,
) -> io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut requests = tokio::task::JoinSet::new();
    while let Some(result) = connection.accept().await {
        while requests.try_join_next().is_some() {}
        let (request, respond) = match result {
            Ok(parts) => parts,
            Err(e) => {
                log::debug!("v2ray http2 transport connection stopped: {e}");
                break;
            }
        };

        requests.spawn(handle_h2_request(
            request,
            respond,
            settings.clone(),
            handler.clone(),
            resolver.clone(),
            peer_addr,
        ));
    }
    requests.abort_all();
    while requests.join_next().await.is_some() {}
    Ok(())
}

async fn handle_h2_request(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    settings: H2TransportSettings,
    handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    peer_addr: Option<SocketAddr>,
) {
    if let Err(e) = handle_h2_request_result(
        request,
        &mut respond,
        settings,
        handler,
        resolver,
        peer_addr,
    )
    .await
    {
        log::debug!("v2ray http2 transport stream failed: {e}");
    }
}

async fn handle_h2_request_result(
    request: Request<h2::RecvStream>,
    respond: &mut h2::server::SendResponse<Bytes>,
    settings: H2TransportSettings,
    handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
    peer_addr: Option<SocketAddr>,
) -> io::Result<()> {
    if let Err(e) = validate_h2_request(&request, &settings) {
        send_h2_error_response(respond, StatusCode::BAD_REQUEST)?;
        return Err(e);
    }

    let (request_parts, recv) = request.into_parts();
    let response = h2_response(&settings.response_headers)?;
    let send = respond.send_response(response, false).map_err(h2_error)?;

    log::debug!(
        "accepted v2ray http2 transport request path={}",
        request_parts.uri.path()
    );

    let stream = Box::new(V2RayHttp2Stream::new(send, recv));
    let mut setup_result = handler
        .setup_server_stream_with_peer_addr(stream, peer_addr)
        .await?;
    setup_result.set_need_initial_flush(true);
    handle_server_setup_result(setup_result, resolver, peer_addr).await
}

fn validate_h2_request<B>(request: &Request<B>, settings: &H2TransportSettings) -> io::Result<()> {
    if let Some(method) = &settings.method
        && !request.method().as_str().eq_ignore_ascii_case(method)
    {
        return invalid(format!(
            "v2ray http2 transport bad method `{}` expected `{method}`",
            request.method()
        ));
    }

    let path = request.uri().path();
    if !settings
        .paths
        .iter()
        .any(|expected| path.starts_with(expected))
    {
        return invalid(format!(
            "v2ray http2 transport bad path `{path}` expected prefix in {:?}",
            settings.paths
        ));
    }

    if !settings.hosts.is_empty() {
        let host = request_authority(request)
            .ok_or_else(|| invalid_error("v2ray http2 transport missing authority/Host"))?;
        if !settings
            .hosts
            .iter()
            .any(|expected| expected.eq_ignore_ascii_case(&host))
        {
            return invalid(format!(
                "v2ray http2 transport bad host `{host}` expected one of {:?}",
                settings.hosts
            ));
        }
    }

    Ok(())
}

fn request_authority<B>(request: &Request<B>) -> Option<String> {
    request
        .uri()
        .authority()
        .map(|authority| authority.as_str().to_string())
        .or_else(|| header_to_str(request.headers(), "host").map(ToOwned::to_owned))
}

fn header_to_str<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers.get(key).and_then(|value| value.to_str().ok())
}

fn h2_response(headers: &HashMap<String, String>) -> io::Result<Response<()>> {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("cache-control", "no-store");
    for (key, value) in headers {
        builder = builder.header(key.to_ascii_lowercase(), value);
    }
    builder.body(()).map_err(|e| invalid_error(e.to_string()))
}

fn send_h2_error_response(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: StatusCode,
) -> io::Result<()> {
    let response = Response::builder()
        .status(status)
        .header("content-length", "0")
        .body(())
        .map_err(|e| invalid_error(e.to_string()))?;
    respond
        .send_response(response, true)
        .map(|_| ())
        .map_err(h2_error)
}

struct V2RayHttp2Stream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    recv_buf: Bytes,
    shutdown_sent: bool,
}

impl V2RayHttp2Stream {
    fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            recv_buf: Bytes::new(),
            shutdown_sent: false,
        }
    }
}

impl AsyncRead for V2RayHttp2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if !self.recv_buf.is_empty() {
            let to_copy = self.recv_buf.len().min(buf.remaining());
            buf.put_slice(&self.recv_buf[..to_copy]);
            self.recv_buf = self.recv_buf.slice(to_copy..);
            return Poll::Ready(Ok(()));
        }

        loop {
            match Pin::new(&mut self.recv).poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    let len = data.len();
                    self.recv
                        .flow_control()
                        .release_capacity(len)
                        .map_err(h2_error)?;
                    if data.is_empty() {
                        continue;
                    }

                    let to_copy = data.len().min(buf.remaining());
                    buf.put_slice(&data[..to_copy]);
                    if to_copy < data.len() {
                        self.recv_buf = data.slice(to_copy..);
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(h2_error(e))),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for V2RayHttp2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.shutdown_sent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "v2ray http2 stream is shut down",
            )));
        }

        let available = if self.send.capacity() > 0 {
            self.send.capacity()
        } else {
            self.send
                .reserve_capacity(buf.len().min(MAX_H2_WRITE_PAYLOAD_LEN));
            match self.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(capacity))) => capacity,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(h2_error(e))),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "v2ray http2 send stream closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        };

        if available == 0 {
            self.send
                .reserve_capacity(buf.len().min(MAX_H2_WRITE_PAYLOAD_LEN));
            return Poll::Pending;
        }

        let payload_len = buf.len().min(MAX_H2_WRITE_PAYLOAD_LEN).min(available);
        self.send
            .send_data(Bytes::copy_from_slice(&buf[..payload_len]), false)
            .map_err(h2_error)?;
        Poll::Ready(Ok(payload_len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown_sent {
            self.send.send_data(Bytes::new(), true).map_err(h2_error)?;
            self.shutdown_sent = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncPing for V2RayHttp2Stream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl Unpin for V2RayHttp2Stream {}

impl AsyncStream for V2RayHttp2Stream {}

impl fmt::Debug for V2RayHttp2Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2RayHttp2Stream")
            .field("recv_buf_len", &self.recv_buf.len())
            .field("shutdown_sent", &self.shutdown_sent)
            .finish()
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
            return invalid(format!(
                "invalid v2ray http transport request line `{first_line}`"
            ));
        }

        let mut headers = HashMap::new();
        let mut line_count = 0usize;
        loop {
            let line = stream_reader.read_line(stream).await?;
            if line.is_empty() {
                break;
            }
            if line.len() >= 4096 {
                return invalid("v2ray http transport request header line is too long");
            }
            let (key, value) = line.split_once(':').ok_or_else(|| {
                invalid_error(format!(
                    "invalid v2ray http transport request header `{line}`"
                ))
            })?;
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
            line_count += 1;
            if line_count >= 64 {
                return invalid("v2ray http transport request has too many headers");
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

fn normalize_paths(paths: Vec<String>) -> Vec<String> {
    let mut normalized: Vec<String> = paths
        .into_iter()
        .filter_map(|path| non_empty(path.trim()))
        .map(|path| {
            if path.starts_with('/') {
                path
            } else {
                format!("/{path}")
            }
        })
        .collect();
    if normalized.is_empty() {
        normalized.push("/".to_string());
    }
    normalized
}

fn normalize_headers(headers: HashMap<String, String>) -> HashMap<String, String> {
    headers
        .into_iter()
        .filter_map(|(key, value)| non_empty(value.trim()).map(|value| (key, value)))
        .collect()
}

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn invalid<T>(msg: impl Into<String>) -> std::io::Result<T> {
    Err(invalid_error(msg))
}

fn invalid_error(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.into())
}

fn h2_error(e: h2::Error) -> io::Error {
    io::Error::other(format!("v2ray http2 transport h2 error: {e}"))
}

#[cfg(test)]
mod tests {
    use ::http::Method;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use parking_lot::Mutex;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

    use super::*;
    use crate::async_stream::AsyncPing;
    use crate::resolver::NativeResolver;

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    #[derive(Debug)]
    struct CaptureHandler {
        captured: Arc<Mutex<Vec<u8>>>,
    }

    #[async_trait]
    impl TcpServerHandler for CaptureHandler {
        async fn setup_server_stream(
            &self,
            mut server_stream: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            let mut buf = [0u8; 4];
            server_stream.read_exact(&mut buf).await?;
            *self.captured.lock() = buf.to_vec();
            server_stream.shutdown().await?;
            Ok(TcpServerSetupResult::completed())
        }
    }

    #[tokio::test]
    async fn accepts_http_transport_and_prepends_buffered_payload() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let handler = V2RayHttpServerHandler::new(
            vec!["edge.example".to_string()],
            vec!["/ray".to_string()],
            Some("PUT".to_string()),
            HashMap::from([("X-Edge".to_string(), "ok".to_string())]),
            Box::new(CaptureHandler {
                captured: captured.clone(),
            }),
        );
        let (mut client, server) = tokio::io::duplex(4096);

        let task = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .unwrap();
        });

        client
            .write_all(b"PUT /ray?id=1 HTTP/1.1\r\nHost: edge.example\r\n\r\nPING")
            .await
            .unwrap();
        let mut response = vec![0u8; 128];
        let n = client.read(&mut response).await.unwrap();
        let response = std::str::from_utf8(&response[..n]).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("X-Edge: ok\r\n"));

        task.await.unwrap();
        assert_eq!(*captured.lock(), b"PING".to_vec());
    }

    #[tokio::test]
    async fn rejects_unexpected_host() {
        let handler = V2RayHttpServerHandler::new(
            vec!["edge.example".to_string()],
            vec!["/".to_string()],
            None,
            HashMap::new(),
            Box::new(CaptureHandler {
                captured: Arc::new(Mutex::new(Vec::new())),
            }),
        );
        let (mut client, server) = tokio::io::duplex(4096);

        let task = tokio::spawn(async move {
            match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => panic!("expected bad host to be rejected"),
                Err(err) => err.to_string(),
            }
        });

        client
            .write_all(b"PUT / HTTP/1.1\r\nHost: other.example\r\n\r\nPING")
            .await
            .unwrap();

        let err = task.await.unwrap();
        assert!(err.contains("bad host"));
    }

    #[tokio::test]
    async fn accepts_http2_transport_and_multiple_streams() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let handler = V2RayHttp2ServerHandler::new(
            vec!["edge.example".to_string()],
            vec!["/ray".to_string()],
            Some("PUT".to_string()),
            HashMap::from([("X-Edge".to_string(), "ok".to_string())]),
            Arc::new(CaptureHandler {
                captured: captured.clone(),
            }),
            Arc::new(NativeResolver::new()),
        );
        let (client, server) = tokio::io::duplex(8192);

        let server_task = tokio::spawn(async move {
            let result = handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .unwrap();
            let TcpServerSetupResult::ConnectionTask(task) = result else {
                panic!("HTTP/2 connection must return an owned connection task")
            };
            task.await.unwrap();
        });

        let (mut send_request, connection) =
            h2::client::handshake(TestStream(client)).await.unwrap();
        let connection_task = tokio::spawn(async move { connection.await.unwrap() });

        for payload in [b"PING".as_slice(), b"PONG".as_slice()] {
            let request = Request::builder()
                .method(Method::PUT)
                .uri("https://edge.example/ray?id=1")
                .body(())
                .unwrap();
            let (response, mut send) = send_request.send_request(request, false).unwrap();
            send.send_data(Bytes::copy_from_slice(payload), true)
                .unwrap();
            let response = response.await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers().get("x-edge").unwrap(), "ok");
        }

        drop(send_request);
        connection_task.abort();
        let _ = connection_task.await;
        server_task.await.unwrap();
        assert_eq!(*captured.lock(), b"PONG".to_vec());
    }

    #[tokio::test]
    async fn rejects_http2_unexpected_authority() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let handler = V2RayHttp2ServerHandler::new(
            vec!["edge.example".to_string()],
            vec!["/".to_string()],
            None,
            HashMap::new(),
            Arc::new(CaptureHandler {
                captured: captured.clone(),
            }),
            Arc::new(NativeResolver::new()),
        );
        let (client, server) = tokio::io::duplex(8192);

        let server_task = tokio::spawn(async move {
            let result = handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .unwrap();
            let TcpServerSetupResult::ConnectionTask(task) = result else {
                panic!("HTTP/2 connection must return an owned connection task")
            };
            task.await.unwrap();
        });

        let (mut send_request, connection) =
            h2::client::handshake(TestStream(client)).await.unwrap();
        let connection_task = tokio::spawn(async move { connection.await.unwrap() });

        let request = Request::builder()
            .method(Method::PUT)
            .uri("https://other.example/")
            .body(())
            .unwrap();
        let (response, mut send) = send_request.send_request(request, false).unwrap();
        send.send_data(Bytes::from_static(b"PING"), true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        drop(send_request);
        connection_task.abort();
        let _ = connection_task.await;
        server_task.await.unwrap();
        assert!(captured.lock().is_empty());
    }
}
