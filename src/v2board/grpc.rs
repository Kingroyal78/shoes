use std::collections::HashSet;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use h2::server::SendResponse;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

const GRPC_FRAME_HEADER_LEN: usize = 5;
const GRPC_HUNK_TAG: u8 = 0x0a;
const GRPC_HUNK_TAG_LEN: usize = 1;
const MAX_VARINT_LEN: usize = 10;
const MAX_GRPC_HUNK_FRAME_OVERHEAD: usize =
    GRPC_FRAME_HEADER_LEN + GRPC_HUNK_TAG_LEN + MAX_VARINT_LEN;
const MAX_GRPC_FRAME_LEN: usize = 16 * 1024 * 1024;
const MAX_WRITE_PAYLOAD_LEN: usize = 16 * 1024;

#[derive(Debug)]
pub struct GrpcServerHandler {
    service_name: Option<String>,
    authority: Option<String>,
    handler: Box<dyn TcpServerHandler>,
}

impl GrpcServerHandler {
    pub fn new(
        service_name: Option<String>,
        authority: Option<String>,
        handler: Box<dyn TcpServerHandler>,
    ) -> Self {
        Self {
            service_name: service_name.and_then(non_empty_trimmed),
            authority: authority.and_then(non_empty_trimmed),
            handler,
        }
    }
}

#[async_trait]
impl TcpServerHandler for GrpcServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_peer_addr(server_stream, None)
            .await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        server_stream: Box<dyn AsyncStream>,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> io::Result<TcpServerSetupResult> {
        let mut connection = h2::server::handshake(server_stream)
            .await
            .map_err(h2_error)?;
        let (request, mut respond) = match connection.accept().await {
            Some(Ok(parts)) => parts,
            Some(Err(e)) => return Err(h2_error(e)),
            None => return invalid("grpc h2 connection closed before request"),
        };

        if let Err(e) = validate_request(
            &request,
            self.service_name.as_deref(),
            self.authority.as_deref(),
        ) {
            send_error_response(respond, StatusCode::BAD_REQUEST)?;
            spawn_connection_driver(connection);
            return Err(e);
        }

        let (request_parts, recv) = request.into_parts();
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc")
            .body(())
            .map_err(|e| invalid_error(e.to_string()))?;
        let send = respond.send_response(response, false).map_err(h2_error)?;
        spawn_connection_driver(connection);

        log::debug!(
            "accepted v2board grpc request path={}",
            request_parts.uri.path()
        );

        let grpc_stream = Box::new(GrpcTransportStream::new(send, recv));
        let mut setup_result = self
            .handler
            .setup_server_stream_with_peer_addr(grpc_stream, peer_addr)
            .await?;
        setup_result.set_need_initial_flush(true);
        Ok(setup_result)
    }
}

fn spawn_connection_driver<T>(mut connection: h2::server::Connection<T, Bytes>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        while let Some(result) = connection.accept().await {
            match result {
                Ok((_request, mut respond)) => {
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                }
                Err(e) => {
                    log::debug!("grpc h2 connection driver stopped: {e}");
                    break;
                }
            }
        }
    });
}

struct GrpcTransportStream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    h2_buf: Bytes,
    recv_buf: Bytes,
    frame_buf: BytesMut,
    header: [u8; GRPC_FRAME_HEADER_LEN],
    header_len: usize,
    frame_remaining: usize,
    shutdown_sent: bool,
}

impl GrpcTransportStream {
    fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            h2_buf: Bytes::new(),
            recv_buf: Bytes::new(),
            frame_buf: BytesMut::new(),
            header: [0; GRPC_FRAME_HEADER_LEN],
            header_len: 0,
            frame_remaining: 0,
            shutdown_sent: false,
        }
    }

    fn poll_next_h2_data(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if !self.h2_buf.is_empty() {
            return Poll::Ready(Ok(true));
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
                    self.h2_buf = data;
                    return Poll::Ready(Ok(true));
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(h2_error(e))),
                Poll::Ready(None) => return Poll::Ready(Ok(false)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_next_data(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if !self.recv_buf.is_empty() {
            return Poll::Ready(Ok(true));
        }

        loop {
            if self.frame_remaining > 0 {
                match self.poll_next_h2_data(cx) {
                    Poll::Ready(Ok(true)) => {
                        let to_copy = self.frame_remaining.min(self.h2_buf.len());
                        self.frame_buf.extend_from_slice(&self.h2_buf[..to_copy]);
                        self.h2_buf = self.h2_buf.slice(to_copy..);
                        self.frame_remaining -= to_copy;

                        if self.frame_remaining > 0 {
                            continue;
                        }

                        let decoded = decode_grpc_transport_payload(&self.frame_buf)?;
                        self.frame_buf.clear();
                        if decoded.is_empty() {
                            continue;
                        }
                        self.recv_buf = decoded;
                        return Poll::Ready(Ok(true));
                    }
                    Poll::Ready(Ok(false)) => {
                        self.frame_buf.clear();
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "grpc stream ended inside a frame",
                        )));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            while self.header_len < GRPC_FRAME_HEADER_LEN {
                match self.poll_next_h2_data(cx) {
                    Poll::Ready(Ok(true)) => {
                        let to_copy =
                            (GRPC_FRAME_HEADER_LEN - self.header_len).min(self.h2_buf.len());
                        let header_len = self.header_len;
                        self.header[header_len..header_len + to_copy]
                            .copy_from_slice(&self.h2_buf[..to_copy]);
                        self.header_len += to_copy;
                        self.h2_buf = self.h2_buf.slice(to_copy..);
                    }
                    Poll::Ready(Ok(false)) => {
                        if self.header_len == 0 {
                            return Poll::Ready(Ok(false));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "grpc stream ended inside a frame header",
                        )));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            self.parse_header()?;
            if self.frame_remaining == 0 {
                continue;
            }
            self.frame_buf.clear();
            self.frame_buf.reserve(self.frame_remaining);
        }
    }

    fn parse_header(&mut self) -> io::Result<()> {
        let header = GrpcFrameHeader::parse(&self.header)?;
        if header.compressed {
            return invalid("grpc compressed frames are not supported");
        }
        if header.len > MAX_GRPC_FRAME_LEN {
            return invalid(format!(
                "grpc frame length {} exceeds limit {}",
                header.len, MAX_GRPC_FRAME_LEN
            ));
        }
        self.frame_remaining = header.len;
        self.header_len = 0;
        Ok(())
    }
}

impl AsyncRead for GrpcTransportStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        match self.poll_next_data(cx) {
            Poll::Ready(Ok(true)) => {
                let to_copy = self.recv_buf.len().min(buf.remaining());
                buf.put_slice(&self.recv_buf[..to_copy]);
                self.recv_buf = self.recv_buf.slice(to_copy..);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(false)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for GrpcTransportStream {
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
                "grpc stream is shut down",
            )));
        }

        let available = if self.send.capacity() > MAX_GRPC_HUNK_FRAME_OVERHEAD {
            self.send.capacity()
        } else {
            self.send.reserve_capacity(
                (MAX_WRITE_PAYLOAD_LEN + MAX_GRPC_HUNK_FRAME_OVERHEAD)
                    .min(buf.len() + MAX_GRPC_HUNK_FRAME_OVERHEAD),
            );
            match self.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(capacity))) => capacity,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(h2_error(e))),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "grpc h2 send stream closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        };

        if available <= MAX_GRPC_HUNK_FRAME_OVERHEAD {
            self.send
                .reserve_capacity(MAX_WRITE_PAYLOAD_LEN + MAX_GRPC_HUNK_FRAME_OVERHEAD);
            return Poll::Pending;
        }

        let payload_len = buf
            .len()
            .min(MAX_WRITE_PAYLOAD_LEN)
            .min(available - MAX_GRPC_HUNK_FRAME_OVERHEAD);
        let hunk = encode_hunk_payload(&buf[..payload_len]);
        let frame = encode_grpc_frame(&hunk)?;
        self.send.send_data(frame, false).map_err(h2_error)?;
        Poll::Ready(Ok(payload_len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown_sent {
            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", HeaderValue::from_static("0"));
            self.send.send_trailers(trailers).map_err(h2_error)?;
            self.shutdown_sent = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for GrpcTransportStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl Unpin for GrpcTransportStream {}

impl AsyncStream for GrpcTransportStream {}

impl fmt::Debug for GrpcTransportStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrpcTransportStream")
            .field("header_len", &self.header_len)
            .field("frame_remaining", &self.frame_remaining)
            .field("shutdown_sent", &self.shutdown_sent)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GrpcFrameHeader {
    compressed: bool,
    len: usize,
}

impl GrpcFrameHeader {
    fn parse(header: &[u8]) -> io::Result<Self> {
        if header.len() != GRPC_FRAME_HEADER_LEN {
            return invalid(format!(
                "grpc frame header length must be {GRPC_FRAME_HEADER_LEN}"
            ));
        }
        let compressed = match header[0] {
            0 => false,
            1 => true,
            value => return invalid(format!("grpc frame has invalid compressed flag {value}")),
        };
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        Ok(Self { compressed, len })
    }
}

fn encode_grpc_frame(payload: &[u8]) -> io::Result<Bytes> {
    let len = u32::try_from(payload.len()).map_err(|_| {
        invalid_error(format!(
            "grpc payload length {} exceeds u32 frame length",
            payload.len()
        ))
    })?;
    let mut frame = BytesMut::with_capacity(GRPC_FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&[0]);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame.freeze())
}

fn encode_hunk_payload(payload: &[u8]) -> Bytes {
    let mut hunk =
        BytesMut::with_capacity(GRPC_HUNK_TAG_LEN + varint_len(payload.len()) + payload.len());
    hunk.extend_from_slice(&[GRPC_HUNK_TAG]);
    write_varint(payload.len(), &mut hunk);
    hunk.extend_from_slice(payload);
    hunk.freeze()
}

fn decode_grpc_transport_payload(payload: &[u8]) -> io::Result<Bytes> {
    if payload.is_empty() {
        return Ok(Bytes::new());
    }
    if payload[0] != GRPC_HUNK_TAG {
        return Ok(Bytes::copy_from_slice(payload));
    }

    let (data_len, varint_len) = read_varint(&payload[1..])?;
    let data_start = 1 + varint_len;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or_else(|| invalid_error("grpc hunk length overflow"))?;
    if data_end != payload.len() {
        return invalid(format!(
            "grpc hunk length mismatch: header says {}, buffer has {} payload bytes",
            data_len,
            payload.len().saturating_sub(data_start)
        ));
    }

    Ok(Bytes::copy_from_slice(&payload[data_start..data_end]))
}

fn write_varint(mut value: usize, buf: &mut BytesMut) {
    while value >= 0x80 {
        buf.extend_from_slice(&[((value as u8) & 0x7f) | 0x80]);
        value >>= 7;
    }
    buf.extend_from_slice(&[value as u8]);
}

fn read_varint(input: &[u8]) -> io::Result<(usize, usize)> {
    let mut value = 0u64;
    for (index, byte) in input.iter().copied().enumerate() {
        if index >= MAX_VARINT_LEN {
            return invalid("grpc hunk varint is too long");
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte < 0x80 {
            let value = usize::try_from(value)
                .map_err(|_| invalid_error("grpc hunk length exceeds usize"))?;
            return Ok((value, index + 1));
        }
    }
    invalid("grpc hunk varint is incomplete")
}

fn varint_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        len += 1;
        value >>= 7;
    }
    len
}

fn decode_complete_grpc_frame(frame: &[u8]) -> io::Result<&[u8]> {
    if frame.len() < GRPC_FRAME_HEADER_LEN {
        return invalid("grpc frame is shorter than header");
    }
    let header = GrpcFrameHeader::parse(&frame[..GRPC_FRAME_HEADER_LEN])?;
    if header.compressed {
        return invalid("grpc compressed frames are not supported");
    }
    let end = GRPC_FRAME_HEADER_LEN + header.len;
    if frame.len() != end {
        return invalid(format!(
            "grpc frame length mismatch: header says {}, buffer has {} payload bytes",
            header.len,
            frame.len().saturating_sub(GRPC_FRAME_HEADER_LEN)
        ));
    }
    Ok(&frame[GRPC_FRAME_HEADER_LEN..end])
}

fn validate_request<B>(
    request: &Request<B>,
    service_name: Option<&str>,
    authority: Option<&str>,
) -> io::Result<()> {
    if request.method() != Method::POST {
        return invalid(format!("grpc bad method `{}`", request.method()));
    }
    let path = request.uri().path();
    let accepted_paths = accepted_paths(service_name);
    if !accepted_paths.contains(path) {
        return invalid(format!(
            "grpc bad path `{path}` expected one of {:?}",
            accepted_paths
        ));
    }
    if let Some(expected_authority) = authority {
        let actual_authority = request_authority(request);
        if !matches!(actual_authority.as_deref(), Some(actual) if actual.eq_ignore_ascii_case(expected_authority))
        {
            return invalid(format!(
                "grpc bad authority, expected `{expected_authority}`"
            ));
        }
    }
    let content_type = header_to_str(request.headers(), "content-type")
        .ok_or_else(|| invalid_error("grpc missing content-type"))?;
    if !is_grpc_content_type(content_type) {
        return invalid(format!("grpc bad content-type `{content_type}`"));
    }
    Ok(())
}

fn accepted_paths(service_name: Option<&str>) -> HashSet<String> {
    let service = service_name
        .and_then(non_empty_trimmed_str)
        .unwrap_or_default();
    let mut paths = HashSet::new();
    if service.is_empty() {
        paths.insert("/Tun".to_string());
        paths.insert("/".to_string());
        return paths;
    }

    paths.insert(format!("/{service}"));
    if service.ends_with("/Tun") {
        paths.insert(format!("/{service}"));
    } else {
        paths.insert(format!("/{service}/Tun"));
    }
    paths
}

fn request_authority<B>(request: &Request<B>) -> Option<String> {
    request
        .uri()
        .authority()
        .map(|authority| authority.as_str().to_string())
        .or_else(|| header_to_str(request.headers(), "host").map(ToOwned::to_owned))
}

fn is_grpc_content_type(value: &str) -> bool {
    let media_type = value.split(';').next().unwrap_or("").trim();
    media_type == "application/grpc" || media_type.starts_with("application/grpc+")
}

fn header_to_str<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers.get(key).and_then(|value| value.to_str().ok())
}

fn send_error_response<T>(mut respond: SendResponse<T>, status: StatusCode) -> io::Result<()>
where
    T: bytes::Buf,
{
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

fn non_empty_trimmed(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn non_empty_trimmed_str(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('/');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn h2_error(e: h2::Error) -> io::Error {
    io::Error::other(format!("grpc h2 error: {e}"))
}

fn invalid<T>(msg: impl Into<String>) -> io::Result<T> {
    Err(invalid_error(msg))
}

fn invalid_error(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: Method, uri: &str, content_type: &str) -> Request<()> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", content_type)
            .body(())
            .unwrap()
    }

    #[test]
    fn validates_grpc_path_headers_and_authority() {
        let request = request(
            Method::POST,
            "https://example.com/demo/Tun",
            "application/grpc",
        );
        validate_request(&request, Some("demo"), Some("example.com")).unwrap();
    }

    #[test]
    fn accepts_compatible_service_name_path() {
        let request = request(Method::POST, "/demo", "application/grpc+proto");
        validate_request(&request, Some("demo"), None).unwrap();
    }

    #[test]
    fn rejects_bad_method_path_authority_and_content_type() {
        let bad_method = request(Method::GET, "/demo/Tun", "application/grpc");
        assert!(validate_request(&bad_method, Some("demo"), None).is_err());

        let bad_path = request(Method::POST, "/other/Tun", "application/grpc");
        assert!(validate_request(&bad_path, Some("demo"), None).is_err());

        let bad_authority = request(
            Method::POST,
            "https://wrong.test/demo/Tun",
            "application/grpc",
        );
        assert!(validate_request(&bad_authority, Some("demo"), Some("example.com")).is_err());

        let bad_content_type = request(Method::POST, "/demo/Tun", "application/octet-stream");
        assert!(validate_request(&bad_content_type, Some("demo"), None).is_err());
    }

    #[test]
    fn encodes_and_decodes_grpc_frames() {
        let frame = encode_grpc_frame(b"hello").unwrap();
        assert_eq!(&frame[..5], &[0, 0, 0, 0, 5]);
        assert_eq!(decode_complete_grpc_frame(&frame).unwrap(), b"hello");
    }

    #[test]
    fn encodes_and_decodes_v2ray_grpc_hunks() {
        let hunk = encode_hunk_payload(b"hello");

        assert_eq!(&hunk[..2], &[GRPC_HUNK_TAG, 5]);
        assert_eq!(
            decode_grpc_transport_payload(&hunk).unwrap(),
            Bytes::from_static(b"hello")
        );
    }

    #[test]
    fn keeps_raw_grpc_transport_payloads_for_compatibility() {
        assert_eq!(
            decode_grpc_transport_payload(b"raw-data").unwrap(),
            Bytes::from_static(b"raw-data")
        );
    }

    #[test]
    fn rejects_malformed_v2ray_grpc_hunks() {
        assert!(decode_grpc_transport_payload(&[GRPC_HUNK_TAG, 5, b'h']).is_err());
        assert!(decode_grpc_transport_payload(&[GRPC_HUNK_TAG, 0x80]).is_err());
    }

    #[test]
    fn rejects_compressed_and_mismatched_frames() {
        let mut compressed = encode_grpc_frame(b"hello").unwrap().to_vec();
        compressed[0] = 1;
        assert!(decode_complete_grpc_frame(&compressed).is_err());

        let mut short = encode_grpc_frame(b"hello").unwrap().to_vec();
        short.pop();
        assert!(decode_complete_grpc_frame(&short).is_err());
    }
}
