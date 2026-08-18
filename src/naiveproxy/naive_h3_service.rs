use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::{Method, Response, StatusCode};
use log::{debug, error};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, split};
use tokio::task::JoinHandle;

use crate::address::NetLocation;
use crate::async_stream::{AsyncPing, AsyncStream};
use crate::client_proxy_selector::ClientProxySelector;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::AuthenticatedUser;
use crate::tls_server_handler::NaiveConfig;

use super::naive_hyper_service::{
    NaiveServiceConfig, NaiveStreamContext, handle_naive_stream, parse_authority,
};
use super::naive_padding_stream::{
    NaivePaddingStream, PaddingDirection, PaddingType, PaddingTypeRequest,
    add_server_padding_response_headers, negotiate_server_padding,
};

const CLOSE_ERR_CODE_OK: u32 = 0x100;
const H3_TUNNEL_BUFFER_SIZE: usize = 256 * 1024;
const H3_DATA_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NaiveQuicCongestionControl {
    Cubic,
    NewReno,
    Bbr,
}

struct NaiveH3TunnelStream(DuplexStream);

impl AsyncRead for NaiveH3TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for NaiveH3TunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl AsyncPing for NaiveH3TunnelStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

// SAFETY: Each tunnel stream is owned by one NaiveProxy request task. The Sync
// bound comes from AsyncStream, but the value is not shared concurrently.
unsafe impl Sync for NaiveH3TunnelStream {}

impl AsyncStream for NaiveH3TunnelStream {}

fn parse_naive_quic_congestion_control(
    value: Option<&str>,
) -> io::Result<NaiveQuicCongestionControl> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(NaiveQuicCongestionControl::Cubic);
    };
    match value.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
        "cubic" => Ok(NaiveQuicCongestionControl::Cubic),
        "newreno" | "reno" => Ok(NaiveQuicCongestionControl::NewReno),
        "bbr" | "bbrstandard" => Ok(NaiveQuicCongestionControl::Bbr),
        "bbr2" | "bbr2variant" => {
            log::warn!(
                "naiveproxy quic_congestion_control `{value}` is mapped to Quinn BBR; native BBR2 is not exposed by the current backend"
            );
            Ok(NaiveQuicCongestionControl::Bbr)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported naiveproxy quic_congestion_control `{value}`"),
        )),
    }
}

pub(crate) fn validate_naive_quic_congestion_control(value: Option<&str>) -> io::Result<()> {
    parse_naive_quic_congestion_control(value).map(|_| ())
}

fn apply_naive_quic_congestion_control(
    transport: &mut quinn::TransportConfig,
    congestion_control: NaiveQuicCongestionControl,
) {
    match congestion_control {
        NaiveQuicCongestionControl::Cubic => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        }
        NaiveQuicCongestionControl::NewReno => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
        }
        NaiveQuicCongestionControl::Bbr => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_naive_h3_server(
    bind_address: SocketAddr,
    quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
    naive_cfg: NaiveConfig,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    num_endpoints: usize,
    congestion_control: Option<String>,
) -> io::Result<Vec<JoinHandle<()>>> {
    let congestion_control = parse_naive_quic_congestion_control(congestion_control.as_deref())?;
    let mut endpoints = Vec::with_capacity(num_endpoints);

    for _ in 0..num_endpoints {
        let mut server_config = quinn::ServerConfig::with_crypto(quic_server_config.clone());
        let idle_timeout = Duration::from_secs(60).try_into().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid naiveproxy H3 idle timeout: {e}"),
            )
        })?;
        let transport = Arc::get_mut(&mut server_config.transport)
            .ok_or_else(|| io::Error::other("failed to configure NaiveProxy H3 transport"))?;
        apply_naive_quic_congestion_control(transport, congestion_control);
        transport
            .max_concurrent_bidi_streams(4096_u32.into())
            .max_concurrent_uni_streams(1024_u32.into())
            .max_idle_timeout(Some(idle_timeout))
            .keep_alive_interval(Some(Duration::from_secs(15)))
            .send_window(16 * 1024 * 1024)
            .receive_window((20u32 * 1024 * 1024).into())
            .stream_receive_window((8u32 * 1024 * 1024).into())
            .initial_mtu(1200)
            .min_mtu(1200)
            .mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()))
            .enable_segmentation_offload(true)
            .initial_rtt(Duration::from_millis(100));

        let socket2_socket = crate::socket_util::new_socket2_udp_socket_with_buffer_size(
            bind_address.is_ipv6(),
            None,
            Some(bind_address),
            true,
            Some(8_625_000),
        )?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket2_socket.into(),
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoints.push(endpoint);
    }

    let service_config = Arc::new(NaiveServiceConfig {
        users: naive_cfg.users,
        fallback_path: naive_cfg.fallback_path,
        resolver,
        proxy_selector: client_proxy_selector,
        outbound_dispatcher: naive_cfg.outbound_dispatcher,
        peer_addr: None,
        udp_enabled: naive_cfg.udp_enabled,
        padding_enabled: naive_cfg.padding_enabled,
        connection_tasks: Arc::new(tokio::sync::Mutex::new(tokio::task::JoinSet::new())),
    });

    let mut join_handles = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let service_config = service_config.clone();
        let join_handle = tokio::spawn(async move {
            while let Some(conn) = endpoint.accept().await {
                let service_config = service_config.clone();
                tokio::spawn(async move {
                    if let Err(e) = process_connection(conn, service_config).await {
                        debug!("NaiveProxy H3 connection error: {e}");
                    }
                });
            }
        });
        join_handles.push(join_handle);
    }

    Ok(join_handles)
}

async fn process_connection(
    conn: quinn::Incoming,
    service_config: Arc<NaiveServiceConfig>,
) -> io::Result<()> {
    let connection = conn.await?;
    let peer_addr = connection.remote_address();
    let h3_quinn_connection = h3_quinn::Connection::new(connection.clone());
    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
        h3::server::Connection::new(h3_quinn_connection)
            .await
            .map_err(|e| io::Error::other(format!("H3 connection setup failed: {e}")))?;

    loop {
        match h3_conn
            .accept()
            .await
            .map_err(|e| io::Error::other(format!("H3 accept failed: {e}")))?
        {
            Some(resolver) => {
                let service_config = service_config.clone();
                tokio::spawn(async move {
                    let Ok((req, stream)) = resolver.resolve_request().await.map_err(|err| {
                        io::Error::other(format!("failed to resolve H3 request: {err}"))
                    }) else {
                        return;
                    };
                    if let Err(e) = handle_h3_request(req, stream, service_config, peer_addr).await
                    {
                        debug!("NaiveProxy H3 request error: {e}");
                    }
                });
            }
            None => return Ok(()),
        }
    }
}

async fn handle_h3_request(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    config: Arc<NaiveServiceConfig>,
    peer_addr: SocketAddr,
) -> io::Result<()> {
    match *req.method() {
        Method::CONNECT => handle_h3_connect(req, stream, config, peer_addr).await,
        Method::GET | Method::HEAD => {
            let is_head = req.method() == Method::HEAD;
            serve_h3_fallback(stream, req.uri().path(), &config.fallback_path, is_head).await
        }
        Method::OPTIONS => {
            let response = Response::builder()
                .status(StatusCode::OK)
                .header("allow", "GET, HEAD, OPTIONS")
                .body(())
                .unwrap();
            stream
                .send_response(response)
                .await
                .map_err(h3_stream_error)?;
            stream.finish().await.map_err(h3_stream_error)
        }
        _ => {
            let response = Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(())
                .unwrap();
            stream
                .send_response(response)
                .await
                .map_err(h3_stream_error)?;
            stream.finish().await.map_err(h3_stream_error)
        }
    }
}

async fn handle_h3_connect(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    config: Arc<NaiveServiceConfig>,
    peer_addr: SocketAddr,
) -> io::Result<()> {
    let has_padding = req.headers().get("padding").is_some();

    // Borrow the table only for validation, copying out this user's identity;
    // see `SharedUsers` for why the borrow must not outlive the handshake.
    let users = config.users.load();
    let validated_user = match req.headers().get("proxy-authorization") {
        Some(auth) => match auth.to_str().ok().and_then(|s| users.validate(s)) {
            Some(user) => user,
            None => return send_h3_status(stream, StatusCode::BAD_REQUEST).await,
        },
        None => return send_h3_status(stream, StatusCode::BAD_REQUEST).await,
    };
    let username = validated_user.name.to_string();
    let authenticated_user = validated_user.authenticated_user.cloned();

    let destination = match req
        .uri()
        .authority()
        .map(|authority| parse_authority(authority.as_str()))
    {
        Some(Ok(destination)) => destination,
        _ => return send_h3_status(stream, StatusCode::BAD_REQUEST).await,
    };

    let padding_type_request = match req.headers().get("padding-type-request") {
        Some(types) => match types.to_str() {
            Ok(types) => PaddingTypeRequest::Value(types),
            Err(_) => PaddingTypeRequest::Malformed,
        },
        None => PaddingTypeRequest::Absent,
    };
    let padding_type =
        negotiate_server_padding(config.padding_enabled, has_padding, padding_type_request);

    let response = add_server_padding_response_headers(
        Response::builder().status(StatusCode::OK),
        padding_type,
    );
    stream
        .send_response(response.body(()).unwrap())
        .await
        .map_err(h3_stream_error)?;

    debug!("[{username}] NaiveProxy H3 CONNECT to {destination}");

    let (send_stream, recv_stream) = stream.split();
    tokio::spawn(async move {
        run_h3_tunnel(
            send_stream,
            recv_stream,
            destination,
            config,
            peer_addr,
            username,
            authenticated_user,
            padding_type,
        )
        .await;
    });

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_h3_tunnel(
    mut send_stream: h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    mut recv_stream: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
    destination: NetLocation,
    config: Arc<NaiveServiceConfig>,
    peer_addr: SocketAddr,
    username: String,
    authenticated_user: Option<AuthenticatedUser>,
    padding_type: PaddingType,
) {
    let (handler_stream, pump_stream) = tokio::io::duplex(H3_TUNNEL_BUFFER_SIZE);
    let (mut pump_reader, mut pump_writer) = split(pump_stream);

    let h3_to_handler = tokio::spawn(async move {
        loop {
            let data = recv_stream.recv_data().await.map_err(h3_stream_error)?;
            let Some(mut data) = data else {
                pump_writer.shutdown().await?;
                return Ok::<(), io::Error>(());
            };
            while data.has_remaining() {
                let chunk = data.copy_to_bytes(data.remaining().min(H3_DATA_CHUNK_SIZE));
                pump_writer.write_all(&chunk).await?;
            }
        }
    });

    let handler_to_h3 = tokio::spawn(async move {
        let mut buf = vec![0; H3_DATA_CHUNK_SIZE];
        loop {
            let n = pump_reader.read(&mut buf).await?;
            if n == 0 {
                send_stream.finish().await.map_err(h3_stream_error)?;
                return Ok::<(), io::Error>(());
            }
            send_stream
                .send_data(Bytes::copy_from_slice(&buf[..n]))
                .await
                .map_err(h3_stream_error)?;
        }
    });

    let handler = tokio::spawn(async move {
        let stream = NaiveH3TunnelStream(handler_stream);
        let stream_context = NaiveStreamContext {
            resolver: config.resolver.clone(),
            proxy_selector: config.proxy_selector.clone(),
            outbound_dispatcher: config.outbound_dispatcher.clone(),
            udp_enabled: config.udp_enabled,
            user_name: username,
            authenticated_user,
            peer_addr: Some(peer_addr),
        };

        if padding_type != PaddingType::None {
            let stream = NaivePaddingStream::new(stream, PaddingDirection::Server, padding_type);
            handle_naive_stream(stream, destination, stream_context).await
        } else {
            handle_naive_stream(stream, destination, stream_context).await
        }
    });

    let (h3_to_handler_result, handler_to_h3_result, handler_result) =
        tokio::join!(h3_to_handler, handler_to_h3, handler);

    for result in [h3_to_handler_result, handler_to_h3_result] {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => debug!("NaiveProxy H3 tunnel pump error: {e}"),
            Err(e) => debug!("NaiveProxy H3 tunnel pump task failed: {e}"),
        }
    }
    match handler_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => debug!("NaiveProxy H3 tunnel error: {e}"),
        Err(e) => debug!("NaiveProxy H3 tunnel task failed: {e}"),
    }
}

async fn serve_h3_fallback(
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    uri_path: &str,
    fallback_path: &Option<PathBuf>,
    is_head: bool,
) -> io::Result<()> {
    let Some(base_path) = fallback_path else {
        return send_h3_status(stream, StatusCode::UNAUTHORIZED).await;
    };

    let request_path = uri_path.trim_start_matches('/');
    let mut file_path = base_path.clone();
    for component in std::path::Path::new(request_path).components() {
        match component {
            std::path::Component::Normal(c) => file_path.push(c),
            std::path::Component::ParentDir => {
                return send_h3_status(stream, StatusCode::FORBIDDEN).await;
            }
            _ => {}
        }
    }
    if file_path.is_dir() {
        file_path.push("index.html");
    }

    match tokio::fs::read(&file_path).await {
        Ok(contents) => {
            let mime = mime_guess::from_path(&file_path)
                .first_or_octet_stream()
                .to_string();
            let response = Response::builder()
                .status(StatusCode::OK)
                .header("content-type", mime)
                .header("content-length", contents.len())
                .body(())
                .unwrap();
            stream
                .send_response(response)
                .await
                .map_err(h3_stream_error)?;
            if !is_head && !contents.is_empty() {
                stream
                    .send_data(Bytes::from(contents))
                    .await
                    .map_err(h3_stream_error)?;
            }
            stream.finish().await.map_err(h3_stream_error)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            send_h3_status(stream, StatusCode::NOT_FOUND).await
        }
        Err(e) => {
            error!(
                "NaiveProxy H3 fallback failed to read {}: {e}",
                file_path.display()
            );
            send_h3_status(stream, StatusCode::INTERNAL_SERVER_ERROR).await
        }
    }
}

async fn send_h3_status(
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
) -> io::Result<()> {
    let response = Response::builder().status(status).body(()).unwrap();
    stream
        .send_response(response)
        .await
        .map_err(h3_stream_error)?;
    stream.finish().await.map_err(h3_stream_error)
}

fn h3_stream_error(error: h3::error::StreamError) -> io::Error {
    io::Error::other(format!("H3 stream error: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_naive_quic_congestion_control_aliases() {
        assert_eq!(
            parse_naive_quic_congestion_control(None).unwrap(),
            NaiveQuicCongestionControl::Cubic
        );
        assert_eq!(
            parse_naive_quic_congestion_control(Some("cubic")).unwrap(),
            NaiveQuicCongestionControl::Cubic
        );
        assert_eq!(
            parse_naive_quic_congestion_control(Some("new_reno")).unwrap(),
            NaiveQuicCongestionControl::NewReno
        );
        assert_eq!(
            parse_naive_quic_congestion_control(Some("reno")).unwrap(),
            NaiveQuicCongestionControl::NewReno
        );
        assert_eq!(
            parse_naive_quic_congestion_control(Some("bbr")).unwrap(),
            NaiveQuicCongestionControl::Bbr
        );
        assert_eq!(
            parse_naive_quic_congestion_control(Some("bbr_standard")).unwrap(),
            NaiveQuicCongestionControl::Bbr
        );
    }

    #[test]
    fn maps_bbr2_naive_quic_congestion_control_to_bbr() {
        assert_eq!(
            parse_naive_quic_congestion_control(Some("bbr2")).unwrap(),
            NaiveQuicCongestionControl::Bbr
        );
        assert_eq!(
            parse_naive_quic_congestion_control(Some("bbr2_variant")).unwrap(),
            NaiveQuicCongestionControl::Bbr
        );
    }

    #[test]
    fn rejects_unsupported_naive_quic_congestion_control() {
        let err = parse_naive_quic_congestion_control(Some("invalid-cc")).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported naiveproxy quic_congestion_control `invalid-cc`")
        );
    }
}
