use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode, Version};
use rand::RngExt;
use rustls::pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpSocket, TcpStream, lookup_host};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::Url;

const NUM_FIRST_PADDINGS: usize = 8;
const PADDING_HEADER_SIZE: usize = 3;
const NONINDEX_CHARS: &[u8] = b"!\"#$&'()*+,;<>?@X";
const UOT_V2_MAGIC_AUTHORITY: &str = "sp.v2.udp-over-tcp.arpa:0";

#[derive(Debug)]
struct Args {
    proxy_host: String,
    proxy_port: u16,
    server_name: String,
    ca_cert: PathBuf,
    username: String,
    password: String,
    workload: Workload,
    bind: Option<IpAddr>,
    http3: bool,
    padding: bool,
    connect_timeout: Duration,
    max_time: Duration,
}

#[derive(Debug)]
enum Workload {
    Http {
        url: Url,
        output: PathBuf,
    },
    UdpEcho {
        target: UdpTarget,
        payload_size: usize,
    },
}

#[derive(Debug)]
struct UdpTarget {
    host: String,
    port: u16,
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let args = match Args::parse() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}");
            usage();
            std::process::exit(2);
        }
    };

    match timeout(args.max_time, run(args)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("naiveproxy e2e client failed: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("naiveproxy e2e client timed out");
            std::process::exit(1);
        }
    }
}

async fn run(args: Args) -> io::Result<()> {
    if args.http3 {
        return if matches!(&args.workload, Workload::UdpEcho { .. }) {
            run_udp_echo_h3(args).await
        } else {
            run_h3(args).await
        };
    }

    if matches!(&args.workload, Workload::UdpEcho { .. }) {
        run_udp_echo_h2(args).await
    } else {
        run_h2_http(args).await
    }
}

async fn run_h2_http(args: Args) -> io::Result<()> {
    let tcp = timeout(args.connect_timeout, connect_tcp(&args))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy TCP connect timed out"))??;
    let tls = connect_tls(tcp, &args).await?;

    let (send_request, connection) = h2::client::Builder::new()
        .initial_window_size(256 * 1024)
        .initial_connection_window_size(256 * 1024)
        .max_frame_size((1 << 24) - 1)
        .max_concurrent_streams(1024)
        .handshake(tls)
        .await
        .map_err(|e| io::Error::other(format!("H2 handshake failed: {e}")))?;

    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    let Workload::Http { url, output } = &args.workload else {
        unreachable!("run_h2_http called for non-HTTP workload");
    };

    let authority = target_authority(url)?;
    let request = naive_connect_request(&args, &authority, Version::HTTP_2)?;

    let mut send_request = send_request
        .ready()
        .await
        .map_err(|e| io::Error::other(format!("H2 client not ready: {e}")))?;

    let (response_future, mut send_stream) = send_request
        .send_request(request, false)
        .map_err(|e| io::Error::other(format!("CONNECT request failed: {e}")))?;
    let mut response = response_future
        .await
        .map_err(|e| io::Error::other(format!("CONNECT response failed: {e}")))?;

    if response.status() != http::StatusCode::OK {
        driver.abort();
        return Err(io::Error::other(format!(
            "CONNECT failed with status {}",
            response.status()
        )));
    }

    let response_padding = response_padding_enabled(&args, response.headers())?;
    let request_bytes = encode_tunnel_payload(response_padding, &build_http_request(url)?);
    send_stream
        .send_data(Bytes::from(request_bytes), true)
        .map_err(|e| io::Error::other(format!("failed to write request body: {e}")))?;

    let mut decoder = PaddingDecoder::new(response_padding);
    let mut raw_response = Vec::new();
    let body_stream = response.body_mut();
    while let Some(chunk) = body_stream.data().await {
        let chunk = chunk.map_err(|e| io::Error::other(format!("failed to read DATA: {e}")))?;
        body_stream
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(|e| io::Error::other(format!("failed to release H2 capacity: {e}")))?;
        decoder.push(&chunk, &mut raw_response);
        if let Some(body) = try_extract_complete_http_body(&raw_response)? {
            write_output(output, body).await?;
            driver.abort();
            return Ok(());
        }
    }
    decoder.finish(&mut raw_response)?;
    driver.abort();

    let body = extract_http_body(&raw_response)?;
    write_output(output, body).await?;

    Ok(())
}

async fn run_h3(args: Args) -> io::Result<()> {
    let remote_addr = resolve_proxy_addr(&args).await?;
    let local_addr = SocketAddr::new(
        args.bind.unwrap_or_else(|| {
            if remote_addr.is_ipv4() {
                IpAddr::from([0, 0, 0, 0])
            } else {
                IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            }
        }),
        0,
    );
    let mut endpoint = quinn::Endpoint::client(local_addr)?;
    endpoint.set_default_client_config(quic_client_config(&args)?);

    let connection = timeout(
        args.connect_timeout,
        endpoint
            .connect(remote_addr, &args.server_name)
            .map_err(|e| io::Error::other(format!("QUIC connect setup failed: {e}")))?,
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy QUIC connect timed out"))?
    .map_err(|e| io::Error::other(format!("QUIC connect failed: {e}")))?;

    let quic = h3_quinn::Connection::new(connection);
    let (mut h3_driver, mut send_request) = h3::client::new(quic)
        .await
        .map_err(|e| io::Error::other(format!("H3 client setup failed: {e}")))?;
    let driver = tokio::spawn(async move {
        let _ = h3_driver.wait_idle().await;
    });

    let Workload::Http { url, output } = &args.workload else {
        unreachable!("run_h3 called for non-HTTP workload");
    };

    let authority = target_authority(url)?;
    let request = naive_connect_request(&args, &authority, Version::HTTP_3)?;

    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|e| io::Error::other(format!("H3 CONNECT request failed: {e}")))?;
    let response = stream
        .recv_response()
        .await
        .map_err(|e| io::Error::other(format!("H3 CONNECT response failed: {e}")))?;

    if response.status() != StatusCode::OK {
        driver.abort();
        return Err(io::Error::other(format!(
            "CONNECT failed with status {}",
            response.status()
        )));
    }

    let response_padding = response_padding_enabled(&args, response.headers())?;
    let request_bytes = encode_tunnel_payload(response_padding, &build_http_request(url)?);
    stream
        .send_data(Bytes::from(request_bytes))
        .await
        .map_err(|e| io::Error::other(format!("failed to write H3 DATA: {e}")))?;
    stream
        .finish()
        .await
        .map_err(|e| io::Error::other(format!("failed to finish H3 request: {e}")))?;

    let mut decoder = PaddingDecoder::new(response_padding);
    let mut raw_response = Vec::new();
    while let Some(mut data) = stream
        .recv_data()
        .await
        .map_err(|e| io::Error::other(format!("failed to read H3 DATA: {e}")))?
    {
        let chunk = data.copy_to_bytes(data.remaining());
        decoder.push(&chunk, &mut raw_response);
        if let Some(body) = try_extract_complete_http_body(&raw_response)? {
            write_output(output, body).await?;
            driver.abort();
            endpoint.close(0u32.into(), b"done");
            endpoint.wait_idle().await;
            return Ok(());
        }
    }
    decoder.finish(&mut raw_response)?;
    driver.abort();
    endpoint.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    let body = extract_http_body(&raw_response)?;
    write_output(output, body).await?;

    Ok(())
}

async fn run_udp_echo_h2(args: Args) -> io::Result<()> {
    let Workload::UdpEcho {
        target,
        payload_size,
    } = &args.workload
    else {
        unreachable!("run_udp_echo_h2 called for non-UDP workload");
    };

    let tcp = timeout(args.connect_timeout, connect_tcp(&args))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy TCP connect timed out"))??;
    let tls = connect_tls(tcp, &args).await?;

    let (send_request, connection) = h2::client::Builder::new()
        .initial_window_size(256 * 1024)
        .initial_connection_window_size(256 * 1024)
        .max_frame_size((1 << 24) - 1)
        .max_concurrent_streams(1024)
        .handshake(tls)
        .await
        .map_err(|e| io::Error::other(format!("H2 handshake failed: {e}")))?;

    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = naive_connect_request(&args, UOT_V2_MAGIC_AUTHORITY, Version::HTTP_2)?;
    let mut send_request = send_request
        .ready()
        .await
        .map_err(|e| io::Error::other(format!("H2 client not ready: {e}")))?;
    let (response_future, mut send_stream) = send_request
        .send_request(request, false)
        .map_err(|e| io::Error::other(format!("UDP CONNECT request failed: {e}")))?;
    let mut response = response_future
        .await
        .map_err(|e| io::Error::other(format!("UDP CONNECT response failed: {e}")))?;

    if response.status() != StatusCode::OK {
        driver.abort();
        return Err(io::Error::other(format!(
            "UDP CONNECT failed with status {}",
            response.status()
        )));
    }

    let expected = build_udp_payload(*payload_size);
    let response_padding = response_padding_enabled(&args, response.headers())?;
    let request_payload = encode_tunnel_payload(
        response_padding,
        &build_uot_v2_connect_payload(target, &expected)?,
    );
    send_stream
        .send_data(Bytes::from(request_payload), false)
        .map_err(|e| io::Error::other(format!("failed to write UDP request body: {e}")))?;

    let echoed = read_uot_v2_response_h2(response.body_mut(), response_padding).await?;

    let _ = send_stream.send_data(Bytes::new(), true);
    driver.abort();

    if echoed != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "UDP echo mismatch: got {} bytes, expected {} bytes",
                echoed.len(),
                expected.len()
            ),
        ));
    }

    println!(
        "naiveproxy udp echo ok bytes={} target={}:{} transport=h2",
        echoed.len(),
        target.host,
        target.port
    );

    Ok(())
}

async fn run_udp_echo_h3(args: Args) -> io::Result<()> {
    let Workload::UdpEcho {
        target,
        payload_size,
    } = &args.workload
    else {
        unreachable!("run_udp_echo_h3 called for non-UDP workload");
    };

    let remote_addr = resolve_proxy_addr(&args).await?;
    let local_addr = SocketAddr::new(
        args.bind.unwrap_or_else(|| {
            if remote_addr.is_ipv4() {
                IpAddr::from([0, 0, 0, 0])
            } else {
                IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            }
        }),
        0,
    );
    let mut endpoint = quinn::Endpoint::client(local_addr)?;
    endpoint.set_default_client_config(quic_client_config(&args)?);

    let connection = timeout(
        args.connect_timeout,
        endpoint
            .connect(remote_addr, &args.server_name)
            .map_err(|e| io::Error::other(format!("QUIC connect setup failed: {e}")))?,
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy QUIC connect timed out"))?
    .map_err(|e| io::Error::other(format!("QUIC connect failed: {e}")))?;

    let quic = h3_quinn::Connection::new(connection);
    let (mut h3_driver, mut send_request) = h3::client::new(quic)
        .await
        .map_err(|e| io::Error::other(format!("H3 client setup failed: {e}")))?;
    let driver = tokio::spawn(async move {
        let _ = h3_driver.wait_idle().await;
    });

    let request = naive_connect_request(&args, UOT_V2_MAGIC_AUTHORITY, Version::HTTP_3)?;
    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|e| io::Error::other(format!("H3 UDP CONNECT request failed: {e}")))?;
    let response = stream
        .recv_response()
        .await
        .map_err(|e| io::Error::other(format!("H3 UDP CONNECT response failed: {e}")))?;

    if response.status() != StatusCode::OK {
        driver.abort();
        endpoint.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
        return Err(io::Error::other(format!(
            "UDP CONNECT failed with status {}",
            response.status()
        )));
    }

    let expected = build_udp_payload(*payload_size);
    let response_padding = response_padding_enabled(&args, response.headers())?;
    let request_payload = encode_tunnel_payload(
        response_padding,
        &build_uot_v2_connect_payload(target, &expected)?,
    );
    stream
        .send_data(Bytes::from(request_payload))
        .await
        .map_err(|e| io::Error::other(format!("failed to write H3 UDP DATA: {e}")))?;

    let echoed = read_uot_v2_response_h3(&mut stream, response_padding).await?;

    let _ = stream.finish().await;
    driver.abort();
    endpoint.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    if echoed != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "UDP echo mismatch: got {} bytes, expected {} bytes",
                echoed.len(),
                expected.len()
            ),
        ));
    }

    println!(
        "naiveproxy udp echo ok bytes={} target={}:{} transport=h3",
        echoed.len(),
        target.host,
        target.port
    );

    Ok(())
}

async fn connect_tcp(args: &Args) -> io::Result<TcpStream> {
    let remote_addr = resolve_proxy_addr(args).await?;
    let socket = if remote_addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    if let Some(bind) = args.bind {
        socket.bind(SocketAddr::new(bind, 0))?;
    }

    let stream = socket.connect(remote_addr).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

async fn resolve_proxy_addr(args: &Args) -> io::Result<SocketAddr> {
    let mut addrs = lookup_host((args.proxy_host.as_str(), args.proxy_port)).await?;
    addrs
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "proxy address did not resolve"))
}

async fn connect_tls(
    tcp: TcpStream,
    args: &Args,
) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&args.ca_cert).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to read CA cert {}: {e}", args.ca_cert.display()),
        )
    })?;
    let mut reader = io::Cursor::new(pem);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CA cert file did not contain certificates",
        ));
    }
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    }

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];

    let server_name = ServerName::try_from(args.server_name.clone()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid TLS server name `{}`: {e}", args.server_name),
        )
    })?;
    TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
}

fn quic_client_config(args: &Args) -> io::Result<quinn::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&args.ca_cert).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to read CA cert {}: {e}", args.ca_cert.display()),
        )
    })?;
    let mut reader = io::Cursor::new(pem);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CA cert file did not contain certificates",
        ));
    }
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    }

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(config).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid QUIC TLS client config: {e}"),
        )
    })?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
}

fn target_authority(url: &Url) -> io::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target URL missing host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target URL missing port"))?;

    if host.contains(':') && !host.starts_with('[') {
        Ok(format!("[{host}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

fn naive_connect_request(
    args: &Args,
    authority: &str,
    version: Version,
) -> io::Result<Request<()>> {
    let credentials = format!("{}:{}", args.username, args.password);
    let auth_header = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(credentials)
    );
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(authority)
        .version(version)
        .header("proxy-authorization", auth_header);
    if args.padding {
        request = request.header("padding", generate_padding_header(24));
        request = request.header("padding-type-request", "1, 0");
    }
    request
        .body(())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn response_padding_enabled(args: &Args, headers: &http::HeaderMap) -> io::Result<bool> {
    let has_padding = headers.contains_key("padding");
    let has_padding_type = headers.contains_key("padding-type-reply");

    if !args.padding && (has_padding || has_padding_type) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server enabled padding for an unpadded CONNECT request",
        ));
    }

    Ok(has_padding_type)
}

fn encode_tunnel_payload(padding_enabled: bool, payload: &[u8]) -> Vec<u8> {
    if padding_enabled {
        encode_padding_frame(payload)
    } else {
        payload.to_vec()
    }
}

fn build_http_request(url: &Url) -> io::Result<Vec<u8>> {
    if url.scheme() != "http" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "e2e client only supports http target URLs",
        ));
    }

    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    let host = target_authority(url)?;
    Ok(format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: shoes-naiveproxy-e2e-client/1\r\nAccept: */*\r\n\r\n"
    )
    .into_bytes())
}

fn generate_padding_header(len: usize) -> String {
    let mut rng = rand::rng();
    let mut buf = Vec::with_capacity(len);
    for _ in 0..len.min(16) {
        buf.push(NONINDEX_CHARS[rng.random_range(0..16)]);
    }
    for _ in 16..len {
        buf.push(NONINDEX_CHARS[16]);
    }
    String::from_utf8(buf).expect("padding header is ASCII")
}

fn encode_padding_frame(payload: &[u8]) -> Vec<u8> {
    let payload_len = u16::try_from(payload.len()).expect("request payload fits in one frame");
    let mut frame = Vec::with_capacity(PADDING_HEADER_SIZE + payload.len());
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.push(0);
    frame.extend_from_slice(payload);
    frame
}

fn build_uot_v2_connect_payload(target: &UdpTarget, payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("UDP payload too large: {}", payload.len()),
        ));
    }

    let mut out = Vec::with_capacity(1 + 32 + 2 + payload.len());
    out.push(1);
    out.extend_from_slice(&encode_socks_address(target)?);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn encode_socks_address(target: &UdpTarget) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(32);
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(addr) => {
                out.push(0x01);
                out.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                out.push(0x04);
                out.extend_from_slice(&addr.octets());
            }
        }
    } else {
        let host = target.host.as_bytes();
        if host.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("UDP target hostname too long: {}", host.len()),
            ));
        }
        out.push(0x03);
        out.push(host.len() as u8);
        out.extend_from_slice(host);
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(out)
}

fn build_udp_payload(size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| index.wrapping_mul(31).wrapping_add(17) as u8)
        .collect()
}

async fn read_uot_v2_response_h2(
    body_stream: &mut h2::RecvStream,
    padding_enabled: bool,
) -> io::Result<Vec<u8>> {
    let mut decoder = PaddingDecoder::new(padding_enabled);
    let mut decoded = Vec::new();

    while let Some(chunk) = body_stream.data().await {
        let chunk = chunk.map_err(|e| io::Error::other(format!("failed to read UDP DATA: {e}")))?;
        body_stream
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(|e| io::Error::other(format!("failed to release H2 capacity: {e}")))?;
        decoder.push(&chunk, &mut decoded);
        if let Some(message) = try_extract_uot_v2_message(&decoded)? {
            return Ok(message);
        }
    }

    decoder.finish(&mut decoded)?;
    try_extract_uot_v2_message(&decoded)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "UDP response ended before a complete UoT V2 message",
        )
    })
}

async fn read_uot_v2_response_h3(
    stream: &mut h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    padding_enabled: bool,
) -> io::Result<Vec<u8>> {
    let mut decoder = PaddingDecoder::new(padding_enabled);
    let mut decoded = Vec::new();

    while let Some(mut data) = stream
        .recv_data()
        .await
        .map_err(|e| io::Error::other(format!("failed to read H3 UDP DATA: {e}")))?
    {
        let chunk = data.copy_to_bytes(data.remaining());
        decoder.push(&chunk, &mut decoded);
        if let Some(message) = try_extract_uot_v2_message(&decoded)? {
            return Ok(message);
        }
    }

    decoder.finish(&mut decoded)?;
    try_extract_uot_v2_message(&decoded)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "UDP response ended before a complete UoT V2 message",
        )
    })
}

fn try_extract_uot_v2_message(decoded: &[u8]) -> io::Result<Option<Vec<u8>>> {
    if decoded.len() < 2 {
        return Ok(None);
    }
    let message_len = u16::from_be_bytes([decoded[0], decoded[1]]) as usize;
    let total_len = 2 + message_len;
    if decoded.len() < total_len {
        return Ok(None);
    }
    Ok(Some(decoded[2..total_len].to_vec()))
}

struct PaddingDecoder {
    enabled: bool,
    frames: usize,
    buffer: VecDeque<u8>,
}

impl PaddingDecoder {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            frames: 0,
            buffer: VecDeque::new(),
        }
    }

    fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        if !self.enabled || self.frames >= NUM_FIRST_PADDINGS {
            out.extend_from_slice(chunk);
            return;
        }

        self.buffer.extend(chunk.iter().copied());
        self.drain(out);
    }

    fn finish(mut self, out: &mut Vec<u8>) -> io::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        self.drain(out);
        if self.frames >= NUM_FIRST_PADDINGS {
            out.extend(self.buffer);
            return Ok(());
        }
        if self.buffer.is_empty() {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "incomplete NaiveProxy padding frame",
        ))
    }

    fn drain(&mut self, out: &mut Vec<u8>) {
        loop {
            if self.frames >= NUM_FIRST_PADDINGS {
                out.extend(self.buffer.drain(..));
                return;
            }
            if self.buffer.len() < PADDING_HEADER_SIZE {
                return;
            }

            let payload_len = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;
            let padding_len = self.buffer[2] as usize;
            let frame_len = PADDING_HEADER_SIZE + payload_len + padding_len;
            if self.buffer.len() < frame_len {
                return;
            }

            self.buffer.drain(..PADDING_HEADER_SIZE);
            out.extend(self.buffer.drain(..payload_len));
            self.buffer.drain(..padding_len);
            self.frames += 1;
        }
    }
}

fn extract_http_body(response: &[u8]) -> io::Result<&[u8]> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "HTTP response missing headers")
        })?;
    let headers = std::str::from_utf8(&response[..header_end]).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("HTTP response headers are not UTF-8: {e}"),
        )
    })?;
    if !headers.starts_with("HTTP/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected HTTP response prefix: {headers:.32}"),
        ));
    }
    if !headers.starts_with("HTTP/1.1 200") && !headers.starts_with("HTTP/1.0 200") {
        return Err(io::Error::other(format!(
            "unexpected target response status: {}",
            headers.lines().next().unwrap_or("<empty>")
        )));
    }

    let body = &response[header_end + 4..];
    if let Some(content_length) = parse_content_length(headers)? {
        if body.len() < content_length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "target response body too short: got {}, expected {content_length}",
                    body.len()
                ),
            ));
        }
        return Ok(&body[..content_length]);
    }

    Ok(body)
}

fn try_extract_complete_http_body(response: &[u8]) -> io::Result<Option<&[u8]>> {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(None);
    };
    let headers = std::str::from_utf8(&response[..header_end]).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("HTTP response headers are not UTF-8: {e}"),
        )
    })?;
    if !headers.starts_with("HTTP/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected HTTP response prefix: {headers:.32}"),
        ));
    }
    if !headers.starts_with("HTTP/1.1 200") && !headers.starts_with("HTTP/1.0 200") {
        return Err(io::Error::other(format!(
            "unexpected target response status: {}",
            headers.lines().next().unwrap_or("<empty>")
        )));
    }

    let body = &response[header_end + 4..];
    let Some(content_length) = parse_content_length(headers)? else {
        return Ok(None);
    };
    if body.len() < content_length {
        return Ok(None);
    }
    Ok(Some(&body[..content_length]))
}

async fn write_output(path: &PathBuf, body: &[u8]) -> io::Result<()> {
    tokio::fs::File::create(path).await?.write_all(body).await
}

fn parse_content_length(headers: &str) -> io::Result<Option<usize>> {
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value.trim().parse::<usize>().map(Some).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid content-length `{}`: {e}", value.trim()),
                )
            });
        }
    }
    Ok(None)
}

impl Args {
    fn parse() -> io::Result<Self> {
        let mut args = std::env::args().skip(1);
        let mut proxy_host = None;
        let mut proxy_port = None;
        let mut server_name = None;
        let mut ca_cert = None;
        let mut username = None;
        let mut password = None;
        let mut url = None;
        let mut output = None;
        let mut udp_echo = None;
        let mut udp_payload_size = 4096usize;
        let mut bind = None;
        let mut http3 = false;
        let mut padding = true;
        let mut connect_timeout = Duration::from_secs(5);
        let mut max_time = Duration::from_secs(60);

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--proxy-host" => proxy_host = Some(next_value(&mut args, "--proxy-host")?),
                "--proxy-port" => {
                    proxy_port = Some(parse_u16(&next_value(&mut args, "--proxy-port")?)?)
                }
                "--server-name" => server_name = Some(next_value(&mut args, "--server-name")?),
                "--ca-cert" => ca_cert = Some(PathBuf::from(next_value(&mut args, "--ca-cert")?)),
                "--username" => username = Some(next_value(&mut args, "--username")?),
                "--password" => password = Some(next_value(&mut args, "--password")?),
                "--url" => {
                    let raw = next_value(&mut args, "--url")?;
                    url = Some(Url::parse(&raw).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("invalid --url `{raw}`: {e}"),
                        )
                    })?);
                }
                "--output" => output = Some(PathBuf::from(next_value(&mut args, "--output")?)),
                "--udp-echo" => {
                    let raw = next_value(&mut args, "--udp-echo")?;
                    udp_echo = Some(parse_udp_target(&raw)?);
                }
                "--udp-payload-size" => {
                    udp_payload_size = parse_usize(&next_value(&mut args, "--udp-payload-size")?)?
                }
                "--http3" => http3 = true,
                "--no-padding" => padding = false,
                "--bind" => {
                    let raw = next_value(&mut args, "--bind")?;
                    bind = Some(raw.parse::<IpAddr>().map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("invalid --bind `{raw}`: {e}"),
                        )
                    })?);
                }
                "--connect-timeout-secs" => {
                    connect_timeout = Duration::from_secs(parse_u64(&next_value(
                        &mut args,
                        "--connect-timeout-secs",
                    )?)?)
                }
                "--max-time-secs" => {
                    max_time =
                        Duration::from_secs(parse_u64(&next_value(&mut args, "--max-time-secs")?)?)
                }
                "-h" | "--help" => {
                    usage();
                    std::process::exit(0);
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unknown argument `{arg}`"),
                    ));
                }
            }
        }

        let workload = match (url, output, udp_echo) {
            (Some(url), Some(output), None) => Workload::Http { url, output },
            (Some(_), None, None) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--url requires --output",
                ));
            }
            (None, Some(_), None) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--output requires --url",
                ));
            }
            (None, None, Some(target)) => Workload::UdpEcho {
                target,
                payload_size: udp_payload_size,
            },
            (Some(_), _, Some(_)) | (None, Some(_), Some(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--url/--output and --udp-echo are mutually exclusive",
                ));
            }
            (None, None, None) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "missing --url/--output or --udp-echo",
                ));
            }
        };

        Ok(Self {
            proxy_host: required(proxy_host, "--proxy-host")?,
            proxy_port: required(proxy_port, "--proxy-port")?,
            server_name: required(server_name, "--server-name")?,
            ca_cert: required(ca_cert, "--ca-cert")?,
            username: required(username, "--username")?,
            password: required(password, "--password")?,
            workload,
            bind,
            http3,
            padding,
            connect_timeout,
            max_time,
        })
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &'static str) -> io::Result<String> {
    args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing value for {flag}"),
        )
    })
}

fn required<T>(value: Option<T>, flag: &'static str) -> io::Result<T> {
    value.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("missing {flag}")))
}

fn parse_u16(value: &str) -> io::Result<u16> {
    value.parse::<u16>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid u16 `{value}`: {e}"),
        )
    })
}

fn parse_u64(value: &str) -> io::Result<u64> {
    value.parse::<u64>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid u64 `{value}`: {e}"),
        )
    })
}

fn parse_usize(value: &str) -> io::Result<usize> {
    value.parse::<usize>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid usize `{value}`: {e}"),
        )
    })
}

fn parse_udp_target(value: &str) -> io::Result<UdpTarget> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(UdpTarget {
            host: addr.ip().to_string(),
            port: addr.port(),
        });
    }

    let (host, port) = value.rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid UDP target `{value}`, expected host:port"),
        )
    })?;
    if host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP target host is empty",
        ));
    }

    Ok(UdpTarget {
        host: host.to_string(),
        port: parse_u16(port)?,
    })
}

fn usage() {
    eprintln!(
        "Usage: shoes-naiveproxy-e2e-client --proxy-host HOST --proxy-port PORT --server-name NAME --ca-cert PATH --username USER --password PASS (--url http://HOST:PORT/PATH --output PATH | --udp-echo HOST:PORT [--udp-payload-size N]) [--http3] [--no-padding] [--bind IP] [--connect-timeout-secs N] [--max-time-secs N]"
    );
}
