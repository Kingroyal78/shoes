use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::{Method, Request, Version};
use rand::Rng;
use rustls::pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpSocket, TcpStream, lookup_host};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::{Url, form_urlencoded};

use shoes::e2e_support::{E2eCryptoStream, VmessE2eSession, connect_reality_tcp_stream};

const VLESS_COMMAND_TCP: u8 = 1;
const VLESS_ADDR_IPV4: u8 = 1;
const VLESS_ADDR_DOMAIN: u8 = 2;
const VLESS_ADDR_IPV6: u8 = 3;
const VLESS_RESPONSE_HEADER_LEN: usize = 2;

#[derive(Debug)]
struct Args {
    proxy_host: String,
    proxy_port: u16,
    server_name: String,
    ca_cert: Option<PathBuf>,
    reality_public_key: Option<String>,
    reality_short_id: Option<String>,
    protocol: ProxyProtocol,
    uuid: String,
    vmess_security: String,
    xhttp_host: String,
    xhttp_path: String,
    xhttp_mode: XHttpMode,
    xhttp_session_placement: XHttpPlacement,
    xhttp_session_key: String,
    xhttp_seq_placement: XHttpPlacement,
    xhttp_seq_key: String,
    xhttp_uplink_data_placement: XHttpDataPlacement,
    xhttp_uplink_data_key: String,
    url: Url,
    output: PathBuf,
    bind: Option<IpAddr>,
    connect_timeout: Duration,
    max_time: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyProtocol {
    Vless,
    Vmess,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XHttpMode {
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XHttpPlacement {
    Path,
    Query,
    Header,
    Cookie,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XHttpDataPlacement {
    Auto,
    Body,
    Header,
    Cookie,
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
            eprintln!("xhttp e2e client failed: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("xhttp e2e client timed out");
            std::process::exit(1);
        }
    }
}

async fn run(args: Args) -> io::Result<()> {
    let tcp = timeout(args.connect_timeout, connect_tcp(&args))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy TCP connect timed out"))??;
    let tls = connect_tls_like_stream(tcp, &args).await?;

    let (send_request, connection) = h2::client::Builder::new()
        .initial_window_size(256 * 1024)
        .initial_connection_window_size(256 * 1024)
        .max_frame_size((1 << 24) - 1)
        .max_concurrent_streams(128)
        .handshake(tls)
        .await
        .map_err(|e| io::Error::other(format!("H2 handshake failed: {e}")))?;

    let mut driver = tokio::spawn(async move {
        connection
            .await
            .map_err(|e| io::Error::other(format!("H2 connection failed: {e}")))
    });

    let session_id = random_session_id();
    let http_request = build_http_request(&args.url)?;
    let (payload, response_decoder) = build_proxy_payload(&args, &http_request).await?;

    let exchange = async {
        match args.xhttp_mode {
            XHttpMode::Auto | XHttpMode::PacketUp => {
                run_packet_up_exchange(send_request, &args, &session_id, payload, response_decoder)
                    .await?;
            }
            XHttpMode::StreamUp => {
                run_stream_up_exchange(send_request, &args, &session_id, payload, response_decoder)
                    .await?;
            }
            XHttpMode::StreamOne => {
                run_stream_one_exchange(send_request, &args, payload, response_decoder).await?;
            }
        }
        Ok::<(), io::Error>(())
    };
    tokio::pin!(exchange);

    let result = tokio::select! {
        result = &mut exchange => result,
        driver_result = &mut driver => {
            match driver_result {
                Ok(Ok(())) => Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "H2 connection closed before XHTTP exchange completed",
                )),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(io::Error::other(format!("H2 connection task failed: {e}"))),
            }
        }
    };

    if !driver.is_finished() {
        driver.abort();
    }
    result
}

async fn run_packet_up_exchange(
    send_request: h2::client::SendRequest<Bytes>,
    args: &Args,
    session_id: &str,
    payload: Vec<u8>,
    response_decoder: ResponseDecoder,
) -> io::Result<()> {
    let (down_request, _) = xhttp_request(args, Method::GET, Some(session_id), None, None)?;
    let (send_request, down_response_future, _) =
        send_h2_request(send_request, down_request, true, "stream-down").await?;

    let (up_request, packet_body) = xhttp_request(
        args,
        Method::POST,
        Some(session_id),
        Some("0"),
        Some(&payload),
    )?;
    let (send_request, up_response_future, mut up_stream) =
        send_h2_request(send_request, up_request, false, "packet-up").await?;
    up_stream
        .send_data(packet_body, true)
        .map_err(|e| io::Error::other(format!("failed to write packet-up body: {e}")))?;
    drop(send_request);
    drop(up_stream);

    tokio::try_join!(
        check_up_response(up_response_future, "packet-up"),
        read_xhttp_response(
            down_response_future,
            &args.output,
            response_decoder,
            "stream-down"
        ),
    )?;
    Ok(())
}

async fn run_stream_up_exchange(
    send_request: h2::client::SendRequest<Bytes>,
    args: &Args,
    session_id: &str,
    payload: Vec<u8>,
    response_decoder: ResponseDecoder,
) -> io::Result<()> {
    let (down_request, _) = xhttp_request(args, Method::GET, Some(session_id), None, None)?;
    let (send_request, down_response_future, _) =
        send_h2_request(send_request, down_request, true, "stream-down").await?;

    let (up_request, _) = xhttp_request(args, Method::POST, Some(session_id), None, None)?;
    let (send_request, up_response_future, mut up_stream) =
        send_h2_request(send_request, up_request, false, "stream-up").await?;
    up_stream
        .send_data(Bytes::from(payload), true)
        .map_err(|e| io::Error::other(format!("failed to write stream-up body: {e}")))?;
    drop(send_request);
    drop(up_stream);

    tokio::try_join!(
        check_up_response(up_response_future, "stream-up"),
        read_xhttp_response(
            down_response_future,
            &args.output,
            response_decoder,
            "stream-down"
        ),
    )?;
    Ok(())
}

async fn run_stream_one_exchange(
    send_request: h2::client::SendRequest<Bytes>,
    args: &Args,
    payload: Vec<u8>,
    response_decoder: ResponseDecoder,
) -> io::Result<()> {
    let (request, _) = xhttp_request(args, Method::POST, None, None, None)?;
    let (send_request, response_future, mut stream) =
        send_h2_request(send_request, request, false, "stream-one").await?;
    stream
        .send_data(Bytes::from(payload), true)
        .map_err(|e| io::Error::other(format!("failed to write stream-one body: {e}")))?;
    drop(send_request);
    drop(stream);

    read_xhttp_response(
        response_future,
        &args.output,
        response_decoder,
        "stream-one",
    )
    .await
}

async fn send_h2_request(
    send_request: h2::client::SendRequest<Bytes>,
    request: Request<()>,
    end_stream: bool,
    label: &'static str,
) -> io::Result<(
    h2::client::SendRequest<Bytes>,
    h2::client::ResponseFuture,
    h2::SendStream<Bytes>,
)> {
    let mut send_request = send_request
        .ready()
        .await
        .map_err(|e| io::Error::other(format!("H2 sender is not ready for {label}: {e}")))?;
    let (response_future, send_stream) = send_request
        .send_request(request, end_stream)
        .map_err(|e| io::Error::other(format!("{label} request failed: {e}")))?;
    Ok((send_request, response_future, send_stream))
}

async fn check_up_response(
    response_future: h2::client::ResponseFuture,
    label: &'static str,
) -> io::Result<()> {
    let mut response = response_future
        .await
        .map_err(|e| io::Error::other(format!("{label} response failed: {e}")))?;
    if response.status() != http::StatusCode::OK {
        return Err(io::Error::other(format!(
            "{label} failed with status {}",
            response.status()
        )));
    }

    let body_stream = response.body_mut();
    while let Some(chunk) = body_stream.data().await {
        let chunk =
            chunk.map_err(|e| io::Error::other(format!("failed to read {label} DATA: {e}")))?;
        body_stream
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(|e| io::Error::other(format!("failed to release H2 capacity: {e}")))?;
    }
    Ok(())
}

async fn read_xhttp_response(
    response_future: h2::client::ResponseFuture,
    output: &PathBuf,
    mut decoder: ResponseDecoder,
    label: &'static str,
) -> io::Result<()> {
    let mut down_response = response_future
        .await
        .map_err(|e| io::Error::other(format!("{label} response failed: {e}")))?;
    if down_response.status() != http::StatusCode::OK {
        return Err(io::Error::other(format!(
            "{label} failed with status {}",
            down_response.status()
        )));
    }

    let mut raw_response = Vec::new();
    let body_stream = down_response.body_mut();
    while let Some(chunk) = body_stream.data().await {
        let chunk =
            chunk.map_err(|e| io::Error::other(format!("failed to read {label} DATA: {e}")))?;
        body_stream
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(|e| io::Error::other(format!("failed to release H2 capacity: {e}")))?;
        decoder.accept_chunk(&chunk, &mut raw_response)?;
        if let Some(body) = try_extract_complete_http_body(&raw_response)? {
            write_output(output, body).await?;
            return Ok(());
        }
    }

    decoder.finish(&mut raw_response)?;
    let body = extract_http_body(&raw_response)?;
    write_output(output, body).await
}

async fn connect_tcp(args: &Args) -> io::Result<TcpStream> {
    let mut addrs = lookup_host((args.proxy_host.as_str(), args.proxy_port)).await?;
    let remote_addr = addrs
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "proxy address did not resolve"))?;
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

async fn connect_tls(tcp: TcpStream, args: &Args) -> io::Result<Box<dyn E2eCryptoStream>> {
    let ca_cert = args.ca_cert.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing --ca-cert for non-REALITY TLS",
        )
    })?;
    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(ca_cert).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to read CA cert {}: {e}", ca_cert.display()),
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
    let tls = TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await?;
    Ok(Box::new(tls))
}

async fn connect_tls_like_stream(
    tcp: TcpStream,
    args: &Args,
) -> io::Result<Box<dyn E2eCryptoStream>> {
    match (&args.reality_public_key, &args.reality_short_id) {
        (Some(public_key), Some(short_id)) => {
            connect_reality_tcp_stream(tcp, &args.server_name, public_key, short_id).await
        }
        (None, None) => connect_tls(tcp, args).await,
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--reality-public-key and --reality-short-id must be provided together",
        )),
    }
}

async fn build_proxy_payload(
    args: &Args,
    http_request: &[u8],
) -> io::Result<(Vec<u8>, ResponseDecoder)> {
    match args.protocol {
        ProxyProtocol::Vless => {
            let mut payload = build_vless_tcp_header(args)?;
            payload.extend_from_slice(http_request);
            Ok((
                payload,
                ResponseDecoder::Vless {
                    pending: VecDeque::new(),
                    response_header_pending: true,
                },
            ))
        }
        ProxyProtocol::Vmess => {
            let (target_host, target_port) = target_endpoint(&args.url)?;
            let mut session =
                VmessE2eSession::new(&args.uuid, &args.vmess_security, target_host, target_port)
                    .await?;
            let payload = session.encode_request(http_request).await?;
            Ok((payload, ResponseDecoder::Vmess(session)))
        }
    }
}

enum ResponseDecoder {
    Vless {
        pending: VecDeque<u8>,
        response_header_pending: bool,
    },
    Vmess(VmessE2eSession),
}

impl ResponseDecoder {
    fn accept_chunk(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            ResponseDecoder::Vless {
                pending,
                response_header_pending,
            } => {
                pending.extend(chunk);
                drain_after_vless_response_header(pending, out, response_header_pending);
                Ok(())
            }
            ResponseDecoder::Vmess(session) => session.feed_encrypted_response(chunk, out),
        }
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            ResponseDecoder::Vless {
                pending,
                response_header_pending,
            } => {
                if *response_header_pending && !pending.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "VLESS response header is incomplete",
                    ));
                }
                out.extend(pending.drain(..));
                Ok(())
            }
            ResponseDecoder::Vmess(session) => session.finish_response(out),
        }
    }
}

fn h2_request(
    method: Method,
    authority: &str,
    path: &str,
    headers: &[(String, String)],
    cookies: &[(String, String)],
) -> io::Result<Request<()>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("https://{authority}{path}"))
        .version(Version::HTTP_2)
        .header("accept", "*/*")
        .header("user-agent", "shoes-xhttp-e2e-client/1");
    for (key, value) in headers {
        builder = builder.header(key, value);
    }
    if !cookies.is_empty() {
        let cookie = cookies
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        builder = builder.header("cookie", cookie);
    }
    builder
        .body(())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn xhttp_request(
    args: &Args,
    method: Method,
    session_id: Option<&str>,
    seq: Option<&str>,
    packet_payload: Option<&[u8]>,
) -> io::Result<(Request<()>, Bytes)> {
    let mut path_parts = Vec::new();
    let mut query = Vec::new();
    let mut headers = Vec::new();
    let mut cookies = Vec::new();
    let mut body = Bytes::new();

    if let Some(session_id) = session_id {
        add_xhttp_meta(
            XHttpMetaValue {
                placement: args.xhttp_session_placement,
                key: &args.xhttp_session_key,
                value: session_id,
                field: "sessionIDKey",
            },
            XHttpMetaTarget {
                path_parts: &mut path_parts,
                query: &mut query,
                headers: &mut headers,
                cookies: &mut cookies,
            },
        )?;
    }
    if let Some(seq) = seq {
        add_xhttp_meta(
            XHttpMetaValue {
                placement: args.xhttp_seq_placement,
                key: &args.xhttp_seq_key,
                value: seq,
                field: "seqKey",
            },
            XHttpMetaTarget {
                path_parts: &mut path_parts,
                query: &mut query,
                headers: &mut headers,
                cookies: &mut cookies,
            },
        )?;
    }
    if let Some(payload) = packet_payload {
        body = add_xhttp_packet_payload(args, payload, &mut headers, &mut cookies)?;
    }

    let path = xhttp_path(
        &args.xhttp_path,
        &path_parts,
        &query,
        args.xhttp_session_placement == XHttpPlacement::Path
            || args.xhttp_seq_placement == XHttpPlacement::Path,
    );
    let request = h2_request(method, &args.xhttp_host, &path, &headers, &cookies)?;
    Ok((request, body))
}

struct XHttpMetaValue<'a> {
    placement: XHttpPlacement,
    key: &'a str,
    value: &'a str,
    field: &'static str,
}

struct XHttpMetaTarget<'a> {
    path_parts: &'a mut Vec<String>,
    query: &'a mut Vec<(String, String)>,
    headers: &'a mut Vec<(String, String)>,
    cookies: &'a mut Vec<(String, String)>,
}

fn add_xhttp_meta(meta: XHttpMetaValue<'_>, target: XHttpMetaTarget<'_>) -> io::Result<()> {
    match meta.placement {
        XHttpPlacement::Path => target.path_parts.push(meta.value.to_string()),
        XHttpPlacement::Query => target.query.push((
            required_xhttp_key(meta.key, meta.field)?,
            meta.value.to_string(),
        )),
        XHttpPlacement::Header => target.headers.push((
            required_xhttp_key(meta.key, meta.field)?,
            meta.value.to_string(),
        )),
        XHttpPlacement::Cookie => target.cookies.push((
            required_xhttp_key(meta.key, meta.field)?,
            meta.value.to_string(),
        )),
    }
    Ok(())
}

fn add_xhttp_packet_payload(
    args: &Args,
    payload: &[u8],
    headers: &mut Vec<(String, String)>,
    cookies: &mut Vec<(String, String)>,
) -> io::Result<Bytes> {
    match args.xhttp_uplink_data_placement {
        XHttpDataPlacement::Auto | XHttpDataPlacement::Body => Ok(Bytes::copy_from_slice(payload)),
        XHttpDataPlacement::Header => {
            let key = required_xhttp_key(&args.xhttp_uplink_data_key, "uplinkDataKey")?;
            add_encoded_chunks(payload, key, "-", headers)?;
            Ok(Bytes::new())
        }
        XHttpDataPlacement::Cookie => {
            let key = required_xhttp_key(&args.xhttp_uplink_data_key, "uplinkDataKey")?;
            add_encoded_chunks(payload, key, "_", cookies)?;
            Ok(Bytes::new())
        }
    }
}

fn add_encoded_chunks(
    payload: &[u8],
    key: String,
    separator: &str,
    target: &mut Vec<(String, String)>,
) -> io::Result<()> {
    let encoded = URL_SAFE_NO_PAD.encode(payload);
    for (index, chunk) in encoded.as_bytes().chunks(3000).enumerate() {
        let value = std::str::from_utf8(chunk).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("encoded XHTTP payload chunk is not UTF-8: {e}"),
            )
        })?;
        target.push((format!("{key}{separator}{index}"), value.to_string()));
    }
    Ok(())
}

fn required_xhttp_key(key: &str, field: &'static str) -> io::Result<String> {
    if key.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("xhttp {field} must be set for non-path placement"),
        ));
    }
    Ok(key.to_string())
}

fn xhttp_path(
    base: &str,
    parts: &[String],
    query: &[(String, String)],
    force_trailing_slash: bool,
) -> String {
    let (base_path, base_query) = base
        .split_once('?')
        .map(|(path, query)| (path, Some(query)))
        .unwrap_or((base, None));
    let mut path = base_path;
    if path.is_empty() {
        path = "/";
    }
    let mut out = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if (force_trailing_slash || !parts.is_empty()) && !out.ends_with('/') {
        out.push('/');
    }
    out.push_str(&parts.join("/"));
    let query = xhttp_query(base_query, query);
    if !query.is_empty() {
        out.push('?');
        out.push_str(&query);
    }
    out
}

fn xhttp_query(base_query: Option<&str>, query: &[(String, String)]) -> String {
    let mut out = base_query.unwrap_or("").to_string();
    if query.is_empty() {
        return out;
    }

    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in query {
        serializer.append_pair(key, value);
    }
    let encoded = serializer.finish();
    if !out.is_empty() {
        out.push('&');
    }
    out.push_str(&encoded);
    out
}

fn random_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn build_vless_tcp_header(args: &Args) -> io::Result<Vec<u8>> {
    let uuid = parse_uuid(&args.uuid)?;
    let (target_host, target_port) = target_endpoint(&args.url)?;

    let mut header = Vec::new();
    header.push(0);
    header.extend_from_slice(&uuid);
    header.push(0);
    header.push(VLESS_COMMAND_TCP);
    header.extend_from_slice(&target_port.to_be_bytes());
    if let Ok(ip) = target_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ip) => {
                header.push(VLESS_ADDR_IPV4);
                header.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                header.push(VLESS_ADDR_IPV6);
                header.extend_from_slice(&ip.octets());
            }
        }
    } else {
        let host = target_host.as_bytes();
        let host_len = u8::try_from(host.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "target host is too long for VLESS",
            )
        })?;
        header.push(VLESS_ADDR_DOMAIN);
        header.push(host_len);
        header.extend_from_slice(host);
    }
    Ok(header)
}

fn target_endpoint(url: &Url) -> io::Result<(&str, u16)> {
    let target_host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target URL missing host"))?;
    let target_port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target URL missing port"))?;
    Ok((target_host, target_port))
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
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: shoes-xhttp-e2e-client/1\r\nAccept: */*\r\n\r\n"
    )
    .into_bytes())
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

fn drain_after_vless_response_header(
    pending: &mut VecDeque<u8>,
    out: &mut Vec<u8>,
    vless_header_pending: &mut bool,
) {
    if *vless_header_pending && pending.len() < VLESS_RESPONSE_HEADER_LEN {
        return;
    }
    if *vless_header_pending {
        pending.drain(..VLESS_RESPONSE_HEADER_LEN);
        *vless_header_pending = false;
    }
    out.extend(pending.drain(..));
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

fn parse_uuid(value: &str) -> io::Result<[u8; 16]> {
    let mut hex = String::with_capacity(32);
    for ch in value.chars() {
        if ch == '-' {
            continue;
        }
        if !ch.is_ascii_hexdigit() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid UUID character `{ch}`"),
            ));
        }
        hex.push(ch);
    }
    if hex.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UUID must contain 32 hex digits",
        ));
    }

    let mut out = [0u8; 16];
    for (index, slot) in out.iter_mut().enumerate() {
        let start = index * 2;
        *slot = u8::from_str_radix(&hex[start..start + 2], 16).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid UUID: {e}"))
        })?;
    }
    Ok(out)
}

impl Args {
    fn parse() -> io::Result<Self> {
        let mut args = std::env::args().skip(1);
        let mut proxy_host = None;
        let mut proxy_port = None;
        let mut server_name = None;
        let mut ca_cert = None;
        let mut reality_public_key = None;
        let mut reality_short_id = None;
        let mut protocol = ProxyProtocol::Vless;
        let mut uuid = None;
        let mut vmess_security = "auto".to_string();
        let mut xhttp_host = None;
        let mut xhttp_path = None;
        let mut xhttp_mode = XHttpMode::PacketUp;
        let mut xhttp_session_placement = XHttpPlacement::Path;
        let mut xhttp_session_key = None;
        let mut xhttp_seq_placement = XHttpPlacement::Path;
        let mut xhttp_seq_key = None;
        let mut xhttp_uplink_data_placement = XHttpDataPlacement::Auto;
        let mut xhttp_uplink_data_key = None;
        let mut url = None;
        let mut output = None;
        let mut bind = None;
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
                "--reality-public-key" => {
                    reality_public_key = Some(next_value(&mut args, "--reality-public-key")?)
                }
                "--reality-short-id" => {
                    reality_short_id = Some(next_value(&mut args, "--reality-short-id")?)
                }
                "--protocol" => protocol = parse_protocol(&next_value(&mut args, "--protocol")?)?,
                "--uuid" => uuid = Some(next_value(&mut args, "--uuid")?),
                "--vmess-security" => vmess_security = next_value(&mut args, "--vmess-security")?,
                "--xhttp-host" => xhttp_host = Some(next_value(&mut args, "--xhttp-host")?),
                "--xhttp-path" => xhttp_path = Some(next_value(&mut args, "--xhttp-path")?),
                "--xhttp-mode" => {
                    xhttp_mode = parse_xhttp_mode(&next_value(&mut args, "--xhttp-mode")?)?
                }
                "--xhttp-session-placement" => {
                    xhttp_session_placement =
                        parse_xhttp_placement(&next_value(&mut args, "--xhttp-session-placement")?)?
                }
                "--xhttp-session-key" => {
                    xhttp_session_key = Some(next_value(&mut args, "--xhttp-session-key")?)
                }
                "--xhttp-seq-placement" => {
                    xhttp_seq_placement =
                        parse_xhttp_placement(&next_value(&mut args, "--xhttp-seq-placement")?)?
                }
                "--xhttp-seq-key" => {
                    xhttp_seq_key = Some(next_value(&mut args, "--xhttp-seq-key")?)
                }
                "--xhttp-uplink-data-placement" => {
                    xhttp_uplink_data_placement = parse_xhttp_data_placement(&next_value(
                        &mut args,
                        "--xhttp-uplink-data-placement",
                    )?)?
                }
                "--xhttp-uplink-data-key" => {
                    xhttp_uplink_data_key = Some(next_value(&mut args, "--xhttp-uplink-data-key")?)
                }
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

        if ca_cert.is_none() && (reality_public_key.is_none() || reality_short_id.is_none()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing --ca-cert or REALITY public key/short_id",
            ));
        }

        Ok(Self {
            proxy_host: required(proxy_host, "--proxy-host")?,
            proxy_port: required(proxy_port, "--proxy-port")?,
            server_name: required(server_name, "--server-name")?,
            ca_cert,
            reality_public_key,
            reality_short_id,
            protocol,
            uuid: required(uuid, "--uuid")?,
            vmess_security,
            xhttp_host: required(xhttp_host, "--xhttp-host")?,
            xhttp_path: required(xhttp_path, "--xhttp-path")?,
            xhttp_mode,
            xhttp_session_placement,
            xhttp_session_key: xhttp_session_key.unwrap_or_else(|| {
                default_xhttp_meta_key(xhttp_session_placement, "X-Session", "x_session")
            }),
            xhttp_seq_placement,
            xhttp_seq_key: xhttp_seq_key
                .unwrap_or_else(|| default_xhttp_meta_key(xhttp_seq_placement, "X-Seq", "x_seq")),
            xhttp_uplink_data_placement,
            xhttp_uplink_data_key: xhttp_uplink_data_key
                .unwrap_or_else(|| default_xhttp_data_key(xhttp_uplink_data_placement)),
            url: required(url, "--url")?,
            output: required(output, "--output")?,
            bind,
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

fn parse_protocol(value: &str) -> io::Result<ProxyProtocol> {
    match value {
        "vless" => Ok(ProxyProtocol::Vless),
        "vmess" => Ok(ProxyProtocol::Vmess),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported --protocol `{value}`"),
        )),
    }
}

fn parse_xhttp_mode(value: &str) -> io::Result<XHttpMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(XHttpMode::Auto),
        "packet-up" | "packet_up" | "packetup" => Ok(XHttpMode::PacketUp),
        "stream-up" | "stream_up" | "streamup" => Ok(XHttpMode::StreamUp),
        "stream-one" | "stream_one" | "streamone" => Ok(XHttpMode::StreamOne),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported --xhttp-mode `{value}`"),
        )),
    }
}

fn parse_xhttp_placement(value: &str) -> io::Result<XHttpPlacement> {
    match value.trim().to_ascii_lowercase().as_str() {
        "path" => Ok(XHttpPlacement::Path),
        "query" => Ok(XHttpPlacement::Query),
        "header" => Ok(XHttpPlacement::Header),
        "cookie" => Ok(XHttpPlacement::Cookie),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported XHTTP placement `{value}`"),
        )),
    }
}

fn parse_xhttp_data_placement(value: &str) -> io::Result<XHttpDataPlacement> {
    match value.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(XHttpDataPlacement::Auto),
        "body" => Ok(XHttpDataPlacement::Body),
        "header" => Ok(XHttpDataPlacement::Header),
        "cookie" => Ok(XHttpDataPlacement::Cookie),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported XHTTP uplink-data placement `{value}`"),
        )),
    }
}

fn default_xhttp_meta_key(
    placement: XHttpPlacement,
    header_key: &'static str,
    keyed_key: &'static str,
) -> String {
    match placement {
        XHttpPlacement::Header => header_key.to_string(),
        XHttpPlacement::Query | XHttpPlacement::Cookie => keyed_key.to_string(),
        XHttpPlacement::Path => String::new(),
    }
}

fn default_xhttp_data_key(placement: XHttpDataPlacement) -> String {
    match placement {
        XHttpDataPlacement::Header | XHttpDataPlacement::Auto => "X-Data".to_string(),
        XHttpDataPlacement::Cookie => "x_data".to_string(),
        XHttpDataPlacement::Body => String::new(),
    }
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

fn usage() {
    eprintln!(
        "Usage: shoes-vless-xhttp-e2e-client --proxy-host HOST --proxy-port PORT --server-name NAME (--ca-cert FILE | --reality-public-key KEY --reality-short-id ID) [--protocol vless|vmess] --uuid UUID [--vmess-security auto|aes-128-gcm|chacha20-poly1305|none] --xhttp-host HOST --xhttp-path PATH [--xhttp-mode auto|packet-up|stream-up|stream-one] [--xhttp-session-placement path|query|header|cookie] [--xhttp-session-key KEY] [--xhttp-seq-placement path|query|header|cookie] [--xhttp-seq-key KEY] [--xhttp-uplink-data-placement auto|body|header|cookie] [--xhttp-uplink-data-key KEY] --url URL --output FILE"
    );
}
