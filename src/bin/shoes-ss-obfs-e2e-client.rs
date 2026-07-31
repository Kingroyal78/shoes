use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce as AesNonce};
use md5::{Digest, Md5};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, lookup_host};
use tokio::time::timeout;
use url::Url;

const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SALT_LEN_AES_128_GCM: usize = 16;
const KEY_LEN_AES_128_GCM: usize = 16;
const MAX_SS_PAYLOAD_LEN: usize = 0x3fff;

#[derive(Debug)]
struct Args {
    proxy_host: String,
    proxy_port: u16,
    method: String,
    password: String,
    obfs_host: String,
    obfs_path: String,
    url: Url,
    output: PathBuf,
    bind: Option<IpAddr>,
    connect_timeout: Duration,
    max_time: Duration,
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
            eprintln!("shadowsocks obfs e2e client failed: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("shadowsocks obfs e2e client timed out");
            std::process::exit(1);
        }
    }
}

async fn run(args: Args) -> io::Result<()> {
    if args.method != "aes-128-gcm" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "e2e client currently supports only aes-128-gcm",
        ));
    }

    let mut tcp = timeout(args.connect_timeout, connect_tcp(&args))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy TCP connect timed out"))??;
    let destination = target_authority(&args.url)?;
    let request_bytes = build_http_request(&args.url)?;
    let first_ss_packet = encrypt_first_shadowsocks_packet(
        &args.password,
        &destination,
        args.url.port_or_known_default().unwrap_or(80),
        &request_bytes,
    )?;
    let obfs_request = build_obfs_request(&args, &first_ss_packet)?;
    tcp.write_all(&obfs_request).await?;
    tcp.flush().await?;

    let mut initial_ciphertext = read_obfs_response(&mut tcp).await?;
    let mut response = Vec::new();
    let mut decryptor = ShadowsocksDecryptor::new(&args.password);
    while let Some(chunk) = decryptor
        .read_next_chunk(&mut tcp, &mut initial_ciphertext)
        .await?
    {
        response.extend_from_slice(&chunk);
        if let Some(body) = try_extract_complete_http_body(&response)? {
            write_output(&args.output, body).await?;
            return Ok(());
        }
    }

    let body = extract_http_body(&response)?;
    write_output(&args.output, body).await
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

fn encrypt_first_shadowsocks_packet(
    password: &str,
    host: &str,
    port: u16,
    first_payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut payload = write_socks_addr(host, port)?;
    payload.extend_from_slice(first_payload);
    if payload.len() > MAX_SS_PAYLOAD_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "first Shadowsocks payload is too large",
        ));
    }

    let mut salt = [0u8; SALT_LEN_AES_128_GCM];
    rand::rng().fill_bytes(&mut salt);
    let cipher = Aes128Gcm::new_from_slice(&derive_session_key(password, &salt)?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid AES key"))?;
    let mut nonce = IncreasingNonce::default();
    let mut packet = Vec::with_capacity(salt.len() + payload.len() + 2 + TAG_LEN * 2);
    packet.extend_from_slice(&salt);
    packet.extend_from_slice(&encrypt_aead_chunk(
        &cipher,
        &mut nonce,
        &(payload.len() as u16).to_be_bytes(),
    )?);
    packet.extend_from_slice(&encrypt_aead_chunk(&cipher, &mut nonce, &payload)?);
    Ok(packet)
}

fn encrypt_aead_chunk(
    cipher: &Aes128Gcm,
    nonce: &mut IncreasingNonce,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let nonce_bytes = nonce.next();
    let nonce: AesNonce<U12> = (&nonce_bytes[..])
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid AES-GCM nonce length"))?;
    cipher
        .encrypt(&nonce, payload)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AEAD encrypt failed"))
}

struct ShadowsocksDecryptor {
    password: String,
    cipher: Option<Aes128Gcm>,
    nonce: IncreasingNonce,
}

impl ShadowsocksDecryptor {
    fn new(password: &str) -> Self {
        Self {
            password: password.to_string(),
            cipher: None,
            nonce: IncreasingNonce::default(),
        }
    }

    async fn read_next_chunk(
        &mut self,
        stream: &mut TcpStream,
        initial: &mut VecDeque<u8>,
    ) -> io::Result<Option<Vec<u8>>> {
        if self.cipher.is_none() {
            let Some(salt) = read_cipher_exact(stream, initial, SALT_LEN_AES_128_GCM).await? else {
                return Ok(None);
            };
            let key = derive_session_key(&self.password, &salt)?;
            self.cipher = Some(
                Aes128Gcm::new_from_slice(&key)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid AES key"))?,
            );
        }

        let Some(encrypted_len) = read_cipher_exact(stream, initial, 2 + TAG_LEN).await? else {
            return Ok(None);
        };
        let cipher = self
            .cipher
            .as_ref()
            .expect("cipher is initialized after reading salt");
        let len_bytes = decrypt_aead_chunk(cipher, &mut self.nonce, &encrypted_len)?;
        if len_bytes.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Shadowsocks length chunk",
            ));
        }
        let payload_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
        if payload_len > MAX_SS_PAYLOAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Shadowsocks payload length exceeds limit",
            ));
        }
        let encrypted_payload = read_cipher_exact(stream, initial, payload_len + TAG_LEN)
            .await?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated SS payload"))?;
        decrypt_aead_chunk(cipher, &mut self.nonce, &encrypted_payload).map(Some)
    }
}

fn decrypt_aead_chunk(
    cipher: &Aes128Gcm,
    nonce: &mut IncreasingNonce,
    encrypted: &[u8],
) -> io::Result<Vec<u8>> {
    let nonce_bytes = nonce.next();
    let nonce: AesNonce<U12> = (&nonce_bytes[..])
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid AES-GCM nonce length"))?;
    cipher
        .decrypt(&nonce, encrypted)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AEAD decrypt failed"))
}

async fn read_cipher_exact(
    stream: &mut TcpStream,
    initial: &mut VecDeque<u8>,
    len: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        while out.len() < len {
            let Some(byte) = initial.pop_front() else {
                break;
            };
            out.push(byte);
        }
        if out.len() == len {
            break;
        }
        let mut buf = [0u8; 4096];
        let read_len = stream.read(&mut buf).await?;
        if read_len == 0 {
            if out.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated ciphertext",
            ));
        }
        initial.extend(buf[..read_len].iter().copied());
    }
    Ok(Some(out))
}

fn derive_session_key(password: &str, salt: &[u8]) -> io::Result<[u8; KEY_LEN_AES_128_GCM]> {
    struct SliceKeyType(usize);
    impl aws_lc_rs::hkdf::KeyType for SliceKeyType {
        fn len(&self) -> usize {
            self.0
        }
    }

    let master_key = evp_bytes_to_key(password, KEY_LEN_AES_128_GCM);
    let hkdf_salt =
        aws_lc_rs::hkdf::Salt::new(aws_lc_rs::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let prk = hkdf_salt.extract(&master_key);
    let okm = prk
        .expand(&[b"ss-subkey"], SliceKeyType(KEY_LEN_AES_128_GCM))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "HKDF expand failed"))?;
    let mut key = [0u8; KEY_LEN_AES_128_GCM];
    okm.fill(&mut key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "HKDF fill failed"))?;
    Ok(key)
}

fn evp_bytes_to_key(password: &str, key_len: usize) -> Vec<u8> {
    let password = password.as_bytes();
    let mut result = Vec::with_capacity(key_len);
    let mut previous: Option<[u8; 16]> = None;
    while result.len() < key_len {
        let mut context = Md5::new();
        if let Some(previous) = previous {
            context.update(previous);
        }
        context.update(password);
        let digest: [u8; 16] = context.finalize().into();
        result.extend_from_slice(&digest);
        previous = Some(digest);
    }
    result.truncate(key_len);
    result
}

#[derive(Default)]
struct IncreasingNonce([u8; NONCE_LEN]);

impl IncreasingNonce {
    fn next(&mut self) -> [u8; NONCE_LEN] {
        let ret = self.0;
        for byte in &mut self.0 {
            *byte = byte.wrapping_add(1);
            if *byte > 0 {
                break;
            }
        }
        ret
    }
}

fn write_socks_addr(host: &str, port: u16) -> io::Result<Vec<u8>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        let mut out = Vec::new();
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
        out.extend_from_slice(&port.to_be_bytes());
        return Ok(out);
    }

    let host_bytes = host.as_bytes();
    if host_bytes.len() > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target hostname is too long",
        ));
    }
    let mut out = Vec::with_capacity(1 + 1 + host_bytes.len() + 2);
    out.push(0x03);
    out.push(host_bytes.len() as u8);
    out.extend_from_slice(host_bytes);
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

fn build_obfs_request(args: &Args, body: &[u8]) -> io::Result<Vec<u8>> {
    let host_header = if args.proxy_port == 80 {
        args.obfs_host.clone()
    } else {
        format!("{}:{}", args.obfs_host, args.proxy_port)
    };
    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/7.79.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: {}\r\n\r\n",
        args.obfs_path,
        host_header,
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    Ok(request)
}

async fn read_obfs_response(stream: &mut TcpStream) -> io::Result<VecDeque<u8>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before obfs response header",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(index) = find_header_end(&buf) {
            return Ok(buf[index + 4..].iter().copied().collect());
        }
        if buf.len() > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "obfs response header too large",
            ));
        }
    }
}

fn target_authority(url: &Url) -> io::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target URL missing host"))?;
    if host.contains(':') && !host.starts_with('[') {
        Ok(format!("[{host}]"))
    } else {
        Ok(host.to_string())
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

    let host = http_host_header(url)?;
    Ok(format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: shoes-ss-obfs-e2e-client/1\r\nAccept: */*\r\n\r\n"
    )
    .into_bytes())
}

fn http_host_header(url: &Url) -> io::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target URL missing host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target URL missing port"))?;
    let default_port = match url.scheme() {
        "http" => 80,
        "https" => 443,
        _ => port,
    };
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == default_port {
        Ok(host)
    } else {
        Ok(format!("{host}:{port}"))
    }
}

fn try_extract_complete_http_body(buf: &[u8]) -> io::Result<Option<&[u8]>> {
    let Some(header_end) = find_header_end(buf) else {
        return Ok(None);
    };
    let headers = std::str::from_utf8(&buf[..header_end]).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid HTTP response header: {e}"),
        )
    })?;
    let body = &buf[header_end + 4..];
    let content_length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("content-length") {
            value.trim().parse::<usize>().ok()
        } else {
            None
        }
    });
    if let Some(content_length) = content_length {
        if body.len() >= content_length {
            return Ok(Some(&body[..content_length]));
        }
        return Ok(None);
    }
    Ok(None)
}

fn extract_http_body(buf: &[u8]) -> io::Result<&[u8]> {
    let header_end = find_header_end(buf).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP response did not contain a complete header",
        )
    })?;
    Ok(&buf[header_end + 4..])
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

async fn write_output(path: &PathBuf, body: &[u8]) -> io::Result<()> {
    tokio::fs::write(path, body).await
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut args = std::env::args().skip(1);
        let mut parsed = Args {
            proxy_host: String::new(),
            proxy_port: 0,
            method: "aes-128-gcm".to_string(),
            password: String::new(),
            obfs_host: "example.com".to_string(),
            obfs_path: "/".to_string(),
            url: Url::parse("http://127.0.0.1/").expect("static URL parses"),
            output: PathBuf::new(),
            bind: None,
            connect_timeout: Duration::from_secs(5),
            max_time: Duration::from_secs(30),
        };

        while let Some(arg) = args.next() {
            let value = match arg.as_str() {
                "--proxy-host" => &mut parsed.proxy_host,
                "--method" => &mut parsed.method,
                "--password" => &mut parsed.password,
                "--obfs-host" => &mut parsed.obfs_host,
                "--obfs-path" => &mut parsed.obfs_path,
                "--url" => {
                    let value = args
                        .next()
                        .ok_or_else(|| format!("{arg} requires a value"))?;
                    parsed.url =
                        Url::parse(&value).map_err(|e| format!("invalid --url `{value}`: {e}"))?;
                    continue;
                }
                "--output" => {
                    let value = args
                        .next()
                        .ok_or_else(|| format!("{arg} requires a value"))?;
                    parsed.output = PathBuf::from(value);
                    continue;
                }
                "--proxy-port" => {
                    let value = args
                        .next()
                        .ok_or_else(|| format!("{arg} requires a value"))?;
                    parsed.proxy_port = value
                        .parse()
                        .map_err(|e| format!("invalid --proxy-port `{value}`: {e}"))?;
                    continue;
                }
                "--bind" => {
                    let value = args
                        .next()
                        .ok_or_else(|| format!("{arg} requires a value"))?;
                    parsed.bind = Some(
                        value
                            .parse()
                            .map_err(|e| format!("invalid --bind `{value}`: {e}"))?,
                    );
                    continue;
                }
                "--connect-timeout-secs" => {
                    let value = args
                        .next()
                        .ok_or_else(|| format!("{arg} requires a value"))?;
                    parsed.connect_timeout =
                        Duration::from_secs(value.parse().map_err(|e| {
                            format!("invalid --connect-timeout-secs `{value}`: {e}")
                        })?);
                    continue;
                }
                "--max-time-secs" => {
                    let value = args
                        .next()
                        .ok_or_else(|| format!("{arg} requires a value"))?;
                    parsed.max_time = Duration::from_secs(
                        value
                            .parse()
                            .map_err(|e| format!("invalid --max-time-secs `{value}`: {e}"))?,
                    );
                    continue;
                }
                "-h" | "--help" => return Err("help requested".to_string()),
                _ => return Err(format!("unknown argument `{arg}`")),
            };
            *value = args
                .next()
                .ok_or_else(|| format!("{arg} requires a value"))?;
        }

        if parsed.proxy_host.is_empty() {
            return Err("--proxy-host is required".to_string());
        }
        if parsed.proxy_port == 0 {
            return Err("--proxy-port is required".to_string());
        }
        if parsed.password.is_empty() {
            return Err("--password is required".to_string());
        }
        if parsed.output.as_os_str().is_empty() {
            return Err("--output is required".to_string());
        }
        if !parsed.obfs_path.starts_with('/') {
            parsed.obfs_path.insert(0, '/');
        }
        Ok(parsed)
    }
}

fn usage() {
    eprintln!(
        "Usage: shoes-ss-obfs-e2e-client --proxy-host HOST --proxy-port PORT --password PASSWORD --url URL --output PATH [--method aes-128-gcm] [--obfs-host HOST] [--obfs-path PATH] [--bind IP]"
    );
}
