#![cfg(feature = "internal-bench")]

use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    let args = match Args::parse() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}");
            usage();
            std::process::exit(2);
        }
    };

    match run(args).await {
        Ok(summary) => {
            println!("{}", summary.to_json());
            if summary.failures > 0 {
                std::process::exit(1);
            }
        }
        Err(err) => {
            eprintln!("basic proxy perf client failed: {err}");
            std::process::exit(1);
        }
    }
}

#[derive(Debug)]
struct Args {
    proxy_host: String,
    proxy_port: u16,
    protocol: ClientProtocol,
    target_host: String,
    target_port: u16,
    path: String,
    requests: u64,
    concurrency: u64,
}

impl Args {
    fn parse() -> io::Result<Self> {
        let mut args = std::env::args().skip(1);
        let mut proxy_host = None;
        let mut proxy_port = None;
        let mut protocol = None;
        let mut target_host = None;
        let mut target_port = None;
        let mut path = "/payload.bin".to_string();
        let mut requests = 200;
        let mut concurrency = 20;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--proxy-host" => proxy_host = Some(next_value(&mut args, "--proxy-host")?),
                "--proxy-port" => {
                    proxy_port = Some(parse_u16(&next_value(&mut args, "--proxy-port")?)?)
                }
                "--protocol" => {
                    protocol = Some(ClientProtocol::from_str(&next_value(
                        &mut args,
                        "--protocol",
                    )?)?)
                }
                "--target-host" => target_host = Some(next_value(&mut args, "--target-host")?),
                "--target-port" => {
                    target_port = Some(parse_u16(&next_value(&mut args, "--target-port")?)?)
                }
                "--path" => path = next_value(&mut args, "--path")?,
                "--requests" => requests = parse_u64(&next_value(&mut args, "--requests")?)?,
                "--concurrency" => {
                    concurrency = parse_u64(&next_value(&mut args, "--concurrency")?)?
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

        if requests == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--requests must be greater than zero",
            ));
        }
        if concurrency == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--concurrency must be greater than zero",
            ));
        }

        Ok(Self {
            proxy_host: proxy_host.ok_or_else(|| missing("--proxy-host"))?,
            proxy_port: proxy_port.ok_or_else(|| missing("--proxy-port"))?,
            protocol: protocol.ok_or_else(|| missing("--protocol"))?,
            target_host: target_host.ok_or_else(|| missing("--target-host"))?,
            target_port: target_port.ok_or_else(|| missing("--target-port"))?,
            path,
            requests,
            concurrency,
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum ClientProtocol {
    Direct,
    Http,
    Socks,
}

impl FromStr for ClientProtocol {
    type Err = io::Error;

    fn from_str(value: &str) -> io::Result<Self> {
        match value {
            "direct" => Ok(Self::Direct),
            "http" => Ok(Self::Http),
            "socks" => Ok(Self::Socks),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported protocol `{value}`"),
            )),
        }
    }
}

#[derive(Default)]
struct WorkerResult {
    latencies_us: Vec<u128>,
    bytes: u64,
    failures: u64,
}

struct Summary {
    protocol: ClientProtocol,
    requests: u64,
    concurrency: u64,
    elapsed_ms: f64,
    successes: u64,
    failures: u64,
    bytes: u64,
    throughput_mib_s: f64,
    requests_per_sec: f64,
    latency_p50_ms: f64,
    latency_p95_ms: f64,
    latency_p99_ms: f64,
    latency_max_ms: f64,
}

impl Summary {
    fn to_json(&self) -> serde_json::Value {
        json!({
            "protocol": self.protocol.as_str(),
            "requests": self.requests,
            "concurrency": self.concurrency,
            "elapsed_ms": round3(self.elapsed_ms),
            "successes": self.successes,
            "failures": self.failures,
            "bytes": self.bytes,
            "throughput_mib_s": round3(self.throughput_mib_s),
            "requests_per_sec": round3(self.requests_per_sec),
            "latency_p50_ms": round3(self.latency_p50_ms),
            "latency_p95_ms": round3(self.latency_p95_ms),
            "latency_p99_ms": round3(self.latency_p99_ms),
            "latency_max_ms": round3(self.latency_max_ms),
        })
    }
}

impl ClientProtocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Http => "http",
            Self::Socks => "socks",
        }
    }
}

async fn run(args: Args) -> io::Result<Summary> {
    let args = Arc::new(args);
    let next_request = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    let mut handles = Vec::new();

    for _ in 0..args.concurrency {
        let args = args.clone();
        let next_request = next_request.clone();
        handles.push(tokio::spawn(async move {
            let mut result = WorkerResult::default();
            loop {
                let request = next_request.fetch_add(1, Ordering::Relaxed);
                if request >= args.requests {
                    break;
                }
                let started = Instant::now();
                match fetch_once(&args).await {
                    Ok(bytes) => {
                        result.latencies_us.push(started.elapsed().as_micros());
                        result.bytes += bytes;
                    }
                    Err(err) => {
                        result.failures += 1;
                        eprintln!("request {request} failed: {err}");
                    }
                }
            }
            result
        }));
    }

    let mut aggregate = WorkerResult::default();
    for handle in handles {
        let result = handle.await.map_err(io::Error::other)?;
        aggregate.bytes += result.bytes;
        aggregate.failures += result.failures;
        aggregate.latencies_us.extend(result.latencies_us);
    }

    let elapsed = started.elapsed();
    aggregate.latencies_us.sort_unstable();
    let successes = aggregate.latencies_us.len() as u64;
    let elapsed_secs = elapsed.as_secs_f64();
    Ok(Summary {
        protocol: args.protocol,
        requests: args.requests,
        concurrency: args.concurrency,
        elapsed_ms: elapsed_secs * 1000.0,
        successes,
        failures: aggregate.failures,
        bytes: aggregate.bytes,
        throughput_mib_s: aggregate.bytes as f64 / 1024.0 / 1024.0 / elapsed_secs,
        requests_per_sec: successes as f64 / elapsed_secs,
        latency_p50_ms: percentile_ms(&aggregate.latencies_us, 0.50),
        latency_p95_ms: percentile_ms(&aggregate.latencies_us, 0.95),
        latency_p99_ms: percentile_ms(&aggregate.latencies_us, 0.99),
        latency_max_ms: aggregate
            .latencies_us
            .last()
            .map(|value| *value as f64 / 1000.0)
            .unwrap_or(0.0),
    })
}

async fn fetch_once(args: &Args) -> io::Result<u64> {
    let connect_addr = match args.protocol {
        ClientProtocol::Direct => (args.target_host.as_str(), args.target_port),
        ClientProtocol::Http | ClientProtocol::Socks => (args.proxy_host.as_str(), args.proxy_port),
    };
    let mut stream = TcpStream::connect(connect_addr).await?;
    stream.set_nodelay(true)?;
    match args.protocol {
        ClientProtocol::Direct => send_origin_http_request(&mut stream, args).await?,
        ClientProtocol::Http => send_http_proxy_request(&mut stream, args).await?,
        ClientProtocol::Socks => {
            send_socks_connect(&mut stream, args).await?;
            send_origin_http_request(&mut stream, args).await?;
        }
    }
    read_http_response_body(stream).await
}

async fn send_http_proxy_request(stream: &mut TcpStream, args: &Args) -> io::Result<()> {
    let target = format!("{}:{}", args.target_host, args.target_port);
    let request = format!(
        "GET http://{}{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: shoes-basic-proxy-perf-client/1\r\nAccept: */*\r\n\r\n",
        target, args.path, target
    );
    stream.write_all(request.as_bytes()).await
}

async fn send_origin_http_request(stream: &mut TcpStream, args: &Args) -> io::Result<()> {
    let target = format!("{}:{}", args.target_host, args.target_port);
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: shoes-basic-proxy-perf-client/1\r\nAccept: */*\r\n\r\n",
        args.path, target
    );
    stream.write_all(request.as_bytes()).await
}

async fn send_socks_connect(stream: &mut TcpStream, args: &Args) -> io::Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0; 2];
    stream.read_exact(&mut method).await?;
    if method != [0x05, 0x00] {
        return Err(io::Error::other(format!(
            "SOCKS method negotiation failed: {method:?}"
        )));
    }

    let mut request = Vec::with_capacity(32 + args.target_host.len());
    request.extend_from_slice(&[0x05, 0x01, 0x00]);
    if let Ok(ip) = args.target_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ip) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
        }
    } else {
        let host = args.target_host.as_bytes();
        if host.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS target hostname is too long",
            ));
        }
        request.push(0x03);
        request.push(host.len() as u8);
        request.extend_from_slice(host);
    }
    request.extend_from_slice(&args.target_port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS connect failed: response={head:?}"
        )));
    }
    match head[3] {
        0x01 => read_exact_discard(stream, 6).await,
        0x03 => {
            let mut len = [0; 1];
            stream.read_exact(&mut len).await?;
            read_exact_discard(stream, len[0] as usize + 2).await
        }
        0x04 => read_exact_discard(stream, 18).await,
        atyp => Err(io::Error::other(format!(
            "SOCKS connect returned invalid atyp {atyp}"
        ))),
    }
}

async fn read_exact_discard(stream: &mut TcpStream, len: usize) -> io::Result<()> {
    let mut remaining = len;
    let mut buf = [0; 64];
    while remaining > 0 {
        let chunk = remaining.min(buf.len());
        stream.read_exact(&mut buf[..chunk]).await?;
        remaining -= chunk;
    }
    Ok(())
}

async fn read_http_response_body(mut stream: TcpStream) -> io::Result<u64> {
    let mut header = Vec::with_capacity(1024);
    let mut body_bytes = 0u64;
    let mut status_checked = false;
    let mut buf = [0; 32 * 1024];

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(body_bytes);
        }

        if status_checked {
            body_bytes += n as u64;
            continue;
        }

        header.extend_from_slice(&buf[..n]);
        if header.len() > 64 * 1024 {
            return Err(io::Error::other("HTTP response header exceeded 64 KiB"));
        }

        if let Some(header_end) = find_header_end(&header) {
            validate_http_status(&header[..header_end])?;
            body_bytes += (header.len() - header_end - 4) as u64;
            status_checked = true;
        }
    }
}

fn validate_http_status(header: &[u8]) -> io::Result<()> {
    let end = header
        .iter()
        .position(|byte| *byte == b'\r' || *byte == b'\n')
        .unwrap_or(header.len());
    let status_line = std::str::from_utf8(&header[..end]).map_err(io::Error::other)?;
    if status_line.starts_with("HTTP/1.") && status_line.contains(" 200 ") {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "unexpected HTTP status line `{status_line}`"
        )))
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn percentile_ms(sorted_us: &[u128], pct: f64) -> f64 {
    if sorted_us.is_empty() {
        return 0.0;
    }
    let idx = ((sorted_us.len() - 1) as f64 * pct).round() as usize;
    sorted_us[idx] as f64 / 1000.0
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn next_value(args: &mut impl Iterator<Item = String>, name: &str) -> io::Result<String> {
    args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing value for {name}"),
        )
    })
}

fn parse_u16(value: &str) -> io::Result<u16> {
    value.parse().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid u16 `{value}`: {err}"),
        )
    })
}

fn parse_u64(value: &str) -> io::Result<u64> {
    value.parse().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid u64 `{value}`: {err}"),
        )
    })
}

fn missing(name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("missing {name}"))
}

fn usage() {
    eprintln!(
        "Usage: shoes-basic-proxy-perf-client --proxy-host HOST --proxy-port PORT --protocol direct|http|socks --target-host HOST --target-port PORT [--path PATH] [--requests N] [--concurrency N]"
    );
}
