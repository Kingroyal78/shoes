#![cfg(feature = "internal-bench")]

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

    if let Err(err) = run(args).await {
        eprintln!("static HTTP perf server failed: {err}");
        std::process::exit(1);
    }
}

#[derive(Debug)]
struct Args {
    listen: String,
    payload_kib: usize,
}

impl Args {
    fn parse() -> io::Result<Self> {
        let mut args = std::env::args().skip(1);
        let mut listen = None;
        let mut payload_kib = 1024;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--listen" => listen = Some(next_value(&mut args, "--listen")?),
                "--payload-kib" => {
                    payload_kib = parse_usize(&next_value(&mut args, "--payload-kib")?)?
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

        if payload_kib == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--payload-kib must be greater than zero",
            ));
        }

        Ok(Self {
            listen: listen.ok_or_else(|| missing("--listen"))?,
            payload_kib,
        })
    }
}

async fn run(args: Args) -> io::Result<()> {
    let listener = TcpListener::bind(&args.listen).await?;
    let payload = Arc::new(payload(args.payload_kib));
    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let payload = payload.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, payload).await {
                log_error(err);
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, payload: Arc<Vec<u8>>) -> io::Result<()> {
    read_request_headers(&mut stream).await?;
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\n\r\n",
        payload.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(&payload).await?;
    stream.shutdown().await
}

async fn read_request_headers(stream: &mut TcpStream) -> io::Result<()> {
    let mut buf = [0; 4096];
    let mut header = Vec::with_capacity(1024);
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client closed before request headers completed",
            ));
        }
        header.extend_from_slice(&buf[..n]);
        if header.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(());
        }
        if header.len() > 64 * 1024 {
            return Err(io::Error::other("request header exceeded 64 KiB"));
        }
    }
}

fn payload(kib: usize) -> Vec<u8> {
    let size = kib * 1024;
    (0..size).map(|i| ((i * 17 + 23) % 256) as u8).collect()
}

fn log_error(err: io::Error) {
    if err.kind() != io::ErrorKind::ConnectionReset
        && err.kind() != io::ErrorKind::BrokenPipe
        && err.kind() != io::ErrorKind::UnexpectedEof
    {
        eprintln!("static HTTP perf connection failed: {err}");
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, name: &str) -> io::Result<String> {
    args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing value for {name}"),
        )
    })
}

fn parse_usize(value: &str) -> io::Result<usize> {
    value.parse().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid usize `{value}`: {err}"),
        )
    })
}

fn missing(name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("missing {name}"))
}

fn usage() {
    eprintln!("Usage: shoes-static-http-perf-server --listen HOST:PORT [--payload-kib N]");
}
