#![cfg(feature = "e2e-client")]

//! Load generator for the Shadowsocks-2022 server path.
//!
//! Two modes, because the client needs somewhere to be proxied to:
//!   --sink <addr>            accept connections and hold them open
//!   --server <addr> ...      open and hold N proxied streams
//!
//! Typical run, all on one host:
//!   shoes-ss2022-load --sink 127.0.0.1:9000
//!   SHOES_ALLOCATOR_STATS_INTERVAL_SECS=5 \
//!     SHOES_ALLOCATOR_STATS_DUMP_INTERVAL_SECS=60 \
//!     shoes-basic-proxy-e2e-server --listen 127.0.0.1:8388 \
//!     --protocol shadowsocks-2022-aes128
//!   shoes-ss2022-load --server 127.0.0.1:8388 --target 127.0.0.1:9000 \
//!     --streams 20000 --concurrency 500 --hold-secs 300

use std::io;
use std::time::Duration;

#[tokio::main]
async fn main() {
    shoes::logging::init_multi_logger(
        vec![Box::new(shoes::logging::StderrWriter)],
        shoes::logging::resolve_directives(),
    );

    let args = match Args::parse() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}");
            usage();
            std::process::exit(2);
        }
    };

    let result = match args.sink {
        Some(listen) => shoes::e2e_server::run_tcp_sink(&listen).await,
        None => {
            shoes::e2e_server::run_ss2022_load_client(
                &args.server,
                &args.target,
                args.streams,
                args.concurrency,
                Duration::from_secs(args.hold_secs),
                args.echo_rounds,
                args.echo_bytes,
            )
            .await
        }
    };

    if let Err(err) = result {
        eprintln!("ss2022 load failed: {err}");
        std::process::exit(1);
    }
}

#[derive(Debug)]
struct Args {
    sink: Option<String>,
    server: String,
    target: String,
    streams: usize,
    concurrency: usize,
    hold_secs: u64,
    echo_rounds: usize,
    echo_bytes: usize,
}

impl Args {
    fn parse() -> io::Result<Self> {
        let mut args = std::env::args().skip(1);
        let mut sink = None;
        let mut server = None;
        let mut target = None;
        let mut streams = 1000_usize;
        let mut concurrency = 200_usize;
        let mut hold_secs = 120_u64;
        let mut echo_rounds = 0_usize;
        let mut echo_bytes = 1024_usize;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--sink" => sink = Some(next_value(&mut args, "--sink")?),
                "--server" => server = Some(next_value(&mut args, "--server")?),
                "--target" => target = Some(next_value(&mut args, "--target")?),
                "--streams" => streams = parse_number(&mut args, "--streams")?,
                "--concurrency" => concurrency = parse_number(&mut args, "--concurrency")?,
                "--hold-secs" => hold_secs = parse_number(&mut args, "--hold-secs")? as u64,
                "--echo-rounds" => echo_rounds = parse_number(&mut args, "--echo-rounds")?,
                "--echo-bytes" => echo_bytes = parse_number(&mut args, "--echo-bytes")?,
                "-h" | "--help" => {
                    usage();
                    std::process::exit(0);
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unknown argument `{other}`"),
                    ));
                }
            }
        }

        if sink.is_some() {
            return Ok(Self {
                sink,
                server: String::new(),
                target: String::new(),
                streams,
                concurrency,
                hold_secs,
                echo_rounds,
                echo_bytes,
            });
        }

        Ok(Self {
            sink: None,
            server: server.ok_or_else(|| missing("--server"))?,
            target: target.ok_or_else(|| missing("--target"))?,
            streams,
            concurrency,
            hold_secs,
            echo_rounds,
            echo_bytes,
        })
    }
}

fn missing(flag: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("missing required argument `{flag}`"),
    )
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> io::Result<String> {
    args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{flag}` requires a value"),
        )
    })
}

fn parse_number(args: &mut impl Iterator<Item = String>, flag: &str) -> io::Result<usize> {
    next_value(args, flag)?.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{flag}` requires a number"),
        )
    })
}

fn usage() {
    eprintln!(
        "usage:\n  \
         shoes-ss2022-load --sink <listen>\n  \
         shoes-ss2022-load --server <addr> --target <addr> \
         [--streams N] [--concurrency N] [--hold-secs N]"
    );
}
