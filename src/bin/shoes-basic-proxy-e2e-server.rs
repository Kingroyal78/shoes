#![cfg(feature = "e2e-client")]

use std::io;

// The bench server measures memory with the same allocator as production so
// jemalloc statistics reflect the real heap (allocated vs retained).
#[cfg(not(any(target_env = "msvc", target_os = "ios", target_os = "android")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[tokio::main]
async fn main() {
    init_logging();
    shoes::alloc_stats::start_allocator_stats_logger();

    let args = match Args::parse() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}");
            usage();
            std::process::exit(2);
        }
    };

    if let Err(err) =
        shoes::e2e_server::run_basic_proxy_server(&args.listen, &args.protocol, &args.targets).await
    {
        eprintln!("basic proxy e2e server failed: {err}");
        std::process::exit(1);
    }
}

fn init_logging() {
    shoes::logging::init_multi_logger(
        vec![Box::new(shoes::logging::StderrWriter)],
        shoes::logging::resolve_directives(),
    );
}

#[derive(Debug)]
struct Args {
    listen: String,
    protocol: String,
    targets: Vec<String>,
}

impl Args {
    fn parse() -> io::Result<Self> {
        let mut args = std::env::args().skip(1);
        let mut listen = None;
        let mut protocol = None;
        let mut targets = Vec::new();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--listen" => listen = Some(next_value(&mut args, "--listen")?),
                "--protocol" => protocol = Some(next_value(&mut args, "--protocol")?),
                "--target" => targets.push(next_value(&mut args, "--target")?),
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

        Ok(Self {
            listen: listen
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing --listen"))?,
            protocol: protocol
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing --protocol"))?,
            targets,
        })
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

fn usage() {
    eprintln!(
        "Usage: shoes-basic-proxy-e2e-server --listen HOST:PORT --protocol socks|http|mixed|websocket-socks|h2mux|shadowsocks-aes128|shadowsocks-chacha20|shadowsocks-2022-aes128|trojan|port-forward [--target HOST:PORT ...]"
    );
}
