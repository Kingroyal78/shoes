#![allow(dead_code, unused_imports)]

mod address;
mod alloc_stats;
mod anytls;
mod app;
mod async_stream;
mod backend_config;
mod buf_reader;
mod client_proxy_chain;
mod client_proxy_selector;
mod config;
mod copy_bidirectional;
mod copy_bidirectional_message;
mod crypto;
mod dns;
mod h2mux;
mod http_handler;
mod hysteria2_obfs;
mod hysteria2_server;
mod logging;
mod mixed_handler;
mod naiveproxy;
mod option_util;
mod port_forward_handler;
mod protocol_sniff;
mod quic_server;
mod quic_stream;
mod reality;
mod reality_client_handler;
mod resolver;
mod routing;
mod rustls_config_util;
mod rustls_connection_util;
mod shadow_tls;
mod shadowsocks;
mod shared_users;
mod slide_buffer;
mod snell;
mod socket_util;
mod socks5_udp_relay;
mod socks_handler;
mod ss_plugins;
mod stream_reader;
mod sync_adapter;
mod tcp;
mod thread_util;
mod tls_client_handler;
mod tls_server_handler;
mod trojan_handler;
mod tuic_server;
#[cfg(unix)]
mod tun;
mod udp_message_stream;
mod uot;
mod util;
mod uuid_util;
mod v2board;
mod vless;
mod vmess;
mod websocket;
mod xudp;

#[cfg(not(any(target_env = "msvc", target_os = "ios", target_os = "android")))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(any(target_env = "msvc", target_os = "ios", target_os = "android")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use log::LevelFilter;
use tokio::runtime::Builder;

use crate::backend_config::AppConfig;
use crate::logging::{Directive, LogWriter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Run,
    Validate,
    SyncOnce,
}

struct Cli {
    command: Command,
    config_path: String,
    threads: usize,
    log_files: Vec<String>,
}

fn main() {
    init_rustls_provider();

    let cli = parse_cli();
    init_logging(&cli);

    if cli.command == Command::Run {
        match socket_util::raise_open_file_limit() {
            Some(limit) => log::info!("open file limit: {limit}"),
            None => log::warn!("could not determine the open file limit"),
        }
    }

    let num_threads = if cli.threads == 0 {
        std::cmp::max(
            2,
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
        )
    } else {
        cli.threads
    };
    thread_util::set_num_threads(num_threads);

    let mut builder = if num_threads == 1 {
        Builder::new_current_thread()
    } else {
        let mut mt = Builder::new_multi_thread();
        mt.worker_threads(num_threads);
        mt
    };

    let runtime = builder
        .enable_io()
        .enable_time()
        .build()
        .expect("could not build tokio runtime");

    let result = runtime.block_on(async move {
        if cli.command == Command::Run {
            crate::alloc_stats::start_allocator_stats_logger();
        }
        match cli.command {
            Command::Run => app::run(&cli.config_path, num_threads).await,
            Command::Validate => app::validate(&cli.config_path).await,
            Command::SyncOnce => app::sync_once(&cli.config_path).await,
        }
    });

    if let Err(e) = result {
        eprintln!("shoes failed: {e}");
        std::process::exit(1);
    }
}

fn init_rustls_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn parse_cli() -> Cli {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("shoes {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_usage_and_exit(0);
    }

    let command = if args
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "run" | "validate" | "sync-once"))
    {
        match args.remove(0).as_str() {
            "run" => Command::Run,
            "validate" => Command::Validate,
            "sync-once" => Command::SyncOnce,
            _ => unreachable!(),
        }
    } else {
        Command::Run
    };

    let mut config_path = "/etc/shoes/config.yml".to_string();
    let mut threads = 0usize;
    let mut log_files = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --config");
                    print_usage_and_exit(1);
                }
                config_path = args[i].clone();
            }
            "-t" | "--threads" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --threads");
                    print_usage_and_exit(1);
                }
                threads = args[i].parse().unwrap_or_else(|e| {
                    eprintln!("invalid thread count `{}`: {e}", args[i]);
                    print_usage_and_exit(1);
                });
            }
            "-l" | "--log-file" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --log-file");
                    print_usage_and_exit(1);
                }
                log_files.push(args[i].clone());
            }
            other => {
                eprintln!("unknown argument `{other}`");
                print_usage_and_exit(1);
            }
        }
        i += 1;
    }

    Cli {
        command,
        config_path,
        threads,
        log_files,
    }
}

fn print_usage_and_exit(code: i32) -> ! {
    eprintln!("Usage: shoes [run|validate|sync-once] -c /etc/shoes/config.yml [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -c, --config PATH      V2Board backend config path");
    eprintln!("  -t, --threads NUM      Tokio worker threads");
    eprintln!("  -l, --log-file PATH    Additional log file, `-` keeps stderr");
    eprintln!("  -V, --version          Print version");
    std::process::exit(code);
}

fn init_logging(cli: &Cli) {
    let mut writers: Vec<Box<dyn LogWriter>> = Vec::new();

    let config_log = std::fs::read_to_string(&cli.config_path)
        .ok()
        .and_then(|raw| serde_yaml::from_str::<AppConfig>(&raw).ok())
        .map(|config| config.log);

    let mut log_files = cli.log_files.clone();
    if let Some(log) = &config_log
        && let Some(file) = &log.file
    {
        log_files.push(file.clone());
    }

    if log_files.is_empty() || log_files.iter().any(|path| path == "-") {
        writers.push(Box::new(logging::StderrWriter));
    }
    for path in &log_files {
        if path == "-" {
            continue;
        }
        match logging::FileLogWriter::new(path) {
            Ok(writer) => writers.push(Box::new(writer)),
            Err(e) => {
                eprintln!("failed to open log file {path}: {e}");
                std::process::exit(1);
            }
        }
    }

    let directives = if let Some(log) = config_log
        && let Some(level) = logging::parse_log_level(&log.level)
    {
        vec![Directive { name: None, level }]
    } else if std::env::var("RUST_LOG").is_err() {
        vec![Directive {
            name: None,
            level: LevelFilter::Info,
        }]
    } else {
        logging::resolve_directives()
    };

    logging::init_multi_logger(writers, directives);
}
