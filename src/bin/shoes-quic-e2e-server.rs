#![cfg(feature = "e2e-client")]

use std::io;

#[tokio::main]
async fn main() {
    init_logging();

    let args = match Args::parse() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}");
            usage();
            std::process::exit(2);
        }
    };

    if let Err(err) = shoes::e2e_server::run_quic_proxy_server(
        &args.listen,
        &args.protocol,
        &args.password,
        args.uuid.as_deref(),
        &args.cert,
        &args.key,
        args.zero_rtt_handshake,
    )
    .await
    {
        eprintln!("QUIC e2e server failed: {err}");
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
    password: String,
    uuid: Option<String>,
    cert: String,
    key: String,
    zero_rtt_handshake: bool,
}

impl Args {
    fn parse() -> io::Result<Self> {
        let mut args = std::env::args().skip(1);
        let mut listen = None;
        let mut protocol = None;
        let mut password = None;
        let mut uuid = None;
        let mut cert = None;
        let mut key = None;
        let mut zero_rtt_handshake = false;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--listen" => listen = Some(next_value(&mut args, "--listen")?),
                "--protocol" => protocol = Some(next_value(&mut args, "--protocol")?),
                "--password" => password = Some(next_value(&mut args, "--password")?),
                "--uuid" => uuid = Some(next_value(&mut args, "--uuid")?),
                "--cert" => cert = Some(next_value(&mut args, "--cert")?),
                "--key" => key = Some(next_value(&mut args, "--key")?),
                "--zero-rtt-handshake" => {
                    zero_rtt_handshake =
                        parse_bool(&next_value(&mut args, "--zero-rtt-handshake")?)?
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

        Ok(Self {
            listen: listen
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing --listen"))?,
            protocol: protocol
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing --protocol"))?,
            password: password
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing --password"))?,
            uuid,
            cert: cert
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing --cert"))?,
            key: key.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing --key"))?,
            zero_rtt_handshake,
        })
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> io::Result<String> {
    args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing value for {flag}"),
        )
    })
}

fn parse_bool(value: &str) -> io::Result<bool> {
    match value {
        "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON" => Ok(true),
        "0" | "false" | "FALSE" | "no" | "NO" | "off" | "OFF" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid boolean `{value}`"),
        )),
    }
}

fn usage() {
    eprintln!(
        "Usage: shoes-quic-e2e-server --listen HOST:PORT --protocol tuic|hysteria2 --password PASSWORD --cert CERT --key KEY [--uuid UUID] [--zero-rtt-handshake true|false]"
    );
}
