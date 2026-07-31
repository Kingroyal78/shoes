#![cfg(feature = "e2e-client")]

use std::io;

#[tokio::main]
async fn main() {
    init_logging();

    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}");
            print_usage();
            std::process::exit(2);
        }
    };

    if let Err(err) = shoes::e2e_server::run_shadowtls_socks_server(
        &args.listen,
        &args.server_name,
        &args.password,
        &args.cert,
        &args.key,
    )
    .await
    {
        eprintln!("shadowtls e2e server failed: {err}");
        std::process::exit(1);
    }
}

fn init_logging() {
    shoes::logging::init_multi_logger(
        vec![Box::new(shoes::logging::StderrWriter)],
        shoes::logging::resolve_directives(),
    );
}

struct Args {
    listen: String,
    server_name: String,
    password: String,
    cert: String,
    key: String,
}

fn parse_args() -> io::Result<Args> {
    let mut listen = None;
    let mut server_name = None;
    let mut password = None;
    let mut cert = None;
    let mut key = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = Some(next_value(&mut args, "--listen")?),
            "--server-name" => server_name = Some(next_value(&mut args, "--server-name")?),
            "--password" => password = Some(next_value(&mut args, "--password")?),
            "--cert" => cert = Some(next_value(&mut args, "--cert")?),
            "--key" => key = Some(next_value(&mut args, "--key")?),
            "--help" | "-h" => {
                print_usage();
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

    Ok(Args {
        listen: listen.ok_or_else(|| missing("--listen"))?,
        server_name: server_name.ok_or_else(|| missing("--server-name"))?,
        password: password.ok_or_else(|| missing("--password"))?,
        cert: cert.ok_or_else(|| missing("--cert"))?,
        key: key.ok_or_else(|| missing("--key"))?,
    })
}

fn next_value(args: &mut impl Iterator<Item = String>, name: &str) -> io::Result<String> {
    args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing value for {name}"),
        )
    })
}

fn missing(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("missing required argument {name}"),
    )
}

fn print_usage() {
    eprintln!(
        "Usage: shoes-shadowtls-e2e-server --listen HOST:PORT --server-name NAME --password PASS --cert CERT_PEM --key KEY_PEM"
    );
}
