use std::io;

#[derive(Debug)]
struct Args {
    listen: String,
    cipher: String,
    password: String,
    udp_enabled: bool,
}

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

    if let Err(err) = shoes::e2e_server::run_snell_server(
        &args.listen,
        &args.cipher,
        &args.password,
        args.udp_enabled,
    )
    .await
    {
        eprintln!("snell e2e server failed: {err}");
        std::process::exit(1);
    }
}

fn init_logging() {
    shoes::logging::init_multi_logger(
        vec![Box::new(shoes::logging::StderrWriter)],
        shoes::logging::resolve_directives(),
    );
}

impl Args {
    fn parse() -> io::Result<Self> {
        let mut args = std::env::args().skip(1);
        let mut listen = None;
        let mut cipher = "chacha20-ietf-poly1305".to_string();
        let mut password = None;
        let mut udp_enabled = true;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--listen" => listen = Some(next_value(&mut args, "--listen")?),
                "--cipher" => cipher = next_value(&mut args, "--cipher")?,
                "--password" => password = Some(next_value(&mut args, "--password")?),
                "--udp-enabled" => {
                    udp_enabled = parse_bool(&next_value(&mut args, "--udp-enabled")?)?
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
            cipher,
            password: password
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing --password"))?,
            udp_enabled,
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
        "Usage: shoes-snell-e2e-server --listen HOST:PORT --password PASSWORD [--cipher CIPHER] [--udp-enabled true|false]"
    );
}
