use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use async_trait::async_trait;
use rustc_hash::FxHashMap;

use crate::address::{NetLocation, NetLocationPortRange, ResolvedLocation};
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::{
    BindLocation, RuleConfig, ServerConfig, ServerProxyConfig, ServerQuicConfig, TcpConfig,
    Transport, WebsocketPingType, direct_allow_rule,
};
use crate::h2mux::handle_h2mux_session;
use crate::http_handler::HttpTcpServerHandler;
use crate::mixed_handler::MixedTcpServerHandler;
use crate::option_util::NoneOrSome;
use crate::port_forward_handler::PortForwardServerHandler;
use crate::quic_server::start_quic_servers;
use crate::resolver::{CachingNativeResolver, Resolver};
use crate::rustls_config_util::create_server_config;
use crate::shadow_tls::{ShadowTlsServerTarget, ShadowTlsServerTargetHandshake};
use crate::shadowsocks::{ShadowsocksCipher, ShadowsocksTcpHandler};
use crate::snell::snell_handler::SnellServerHandler;
use crate::socks_handler::SocksTcpServerHandler;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpServerHandler, TcpServerSetupResult};
use crate::tcp::tcp_server::start_tcp_handler_servers;
use crate::tls_server_handler::{TlsServerHandler, TlsServerTarget};
use crate::trojan_handler::TrojanTcpHandler;
use crate::websocket::{WebsocketServerTarget, WebsocketTcpServerHandler};

pub async fn run_snell_server(
    listen: &str,
    cipher: &str,
    password: &str,
    udp_enabled: bool,
) -> io::Result<()> {
    let listen = NetLocationPortRange::from_str(listen).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid listen address `{listen}`: {err}"),
        )
    })?;
    let cipher = cipher.try_into()?;
    let resolver: Arc<dyn Resolver> = Arc::new(CachingNativeResolver::new());
    let selector = Arc::new(create_tcp_client_proxy_selector(
        vec![RuleConfig::default()],
        resolver.clone(),
    ));
    let handler: Arc<dyn TcpServerHandler> = Arc::new(SnellServerHandler::new(
        cipher,
        password,
        udp_enabled,
        selector,
        resolver.clone(),
    ));

    let handles = start_tcp_handler_servers(
        BindLocation::Address(listen),
        TcpConfig::default(),
        handler,
        resolver,
    )
    .await?;

    tokio::signal::ctrl_c().await?;
    for handle in handles {
        handle.abort();
    }

    Ok(())
}

pub async fn run_shadowtls_socks_server(
    listen: &str,
    server_name: &str,
    password: &str,
    cert_path: &str,
    key_path: &str,
) -> io::Result<()> {
    let listen = NetLocationPortRange::from_str(listen).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid listen address `{listen}`: {err}"),
        )
    })?;
    let cert_bytes = tokio::fs::read(cert_path).await.map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to read certificate `{cert_path}`: {err}"),
        )
    })?;
    let key_bytes = tokio::fs::read(key_path).await.map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to read private key `{key_path}`: {err}"),
        )
    })?;

    let resolver: Arc<dyn Resolver> = Arc::new(CachingNativeResolver::new());
    let selector = Arc::new(create_tcp_client_proxy_selector(
        vec![RuleConfig::default()],
        resolver.clone(),
    ));
    let alpn_protocols = vec!["h2".to_string(), "http/1.1".to_string()];
    let server_config = Arc::new(create_server_config(
        &cert_bytes,
        &key_bytes,
        vec![],
        &alpn_protocols,
        &[],
    ));
    let inner_handler: Box<dyn TcpServerHandler> = Box::new(SocksTcpServerHandler::new(
        None,
        false,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        selector,
        resolver.clone(),
    ));
    let shadowtls_target = ShadowTlsServerTarget::new(
        password.to_string(),
        ShadowTlsServerTargetHandshake::new_local(server_config),
        inner_handler,
    );
    let mut sni_targets = FxHashMap::default();
    sni_targets.insert(
        server_name.to_string(),
        TlsServerTarget::ShadowTls(shadowtls_target),
    );
    let handler: Arc<dyn TcpServerHandler> = Arc::new(TlsServerHandler::new(
        sni_targets,
        None,
        None,
        resolver.clone(),
    ));

    let handles = start_tcp_handler_servers(
        BindLocation::Address(listen),
        TcpConfig::default(),
        handler,
        resolver,
    )
    .await?;

    tokio::signal::ctrl_c().await?;
    for handle in handles {
        handle.abort();
    }

    Ok(())
}

pub async fn run_basic_proxy_server(
    listen: &str,
    protocol: &str,
    port_forward_targets: &[String],
) -> io::Result<()> {
    let listen = NetLocationPortRange::from_str(listen).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid listen address `{listen}`: {err}"),
        )
    })?;
    let resolver: Arc<dyn Resolver> = Arc::new(CachingNativeResolver::new());
    let selector = Arc::new(create_tcp_client_proxy_selector(
        vec![RuleConfig::default()],
        resolver.clone(),
    ));
    let bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let handler: Arc<dyn TcpServerHandler> = match protocol {
        "socks" => Arc::new(SocksTcpServerHandler::new(
            None,
            false,
            bind_ip,
            selector,
            resolver.clone(),
        )),
        "http" => Arc::new(HttpTcpServerHandler::new(None, selector)),
        "mixed" => Arc::new(MixedTcpServerHandler::new(
            None,
            false,
            bind_ip,
            selector,
            resolver.clone(),
        )),
        "websocket-socks" => Arc::new(WebsocketTcpServerHandler::new(vec![
            WebsocketServerTarget {
                matching_path: Some("/ws".to_string()),
                matching_headers: None,
                max_early_data: None,
                early_data_header_name: None,
                ping_type: WebsocketPingType::Disabled,
                handler: Box::new(SocksTcpServerHandler::new(
                    None,
                    false,
                    bind_ip,
                    selector,
                    resolver.clone(),
                )),
            },
        ])),
        "h2mux" => Arc::new(RawH2MuxServerHandler {
            udp_enabled: false,
            proxy_selector: selector,
            resolver: resolver.clone(),
        }),
        "shadowsocks-aes128" => {
            let cipher: ShadowsocksCipher = "aes-128-gcm".try_into()?;
            Arc::new(ShadowsocksTcpHandler::new_server(
                cipher,
                "shoes-e2e-password",
                true,
                selector,
                resolver.clone(),
            ))
        }
        "shadowsocks-chacha20" => {
            let cipher: ShadowsocksCipher = "chacha20-ietf-poly1305".try_into()?;
            Arc::new(ShadowsocksTcpHandler::new_server(
                cipher,
                "shoes-e2e-password",
                true,
                selector,
                resolver.clone(),
            ))
        }
        "shadowsocks-2022-aes128" => {
            let cipher: ShadowsocksCipher = "aes-128-gcm".try_into()?;
            Arc::new(ShadowsocksTcpHandler::new_aead2022_server(
                cipher,
                &SHADOWSOCKS_2022_AES128_KEY,
                true,
                selector,
                resolver.clone(),
            ))
        }
        "trojan" => Arc::new(TrojanTcpHandler::new_server(
            "shoes-e2e-password",
            &None,
            selector,
            resolver.clone(),
        )),
        "port-forward" | "forward" => {
            if port_forward_targets.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "port-forward requires at least one --target",
                ));
            }
            let mut targets = Vec::with_capacity(port_forward_targets.len());
            for target in port_forward_targets {
                let location = NetLocation::from_str(target, None).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid port-forward target `{target}`: {err}"),
                    )
                })?;
                targets.push(location);
            }
            Arc::new(PortForwardServerHandler::new(targets, selector))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported basic proxy protocol `{protocol}`"),
            ));
        }
    };

    let handles = start_tcp_handler_servers(
        BindLocation::Address(listen),
        TcpConfig::default(),
        handler,
        resolver,
    )
    .await?;

    tokio::signal::ctrl_c().await?;
    for handle in handles {
        handle.abort();
    }

    Ok(())
}

pub async fn run_quic_proxy_server(
    listen: &str,
    protocol: &str,
    password: &str,
    uuid: Option<&str>,
    cert_path: &str,
    key_path: &str,
    zero_rtt_handshake: bool,
) -> io::Result<()> {
    let listen = NetLocationPortRange::from_str(listen).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid listen address `{listen}`: {err}"),
        )
    })?;
    let cert = tokio::fs::read_to_string(cert_path).await.map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to read certificate `{cert_path}`: {err}"),
        )
    })?;
    let key = tokio::fs::read_to_string(key_path).await.map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to read private key `{key_path}`: {err}"),
        )
    })?;

    let protocol = match protocol {
        "tuic" | "tuic-v5" | "tuicv5" => {
            let uuid = uuid.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing --uuid for TUIC")
            })?;
            ServerProxyConfig::TuicV5 {
                uuid: uuid.to_string(),
                password: password.to_string(),
                zero_rtt_handshake,
            }
        }
        "hysteria2" | "hy2" => ServerProxyConfig::Hysteria2 {
            password: password.to_string(),
            udp_enabled: true,
        },
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported QUIC e2e protocol `{other}`"),
            ));
        }
    };

    let resolver: Arc<dyn Resolver> = Arc::new(CachingNativeResolver::new());
    let config = ServerConfig {
        bind_location: BindLocation::Address(listen),
        protocol,
        transport: Transport::Quic,
        tcp_settings: None,
        quic_settings: Some(ServerQuicConfig {
            cert,
            key,
            alpn_protocols: NoneOrSome::One("h3".to_string()),
            client_ca_certs: NoneOrSome::None,
            client_fingerprints: NoneOrSome::None,
            num_endpoints: 1,
        }),
        rules: direct_allow_rule(),
        dns: None,
    };

    let handles = start_quic_servers(config, resolver).await?;

    tokio::signal::ctrl_c().await?;
    for handle in handles {
        handle.abort();
    }

    Ok(())
}

const SHADOWSOCKS_2022_AES128_KEY: [u8; 16] = [
    0x73, 0x68, 0x6f, 0x65, 0x73, 0x2d, 0x65, 0x32, 0x65, 0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x31, 0x36,
];

#[derive(Debug)]
struct RawH2MuxServerHandler {
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
}

#[async_trait]
impl TcpServerHandler for RawH2MuxServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn crate::async_stream::AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        let udp_enabled = self.udp_enabled;
        let proxy_selector = self.proxy_selector.clone();
        let resolver = self.resolver.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_h2mux_session(
                server_stream,
                None,
                udp_enabled,
                proxy_selector,
                resolver,
                None,
            )
            .await
            {
                log::debug!("raw h2mux e2e session ended: {err}");
            }
        });

        Ok(TcpServerSetupResult::AlreadyHandled)
    }
}

/// Open and hold `streams` concurrent Shadowsocks-2022 connections through a
/// server.
///
/// Everything measured about this proxy so far came from watching production,
/// which tops out in the hundreds of concurrent streams -- far below where the
/// per-stream costs actually matter. This drives the same handler stack, accept
/// path and copy loop as production so a change can be measured against a
/// reproducible load instead of inferred from a quiet node.
///
/// Pair it with `SHOES_ALLOCATOR_STATS_DUMP_INTERVAL_SECS` on the server and
/// diff the size classes with `scripts/jemalloc_size_classes.py`; divide by the
/// `streams=` counter the server reports to get cost per stream.
pub async fn run_ss2022_load_client(
    server: &str,
    target: &str,
    streams: usize,
    concurrency: usize,
    hold: std::time::Duration,
    echo_rounds: usize,
    echo_bytes: usize,
) -> io::Result<()> {
    let server_addr = tokio::net::lookup_host(server)
        .await?
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("could not resolve server `{server}`"),
            )
        })?;
    let target = NetLocation::from_str(target, None).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid target `{target}`: {err}"),
        )
    })?;

    let cipher: ShadowsocksCipher = "aes-128-gcm".try_into()?;
    let handler = Arc::new(ShadowsocksTcpHandler::new_aead2022_client(
        cipher,
        &SHADOWSOCKS_2022_AES128_KEY,
        false,
    ));

    // Bound only the handshakes in flight. The whole point is to end up with
    // `streams` connections open at once, so nothing here limits the total.
    let gate = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let established = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let failed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let nanos = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let rounds = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let reporter = {
        let established = established.clone();
        let failed = failed.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                ticker.tick().await;
                log::info!(
                    "load: established={} failed={}",
                    established.load(std::sync::atomic::Ordering::Relaxed),
                    failed.load(std::sync::atomic::Ordering::Relaxed)
                );
            }
        })
    };

    let mut tasks = Vec::with_capacity(streams);
    for _ in 0..streams {
        let gate = gate.clone();
        let handler = handler.clone();
        let target = target.clone();
        let established = established.clone();
        let failed = failed.clone();
        let bytes = bytes.clone();
        let nanos = nanos.clone();
        let rounds = rounds.clone();
        tasks.push(tokio::spawn(async move {
            let permit = gate
                .acquire_owned()
                .await
                .expect("semaphore is never closed");
            let held = match open_ss2022_stream(&handler, server_addr, target).await {
                Ok(stream) => {
                    established.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    stream
                }
                Err(error) => {
                    failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    log::debug!("load: stream failed: {error}");
                    return;
                }
            };
            // Release the handshake slot but keep the connection, so the server
            // accumulates open streams rather than churning through them.
            drop(permit);
            let mut held = held;
            if echo_rounds > 0 {
                match echo_round_trips(&mut held, echo_rounds, echo_bytes).await {
                    Ok(elapsed) => {
                        bytes.fetch_add(
                            (echo_rounds * echo_bytes * 2) as u64,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        nanos.fetch_add(elapsed, std::sync::atomic::Ordering::Relaxed);
                        rounds.fetch_add(echo_rounds as u64, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(error) => {
                        failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        log::debug!("load: echo failed: {error}");
                    }
                }
            }
            tokio::time::sleep(hold).await;
            drop(held);
        }));
    }

    for task in tasks {
        let _ = task.await;
    }
    reporter.abort();
    let total_rounds = rounds.load(std::sync::atomic::Ordering::Relaxed);
    log::info!(
        "load finished: established={} failed={}",
        established.load(std::sync::atomic::Ordering::Relaxed),
        failed.load(std::sync::atomic::Ordering::Relaxed)
    );
    let total_nanos = nanos.load(std::sync::atomic::Ordering::Relaxed);
    if let Some(mean_nanos) = total_nanos.checked_div(total_rounds)
        && total_nanos > 0
    {
        let total_bytes = bytes.load(std::sync::atomic::Ordering::Relaxed);
        log::info!(
            "echo: rounds={total_rounds} mean_rtt_us={} throughput_MiB_s={:.1}",
            mean_nanos / 1000,
            total_bytes as f64 / (total_nanos as f64 / 1e9) / (1024.0 * 1024.0)
        );
    }
    Ok(())
}

/// Round-trip `bytes` through an established stream `rounds` times, returning
/// the total nanoseconds spent waiting. Measures what a request actually costs
/// through the proxy, which holding an idle connection cannot show.
async fn echo_round_trips(
    stream: &mut Box<dyn crate::async_stream::AsyncStream>,
    rounds: usize,
    bytes: usize,
) -> io::Result<u64> {
    let payload = vec![0x5a_u8; bytes];
    let mut received = vec![0_u8; bytes];
    let started = std::time::Instant::now();
    for _ in 0..rounds {
        tokio::io::AsyncWriteExt::write_all(stream, &payload).await?;
        tokio::io::AsyncReadExt::read_exact(stream, &mut received).await?;
    }
    Ok(started.elapsed().as_nanos() as u64)
}

async fn open_ss2022_stream(
    handler: &ShadowsocksTcpHandler,
    server_addr: std::net::SocketAddr,
    target: NetLocation,
) -> io::Result<Box<dyn crate::async_stream::AsyncStream>> {
    let tcp = tokio::net::TcpStream::connect(server_addr).await?;
    tcp.set_nodelay(true)?;
    let setup = handler
        .setup_client_tcp_stream(Box::new(tcp), ResolvedLocation::new(target))
        .await?;
    Ok(setup.client_stream)
}

/// A destination that accepts connections and holds them open.
///
/// The load client needs somewhere to be proxied *to*; without this the server
/// would be measured against whatever the outbound happened to reach.
pub async fn run_tcp_sink(listen: &str) -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    log::info!("sink listening on {}", listener.local_addr()?);
    let held = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    loop {
        let (stream, _) = listener.accept().await?;
        let held = held.clone();
        tokio::spawn(async move {
            held.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Hold it open and consume anything sent, so the proxied stream
            // stays established instead of completing immediately.
            let mut stream = stream;
            let mut buffer = vec![0_u8; 65536];
            loop {
                match tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await {
                    Ok(0) | Err(_) => break,
                    // Echo, so a client can time a round trip through the proxy
                    // rather than only hold the connection open.
                    Ok(read) => {
                        if tokio::io::AsyncWriteExt::write_all(&mut stream, &buffer[..read])
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            held.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
    }
}
