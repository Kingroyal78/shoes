use std::sync::Arc;

use async_trait::async_trait;
use log::debug;
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::crypto::CryptoTlsStream;
use crate::h2mux::{MUX_DESTINATION_HOST, MUX_DESTINATION_PORT, handle_h2mux_session};
use crate::resolver::Resolver;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    AuthenticatedUser, ServerUser, TcpServerHandler, TcpServerSetupResult,
};
use crate::util::write_all;
use crate::uuid_util::parse_uuid;
use crate::xudp::XudpMessageStream;

use super::vision_stream::VisionStream;
use super::vless_message_stream::VlessMessageStream;
use super::vless_util::{
    COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, XTLS_VISION_FLOW, parse_addons_from_reader,
    parse_remote_location_from_reader,
};

pub struct VlessTcpServerHandler {
    users: Vec<(Box<[u8]>, Option<AuthenticatedUser>)>,
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    fallback: Option<NetLocation>,
    outbound_dispatcher: Option<Arc<crate::v2board::outbound::dispatcher::OutboundDispatcher>>,
}

impl VlessTcpServerHandler {
    /// Attaches the node-side outbound dispatcher used for the TCP forward
    /// dial. `None` (the default) keeps the legacy selector direct dial.
    pub fn with_outbound_dispatcher(
        mut self,
        outbound_dispatcher: Option<Arc<crate::v2board::outbound::dispatcher::OutboundDispatcher>>,
    ) -> Self {
        self.outbound_dispatcher = outbound_dispatcher;
        self
    }
}

pub trait VlessVisionUserLookup {
    fn lookup_vless_vision_user(&self, target_id: &[u8]) -> Option<Option<AuthenticatedUser>>;
}

impl VlessVisionUserLookup for &[u8] {
    fn lookup_vless_vision_user(&self, target_id: &[u8]) -> Option<Option<AuthenticatedUser>> {
        if self.ct_eq(target_id).unwrap_u8() == 1 {
            Some(None)
        } else {
            None
        }
    }
}

impl VlessVisionUserLookup for &Box<[u8]> {
    fn lookup_vless_vision_user(&self, target_id: &[u8]) -> Option<Option<AuthenticatedUser>> {
        self.as_ref().lookup_vless_vision_user(target_id)
    }
}

impl VlessVisionUserLookup for &[(Box<[u8]>, Option<AuthenticatedUser>)] {
    fn lookup_vless_vision_user(&self, target_id: &[u8]) -> Option<Option<AuthenticatedUser>> {
        self.iter().find_map(|(user_id, authenticated_user)| {
            if user_id.ct_eq(target_id).unwrap_u8() == 1 {
                Some(authenticated_user.clone())
            } else {
                None
            }
        })
    }
}

impl VlessVisionUserLookup for &Vec<(Box<[u8]>, Option<AuthenticatedUser>)> {
    fn lookup_vless_vision_user(&self, target_id: &[u8]) -> Option<Option<AuthenticatedUser>> {
        self.as_slice().lookup_vless_vision_user(target_id)
    }
}

impl VlessVisionUserLookup for Vec<(Box<[u8]>, Option<AuthenticatedUser>)> {
    fn lookup_vless_vision_user(&self, target_id: &[u8]) -> Option<Option<AuthenticatedUser>> {
        self.as_slice().lookup_vless_vision_user(target_id)
    }
}

impl std::fmt::Debug for VlessTcpServerHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessTcpServerHandler")
            .field("user_count", &self.users.len())
            .field("udp_enabled", &self.udp_enabled)
            .field("fallback", &self.fallback)
            .finish()
    }
}

impl VlessTcpServerHandler {
    pub fn new(
        user_id: &str,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        fallback: Option<NetLocation>,
    ) -> Self {
        Self {
            users: vec![(parse_uuid(user_id).unwrap().into_boxed_slice(), None)],
            udp_enabled,
            proxy_selector,
            resolver,
            fallback,
            outbound_dispatcher: None,
        }
    }

    pub fn new_multi(
        users: Vec<ServerUser>,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        fallback: Option<NetLocation>,
    ) -> Self {
        let users = users
            .into_iter()
            .map(|user| {
                (
                    parse_uuid(&user.credential).unwrap().into_boxed_slice(),
                    Some(user.authenticated_user),
                )
            })
            .collect();
        Self {
            users,
            udp_enabled,
            proxy_selector,
            resolver,
            fallback,
            outbound_dispatcher: None,
        }
    }
}

const SERVER_RESPONSE_HEADER: &[u8] = &[
    0u8, // version
    0u8, // addons length
];

/// Forward the connection to a fallback destination when VLESS authentication fails.
///
/// This makes the server indistinguishable from a legitimate server by transparently
/// proxying failed auth attempts to the configured fallback destination.
///
/// Used by both `VlessTcpServerHandler` and `setup_custom_tls_vision_vless_server_stream`.
async fn vless_fallback_to_dest<S: AsyncStream + 'static>(
    client_stream: S,
    reader: StreamReader,
    fallback: &NetLocation,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<TcpServerSetupResult> {
    debug!("VLESS FALLBACK: Connecting to fallback: {}", fallback);

    let unconsumed_data = reader.unparsed_data();
    let dest_addr = crate::resolver::resolve_single_address(resolver, fallback).await?;

    debug!("VLESS FALLBACK: Resolved {} to {}", fallback, dest_addr);

    let mut dest_stream: Box<dyn AsyncStream> = Box::new(TcpStream::connect(dest_addr).await?);

    debug!(
        "VLESS FALLBACK: Connected to fallback, forwarding {} bytes",
        unconsumed_data.len()
    );

    if !unconsumed_data.is_empty() {
        write_all(&mut dest_stream, unconsumed_data).await?;
        dest_stream.flush().await?;
    }

    debug!("VLESS FALLBACK: Spawning bidirectional copy");

    // Spawn the long-running bidirectional copy as a background task.
    // This allows the setup to complete within the timeout while the actual
    // data transfer runs indefinitely.
    tokio::spawn(async move {
        let mut client_stream = client_stream;
        let result = crate::copy_bidirectional::copy_bidirectional(
            &mut client_stream,
            &mut *dest_stream,
            false, // client doesn't need initial flush
            false, // dest doesn't need initial flush
        )
        .await;

        let _ = client_stream.shutdown().await;
        let _ = dest_stream.shutdown().await;

        if let Err(e) = result {
            debug!("VLESS FALLBACK: Connection ended: {}", e);
        } else {
            debug!("VLESS FALLBACK: Connection completed");
        }
    });

    Ok(TcpServerSetupResult::AlreadyHandled)
}

#[async_trait]
impl TcpServerHandler for VlessTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let mut stream_reader = StreamReader::new_with_buffer_size(800);

        let client_version = stream_reader.peek_u8(&mut server_stream).await?;
        if client_version != 0 {
            debug!("VLESS version mismatch: expected 0, got {}", client_version);
            if let Some(ref fallback) = self.fallback {
                return vless_fallback_to_dest(
                    server_stream,
                    stream_reader,
                    fallback,
                    &self.resolver,
                )
                .await;
            }
            return Err(std::io::Error::other(format!(
                "invalid client protocol version, expected 0, got {client_version}"
            )));
        }

        let header = stream_reader.peek_slice(&mut server_stream, 17).await?;
        let target_id = &header[1..17];

        let matched_user = self.users.iter().find_map(|(user_id, auth)| {
            if user_id.ct_eq(target_id).unwrap_u8() == 1 {
                Some(auth.clone())
            } else {
                None
            }
        });

        if matched_user.is_none() {
            debug!("VLESS UUID mismatch");
            if let Some(ref fallback) = self.fallback {
                return vless_fallback_to_dest(
                    server_stream,
                    stream_reader,
                    fallback,
                    &self.resolver,
                )
                .await;
            }
            return Err(std::io::Error::other("Unknown user id"));
        }
        let authenticated_user = matched_user.flatten();

        stream_reader.consume(17);

        let addon_length = stream_reader.read_u8(&mut server_stream).await?;
        if addon_length > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VLESS addons not supported in current configuration, use TLS protocol config for VISION support",
            ));
        }

        let instruction = stream_reader.read_u8(&mut server_stream).await?;

        match instruction {
            COMMAND_TCP => {
                let remote_location =
                    parse_remote_location_from_reader(&mut stream_reader, &mut server_stream)
                        .await?;

                // Check for h2mux magic destination
                if let Address::Hostname(host) = remote_location.address()
                    && host == MUX_DESTINATION_HOST
                    && remote_location.port() == MUX_DESTINATION_PORT
                {
                    if authenticated_user.is_some() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "h2mux is not supported for authenticated V2Board users",
                        ));
                    }

                    // Send VLESS success response before spawning h2mux session
                    write_all(&mut server_stream, SERVER_RESPONSE_HEADER).await?;

                    let proxy_selector = self.proxy_selector.clone();
                    let resolver = self.resolver.clone();
                    let udp_enabled = self.udp_enabled;
                    let outbound_dispatcher = self.outbound_dispatcher.clone();

                    // Pass any unparsed data for the h2mux session
                    let initial_data = stream_reader.unparsed_data_owned();

                    tokio::spawn(async move {
                        if let Err(e) = handle_h2mux_session(
                            server_stream,
                            initial_data,
                            udp_enabled,
                            proxy_selector,
                            resolver,
                            outbound_dispatcher,
                        )
                        .await
                        {
                            debug!("H2MUX session ended: {}", e);
                        }
                    });

                    return Ok(TcpServerSetupResult::AlreadyHandled);
                }

                let unparsed_data = stream_reader.unparsed_data();

                Ok(TcpServerSetupResult::TcpForward {
                    remote_location,
                    stream: server_stream,
                    need_initial_flush: false,
                    connection_success_response: Some(
                        SERVER_RESPONSE_HEADER.to_vec().into_boxed_slice(),
                    ),
                    initial_remote_data: if unparsed_data.is_empty() {
                        None
                    } else {
                        Some(unparsed_data.to_vec().into_boxed_slice())
                    },
                    proxy_selector: self.proxy_selector.clone(),
                    outbound_dispatcher: self.outbound_dispatcher.clone(),
                    authenticated_user: authenticated_user.clone(),
                })
            }
            COMMAND_UDP => {
                if !self.udp_enabled {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "UDP not enabled",
                    ));
                }

                let remote_location =
                    parse_remote_location_from_reader(&mut stream_reader, &mut server_stream)
                        .await?;
                let unparsed_data = stream_reader.unparsed_data();

                write_all(&mut server_stream, SERVER_RESPONSE_HEADER).await?;
                let mut vless_stream = VlessMessageStream::new(server_stream);
                if !unparsed_data.is_empty() {
                    vless_stream.feed_initial_read_data(unparsed_data)?;
                }

                Ok(TcpServerSetupResult::BidirectionalUdp {
                    remote_location,
                    stream: Box::new(vless_stream),
                    need_initial_flush: false,
                    proxy_selector: self.proxy_selector.clone(),
                    outbound_dispatcher: self.outbound_dispatcher.clone(),
                    authenticated_user: authenticated_user.clone(),
                })
            }
            COMMAND_MUX => {
                if !self.udp_enabled {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "MUX/XUDP requires UDP to be enabled",
                    ));
                }

                // MUX/XUDP: Destination comes in XUDP frames, not VLESS header
                let unparsed_data = stream_reader.unparsed_data();
                write_all(&mut server_stream, SERVER_RESPONSE_HEADER).await?;
                let mut xudp_stream = XudpMessageStream::new(server_stream);
                if !unparsed_data.is_empty() {
                    xudp_stream.feed_initial_read_data(unparsed_data)?;
                }

                Ok(TcpServerSetupResult::SessionBasedUdp {
                    stream: Box::new(xudp_stream),
                    need_initial_flush: false,
                    proxy_selector: self.proxy_selector.clone(),
                    outbound_dispatcher: self.outbound_dispatcher.clone(),
                    authenticated_user,
                })
            }
            unknown_protocol_type => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unknown requested protocol: {unknown_protocol_type}"),
                ));
            }
        }
    }
}

/// Setup a VISION+VLESS stream from a CryptoTlsStream (for REALITY+Vision support)
pub async fn setup_custom_tls_vision_vless_server_stream<IO, U>(
    mut tls_stream: CryptoTlsStream<IO>,
    users: U,
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    fallback: Option<NetLocation>,
    outbound_dispatcher: Option<Arc<crate::v2board::outbound::dispatcher::OutboundDispatcher>>,
) -> std::io::Result<TcpServerSetupResult>
where
    IO: AsyncStream + 'static,
    U: VlessVisionUserLookup,
{
    let mut stream_reader = StreamReader::new_with_buffer_size(800);

    let client_version = stream_reader.peek_u8(&mut tls_stream).await?;
    if client_version != 0 {
        debug!(
            "VLESS/Vision version mismatch: expected 0, got {}",
            client_version
        );
        if let Some(ref fb) = fallback {
            return vless_fallback_to_dest(tls_stream, stream_reader, fb, resolver).await;
        }
        return Err(std::io::Error::other(format!(
            "invalid client protocol version, expected 0, got {client_version}"
        )));
    }

    let header = stream_reader.peek_slice(&mut tls_stream, 17).await?;
    let target_id = &header[1..17];

    let authenticated_user = match users.lookup_vless_vision_user(target_id) {
        Some(authenticated_user) => authenticated_user,
        None => {
            debug!("VLESS/Vision UUID mismatch");
            if let Some(ref fb) = fallback {
                return vless_fallback_to_dest(tls_stream, stream_reader, fb, resolver).await;
            }
            return Err(std::io::Error::other("Unknown user id"));
        }
    };

    // Both checks passed - copy UUID for VisionStream, then consume version + UUID
    let mut user_uuid = [0u8; 16];
    user_uuid.copy_from_slice(target_id);
    stream_reader.consume(17);

    let addon_length = stream_reader.read_u8(&mut tls_stream).await?;
    let flow = if addon_length > 0 {
        parse_addons_from_reader(&mut stream_reader, &mut tls_stream, addon_length).await?
    } else {
        String::new()
    };

    setup_custom_tls_vision_vless_server_stream_after_auth(
        tls_stream,
        stream_reader,
        user_uuid,
        authenticated_user,
        flow,
        udp_enabled,
        proxy_selector,
        outbound_dispatcher,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn setup_custom_tls_vision_vless_server_stream_after_auth<IO>(
    mut tls_stream: CryptoTlsStream<IO>,
    mut stream_reader: StreamReader,
    user_uuid: [u8; 16],
    authenticated_user: Option<AuthenticatedUser>,
    flow: String,
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    outbound_dispatcher: Option<Arc<crate::v2board::outbound::dispatcher::OutboundDispatcher>>,
) -> std::io::Result<TcpServerSetupResult>
where
    IO: AsyncStream + 'static,
{
    let instruction = stream_reader.read_u8(&mut tls_stream).await?;

    match instruction {
        COMMAND_TCP => {
            if flow != XTLS_VISION_FLOW {
                return Err(std::io::Error::other("expected vision flow for TCP"));
            }

            debug!("Parsing remote location...");
            let remote_location =
                parse_remote_location_from_reader(&mut stream_reader, &mut tls_stream).await?;
            debug!("Remote location parsed: {}", remote_location);
            let unparsed_data = stream_reader.unparsed_data();

            let flow_stream: Box<dyn AsyncStream> = if flow == XTLS_VISION_FLOW {
                debug!("Creating VISION stream (Custom TLS) for flow: {}", flow);
                let (io, session) = tls_stream.into_inner();

                Box::new(VisionStream::new_server(
                    io,
                    session,
                    user_uuid,
                    unparsed_data,
                )?)
            } else {
                Box::new(tls_stream)
            };

            Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: flow_stream,
                need_initial_flush: false,
                connection_success_response: None, // VisionStream will send VLESS response with first write
                initial_remote_data: None,         // Data fed to VisionStream instead
                proxy_selector: proxy_selector.clone(),
                outbound_dispatcher: outbound_dispatcher.clone(),
                authenticated_user,
            })
        }
        COMMAND_UDP => {
            if flow == XTLS_VISION_FLOW {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "xtls-rprx-vision flow does not support VLESS COMMAND_UDP",
                ));
            }
            Err(std::io::Error::other("expected vision flow for UDP"))
        }
        COMMAND_MUX => {
            if flow != XTLS_VISION_FLOW {
                return Err(std::io::Error::other("expected vision flow for MUX/XUDP"));
            }
            if !udp_enabled {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "MUX/XUDP requires UDP to be enabled",
                ));
            }
            let unparsed_data = stream_reader.unparsed_data();

            debug!("Creating VISION+XUDP stream (Custom TLS) with session-based UDP sockets");

            // Extract components from CryptoTlsStream
            let (io, session) = tls_stream.into_inner();

            // Create VISION stream (will send VLESS response automatically on first write)
            let vision_stream = VisionStream::new_server(io, session, user_uuid, unparsed_data)?;

            // Wrap VISION stream in XUDP stream
            let xudp_stream = XudpMessageStream::new(Box::new(vision_stream));

            Ok(TcpServerSetupResult::SessionBasedUdp {
                stream: Box::new(xudp_stream),
                need_initial_flush: false, // VisionStream sends VLESS response on first write
                proxy_selector: proxy_selector.clone(),
                outbound_dispatcher: outbound_dispatcher.clone(),
                authenticated_user,
            })
        }
        unknown_protocol_type => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Unknown requested protocol: {unknown_protocol_type}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncWriteExt, DuplexStream, duplex};

    use super::*;
    use crate::async_stream::AsyncPing;
    use crate::client_proxy_selector::ClientProxySelector;
    use crate::crypto::{CryptoConnection, perform_crypto_handshake};
    use crate::resolver::Resolver;
    use crate::rustls_config_util::{create_client_config, create_server_config};
    use crate::tcp::tcp_handler::TcpServerSetupResult;
    use crate::vless::vless_util::vision_flow_addon_data;

    impl AsyncPing for DuplexStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            unreachable!("duplex test stream does not support ping")
        }
    }

    impl AsyncStream for DuplexStream {}

    #[derive(Debug)]
    struct NoopResolver;

    impl Resolver for NoopResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
            Box::pin(async { Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80)]) })
        }
    }

    fn auth_user(uid: u64) -> AuthenticatedUser {
        AuthenticatedUser {
            node_tag: "vless-vision".to_string(),
            uid,
            user_key: format!("user-{uid}"),
            speed_limit: None,
            device_limit: None,
            recorder: None,
        }
    }

    async fn tls_pair() -> (
        CryptoTlsStream<Box<dyn AsyncStream>>,
        CryptoTlsStream<Box<dyn AsyncStream>>,
    ) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = certified.cert.pem();
        let key_pem = certified.signing_key.serialize_pem();

        let server_config = Arc::new(create_server_config(
            cert_pem.as_bytes(),
            key_pem.as_bytes(),
            Vec::new(),
            &[],
            &[],
        ));
        let client_config = Arc::new(create_client_config(
            false,
            Vec::new(),
            Vec::new(),
            true,
            None,
            false,
        ));

        let server_conn = rustls::ServerConnection::new(server_config).unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let client_conn = rustls::ClientConnection::new(client_config, server_name).unwrap();

        let (client_io, server_io) = duplex(64 * 1024);
        let mut client_stream: Box<dyn AsyncStream> = Box::new(client_io);
        let mut server_stream: Box<dyn AsyncStream> = Box::new(server_io);

        let server_task = tokio::spawn(async move {
            let mut connection = CryptoConnection::new_rustls_server(server_conn);
            perform_crypto_handshake(&mut connection, &mut server_stream, 16 * 1024)
                .await
                .unwrap();
            CryptoTlsStream::new(server_stream, connection)
        });

        let client_task = tokio::spawn(async move {
            let mut connection = CryptoConnection::new_rustls_client(client_conn);
            perform_crypto_handshake(&mut connection, &mut client_stream, 16 * 1024)
                .await
                .unwrap();
            CryptoTlsStream::new(client_stream, connection)
        });

        let (server_tls, client_tls) = tokio::join!(server_task, client_task);
        (server_tls.unwrap(), client_tls.unwrap())
    }

    fn vision_tcp_header(user_id: &[u8], remote: NetLocation) -> Vec<u8> {
        let addon = vision_flow_addon_data();
        let mut header = Vec::new();
        header.push(0);
        header.extend_from_slice(user_id);
        header.push(addon.len() as u8);
        header.extend_from_slice(addon);
        header.push(COMMAND_TCP);
        header.push((remote.port() >> 8) as u8);
        header.push((remote.port() & 0xff) as u8);
        match remote.address() {
            Address::Ipv4(addr) => {
                header.push(1);
                header.extend_from_slice(&addr.octets());
            }
            Address::Ipv6(addr) => {
                header.push(3);
                header.extend_from_slice(&addr.octets());
            }
            Address::Hostname(host) => {
                header.push(2);
                header.push(host.len() as u8);
                header.extend_from_slice(host.as_bytes());
            }
        }
        header
    }

    fn vision_command_header(user_id: &[u8], command: u8) -> Vec<u8> {
        let addon = vision_flow_addon_data();
        let mut header = Vec::new();
        header.push(0);
        header.extend_from_slice(user_id);
        header.push(addon.len() as u8);
        header.extend_from_slice(addon);
        header.push(command);
        header
    }

    fn empty_flow_command_header(user_id: &[u8], command: u8) -> Vec<u8> {
        let mut header = Vec::new();
        header.push(0);
        header.extend_from_slice(user_id);
        header.push(0);
        header.push(command);
        header
    }

    #[tokio::test]
    async fn custom_tls_vision_vless_returns_matched_authenticated_user_from_multi_user_lookup() {
        let user1 = parse_uuid("11111111-1111-4111-8111-111111111111").unwrap();
        let user2 = parse_uuid("22222222-2222-4222-8222-222222222222").unwrap();
        let users = vec![
            (user1.into_boxed_slice(), Some(auth_user(101))),
            (user2.clone().into_boxed_slice(), Some(auth_user(202))),
        ];

        let (server_tls, mut client_tls) = tls_pair().await;
        let remote = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        let header = vision_tcp_header(&user2, remote.clone());
        client_tls.write_all(&header).await.unwrap();
        client_tls.flush().await.unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(NoopResolver);

        let result = setup_custom_tls_vision_vless_server_stream(
            server_tls,
            users,
            true,
            Arc::new(ClientProxySelector::new(Vec::new())),
            &resolver,
            None,
            None,
        )
        .await
        .unwrap();

        match result {
            TcpServerSetupResult::TcpForward {
                remote_location,
                authenticated_user,
                ..
            } => {
                assert_eq!(remote_location, remote);
                assert_eq!(authenticated_user.unwrap().uid, 202);
            }
            _ => panic!("expected TcpForward"),
        }
    }

    #[tokio::test]
    async fn custom_tls_vision_vless_rejects_command_udp() {
        let user = parse_uuid("11111111-1111-4111-8111-111111111111").unwrap();
        let users = vec![(user.clone().into_boxed_slice(), Some(auth_user(101)))];

        let (server_tls, mut client_tls) = tls_pair().await;
        let header = vision_command_header(&user, COMMAND_UDP);
        client_tls.write_all(&header).await.unwrap();
        client_tls.flush().await.unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(NoopResolver);

        let result = setup_custom_tls_vision_vless_server_stream(
            server_tls,
            users,
            true,
            Arc::new(ClientProxySelector::new(Vec::new())),
            &resolver,
            None,
            None,
        )
        .await;
        let err = match result {
            Ok(_) => panic!("expected COMMAND_UDP to be rejected for vision flow"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert!(
            err.to_string()
                .contains("xtls-rprx-vision flow does not support VLESS COMMAND_UDP")
        );
    }

    #[tokio::test]
    async fn custom_tls_vision_vless_rejects_empty_flow_mux() {
        let user = parse_uuid("11111111-1111-4111-8111-111111111111").unwrap();
        let users = vec![(user.clone().into_boxed_slice(), Some(auth_user(101)))];

        let (server_tls, mut client_tls) = tls_pair().await;
        let header = empty_flow_command_header(&user, COMMAND_MUX);
        client_tls.write_all(&header).await.unwrap();
        client_tls.flush().await.unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(NoopResolver);

        let result = setup_custom_tls_vision_vless_server_stream(
            server_tls,
            users,
            true,
            Arc::new(ClientProxySelector::new(Vec::new())),
            &resolver,
            None,
            None,
        )
        .await;
        let err = match result {
            Ok(_) => panic!("expected empty-flow MUX to be rejected for vision target"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(
            err.to_string()
                .contains("expected vision flow for MUX/XUDP")
        );
    }
}
