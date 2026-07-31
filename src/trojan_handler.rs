use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use aws_lc_rs::digest::SHA224;
use futures::ready;
use log::debug;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::address::{Address, NetLocationMask, ResolvedLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncReadTargetedMessage,
    AsyncShutdownMessage, AsyncStream, AsyncTargetedMessageStream, AsyncWriteMessage,
    AsyncWriteSourcedMessage,
};
use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
use crate::config::ShadowsocksConfig;
use crate::h2mux::{MUX_DESTINATION_HOST, MUX_DESTINATION_PORT, handle_h2mux_session};
use crate::resolver::Resolver;
use crate::shadowsocks::{
    DefaultKey, ShadowsocksCipher, ShadowsocksKey, ShadowsocksStream, ShadowsocksStreamType,
};
use crate::slide_buffer::SlideBuffer;
#[cfg(test)]
use crate::socks_handler::write_location_to_vec;
use crate::socks_handler::{
    CMD_CONNECT, CMD_UDP_ASSOCIATE, read_location, try_write_location_to_vec,
};
use crate::stream_reader::StreamReader;
use crate::tcp::chain_builder::build_direct_chain_group;
use crate::tcp::tcp_handler::{
    AuthenticatedUser, ServerUser, TcpClientHandler, TcpClientSetupResult, TcpServerHandler,
    TcpServerSetupResult,
};
use crate::util::{allocate_vec, write_all};

#[derive(Debug)]
struct ShadowsocksData {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
}

#[derive(Debug)]
pub struct TrojanTcpHandler {
    users: Vec<(Box<[u8]>, Option<AuthenticatedUser>)>,
    shadowsocks_data: Option<ShadowsocksData>,
    /// Proxy selector for server handler use. None when used as client handler.
    proxy_selector: Option<Arc<ClientProxySelector>>,
    /// DNS resolver for h2mux sessions. None when used as client handler.
    resolver: Option<Arc<dyn Resolver>>,
    /// TLS-decoded destination for unauthenticated or malformed probe traffic.
    fallback: Option<crate::address::NetLocation>,
    fallback_proxy_selector: Option<Arc<ClientProxySelector>>,
    /// Node-side outbound dispatcher for server handler use.
    outbound_dispatcher: Option<Arc<crate::v2board::outbound::dispatcher::OutboundDispatcher>>,
}

impl TrojanTcpHandler {
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

const TROJAN_PASSWORD_HASH_LEN: usize = 56;
const TROJAN_MAX_UDP_PAYLOAD_LEN: usize = u16::MAX as usize;
const TROJAN_MAX_SOCKS_ADDR_LEN: usize = 1 + 255 + 2;
const TROJAN_HEADER_BUFFER_SIZE: usize = 400;
const TROJAN_UDP_FRAME_BUFFER_SIZE: usize =
    TROJAN_MAX_UDP_PAYLOAD_LEN + TROJAN_MAX_SOCKS_ADDR_LEN + 2 + CRLF_BYTES.len();

struct RecordingStream {
    inner: Box<dyn AsyncStream>,
    read_data: Vec<u8>,
}

impl RecordingStream {
    fn new(inner: Box<dyn AsyncStream>) -> Self {
        Self {
            inner,
            read_data: Vec::with_capacity(TROJAN_HEADER_BUFFER_SIZE),
        }
    }

    fn into_parts(self) -> (Box<dyn AsyncStream>, Option<Box<[u8]>>) {
        let data = if self.read_data.is_empty() {
            None
        } else {
            Some(self.read_data.into_boxed_slice())
        };
        (self.inner, data)
    }
}

impl AsyncRead for RecordingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let filled_before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled_after = buf.filled().len();
                if filled_after > filled_before {
                    self.read_data
                        .extend_from_slice(&buf.filled()[filled_before..filled_after]);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for RecordingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for RecordingStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl AsyncStream for RecordingStream {}

struct ParsedTrojanRequest {
    authenticated_user: Option<AuthenticatedUser>,
    command_type: u8,
    remote_location: crate::address::NetLocation,
    initial_data: Option<Box<[u8]>>,
}

struct TrojanPacketStream {
    stream: Box<dyn AsyncStream>,
    fixed_target: Option<crate::address::NetLocation>,
    read_buf: SlideBuffer,
    write_buf: Box<[u8]>,
    write_buf_len: usize,
    write_buf_sent: usize,
    is_eof: bool,
}

impl TrojanPacketStream {
    fn new(stream: Box<dyn AsyncStream>) -> Self {
        Self::new_inner(stream, None)
    }

    fn new_fixed_target(stream: Box<dyn AsyncStream>, target: crate::address::NetLocation) -> Self {
        Self::new_inner(stream, Some(target))
    }

    fn new_inner(
        stream: Box<dyn AsyncStream>,
        fixed_target: Option<crate::address::NetLocation>,
    ) -> Self {
        Self {
            stream,
            fixed_target,
            read_buf: SlideBuffer::new(TROJAN_UDP_FRAME_BUFFER_SIZE),
            write_buf: allocate_vec(TROJAN_UDP_FRAME_BUFFER_SIZE).into_boxed_slice(),
            write_buf_len: 0,
            write_buf_sent: 0,
            is_eof: false,
        }
    }

    fn feed_initial_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        if data.len() > self.read_buf.remaining_capacity() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Trojan UDP initial data too large: {} > {}",
                    data.len(),
                    self.read_buf.remaining_capacity()
                ),
            ));
        }
        self.read_buf.extend_from_slice(data);
        Ok(())
    }

    fn try_parse_packet(
        &self,
    ) -> std::io::Result<Option<(crate::address::NetLocation, usize, usize)>> {
        let data = self.read_buf.as_slice();
        let (target, addr_len) = match parse_trojan_packet_address(data)? {
            Some(result) => result,
            None => return Ok(None),
        };
        if data.len() < addr_len + 2 + CRLF_BYTES.len() {
            return Ok(None);
        }
        let payload_len = u16::from_be_bytes([data[addr_len], data[addr_len + 1]]) as usize;
        let crlf_start = addr_len + 2;
        if data[crlf_start..crlf_start + CRLF_BYTES.len()] != CRLF_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Trojan UDP frame missing CRLF after length",
            ));
        }
        let payload_start = crlf_start + CRLF_BYTES.len();
        let total_len = payload_start + payload_len;
        if data.len() < total_len {
            return Ok(None);
        }
        Ok(Some((target, payload_start, payload_len)))
    }

    fn poll_read_packet(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<crate::address::NetLocation>> {
        if self.is_eof {
            return Poll::Ready(Ok(crate::address::NetLocation::UNSPECIFIED));
        }

        loop {
            match self.try_parse_packet()? {
                Some((target, payload_start, payload_len)) => {
                    let total_consumed = payload_start + payload_len;
                    if payload_len == 0 {
                        self.read_buf.consume(total_consumed);
                        continue;
                    }
                    if buf.remaining() < payload_len {
                        return Poll::Ready(Err(std::io::Error::other(
                            "buffer too small for Trojan UDP packet",
                        )));
                    }
                    let data = self.read_buf.as_slice();
                    buf.put_slice(&data[payload_start..payload_start + payload_len]);
                    self.read_buf.consume(total_consumed);
                    return Poll::Ready(Ok(target));
                }
                None => {
                    self.read_buf.maybe_compact(4096);
                    if self.read_buf.remaining_capacity() == 0 {
                        return Poll::Ready(Err(std::io::Error::other(
                            "Trojan UDP read buffer full but no complete packet",
                        )));
                    }
                    let write_slice = self.read_buf.write_slice();
                    let mut read_buf = ReadBuf::new(write_slice);
                    match Pin::new(&mut self.stream).poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {
                            let bytes_read = read_buf.filled().len();
                            if bytes_read == 0 {
                                self.is_eof = true;
                                return Poll::Ready(Ok(crate::address::NetLocation::UNSPECIFIED));
                            }
                            self.read_buf.advance_write(bytes_read);
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }

    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.write_buf_sent < self.write_buf_len {
            let remaining = &self.write_buf[self.write_buf_sent..self.write_buf_len];
            match Pin::new(&mut self.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write Trojan UDP frame",
                    )));
                }
                Poll::Ready(Ok(n)) => self.write_buf_sent += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_buf_len = 0;
        self.write_buf_sent = 0;
        Poll::Ready(Ok(()))
    }

    fn queue_packet(
        &mut self,
        buf: &[u8],
        target: &crate::address::NetLocation,
    ) -> std::io::Result<()> {
        if buf.len() > TROJAN_MAX_UDP_PAYLOAD_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Trojan UDP payload too large: {} > {}",
                    buf.len(),
                    TROJAN_MAX_UDP_PAYLOAD_LEN
                ),
            ));
        }
        let addr_len = write_trojan_packet_address(&mut self.write_buf, target)?;
        let total_len = addr_len + 2 + CRLF_BYTES.len() + buf.len();
        if total_len > self.write_buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Trojan UDP frame too large: {total_len} > {}",
                    self.write_buf.len()
                ),
            ));
        }
        self.write_buf[addr_len..addr_len + 2].copy_from_slice(&(buf.len() as u16).to_be_bytes());
        let crlf_start = addr_len + 2;
        self.write_buf[crlf_start..crlf_start + CRLF_BYTES.len()].copy_from_slice(&CRLF_BYTES);
        let payload_start = crlf_start + CRLF_BYTES.len();
        self.write_buf[payload_start..payload_start + buf.len()].copy_from_slice(buf);
        self.write_buf_len = total_len;
        self.write_buf_sent = 0;
        Ok(())
    }
}

fn parse_trojan_packet_address(
    data: &[u8],
) -> std::io::Result<Option<(crate::address::NetLocation, usize)>> {
    if data.is_empty() {
        return Ok(None);
    }
    match data[0] {
        crate::socks_handler::ADDR_TYPE_IPV4 => {
            if data.len() < 7 {
                return Ok(None);
            }
            let addr = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok(Some((
                crate::address::NetLocation::new(Address::Ipv4(addr), port),
                7,
            )))
        }
        crate::socks_handler::ADDR_TYPE_DOMAIN_NAME => {
            if data.len() < 2 {
                return Ok(None);
            }
            let domain_len = data[1] as usize;
            let total_len = 2 + domain_len + 2;
            if data.len() < total_len {
                return Ok(None);
            }
            let domain = std::str::from_utf8(&data[2..2 + domain_len]).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid Trojan UDP domain encoding: {e}"),
                )
            })?;
            let port = u16::from_be_bytes([data[2 + domain_len], data[2 + domain_len + 1]]);
            Ok(Some((
                crate::address::NetLocation::new(Address::from(domain)?, port),
                total_len,
            )))
        }
        crate::socks_handler::ADDR_TYPE_IPV6 => {
            if data.len() < 19 {
                return Ok(None);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let addr = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok(Some((
                crate::address::NetLocation::new(Address::Ipv6(addr), port),
                19,
            )))
        }
        atyp => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown Trojan UDP address type: {atyp}"),
        )),
    }
}

fn write_trojan_packet_address(
    buf: &mut [u8],
    location: &crate::address::NetLocation,
) -> std::io::Result<usize> {
    let (address, port) = location.components();
    match address {
        Address::Ipv4(addr) => {
            if buf.len() < 7 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "buffer too small for Trojan IPv4 address",
                ));
            }
            buf[0] = crate::socks_handler::ADDR_TYPE_IPV4;
            buf[1..5].copy_from_slice(&addr.octets());
            buf[5..7].copy_from_slice(&port.to_be_bytes());
            Ok(7)
        }
        Address::Ipv6(addr) => {
            if buf.len() < 19 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "buffer too small for Trojan IPv6 address",
                ));
            }
            buf[0] = crate::socks_handler::ADDR_TYPE_IPV6;
            buf[1..17].copy_from_slice(&addr.octets());
            buf[17..19].copy_from_slice(&port.to_be_bytes());
            Ok(19)
        }
        Address::Hostname(host) => {
            let host_bytes = host.as_bytes();
            if host_bytes.len() > u8::MAX as usize {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Trojan hostname too long: {}", host_bytes.len()),
                ));
            }
            let total_len = 2 + host_bytes.len() + 2;
            if buf.len() < total_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "buffer too small for Trojan domain address",
                ));
            }
            buf[0] = crate::socks_handler::ADDR_TYPE_DOMAIN_NAME;
            buf[1] = host_bytes.len() as u8;
            buf[2..2 + host_bytes.len()].copy_from_slice(host_bytes);
            buf[2 + host_bytes.len()..total_len].copy_from_slice(&port.to_be_bytes());
            Ok(total_len)
        }
    }
}

fn socket_addr_to_location(addr: &SocketAddr) -> crate::address::NetLocation {
    let address = match addr.ip() {
        IpAddr::V4(addr) => Address::Ipv4(addr),
        IpAddr::V6(addr) => Address::Ipv6(addr),
    };
    crate::address::NetLocation::new(address, addr.port())
}

impl AsyncReadTargetedMessage for TrojanPacketStream {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<crate::address::NetLocation>> {
        self.get_mut().poll_read_packet(cx, buf)
    }
}

impl AsyncWriteSourcedMessage for TrojanPacketStream {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_pending(cx))?;
        let source = socket_addr_to_location(source);
        this.queue_packet(buf, &source)?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncReadMessage for TrojanPacketStream {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.get_mut()
            .poll_read_packet(cx, buf)
            .map(|result| result.map(|_| ()))
    }
}

impl AsyncWriteMessage for TrojanPacketStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_pending(cx))?;
        let target = this.fixed_target.clone().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Trojan UDP message stream missing fixed target",
            )
        })?;
        this.queue_packet(buf, &target)?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for TrojanPacketStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_pending(cx))?;
        Pin::new(&mut this.stream).poll_flush(cx)
    }
}

impl AsyncShutdownMessage for TrojanPacketStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut *this).poll_flush_message(cx))?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl AsyncPing for TrojanPacketStream {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.stream).poll_write_ping(cx)
    }
}

impl AsyncTargetedMessageStream for TrojanPacketStream {}
impl AsyncMessageStream for TrojanPacketStream {}

impl TrojanTcpHandler {
    /// Create a new handler for server use (with proxy_selector for routing)
    pub fn new_server(
        password: &str,
        shadowsocks_config: &Option<ShadowsocksConfig>,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self::new_server_with_fallback(password, shadowsocks_config, proxy_selector, resolver, None)
    }

    pub fn new_server_with_fallback(
        password: &str,
        shadowsocks_config: &Option<ShadowsocksConfig>,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        fallback: Option<crate::address::NetLocation>,
    ) -> Self {
        Self::new_inner(
            password,
            shadowsocks_config,
            Some(proxy_selector),
            Some(resolver),
            fallback,
        )
    }

    /// Create a new handler for client use (no proxy_selector needed)
    pub fn new_client(password: &str, shadowsocks_config: &Option<ShadowsocksConfig>) -> Self {
        Self::new_inner(password, shadowsocks_config, None, None, None)
    }

    pub fn new_multi_server(
        users: Vec<ServerUser>,
        shadowsocks_config: &Option<ShadowsocksConfig>,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        fallback: Option<crate::address::NetLocation>,
    ) -> Self {
        let mut handler = Self::new_inner(
            "",
            shadowsocks_config,
            Some(proxy_selector),
            Some(resolver),
            fallback,
        );
        handler.users = users
            .into_iter()
            .map(|user| {
                (
                    create_password_hash(&user.credential),
                    Some(user.authenticated_user),
                )
            })
            .collect();
        handler
    }

    fn new_inner(
        password: &str,
        shadowsocks_config: &Option<ShadowsocksConfig>,
        proxy_selector: Option<Arc<ClientProxySelector>>,
        resolver: Option<Arc<dyn Resolver>>,
        fallback: Option<crate::address::NetLocation>,
    ) -> Self {
        let password_hash = create_password_hash(password);
        let shadowsocks_data = shadowsocks_config.as_ref().map(|config| match config {
            ShadowsocksConfig::Legacy {
                cipher,
                password: shadowsocks_password,
            } => {
                let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new(
                    shadowsocks_password,
                    cipher.algorithm().key_len(),
                )));
                ShadowsocksData {
                    cipher: *cipher,
                    key,
                }
            }
            ShadowsocksConfig::Aead2022 { .. } => {
                panic!("Trojan does not support shadowsocks 2022 ciphers (checked during config validation)")
            }
        });
        let fallback_proxy_selector = if fallback.is_some() {
            resolver.as_ref().map(|resolver| {
                Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
                    vec![NetLocationMask::ANY],
                    ConnectAction::new_allow(None, build_direct_chain_group(resolver.clone())),
                )]))
            })
        } else {
            None
        };

        Self {
            users: vec![(password_hash, None)],
            shadowsocks_data,
            proxy_selector,
            resolver,
            fallback,
            fallback_proxy_selector,
            outbound_dispatcher: None,
        }
    }

    async fn parse_server_request(
        &self,
        server_stream: &mut RecordingStream,
    ) -> std::io::Result<ParsedTrojanRequest> {
        let mut stream_reader = StreamReader::new_with_buffer_size(TROJAN_HEADER_BUFFER_SIZE);

        // Read the entire line so ordinary HTTP probe traffic is bounded by the
        // same maximum header size and can be replayed to the fallback.
        let received_hash = stream_reader.read_line_bytes(server_stream).await?;
        if received_hash.len() != TROJAN_PASSWORD_HASH_LEN {
            return Err(std::io::Error::other(format!(
                "Invalid password hash length, expected {}, got {}",
                TROJAN_PASSWORD_HASH_LEN,
                received_hash.len()
            )));
        }

        // Use constant-time comparison to prevent timing attacks.
        let authenticated_user = self.users.iter().find_map(|(password_hash, auth)| {
            if password_hash.ct_eq(received_hash).unwrap_u8() == 1 {
                Some(auth.clone())
            } else {
                None
            }
        });
        if authenticated_user.is_none() {
            return Err(std::io::Error::other("Invalid password hash"));
        }
        let authenticated_user = authenticated_user.flatten();

        let command_type = stream_reader.read_u8(server_stream).await?;
        if !matches!(command_type, CMD_CONNECT | CMD_UDP_ASSOCIATE) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid command code: {command_type}"),
            ));
        }

        let remote_location = read_location(server_stream, &mut stream_reader).await?;
        let request_suffix = stream_reader.read_u16_be(server_stream).await?;
        if request_suffix != 0x0d0a {
            return Err(std::io::Error::other(format!(
                "Invalid request suffix bytes {request_suffix}"
            )));
        }

        Ok(ParsedTrojanRequest {
            authenticated_user,
            command_type,
            remote_location,
            initial_data: stream_reader.unparsed_data_owned(),
        })
    }

    fn fallback_result(
        &self,
        stream: RecordingStream,
        fallback: crate::address::NetLocation,
    ) -> TcpServerSetupResult {
        let (stream, initial_remote_data) = stream.into_parts();
        TcpServerSetupResult::TcpForward {
            remote_location: fallback,
            stream,
            need_initial_flush: false,
            connection_success_response: None,
            initial_remote_data,
            proxy_selector: self
                .fallback_proxy_selector
                .clone()
                .expect("fallback proxy selector required when fallback is configured"),
            outbound_dispatcher: None,
            authenticated_user: None,
        }
    }
}

#[async_trait]
impl TcpServerHandler for TrojanTcpHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        if let Some(ShadowsocksData {
            ref cipher,
            ref key,
        }) = self.shadowsocks_data
        {
            server_stream = Box::new(ShadowsocksStream::new(
                server_stream,
                ShadowsocksStreamType::Aead,
                cipher.algorithm(),
                cipher.salt_len(),
                key.clone(),
                None,
            ));
        }

        let mut recording_stream = RecordingStream::new(server_stream);
        let ParsedTrojanRequest {
            authenticated_user,
            command_type,
            remote_location,
            initial_data,
        } = match self.parse_server_request(&mut recording_stream).await {
            Ok(request) => request,
            Err(error) => {
                if let Some(fallback) = self.fallback.clone() {
                    debug!(
                        "Trojan request did not authenticate; forwarding probe traffic to {}: {}",
                        fallback, error
                    );
                    return Ok(self.fallback_result(recording_stream, fallback));
                }
                return Err(error);
            }
        };
        let (server_stream, _) = recording_stream.into_parts();

        if command_type == CMD_UDP_ASSOCIATE {
            let mut udp_stream = TrojanPacketStream::new(server_stream);
            if let Some(initial_data) = initial_data {
                udp_stream.feed_initial_data(&initial_data)?;
            }
            return Ok(TcpServerSetupResult::MultiDirectionalUdp {
                need_initial_flush: false,
                stream: Box::new(udp_stream),
                proxy_selector: self
                    .proxy_selector
                    .clone()
                    .expect("proxy_selector required for server handler"),
                outbound_dispatcher: self.outbound_dispatcher.clone(),
                authenticated_user,
            });
        }

        // Checks for h2mux magic destination
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

            let proxy_selector = self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler");
            let resolver = self.resolver.clone().expect("resolver required for h2mux");
            let outbound_dispatcher = self.outbound_dispatcher.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_h2mux_session(
                    server_stream,
                    initial_data,
                    false,
                    proxy_selector,
                    resolver,
                    outbound_dispatcher,
                )
                .await
                {
                    debug!("Trojan h2mux session ended: {}", e);
                }
            });

            return Ok(TcpServerSetupResult::AlreadyHandled);
        }

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: server_stream,
            need_initial_flush: false,
            connection_success_response: None,
            initial_remote_data: initial_data,
            proxy_selector: self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler"),
            outbound_dispatcher: self.outbound_dispatcher.clone(),
            authenticated_user,
        })
    }
}

const CRLF_BYTES: [u8; 2] = [0x0d, 0x0a];

#[async_trait]
impl TcpClientHandler for TrojanTcpHandler {
    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        if let Some(ShadowsocksData {
            ref cipher,
            ref key,
        }) = self.shadowsocks_data
        {
            client_stream = Box::new(ShadowsocksStream::new(
                client_stream,
                ShadowsocksStreamType::Aead,
                cipher.algorithm(),
                cipher.salt_len(),
                key.clone(),
                None,
            ));
        }

        let password_hash = &self.users[0].0;
        write_all(&mut client_stream, password_hash).await?;
        write_all(&mut client_stream, &CRLF_BYTES).await?;
        write_all(&mut client_stream, &[CMD_CONNECT]).await?;
        let location_bytes = try_write_location_to_vec(remote_location.location())?;
        write_all(&mut client_stream, &location_bytes).await?;
        write_all(&mut client_stream, &CRLF_BYTES).await?;
        client_stream.flush().await?;
        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        true
    }

    async fn setup_client_udp_bidirectional(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if let Some(ShadowsocksData {
            ref cipher,
            ref key,
        }) = self.shadowsocks_data
        {
            client_stream = Box::new(ShadowsocksStream::new(
                client_stream,
                ShadowsocksStreamType::Aead,
                cipher.algorithm(),
                cipher.salt_len(),
                key.clone(),
                None,
            ));
        }

        let target = target.into_location();
        let password_hash = &self.users[0].0;
        write_all(&mut client_stream, password_hash).await?;
        write_all(&mut client_stream, &CRLF_BYTES).await?;
        write_all(&mut client_stream, &[CMD_UDP_ASSOCIATE]).await?;
        let location_bytes = try_write_location_to_vec(&target)?;
        write_all(&mut client_stream, &location_bytes).await?;
        write_all(&mut client_stream, &CRLF_BYTES).await?;
        client_stream.flush().await?;

        Ok(Box::new(TrojanPacketStream::new_fixed_target(
            client_stream,
            target,
        )))
    }
}

fn create_password_hash(password: &str) -> Box<[u8]> {
    let digest = aws_lc_rs::digest::digest(&SHA224, password.as_bytes());
    let hash_bytes = digest.as_ref();
    let mut hex_str = String::with_capacity(hash_bytes.len() * 2);
    for b in hash_bytes {
        hex_str.push_str(&format!("{b:02x}"));
    }
    let hex_bytes = hex_str.into_bytes().into_boxed_slice();
    if hex_bytes.len() != TROJAN_PASSWORD_HASH_LEN {
        panic!(
            "Invalid password hash length, expected {}, got {}",
            TROJAN_PASSWORD_HASH_LEN,
            hex_bytes.len()
        );
    }
    hex_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::future::Future;
    use std::future::poll_fn;
    use std::io;

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, duplex};

    use crate::address::{NetLocation, ResolvedLocation};

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    #[derive(Debug)]
    struct NoopResolver;

    impl Resolver for NoopResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    fn append_trojan_udp_frame(buf: &mut Vec<u8>, target: &NetLocation, payload: &[u8]) {
        buf.extend_from_slice(&write_location_to_vec(target));
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&CRLF_BYTES);
        buf.extend_from_slice(payload);
    }

    #[tokio::test]
    async fn unauthenticated_probe_is_replayed_to_fallback_without_user_scope() {
        let (mut client_io, server_io) = duplex(4096);
        let request = b"GET /health HTTP/1.1\r\nHost: decoy.example\r\n\r\n";
        client_io.write_all(request).await.unwrap();
        client_io.shutdown().await.unwrap();

        let fallback = NetLocation::new(Address::Hostname("decoy.example".to_string()), 8443);
        let handler = TrojanTcpHandler::new_server_with_fallback(
            "secret",
            &None,
            Arc::new(ClientProxySelector::new(Vec::new())),
            Arc::new(NoopResolver),
            Some(fallback.clone()),
        );

        let setup_result = handler
            .setup_server_stream(Box::new(TestStream(server_io)))
            .await
            .unwrap();

        let (mut stream, initial_data) = match setup_result {
            TcpServerSetupResult::TcpForward {
                remote_location,
                stream,
                initial_remote_data,
                authenticated_user,
                ..
            } => {
                assert_eq!(remote_location, fallback);
                assert!(authenticated_user.is_none());
                (stream, initial_remote_data)
            }
            _ => panic!("expected unauthenticated Trojan probe to use TCP fallback"),
        };

        let mut replayed = initial_data.map(Vec::from).unwrap_or_default();
        stream.read_to_end(&mut replayed).await.unwrap();
        assert_eq!(replayed, request);
    }

    #[tokio::test]
    async fn unauthenticated_probe_without_fallback_is_rejected() {
        let (mut client_io, server_io) = duplex(4096);
        client_io
            .write_all(b"GET / HTTP/1.1\r\nHost: example\r\n\r\n")
            .await
            .unwrap();

        let handler = TrojanTcpHandler::new_server(
            "secret",
            &None,
            Arc::new(ClientProxySelector::new(Vec::new())),
            Arc::new(NoopResolver),
        );
        let error = handler
            .setup_server_stream(Box::new(TestStream(server_io)))
            .await
            .err()
            .expect("probe must fail without an explicit fallback");
        assert!(
            error.to_string().contains("password hash length"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn malformed_authenticated_header_is_replayed_without_user_scope() {
        let (mut client_io, server_io) = duplex(4096);
        let mut request = Vec::new();
        request.extend_from_slice(&create_password_hash("secret"));
        request.extend_from_slice(&CRLF_BYTES);
        request.push(0x7f);
        request.extend_from_slice(b"not-a-trojan-command");
        client_io.write_all(&request).await.unwrap();
        client_io.shutdown().await.unwrap();

        let fallback = NetLocation::new(Address::Hostname("decoy.example".to_string()), 8443);
        let handler = TrojanTcpHandler::new_server_with_fallback(
            "secret",
            &None,
            Arc::new(ClientProxySelector::new(Vec::new())),
            Arc::new(NoopResolver),
            Some(fallback),
        );
        let setup_result = handler
            .setup_server_stream(Box::new(TestStream(server_io)))
            .await
            .unwrap();

        let (mut stream, initial_data, authenticated_user) = match setup_result {
            TcpServerSetupResult::TcpForward {
                stream,
                initial_remote_data,
                authenticated_user,
                ..
            } => (stream, initial_remote_data, authenticated_user),
            _ => panic!("expected malformed Trojan header to use fallback"),
        };
        assert!(authenticated_user.is_none());

        let mut replayed = initial_data.map(Vec::from).unwrap_or_default();
        stream.read_to_end(&mut replayed).await.unwrap();
        assert_eq!(replayed, request);
    }

    #[tokio::test]
    async fn trojan_packet_stream_round_trips_targeted_and_fixed_messages() {
        let (client_io, server_io) = duplex(4096);
        let target = NetLocation::new(Address::Hostname("dns.example".to_string()), 53);
        let source: SocketAddr = "127.0.0.1:5300".parse().unwrap();
        let mut client =
            TrojanPacketStream::new_fixed_target(Box::new(TestStream(client_io)), target.clone());
        let mut server = TrojanPacketStream::new(Box::new(TestStream(server_io)));

        poll_fn(|cx| Pin::new(&mut client).poll_write_message(cx, b"query"))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut client).poll_flush_message(cx))
            .await
            .unwrap();

        let mut read_buf = [0u8; 16];
        let mut read = ReadBuf::new(&mut read_buf);
        let got_target =
            poll_fn(|cx| Pin::new(&mut server).poll_read_targeted_message(cx, &mut read))
                .await
                .unwrap();
        assert_eq!(got_target, target);
        assert_eq!(read.filled(), b"query");

        poll_fn(|cx| Pin::new(&mut server).poll_write_sourced_message(cx, b"answer", &source))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut server).poll_flush_message(cx))
            .await
            .unwrap();

        let mut read_buf = [0u8; 16];
        let mut read = ReadBuf::new(&mut read_buf);
        poll_fn(|cx| Pin::new(&mut client).poll_read_message(cx, &mut read))
            .await
            .unwrap();
        assert_eq!(read.filled(), b"answer");
    }

    #[tokio::test]
    async fn setup_server_stream_accepts_udp_command_and_preserves_initial_packet() {
        let (mut client_io, server_io) = duplex(4096);
        let target = NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let payload = b"dns query";
        let mut request = Vec::new();
        request.extend_from_slice(&create_password_hash("secret"));
        request.extend_from_slice(&CRLF_BYTES);
        request.push(CMD_UDP_ASSOCIATE);
        request.extend_from_slice(&write_location_to_vec(&target));
        request.extend_from_slice(&CRLF_BYTES);
        append_trojan_udp_frame(&mut request, &target, payload);
        client_io.write_all(&request).await.unwrap();

        let handler = TrojanTcpHandler::new_server(
            "secret",
            &None,
            Arc::new(ClientProxySelector::new(Vec::new())),
            Arc::new(NoopResolver),
        );
        let setup_result = handler
            .setup_server_stream(Box::new(TestStream(server_io)))
            .await
            .unwrap();

        let mut stream = match setup_result {
            TcpServerSetupResult::MultiDirectionalUdp { stream, .. } => stream,
            _ => panic!("expected Trojan UDP command to return MultiDirectionalUdp"),
        };

        let mut read_buf = [0u8; 64];
        let mut read = ReadBuf::new(&mut read_buf);
        let got_target =
            poll_fn(|cx| Pin::new(&mut stream).poll_read_targeted_message(cx, &mut read))
                .await
                .unwrap();

        assert_eq!(got_target, target);
        assert_eq!(read.filled(), payload);
    }

    #[tokio::test]
    async fn setup_client_udp_bidirectional_writes_trojan_udp_header() {
        let (client_io, mut server_io) = duplex(4096);
        let target = NetLocation::new(Address::Hostname("example.com".to_string()), 443);
        let handler = TrojanTcpHandler::new_client("secret", &None);

        let mut stream = handler
            .setup_client_udp_bidirectional(
                Box::new(TestStream(client_io)),
                ResolvedLocation::new(target.clone()),
            )
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, b"payload"))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
            .await
            .unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&create_password_hash("secret"));
        expected.extend_from_slice(&CRLF_BYTES);
        expected.push(CMD_UDP_ASSOCIATE);
        expected.extend_from_slice(&write_location_to_vec(&target));
        expected.extend_from_slice(&CRLF_BYTES);
        append_trojan_udp_frame(&mut expected, &target, b"payload");

        let mut received = vec![0u8; expected.len()];
        server_io.read_exact(&mut received).await.unwrap();

        assert_eq!(received, expected);
    }
}
