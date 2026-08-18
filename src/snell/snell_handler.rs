use std::sync::Arc;

use argon2::{Config as Argon2Config, ThreadMode, Variant, Version};
use async_trait::async_trait;
use log::debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::snell_fixed_target_stream::SnellFixedTargetStream;
use super::snell_udp_stream::{SnellUdpClientStream, SnellUdpStream};
use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::h2mux::{MUX_DESTINATION_HOST, MUX_DESTINATION_PORT, handle_h2mux_session};
use crate::resolver::Resolver;
use crate::shadowsocks::{
    ShadowsocksCipher, ShadowsocksKey, ShadowsocksStream, ShadowsocksStreamType,
};
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::util::write_all;

// Snell protocol Argon2 parameters
// ref: https://github.com/icpz/open-snell/blob/master/components/aead/cipher.go#L48
const SNELL_ARGON2_CONFIG: Argon2Config<'static> = Argon2Config {
    variant: Variant::Argon2id,
    version: Version::Version13,
    mem_cost: 8,  // 8 KB
    time_cost: 3, // 3 iterations
    lanes: 1,     // parallelism = 1
    thread_mode: ThreadMode::Sequential,
    secret: &[],
    ad: &[],
    hash_length: 32,
};

#[derive(Debug, Clone)]
struct SnellKey {
    password_bytes: Box<[u8]>,
    key_len: usize,
}

impl SnellKey {
    pub fn new(password: &str, key_len: usize) -> Self {
        Self {
            password_bytes: password.as_bytes().to_vec().into_boxed_slice(),
            key_len,
        }
    }
}

impl ShadowsocksKey for SnellKey {
    fn create_session_key(&self, salt: &[u8]) -> Box<[u8]> {
        let output = argon2::hash_raw(&self.password_bytes, salt, &SNELL_ARGON2_CONFIG).unwrap();

        if self.key_len == 32 {
            output.into_boxed_slice()
        } else {
            output[0..self.key_len].to_vec().into_boxed_slice()
        }
    }
}

#[derive(Debug)]
pub struct SnellServerHandler {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
}

impl SnellServerHandler {
    pub fn new(
        cipher: ShadowsocksCipher,
        password: &str,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(SnellKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            udp_enabled,
            proxy_selector,
            resolver,
        }
    }
}

const TCP_TUNNEL_RESPONSE: &[u8] = &[0x0];
const UDP_READY_RESPONSE: &[u8] = TCP_TUNNEL_RESPONSE;

#[async_trait]
impl TcpServerHandler for SnellServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let mut server_stream = ShadowsocksStream::new(
            server_stream,
            ShadowsocksStreamType::Aead,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            self.key.clone(),
            None,
        );

        let mut snell_header = [0u8; 3];
        server_stream.read_exact(&mut snell_header).await?;

        let version = snell_header[0];
        if version != 1 {
            return Err(std::io::Error::other(format!(
                "unexpected snell version: {version}"
            )));
        }

        let command_type = snell_header[1];
        let is_udp = match command_type {
            0 => {
                // Ping command
                write_all(&mut server_stream, &[0x01]).await?;
                server_stream.flush().await?;
                return Err(std::io::Error::other("responded to ping"));
            }
            1 | 5 => {
                // 1 is Connect, used by Snell v3
                // 5 is Connect v2, used by Snell v2
                false
            }
            6 => {
                // UDP command
                if !self.udp_enabled {
                    return Err(std::io::Error::other("snell UDP requested but not enabled"));
                }
                true
            }
            unknown_command => {
                return Err(std::io::Error::other(format!(
                    "Got unknown command: {unknown_command}"
                )));
            }
        };

        let client_id_len = snell_header[2];
        if client_id_len > 0 {
            let mut client_id = vec![0u8; client_id_len as usize];
            server_stream.read_exact(&mut client_id).await?;
        }

        if !is_udp {
            let mut hostname_len = [0u8; 1];
            server_stream.read_exact(&mut hostname_len).await?;
            let hostname_len = hostname_len[0] as usize;

            let mut hostname_and_port_bytes = vec![0u8; hostname_len + 2];
            server_stream
                .read_exact(&mut hostname_and_port_bytes)
                .await?;

            let hostname_str = match std::str::from_utf8(&hostname_and_port_bytes[0..hostname_len])
            {
                Ok(s) => s,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to decode hostname: {e}"),
                    ));
                }
            };

            let port =
                u16::from_be_bytes(hostname_and_port_bytes[hostname_len..].try_into().unwrap());

            let remote_location = NetLocation::new(Address::from(hostname_str)?, port);

            // Checks for h2mux magic destination
            if let Address::Hostname(host) = remote_location.address()
                && host == MUX_DESTINATION_HOST
                && remote_location.port() == MUX_DESTINATION_PORT
            {
                // Send Snell success response before spawning h2mux session
                write_all(&mut server_stream, TCP_TUNNEL_RESPONSE).await?;
                server_stream.flush().await?;

                let proxy_selector = self.proxy_selector.clone();
                let resolver = self.resolver.clone();
                let udp_enabled = self.udp_enabled;

                return Ok(TcpServerSetupResult::connection_task(async move {
                    if let Err(e) = handle_h2mux_session(
                        server_stream,
                        None,
                        udp_enabled,
                        proxy_selector,
                        resolver,
                        None,
                    )
                    .await
                    {
                        debug!("Snell h2mux session ended: {}", e);
                    }
                    Ok(())
                }));
            }

            Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: Box::new(server_stream),

                // flush the tunnel response
                need_initial_flush: true,
                connection_success_response: Some(TCP_TUNNEL_RESPONSE.to_vec().into_boxed_slice()),
                initial_remote_data: None,
                proxy_selector: self.proxy_selector.clone(),
                outbound_dispatcher: None,
                authenticated_user: None,
            })
        } else {
            write_all(&mut server_stream, UDP_READY_RESPONSE).await?;
            server_stream.flush().await?;

            let udp_stream = SnellUdpStream::new(
                Box::new(server_stream),
                ShadowsocksStreamType::Aead.max_payload_len(),
            );

            Ok(TcpServerSetupResult::MultiDirectionalUdp {
                stream: Box::new(udp_stream),
                need_initial_flush: false,
                proxy_selector: self.proxy_selector.clone(),
                outbound_dispatcher: None,
                authenticated_user: None,
            })
        }
    }
}

#[derive(Debug)]
pub struct SnellClientHandler {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
    udp_enabled: bool,
}

impl SnellClientHandler {
    pub fn new(cipher: ShadowsocksCipher, password: &str, udp_enabled: bool) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(SnellKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            udp_enabled,
        }
    }
}

#[async_trait]
impl TcpClientHandler for SnellClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let mut client_stream: Box<dyn AsyncStream> = Box::new(ShadowsocksStream::new(
            client_stream,
            ShadowsocksStreamType::Aead,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            self.key.clone(),
            None,
        ));

        let hostname_bytes = remote_location.address().to_string().into_bytes();

        if hostname_bytes.len() > 255 {
            return Err(std::io::Error::other("hostname is too long"));
        }

        write_all(
            &mut client_stream,
            &[
                1, // snell version,
                1, // connect command,
                0, // client id length,
                hostname_bytes.len() as u8,
            ],
        )
        .await?;

        write_all(&mut client_stream, &hostname_bytes).await?;

        let port = remote_location.location().port();

        write_all(
            &mut client_stream,
            &[(port >> 8) as u8, (port & 0xff) as u8],
        )
        .await?;

        client_stream.flush().await?;

        let mut response = [0u8; 1];
        let n = client_stream.read(&mut response).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF when reading tunnel response",
            ));
        }

        if response[0] != 0 {
            return Err(std::io::Error::other(format!(
                "Got non-tunnel response ({})",
                response[0]
            )));
        }

        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let mut ss_stream = ShadowsocksStream::new(
            client_stream,
            ShadowsocksStreamType::Aead,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            self.key.clone(),
            None,
        );

        write_all(
            &mut ss_stream,
            &[
                1, // snell version
                6, // UDP command
                0, // client id length
            ],
        )
        .await?;
        ss_stream.flush().await?;

        let mut response = [0u8; 1];
        let n = ss_stream.read(&mut response).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF when reading UDP ready response",
            ));
        }

        if response[0] != 0 {
            return Err(std::io::Error::other(format!(
                "Got non-UDP-ready response ({})",
                response[0]
            )));
        }

        // Wraps multi-directional Snell UDP with a fixed target adapter for single-target mode.
        let max_payload_size = ShadowsocksStreamType::Aead.max_payload_len();
        let snell_udp_client_stream =
            SnellUdpClientStream::new(Box::new(ss_stream), max_payload_size);
        let fixed_target_stream =
            SnellFixedTargetStream::new(snell_udp_client_stream, target.into_location());

        Ok(Box::new(fixed_target_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::poll_fn;
    use std::future::Future;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex};

    use crate::async_stream::{AsyncPing, AsyncReadTargetedMessage};

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

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
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

    #[tokio::test]
    async fn udp_setup_preserves_first_packet_coalesced_with_header() {
        let (client_io, server_io) = duplex(8192);
        let cipher: ShadowsocksCipher = "aes-128-gcm".try_into().unwrap();
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(SnellKey::new(
            "secretpass",
            cipher.algorithm().key_len(),
        )));
        let mut client_stream = ShadowsocksStream::new(
            Box::new(TestStream(client_io)),
            ShadowsocksStreamType::Aead,
            cipher.algorithm(),
            cipher.salt_len(),
            key,
            None,
        );
        let mut first_write = vec![1, 6, 0, 1, 0, 4, 127, 0, 0, 1];
        first_write.extend_from_slice(&53u16.to_be_bytes());
        first_write.extend_from_slice(b"query");
        client_stream.write_all(&first_write).await.unwrap();
        client_stream.flush().await.unwrap();

        let handler = SnellServerHandler::new(
            cipher,
            "secretpass",
            true,
            Arc::new(ClientProxySelector::new(Vec::new())),
            Arc::new(NoopResolver),
        );
        let setup_result = handler
            .setup_server_stream(Box::new(TestStream(server_io)))
            .await
            .unwrap();
        let mut stream = match setup_result {
            TcpServerSetupResult::MultiDirectionalUdp { stream, .. } => stream,
            _ => panic!("expected Snell UDP setup"),
        };

        let mut payload = [0u8; 32];
        let mut read = ReadBuf::new(&mut payload);
        let target = poll_fn(|cx| Pin::new(&mut stream).poll_read_targeted_message(cx, &mut read))
            .await
            .unwrap();

        assert_eq!(
            target,
            NetLocation::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 53)
        );
        assert_eq!(read.filled(), b"query");
    }
}
