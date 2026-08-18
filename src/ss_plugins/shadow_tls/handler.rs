use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use parking_lot::Mutex as ParkingMutex;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    address::{Address, NetLocation},
    async_stream::{AsyncPing, AsyncStream},
    client_proxy_chain::ClientProxyChain,
    resolver::Resolver,
    shadow_tls::{ShadowTlsServerTarget, read_client_hello, setup_shadowtls_server_stream},
    tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
};

use super::{ShadowTlsV1Config, ShadowTlsV2Config, ShadowTlsV2Outcome, accept_v1, accept_v2};

#[async_trait]
pub trait ShadowTlsCamouflageConnector: Send + Sync + fmt::Debug {
    async fn connect(&self) -> io::Result<Box<dyn AsyncStream>>;
}

pub struct ClientChainShadowTlsConnector {
    location: NetLocation,
    chain: Arc<ClientProxyChain>,
    resolver: Arc<dyn Resolver>,
}

impl fmt::Debug for ClientChainShadowTlsConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientChainShadowTlsConnector")
            .field("location", &self.location)
            .field("chain", &self.chain)
            .finish_non_exhaustive()
    }
}

impl ClientChainShadowTlsConnector {
    pub fn new(
        host: &str,
        chain: ClientProxyChain,
        resolver: Arc<dyn Resolver>,
    ) -> io::Result<Self> {
        validate_host(host)?;
        Ok(Self {
            location: NetLocation::new(Address::from(host)?, 443),
            chain: Arc::new(chain),
            resolver,
        })
    }
}

#[async_trait]
impl ShadowTlsCamouflageConnector for ClientChainShadowTlsConnector {
    async fn connect(&self) -> io::Result<Box<dyn AsyncStream>> {
        let result = self
            .chain
            .connect_tcp(self.location.clone().into(), &self.resolver)
            .await?;
        if result.early_data.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "camouflage connector returned unexpected early data",
            ));
        }
        Ok(result.client_stream)
    }
}

#[allow(clippy::large_enum_variant)]
enum Mode {
    V1 {
        config: ShadowTlsV1Config,
        connector: Arc<dyn ShadowTlsCamouflageConnector>,
        inner: Arc<dyn TcpServerHandler>,
    },
    V2 {
        config: ShadowTlsV2Config,
        connector: Arc<dyn ShadowTlsCamouflageConnector>,
        inner: Arc<dyn TcpServerHandler>,
    },
    V3 {
        target: Arc<ShadowTlsServerTarget>,
        resolver: Arc<dyn Resolver>,
        fallback_connector: Option<Arc<dyn ShadowTlsCamouflageConnector>>,
    },
}

pub struct ShadowTlsPluginServerHandler {
    mode: Mode,
}

impl fmt::Debug for ShadowTlsPluginServerHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let version = match &self.mode {
            Mode::V1 { .. } => 1,
            Mode::V2 { .. } => 2,
            Mode::V3 { .. } => 3,
        };
        formatter
            .debug_struct("ShadowTlsPluginServerHandler")
            .field("version", &version)
            .finish_non_exhaustive()
    }
}

impl ShadowTlsPluginServerHandler {
    pub fn new_v1(
        connector: Arc<dyn ShadowTlsCamouflageConnector>,
        inner: Arc<dyn TcpServerHandler>,
    ) -> Self {
        Self {
            mode: Mode::V1 {
                config: ShadowTlsV1Config::default(),
                connector,
                inner,
            },
        }
    }

    pub fn new_v2(
        password: impl AsRef<[u8]>,
        connector: Arc<dyn ShadowTlsCamouflageConnector>,
        inner: Arc<dyn TcpServerHandler>,
    ) -> io::Result<Self> {
        Ok(Self {
            mode: Mode::V2 {
                config: ShadowTlsV2Config::new(password)?,
                connector,
                inner,
            },
        })
    }

    pub fn new_v3(target: Arc<ShadowTlsServerTarget>, resolver: Arc<dyn Resolver>) -> Self {
        Self {
            mode: Mode::V3 {
                target,
                resolver,
                fallback_connector: None,
            },
        }
    }

    pub fn new_v3_with_fallback(
        target: Arc<ShadowTlsServerTarget>,
        resolver: Arc<dyn Resolver>,
        fallback_connector: Arc<dyn ShadowTlsCamouflageConnector>,
    ) -> Self {
        Self {
            mode: Mode::V3 {
                target,
                resolver,
                fallback_connector: Some(fallback_connector),
            },
        }
    }
}

#[async_trait]
impl TcpServerHandler for ShadowTlsPluginServerHandler {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_peer_addr(stream, None).await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        stream: Box<dyn AsyncStream>,
        peer_addr: Option<SocketAddr>,
    ) -> io::Result<TcpServerSetupResult> {
        match &self.mode {
            Mode::V1 {
                config,
                connector,
                inner,
            } => {
                let camouflage = connector.connect().await?;
                let stream = accept_v1(stream, camouflage, *config).await?;
                inner
                    .setup_server_stream_with_peer_addr(stream, peer_addr)
                    .await
            }
            Mode::V2 {
                config,
                connector,
                inner,
            } => {
                let camouflage = connector.connect().await?;
                match accept_v2(stream, camouflage, config).await? {
                    ShadowTlsV2Outcome::Authenticated(stream) => {
                        inner
                            .setup_server_stream_with_peer_addr(Box::new(stream), peer_addr)
                            .await
                    }
                    ShadowTlsV2Outcome::Fallback(fallback) => {
                        Ok(TcpServerSetupResult::connection_task(async move {
                            let _ = fallback.relay().await;
                            Ok(())
                        }))
                    }
                }
            }
            Mode::V3 {
                target,
                resolver,
                fallback_connector,
            } => {
                let (mut stream, capture) = CapturingProbeStream::wrap(stream);
                let parsed = match read_client_hello(&mut stream).await {
                    Ok(parsed) => {
                        capture.finish(false);
                        parsed
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
                        ) && fallback_connector.is_some() =>
                    {
                        let consumed = capture.finish(true);
                        if consumed.is_empty() {
                            return Err(error);
                        }
                        return fallback_v3_probe(
                            stream,
                            fallback_connector
                                .as_ref()
                                .ok_or_else(|| io::Error::other("missing v3 fallback connector"))?,
                            &consumed,
                        )
                        .await;
                    }
                    Err(error) => {
                        capture.finish(false);
                        return Err(error);
                    }
                };
                let result =
                    setup_shadowtls_server_stream(stream, target, parsed, resolver).await?;
                Ok(with_transport_peer_addr(result, peer_addr))
            }
        }
    }
}

#[derive(Default)]
struct ProbeCaptureState {
    enabled: bool,
    bytes: Vec<u8>,
}

#[derive(Clone)]
struct ProbeCapture(Arc<ParkingMutex<ProbeCaptureState>>);

impl ProbeCapture {
    fn finish(&self, take_bytes: bool) -> Vec<u8> {
        let mut state = self.0.lock();
        state.enabled = false;
        if take_bytes {
            std::mem::take(&mut state.bytes)
        } else {
            state.bytes.clear();
            Vec::new()
        }
    }
}

struct CapturingProbeStream {
    inner: Box<dyn AsyncStream>,
    capture: ProbeCapture,
}

impl CapturingProbeStream {
    fn wrap(stream: Box<dyn AsyncStream>) -> (Box<dyn AsyncStream>, ProbeCapture) {
        let capture = ProbeCapture(Arc::new(ParkingMutex::new(ProbeCaptureState {
            enabled: true,
            bytes: Vec::new(),
        })));
        (
            Box::new(Self {
                inner: stream,
                capture: capture.clone(),
            }),
            capture,
        )
    }
}

impl AsyncRead for CapturingProbeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let previous_len = output.filled().len();
        let result = Pin::new(&mut *self.inner).poll_read(cx, output);
        if matches!(&result, Poll::Ready(Ok(()))) {
            let newly_read = &output.filled()[previous_len..];
            let mut capture = self.capture.0.lock();
            if capture.enabled {
                capture.bytes.extend_from_slice(newly_read);
            }
        }
        result
    }
}

impl AsyncWrite for CapturingProbeStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for CapturingProbeStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut *self.inner).poll_write_ping(cx)
    }
}

impl AsyncStream for CapturingProbeStream {}

async fn fallback_v3_probe(
    mut client: Box<dyn AsyncStream>,
    connector: &Arc<dyn ShadowTlsCamouflageConnector>,
    consumed: &[u8],
) -> io::Result<TcpServerSetupResult> {
    let mut camouflage = connector.connect().await?;
    camouflage.write_all(consumed).await?;
    camouflage.flush().await?;
    Ok(TcpServerSetupResult::connection_task(async move {
        let _ = tokio::io::copy_bidirectional(&mut client, &mut camouflage).await;
        let _ = client.shutdown().await;
        let _ = camouflage.shutdown().await;
        Ok(())
    }))
}

/// Keep the transport peer outside any protocol-derived override. The TCP
/// server applies nested overrides from outside to inside, so a non-empty
/// address produced by the inner v3 target remains authoritative.
fn with_transport_peer_addr(
    result: TcpServerSetupResult,
    peer_addr: Option<SocketAddr>,
) -> TcpServerSetupResult {
    TcpServerSetupResult::PeerAddressOverride {
        peer_addr,
        result: Box::new(result),
    }
}

fn validate_host(host: &str) -> io::Result<()> {
    let invalid = host.is_empty()
        || host.len() > 253
        || host.contains(['\0', '\r', '\n'])
        || host.trim() != host
        || (host.contains(':') && host.parse::<IpAddr>().is_err());
    if invalid {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid ShadowTLS camouflage host",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::Mutex,
        task::{Context, Poll},
    };

    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex};

    use super::*;
    use crate::async_stream::AsyncPing;

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, output)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, input)
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

    struct OneShotConnector(Mutex<Option<TestStream>>);

    impl fmt::Debug for OneShotConnector {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("OneShotConnector")
        }
    }

    #[async_trait]
    impl ShadowTlsCamouflageConnector for OneShotConnector {
        async fn connect(&self) -> io::Result<Box<dyn AsyncStream>> {
            self.0
                .lock()
                .map_err(|_| io::Error::other("test connector lock poisoned"))?
                .take()
                .map(|stream| Box::new(stream) as Box<dyn AsyncStream>)
                .ok_or_else(|| io::Error::other("test connector already consumed"))
        }
    }

    #[derive(Debug)]
    struct CapturePeer(Mutex<Vec<Option<SocketAddr>>>);

    #[async_trait]
    impl TcpServerHandler for CapturePeer {
        async fn setup_server_stream(
            &self,
            stream: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            self.setup_server_stream_with_peer_addr(stream, None).await
        }

        async fn setup_server_stream_with_peer_addr(
            &self,
            _stream: Box<dyn AsyncStream>,
            peer_addr: Option<SocketAddr>,
        ) -> io::Result<TcpServerSetupResult> {
            self.0
                .lock()
                .map_err(|_| io::Error::other("test peer lock poisoned"))?
                .push(peer_addr);
            Ok(TcpServerSetupResult::completed())
        }
    }

    #[test]
    fn camouflage_host_is_always_a_bare_host_for_port_443() {
        assert!(validate_host("example.com").is_ok());
        assert!(validate_host("2001:db8::1").is_ok());
        assert!(validate_host("example.com:8443").is_err());
        assert!(validate_host("[2001:db8::1]:8443").is_err());
        assert!(validate_host("bad\r\nhost").is_err());
    }

    #[tokio::test]
    async fn v1_handler_passes_transport_peer_to_inner_handler() {
        let (mut client_peer, client_server) = duplex(4096);
        let (camouflage_server, mut camouflage_peer) = duplex(4096);
        let captured = Arc::new(CapturePeer(Mutex::new(Vec::new())));
        let handler = ShadowTlsPluginServerHandler::new_v1(
            Arc::new(OneShotConnector(Mutex::new(Some(TestStream(
                camouflage_server,
            ))))),
            captured.clone(),
        );
        let peer_addr = "192.0.2.10:4242".parse().unwrap();

        let setup = tokio::spawn(async move {
            handler
                .setup_server_stream_with_peer_addr(
                    Box::new(TestStream(client_server)),
                    Some(peer_addr),
                )
                .await
        });

        super::super::TlsRecord::new(22, 0x0301, vec![1, 0, 0, 1, 9])
            .unwrap()
            .write_to(&mut client_peer)
            .await
            .unwrap();
        super::super::TlsRecord::new(20, 0x0303, vec![1])
            .unwrap()
            .write_to(&mut client_peer)
            .await
            .unwrap();
        super::super::TlsRecord::new(22, 0x0303, vec![20, 0, 0, 0])
            .unwrap()
            .write_to(&mut client_peer)
            .await
            .unwrap();
        for _ in 0..3 {
            let _ = super::super::record::read_record(&mut camouflage_peer)
                .await
                .unwrap();
        }

        super::super::TlsRecord::new(22, 0x0303, vec![2, 0, 0, 0])
            .unwrap()
            .write_to(&mut camouflage_peer)
            .await
            .unwrap();
        super::super::TlsRecord::new(20, 0x0303, vec![1])
            .unwrap()
            .write_to(&mut camouflage_peer)
            .await
            .unwrap();
        super::super::TlsRecord::new(22, 0x0303, vec![20, 0, 0, 0])
            .unwrap()
            .write_to(&mut camouflage_peer)
            .await
            .unwrap();
        for _ in 0..3 {
            let _ = super::super::record::read_record(&mut client_peer)
                .await
                .unwrap();
        }

        let TcpServerSetupResult::ConnectionTask(task) = setup.await.unwrap().unwrap() else {
            panic!("fallback must return an owned connection task")
        };
        task.await.unwrap();
        assert_eq!(
            *captured.0.lock().unwrap(),
            vec![Some("192.0.2.10:4242".parse().unwrap())]
        );
    }

    #[test]
    fn v3_transport_peer_stays_outside_a_more_specific_inner_override() {
        let transport_peer = Some("192.0.2.1:1000".parse().unwrap());
        let protocol_peer = Some("198.51.100.2:2000".parse().unwrap());
        let nested = TcpServerSetupResult::PeerAddressOverride {
            peer_addr: protocol_peer,
            result: Box::new(TcpServerSetupResult::completed()),
        };
        let wrapped = with_transport_peer_addr(nested, transport_peer);

        let TcpServerSetupResult::PeerAddressOverride { peer_addr, result } = wrapped else {
            panic!("transport override was not retained")
        };
        assert_eq!(peer_addr, transport_peer);
        let TcpServerSetupResult::PeerAddressOverride { peer_addr, .. } = *result else {
            panic!("protocol override was overwritten")
        };
        assert_eq!(peer_addr, protocol_peer);
    }

    #[tokio::test]
    async fn v3_malformed_client_hello_falls_back_without_losing_bytes() {
        let certified =
            rcgen::generate_simple_self_signed(vec!["camouflage.example".to_string()]).unwrap();
        let server_config = Arc::new(crate::rustls_config_util::create_server_config(
            certified.cert.pem().as_bytes(),
            certified.signing_key.serialize_pem().as_bytes(),
            Vec::new(),
            &[],
            &[],
        ));
        let target = Arc::new(ShadowTlsServerTarget::new(
            "password".to_string(),
            crate::shadow_tls::ShadowTlsServerTargetHandshake::new_local(server_config),
            Box::new(CapturePeer(Mutex::new(Vec::new()))),
        ));
        let (mut client_peer, client_server) = duplex(4096);
        let (camouflage_server, mut camouflage_peer) = duplex(4096);
        let handler = ShadowTlsPluginServerHandler::new_v3_with_fallback(
            target,
            Arc::new(crate::resolver::NativeResolver::new()),
            Arc::new(OneShotConnector(Mutex::new(Some(TestStream(
                camouflage_server,
            ))))),
        );

        let setup = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(client_server)))
                .await
        });

        // Invalid TLS content type plus bytes that the ClientHello reader may
        // consume in the same poll.
        let initial = [0x01, 0x03, 0x03, 0x00, 0x00, 1, 2, 3];
        client_peer.write_all(&initial).await.unwrap();
        let TcpServerSetupResult::ConnectionTask(task) = setup.await.unwrap().unwrap() else {
            panic!("fallback must return an owned connection task")
        };
        let fallback_task = tokio::spawn(task);

        client_peer.write_all(&[4, 5, 6]).await.unwrap();
        let mut forwarded = [0u8; 11];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            tokio::io::AsyncReadExt::read_exact(&mut camouflage_peer, &mut forwarded),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(forwarded, [0x01, 0x03, 0x03, 0, 0, 1, 2, 3, 4, 5, 6]);
        fallback_task.abort();
        let _ = fallback_task.await;
    }
}
