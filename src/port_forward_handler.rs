use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

#[derive(Debug)]
pub struct PortForwardServerHandler {
    targets: Vec<NetLocation>,
    next_target_index: AtomicU32,
    proxy_selector: Arc<ClientProxySelector>,
}

impl PortForwardServerHandler {
    pub fn new(targets: Vec<NetLocation>, proxy_selector: Arc<ClientProxySelector>) -> Self {
        Self {
            targets,
            next_target_index: AtomicU32::new(0),
            proxy_selector,
        }
    }
}

#[async_trait]
impl TcpServerHandler for PortForwardServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let location = if self.targets.len() == 1 {
            &self.targets[0]
        } else {
            let target_index = self.next_target_index.fetch_add(1, Ordering::Relaxed) as usize;
            &self.targets[target_index % self.targets.len()]
        };

        Ok(TcpServerSetupResult::TcpForward {
            remote_location: location.clone(),
            stream: server_stream,
            need_initial_flush: true,
            connection_success_response: None,
            initial_remote_data: None,
            proxy_selector: self.proxy_selector.clone(),
            outbound_dispatcher: None,
            authenticated_user: None,
        })
    }
}

#[derive(Debug)]
pub struct PortForwardClientHandler;

#[async_trait]
impl TcpClientHandler for PortForwardClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        _remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex};

    use super::*;
    use crate::config::RuleConfig;
    use crate::resolver::{NativeResolver, Resolver};
    use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;

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

    impl crate::async_stream::AsyncPing for TestStream {
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

    fn selector() -> Arc<ClientProxySelector> {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        Arc::new(create_tcp_client_proxy_selector(
            vec![RuleConfig::default()],
            resolver,
        ))
    }

    fn target(port: u16) -> NetLocation {
        NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    async fn selected_port(handler: &PortForwardServerHandler) -> u16 {
        let (stream, _peer) = duplex(64);
        let result = handler
            .setup_server_stream(Box::new(TestStream(stream)))
            .await
            .unwrap();
        let TcpServerSetupResult::TcpForward {
            remote_location, ..
        } = result
        else {
            panic!("expected TcpForward");
        };
        remote_location.components().1
    }

    #[tokio::test]
    async fn single_target_is_stable() {
        let handler = PortForwardServerHandler::new(vec![target(18080)], selector());

        assert_eq!(selected_port(&handler).await, 18080);
        assert_eq!(selected_port(&handler).await, 18080);
    }

    #[tokio::test]
    async fn multiple_targets_round_robin_per_connection() {
        let handler = PortForwardServerHandler::new(vec![target(18080), target(18081)], selector());

        assert_eq!(selected_port(&handler).await, 18080);
        assert_eq!(selected_port(&handler).await, 18081);
        assert_eq!(selected_port(&handler).await, 18080);
    }
}
