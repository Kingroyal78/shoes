//! Outbound dispatcher: the single dial path for every inbound handler.
//!
//! Without local routing configured this is a plain direct connect, i.e.
//! behavior identical to today. With routing configured, the target is judged
//! against the compiled rules and the first-match outbound's chain group is
//! used. Blocked targets and dial failures are errors (fail-closed).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::backend_config::{RouteRuleSetsConfig, RuleProviderConfig};
use crate::client_proxy_chain::ClientChainGroup;
use crate::client_proxy_selector::SniffedProtocol;
use crate::h2mux::PrependStream;
use crate::resolver::{Resolver, resolve_addresses};

use super::compiler::{compile_route_rules, provider_mtimes};
use super::index::CompiledRules;

/// Dial result: the established stream (direct or proxied).
pub type DialedStream = Box<dyn AsyncStream>;

/// Failure to dial a target. Distinct variants let handlers log accurately.
#[derive(Debug)]
pub enum DialError {
    /// Target rejected by routing rules.
    Blocked(NetLocation),
    /// A rule referenced an outbound tag that has no chain group.
    MissingOutbound,
    /// Underlying I/O failure.
    Io(std::io::Error),
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialError::Blocked(target) => write!(f, "target blocked by routing rules: {target}"),
            DialError::MissingOutbound => write!(f, "no outbound configured for rule result"),
            DialError::Io(err) => write!(f, "io error: {err}"),
        }
    }
}

impl std::error::Error for DialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DialError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DialError {
    fn from(err: std::io::Error) -> Self {
        DialError::Io(err)
    }
}

/// The node-side outbound dispatcher. Shared (`Arc`) across handlers.
pub struct OutboundDispatcher {
    /// Compiled rules; `None` when no local routing is configured. Guarded so
    /// rule-provider hot reload can swap the compiled set.
    rules: RwLock<Option<Arc<CompiledRules>>>,
    /// Tag → chain group (round-robin over chains).
    chains: HashMap<String, Arc<ClientChainGroup>>,
    /// Fallback outbound tag when no rule matches; `None` = direct.
    default_out: Option<String>,
    /// Prebuilt direct chain group used when no routing is configured.
    direct: Arc<ClientChainGroup>,
    /// Rule-provider reload state; `None` when hot reload is not configured.
    refresh: Option<RwLock<RuleRefreshState>>,
}

/// Hot-reload state for `rule_providers` files. The compiled rule set is
/// swapped lazily on the next dial once provider mtimes change.
struct RuleRefreshState {
    node_tag: String,
    config_lines: Vec<String>,
    providers: Vec<RuleProviderConfig>,
    rule_sets: RouteRuleSetsConfig,
    interval: Duration,
    last_check: Instant,
    last_mtimes: HashMap<String, u64>,
}

impl std::fmt::Debug for OutboundDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundDispatcher")
            .field("has_routing", &self.rules_read().is_some())
            .field("chain_tags", &self.chains.keys().collect::<Vec<_>>())
            .field("default_out", &self.default_out)
            .field("hot_reload", &self.refresh.is_some())
            .finish_non_exhaustive()
    }
}

/// Dial through `group`, converting the setup result into a `DialedStream`.
/// Early data buffered during the outbound handshake is preserved by
/// prepending it to the stream (same pattern as the server-side
/// `PrependStream` usage), so no destination bytes are lost.
async fn dial_via_group(
    group: &ClientChainGroup,
    target: &NetLocation,
    resolver: &Arc<dyn Resolver>,
) -> Result<DialedStream, DialError> {
    let result = group
        .connect_tcp(ResolvedLocation::new(target.clone()), resolver)
        .await?;
    let client_stream = result.client_stream;
    Ok(match result.early_data {
        Some(data) => {
            log::debug!(
                "outbound dispatch {target}: wrapping {} bytes of early data",
                data.len()
            );
            Box::new(PrependStream::new(
                client_stream,
                Some(data.into_boxed_slice()),
            ))
        }
        None => client_stream,
    })
}

impl OutboundDispatcher {
    fn rules_read(&self) -> std::sync::RwLockReadGuard<'_, Option<Arc<CompiledRules>>> {
        self.rules.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn new(
        rules: Option<Arc<CompiledRules>>,
        chains: HashMap<String, Arc<ClientChainGroup>>,
        default_out: Option<String>,
        direct: Arc<ClientChainGroup>,
    ) -> Self {
        Self {
            rules: RwLock::new(rules),
            chains,
            default_out,
            direct,
            refresh: None,
        }
    }

    /// Attaches rule-provider hot reload. `interval` is the minimum of the
    /// configured provider reload intervals; `last_mtimes` seeds the mtime
    /// baseline so the first dial does not reload unnecessarily.
    pub fn with_rule_refresh(
        mut self,
        node_tag: &str,
        config_lines: &[String],
        providers: Vec<RuleProviderConfig>,
        rule_sets: RouteRuleSetsConfig,
        interval: Duration,
        last_mtimes: HashMap<String, u64>,
    ) -> Self {
        self.refresh = Some(RwLock::new(RuleRefreshState {
            node_tag: node_tag.to_string(),
            config_lines: config_lines.to_vec(),
            providers,
            rule_sets,
            interval,
            last_check: Instant::now(),
            last_mtimes,
        }));
        self
    }

    /// Recompiles the rule set when a rule-provider file's mtime changed and
    /// the reload interval elapsed. Swaps the compiled set on success; on
    /// failure keeps the previous set and retries on the next check.
    pub fn maybe_refresh_rules(&self) {
        let Some(lock) = &self.refresh else {
            return;
        };
        let mut state = match lock.try_write() {
            Ok(state) => state,
            Err(_) => return,
        };
        if state.last_check.elapsed() < state.interval {
            return;
        }
        state.last_check = Instant::now();
        let Ok(mtimes) = provider_mtimes(&state.providers) else {
            return;
        };
        if mtimes == state.last_mtimes {
            return;
        }
        match compile_route_rules(
            &state.node_tag,
            &state.config_lines,
            &state.providers,
            &state.rule_sets,
        ) {
            Ok(compiled) => {
                state.last_mtimes = mtimes;
                *self.rules.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(compiled));
                log::info!("outbound rules reloaded: provider mtimes changed");
            }
            Err(err) => log::warn!("outbound rules reload failed: {err}"),
        }
    }

    pub fn has_routing(&self) -> bool {
        self.rules_read().is_some()
    }

    /// True when the compiled rules contain `PROTOCOL` matchers, requiring
    /// protocol sniffing on incoming connections.
    pub fn requires_protocol_sniff(&self) -> bool {
        self.rules
            .read()
            .unwrap()
            .as_ref()
            .is_some_and(|rules| rules.has_protocol_rules())
    }

    /// Decides the outbound tag for `target`, mirroring `dial_tcp`'s decision
    /// order. `None` means direct. Sniffed protocols are only consulted when
    /// `sniffed` is `Some`.
    async fn select_outbound(
        &self,
        target: &NetLocation,
        sniffed: Option<SniffedProtocol>,
        resolver: &Arc<dyn Resolver>,
    ) -> Result<Option<String>, DialError> {
        let Some(rules) = self.rules_read().clone() else {
            return Ok(None);
        };
        if rules.is_empty() {
            return Ok(None);
        }

        // 1. Protocol bucket, only consulted when a protocol was sniffed.
        let mut outbound: Option<&str> = None;
        if let Some(protocol) = sniffed
            && let Some(tag) = rules.match_protocol(protocol)
        {
            outbound = Some(tag);
        }

        // 2. Domain rules apply to hostname targets only.
        if outbound.is_none()
            && let Some(domain) = target.address().hostname()
        {
            outbound = rules.match_domain(domain);
        }

        // 3. IP rules: IP literals match directly; hostname targets are
        //    resolved first (only when any IP rule exists). Resolution
        //    failure is fail-closed.
        if outbound.is_none() {
            outbound = match target.address() {
                Address::Ipv4(ip) => rules.match_ip(IpAddr::V4(*ip), target.port()),
                Address::Ipv6(ip) => rules.match_ip(IpAddr::V6(*ip), target.port()),
                Address::Hostname(_) if rules.has_ip_rules() => {
                    let addrs = resolve_addresses(resolver, target).await?;
                    addrs
                        .iter()
                        .find_map(|addr| rules.match_ip(addr.ip(), target.port()))
                }
                Address::Hostname(_) => None,
            };
        }

        // 4. Fallbacks: MATCH catch-all, then default_out, then direct.
        Ok(outbound
            .map(str::to_string)
            .or_else(|| rules.match_catch_all().map(str::to_string))
            .or_else(|| self.default_out.clone()))
    }

    /// Dial `target`, optionally with a sniffed protocol. Resolver is used to
    /// resolve hostname targets when IP rules exist.
    ///
    /// Decision order: protocol rule (only when `sniffed` is `Some`), then
    /// domain rule (hostname targets only), then IP rule (IP literals
    /// directly, hostname targets via DNS when IP rules exist), then the
    /// `MATCH` catch-all, then `default_out`, then direct. The `match_*`
    /// indexes each return the smallest-order hit within their matcher type,
    /// so cross-type order (protocol vs domain vs IP) is approximated by this
    /// fixed priority rather than by global rule order.
    pub async fn dial_tcp(
        &self,
        target: &NetLocation,
        sniffed: Option<SniffedProtocol>,
        resolver: &Arc<dyn Resolver>,
    ) -> Result<DialedStream, DialError> {
        self.maybe_refresh_rules();
        let Some(outbound) = self.select_outbound(target, sniffed, resolver).await? else {
            log::debug!("outbound dispatch {target}: no rule matched, direct");
            return dial_via_group(&self.direct, target, resolver).await;
        };

        // Dial through the matched outbound's chain group. A tag without a
        // chain group is a configuration error: fail-closed.
        let group = self
            .chains
            .get(&outbound)
            .ok_or(DialError::MissingOutbound)?;
        log::debug!("outbound dispatch {target}: outbound `{outbound}`");
        dial_via_group(group, target, resolver).await
    }

    /// Establishes a bidirectional UDP relay stream for `target` through the
    /// matched outbound's chain group. The target is pre-resolved (callers
    /// resolve hostnames), so only domain/IP literals and fallbacks apply.
    pub async fn connect_udp_bidirectional(
        &self,
        target: &ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        self.maybe_refresh_rules();
        let Some(rules) = self.rules_read().clone() else {
            log::debug!("outbound dispatch {target}: no routing configured, direct");
            return self
                .direct
                .connect_udp_bidirectional(resolver, target.clone())
                .await;
        };
        if rules.is_empty() {
            log::debug!("outbound dispatch {target}: empty rule set, direct");
            return self
                .direct
                .connect_udp_bidirectional(resolver, target.clone())
                .await;
        }

        // 1. Domain rules apply to hostname targets only.
        let mut outbound: Option<String> = None;
        if let Some(domain) = target.address().hostname() {
            outbound = rules.match_domain(domain).map(str::to_string);
        }

        // 2. IP rules match the pre-resolved address directly.
        if outbound.is_none() {
            outbound = match target.address() {
                Address::Ipv4(ip) => rules
                    .match_ip(IpAddr::V4(*ip), target.location().port())
                    .map(str::to_string),
                Address::Ipv6(ip) => rules
                    .match_ip(IpAddr::V6(*ip), target.location().port())
                    .map(str::to_string),
                Address::Hostname(_) => None,
            };
        }

        // 3. Fallbacks: MATCH catch-all, then default_out, then direct.
        let Some(outbound) = outbound
            .or_else(|| rules.match_catch_all().map(str::to_string))
            .or_else(|| self.default_out.clone())
        else {
            log::debug!("outbound dispatch {target}: no rule matched, direct");
            return self
                .direct
                .connect_udp_bidirectional(resolver, target.clone())
                .await;
        };

        let group = self
            .chains
            .get(&outbound)
            .ok_or_else(|| DialError::MissingOutbound.to_io_error())?;
        log::debug!("outbound dispatch {target}: outbound `{outbound}` (udp)");
        group
            .connect_udp_bidirectional(resolver, target.clone())
            .await
    }
}

impl DialError {
    pub(crate) fn to_io_error(&self) -> std::io::Error {
        match self {
            DialError::Blocked(target) => std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("target blocked by routing rules: {target}"),
            ),
            DialError::MissingOutbound => {
                std::io::Error::new(std::io::ErrorKind::NotFound, self.to_string())
            }
            DialError::Io(err) => std::io::Error::new(err.kind(), err.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::future::poll_fn;
    use std::net::Ipv4Addr;
    use std::pin::Pin;
    use std::task::Poll;

    use tokio::io::ReadBuf;

    use crate::async_stream::{AsyncFlushMessage, AsyncReadMessage, AsyncWriteMessage};
    use crate::tcp::chain_builder::build_direct_chain_group;
    use crate::util::allocate_vec;

    fn test_resolver() -> Arc<dyn Resolver> {
        Arc::new(crate::resolver::NativeResolver::new())
    }

    /// Returns a localhost port with no listener on it. Binding to port 0 and
    /// dropping the listener gives a port that is almost certainly closed.
    fn closed_local_port() -> u16 {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.local_addr().unwrap().port()
    }

    fn localhost(port: u16) -> NetLocation {
        NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), port)
    }

    /// Direct dial to a closed localhost port must fail with an Io error
    /// (connection refused), not Blocked/MissingOutbound — proving the
    /// no-routing dispatcher takes the direct path.
    #[tokio::test]
    async fn no_routing_is_direct() {
        let resolver = test_resolver();
        let dispatcher = OutboundDispatcher::new(
            None,
            HashMap::new(),
            None,
            Arc::new(build_direct_chain_group(resolver.clone())),
        );

        assert!(!dispatcher.has_routing());

        let result = dispatcher
            .dial_tcp(&localhost(closed_local_port()), None, &resolver)
            .await;
        let err = match result {
            Ok(_) => panic!("dial to a closed port must fail"),
            Err(err) => err,
        };
        match err {
            DialError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionRefused),
            other => panic!("expected DialError::Io, got {other:?}"),
        }
    }

    /// A present-but-empty rule set behaves exactly like no routing at all.
    #[tokio::test]
    async fn empty_rules_fall_back_to_direct() {
        let resolver = test_resolver();
        let dispatcher = OutboundDispatcher::new(
            Some(Arc::new(CompiledRules::empty())),
            HashMap::new(),
            None,
            Arc::new(build_direct_chain_group(resolver.clone())),
        );

        assert!(dispatcher.has_routing());

        let result = dispatcher
            .dial_tcp(&localhost(closed_local_port()), None, &resolver)
            .await;
        let err = match result {
            Ok(_) => panic!("dial to a closed port must fail"),
            Err(err) => err,
        };
        assert!(
            matches!(err, DialError::Io(ref e) if e.kind() == std::io::ErrorKind::ConnectionRefused),
            "expected DialError::Io(ConnectionRefused), got {err:?}"
        );
    }

    #[test]
    fn has_routing_reflects_rules_presence() {
        let resolver = test_resolver();
        let direct = Arc::new(build_direct_chain_group(resolver));

        let none = OutboundDispatcher::new(None, HashMap::new(), None, direct.clone());
        assert!(!none.has_routing());

        let some = OutboundDispatcher::new(
            Some(Arc::new(CompiledRules::empty())),
            HashMap::new(),
            None,
            direct,
        );
        assert!(some.has_routing());
    }

    /// `DialError::Blocked` cannot be produced by `dial_tcp` (blocking is the
    /// existing V2Board selector's job, not the dispatcher's), so this test
    /// verifies the variant's construction and rendering instead.
    #[test]
    fn blocked_error_construction_and_display() {
        let target = localhost(443);
        let err = DialError::Blocked(target.clone());
        assert_eq!(
            err.to_string(),
            "target blocked by routing rules: 127.0.0.1:443"
        );
        assert!(err.source().is_none());

        let io_err = std::io::Error::other("boom");
        let err = DialError::Io(io_err);
        assert_eq!(err.to_string(), "io error: boom");
        assert!(err.source().is_some());

        let err: DialError =
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused").into();
        assert!(matches!(err, DialError::Io(_)));
    }

    /// Verify that an IP-CIDR rule routes traffic to the configured outbound
    /// chain. Spawns a local TCP echo server, configures an IP-CIDR rule
    /// matching 127.0.0.1 → `direct-out`, and dials through the dispatcher.
    #[tokio::test]
    async fn ip_cidr_rule_routes_to_configured_outbound() {
        let resolver = test_resolver();
        let direct_group = Arc::new(build_direct_chain_group(resolver.clone()));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let _echo_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.split();
            tokio::io::copy(&mut r, &mut w).await.unwrap();
            let _ = done_tx.send(());
        });

        let config_lines = vec!["IP-CIDR,127.0.0.1/32,direct-out".to_string()];
        let compiled = compile_route_rules(
            "test",
            &config_lines,
            &[],
            &RouteRuleSetsConfig {
                geosite: HashMap::new(),
                geoip: HashMap::new(),
            },
        )
        .unwrap();

        let mut chains = HashMap::new();
        chains.insert("direct-out".to_string(), direct_group.clone());

        let dispatcher =
            OutboundDispatcher::new(Some(Arc::new(compiled)), chains, None, direct_group.clone());

        assert!(dispatcher.has_routing());

        let target = NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), echo_addr.port());
        let mut stream = dispatcher
            .dial_tcp(&target, None, &resolver)
            .await
            .expect("dial_tcp must succeed via IP-CIDR rule");

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let message = b"hello-dispatcher";
        stream.write_all(message).await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], message, "echo must return original bytes");

        drop(stream);
        done_rx.await.ok();
    }

    /// Without rules (empty rule set), `dial_tcp` falls back to direct,
    /// connecting to the target without any routing.
    #[tokio::test]
    async fn no_rules_dials_direct_to_tcp_echo() {
        let resolver = test_resolver();
        let direct_group = Arc::new(build_direct_chain_group(resolver.clone()));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let _echo_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = stream.split();
            tokio::io::copy(&mut r, &mut w).await.unwrap();
            let _ = done_tx.send(());
        });

        let dispatcher = OutboundDispatcher::new(None, HashMap::new(), None, direct_group);

        assert!(!dispatcher.has_routing());

        let target = NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), echo_addr.port());
        let mut stream = dispatcher
            .dial_tcp(&target, None, &resolver)
            .await
            .expect("no-rules dial_tcp must succeed via direct");

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let message = b"direct-echo";
        stream.write_all(message).await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.unwrap();
        assert!(
            n > 0,
            "echo from direct fallback must return a positive number of bytes"
        );

        drop(stream);
        done_rx.await.ok();
    }

    /// `connect_udp_bidirectional` with no-rules dispatcher sends a UDP
    /// datagram and receives an echo through the direct chain group.
    #[tokio::test]
    async fn udp_bidirectional_no_rules_echoes() {
        let resolver = test_resolver();
        let direct_group = Arc::new(build_direct_chain_group(resolver.clone()));

        let echo_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_socket.local_addr().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let _echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (n, addr) = echo_socket.recv_from(&mut buf).await.unwrap();
            echo_socket.send_to(&buf[..n], addr).await.unwrap();
            let _ = done_tx.send(());
        });

        let dispatcher = OutboundDispatcher::new(None, HashMap::new(), None, direct_group);

        let resolved = ResolvedLocation::with_resolved(
            NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), echo_addr.port()),
            echo_addr,
        );
        let stream = dispatcher
            .connect_udp_bidirectional(&resolved, &resolver)
            .await
            .expect("no-rules connect_udp_bidirectional must succeed");

        let mut stream = stream;

        let message = b"udp-echo";
        poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, message))
            .await
            .unwrap();
        poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
            .await
            .unwrap();

        let mut read_buf = allocate_vec(2048);
        let n = poll_fn(|cx| {
            let mut rb = ReadBuf::new(&mut read_buf);
            match Pin::new(&mut stream).poll_read_message(cx, &mut rb) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
        .unwrap();
        assert!(n > 0, "UDP echo must return a positive number of bytes");

        done_rx.await.ok();
    }

    /// Verifies that rule-provider hot reload can be attached to a new
    /// dispatcher without panicking, and the dispatcher remains usable.
    #[test]
    fn with_rule_refresh_seeds_refresh_state() {
        let resolver = test_resolver();
        let direct = Arc::new(build_direct_chain_group(resolver));
        let empty_rules = Arc::new(CompiledRules::empty());

        let mtimes: HashMap<String, u64> = HashMap::new();
        let d = OutboundDispatcher::new(Some(empty_rules), HashMap::new(), None, direct)
            .with_rule_refresh(
                "test-node",
                &[],
                vec![],
                RouteRuleSetsConfig {
                    geosite: HashMap::new(),
                    geoip: HashMap::new(),
                },
                Duration::from_secs(300),
                mtimes,
            );
        assert!(d.has_routing());
    }

    /// Calling `maybe_refresh_rules` on an empty/no-provider dispatcher is a
    /// no-op — no reload is needed and no error is raised.
    #[tokio::test]
    async fn maybe_refresh_rules_no_providers_is_noop() {
        let resolver = test_resolver();
        let direct = Arc::new(build_direct_chain_group(resolver));
        let empty_rules = Arc::new(CompiledRules::empty());

        let mtimes: HashMap<String, u64> = HashMap::new();
        let d = std::sync::Arc::new(
            OutboundDispatcher::new(Some(empty_rules), HashMap::new(), None, direct)
                .with_rule_refresh(
                    "test-node",
                    &[],
                    vec![],
                    RouteRuleSetsConfig {
                        geosite: HashMap::new(),
                        geoip: HashMap::new(),
                    },
                    Duration::from_secs(300),
                    mtimes,
                ),
        );

        // No providers, so reload is a no-op
        d.maybe_refresh_rules();
        // shouldn't panic
    }
}
