//! Outbound dispatcher: the single dial path for every inbound handler.
//!
//! Without local routing configured this is a plain direct connect, i.e.
//! behavior identical to today. With routing configured, the target is judged
//! against the compiled rules and the first-match outbound's chain group is
//! used. Blocked targets and dial failures are errors (fail-closed).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_chain::ClientChainGroup;
use crate::client_proxy_selector::SniffedProtocol;
use crate::h2mux::PrependStream;
use crate::resolver::{Resolver, resolve_addresses};

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
    /// Compiled rules; `None` when no local routing is configured.
    rules: Option<Arc<CompiledRules>>,
    /// Tag → chain group (round-robin over chains).
    chains: HashMap<String, Arc<ClientChainGroup>>,
    /// Fallback outbound tag when no rule matches; `None` = direct.
    default_out: Option<String>,
    /// Prebuilt direct chain group used when no routing is configured.
    direct: Arc<ClientChainGroup>,
}

impl std::fmt::Debug for OutboundDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundDispatcher")
            .field("has_routing", &self.rules.is_some())
            .field("chain_tags", &self.chains.keys().collect::<Vec<_>>())
            .field("default_out", &self.default_out)
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
    pub fn new(
        rules: Option<Arc<CompiledRules>>,
        chains: HashMap<String, Arc<ClientChainGroup>>,
        default_out: Option<String>,
        direct: Arc<ClientChainGroup>,
    ) -> Self {
        Self {
            rules,
            chains,
            default_out,
            direct,
        }
    }

    pub fn has_routing(&self) -> bool {
        self.rules.is_some()
    }

    /// True when the compiled rules contain `PROTOCOL` matchers, requiring
    /// protocol sniffing on incoming connections.
    pub fn requires_protocol_sniff(&self) -> bool {
        self.rules
            .as_ref()
            .is_some_and(|rules| rules.has_protocol_rules())
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
        let Some(rules) = self.rules.as_ref() else {
            log::debug!("outbound dispatch {target}: no routing configured, direct");
            return dial_via_group(&self.direct, target, resolver).await;
        };
        if rules.is_empty() {
            log::debug!("outbound dispatch {target}: empty rule set, direct");
            return dial_via_group(&self.direct, target, resolver).await;
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
        let outbound = match outbound {
            Some(tag) => tag,
            None => match rules.match_catch_all().or(self.default_out.as_deref()) {
                Some(tag) => tag,
                None => {
                    log::debug!("outbound dispatch {target}: no rule matched, direct");
                    return dial_via_group(&self.direct, target, resolver).await;
                }
            },
        };

        // 5. Dial through the matched outbound's chain group. A tag without a
        //    chain group is a configuration error: fail-closed.
        let group = self
            .chains
            .get(outbound)
            .ok_or(DialError::MissingOutbound)?;
        log::debug!("outbound dispatch {target}: outbound `{outbound}`");
        dial_via_group(group, target, resolver).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::net::Ipv4Addr;

    use crate::tcp::chain_builder::build_direct_chain_group;

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

    /// The full missing-outbound path (rule hit → tag absent from `chains`)
    /// needs a non-empty `CompiledRules`, whose `compile()` lives in another
    /// agent's module; here the error variant's rendering is verified.
    #[test]
    fn missing_outbound_error_display() {
        let err = DialError::MissingOutbound;
        assert_eq!(err.to_string(), "no outbound configured for rule result");
        assert!(err.source().is_none());
    }
}
