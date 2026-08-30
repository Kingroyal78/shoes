//! Per-user dedicated egress.
//!
//! The panel sells a user an exit IP that is theirs alone and publishes it on
//! the user list as `dedicated_ip` (see the panel's
//! `docs/dedicated-ip-contract-v1.md`). Inbound is untouched: the buyer keeps
//! connecting to the node they were already using, authenticating as
//! themselves. Only the way the node sends their traffic out changes.
//!
//! Two ways to obtain that exit, both landing on the same dial path:
//!
//! * `Source` — the box itself holds the address, so outbound sockets bind to
//!   it before connecting.
//! * `Upstream` — the address belongs to a third-party SOCKS5/HTTP proxy the
//!   operator bought, so outbound is dialed through that proxy.
//!
//! Building a chain per egress, instead of threading a bind address through
//! `SocketConnector::connect`, keeps the trait and all of its implementations
//! untouched. A chain is a couple of small allocations and is cached for the
//! process lifetime, so a node with a /24 of sold addresses holds 256 of them.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock, RwLock};

use log::warn;

use crate::address::{Address, NetLocation};
use crate::client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry};
use crate::config::{ClientConfig, ClientProxyConfig};
use crate::resolver::Resolver;
use crate::tcp::proxy_connector_impl::ProxyConnectorImpl;
use crate::tcp::socket_connector_impl::SocketConnectorImpl;
use crate::v2board::outbound::dispatcher::OutboundDispatcher;

use super::types::DedicatedIp;

/// How a user's traffic leaves the box.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DedicatedEgress {
    /// Bind outbound sockets to this source address.
    Source(IpAddr),
    /// Dial through this upstream proxy.
    Upstream(UpstreamProxy),
}

/// A bought proxy the panel handed over, credentials included.
///
/// These credentials are the node's dialing credentials, never the buyer's:
/// the panel does not publish them to the user. That makes them the
/// operator's to lose, and `Debug` is how they leaked: every dial site
/// printed the whole binding with `{:?}` when it skipped one, so a node with
/// an outbound dispatcher wrote the upstream's password to the log on every
/// connection. Redacted here rather than at each call site, because the next
/// call site would not know to.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct UpstreamProxy {
    pub protocol: UpstreamProtocol,
    pub addr: IpAddr,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl std::fmt::Debug for UpstreamProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keeps what identifies the egress and drops what authenticates to
        // it. Whether credentials were configured is itself diagnostic -- an
        // upstream refusing an unauthenticated dial reads very differently
        // from one refusing a wrong password -- so say that much and no more.
        f.debug_struct("UpstreamProxy")
            .field("protocol", &self.protocol)
            .field("addr", &self.addr)
            .field("port", &self.port)
            .field(
                "credentials",
                &if self.username.is_some() || self.password.is_some() {
                    "[REDACTED]"
                } else {
                    "none"
                },
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UpstreamProtocol {
    Socks5,
    Http,
}

/// Per-connection copies are one atomic increment rather than a string clone.
pub type DedicatedIpBinding = Arc<DedicatedEgress>;

/// `None` when the panel sent something unusable.
///
/// A bad value is logged and dropped rather than failing the sync: losing one
/// user's dedicated egress is a far smaller problem than a whole node refusing
/// to load its user list because of one malformed row.
pub fn binding_from_wire(
    wire: &DedicatedIp,
    node_tag: &str,
    uid: u64,
) -> Option<DedicatedIpBinding> {
    let addr = match wire.ip.trim().parse::<IpAddr>() {
        Ok(addr) => addr,
        Err(_) => {
            warn!(
                "node `{}` user {} has an unparseable dedicated_ip.ip `{}`, ignoring it",
                node_tag, uid, wire.ip
            );
            return None;
        }
    };

    let egress = match wire.mode.as_deref().map(str::trim) {
        // The historical default, and what a panel that predates upstream
        // pools sends.
        None | Some("") | Some("egress") => DedicatedEgress::Source(addr),
        Some("proxy") => upstream_from_wire(wire, addr, node_tag, uid)?,
        Some(other) => {
            // Forward compatibility: a mode this build predates cannot be
            // guessed at. Binding the source address would be wrong for
            // anything proxy-shaped, so drop it and say why.
            warn!(
                "node `{}` user {} has an unknown dedicated_ip.mode `{}`, ignoring the binding",
                node_tag, uid, other
            );
            return None;
        }
    };

    Some(Arc::new(egress))
}

fn upstream_from_wire(
    wire: &DedicatedIp,
    addr: IpAddr,
    node_tag: &str,
    uid: u64,
) -> Option<DedicatedEgress> {
    let protocol = match wire.protocol.as_deref().map(str::trim) {
        Some("socks5") | Some("socks") => UpstreamProtocol::Socks5,
        Some("http") => UpstreamProtocol::Http,
        other => {
            warn!(
                "node `{}` user {} has an unsupported dedicated_ip.protocol `{}`, ignoring the binding",
                node_tag,
                uid,
                other.unwrap_or("")
            );
            return None;
        }
    };

    let port = match wire.port {
        Some(port) if port > 0 => port,
        _ => {
            warn!(
                "node `{}` user {} has no usable dedicated_ip.port for its upstream proxy, ignoring the binding",
                node_tag, uid
            );
            return None;
        }
    };

    // A username with no password is a truncated credential, not an anonymous
    // proxy. Dialing anyway would authenticate as nobody and most likely leak
    // the node's own address on the retry path.
    let username = non_empty(wire.username.as_deref());
    let password = non_empty(wire.password.as_deref());
    if username.is_some() != password.is_some() {
        warn!(
            "node `{}` user {} has a half-filled dedicated_ip credential, ignoring the binding",
            node_tag, uid
        );
        return None;
    }

    Some(DedicatedEgress::Upstream(UpstreamProxy {
        protocol,
        addr,
        port,
        username,
        password,
    }))
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
}

/// Chains are immutable once built and shared by every connection using that
/// egress, so the lock is only ever contended on the first connection out of a
/// newly sold IP.
static EGRESS_CHAINS: LazyLock<RwLock<HashMap<DedicatedEgress, Arc<ClientChainGroup>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// The chain this egress dials through, built on first use.
pub fn chain_group_for(
    egress: &DedicatedEgress,
    resolver: &Arc<dyn Resolver>,
) -> Arc<ClientChainGroup> {
    if let Some(existing) = EGRESS_CHAINS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(egress)
    {
        return existing.clone();
    }

    let mut chains = EGRESS_CHAINS.write().unwrap_or_else(|e| e.into_inner());
    // Another connection may have built it between the two locks.
    chains
        .entry(egress.clone())
        .or_insert_with(|| Arc::new(build_chain(egress, resolver)))
        .clone()
}

/// The chain a dial should use to honour a dedicated egress, or `None` when
/// this dial cannot honour one.
///
/// An egress only works on a direct path: there is no way to make an upstream
/// proxy send from an address it does not own, so a configured dispatcher or a
/// multi-hop chain keeps its own routing.
///
/// That predicate used to be written out at each dial site -- four copies,
/// three different log levels between them, and one that logged nothing. The
/// cost was not the duplication: it was that AnyTLS single-destination UDP
/// simply never grew a copy, so a buyer's traffic left from the node's shared
/// address with nothing anywhere saying so. One function is one place to add
/// a dial site to, and one place to get it wrong.
///
/// Skips report at debug because the condition is a static property of the
/// node's configuration, identical for every connection and every
/// destination; warning per dial buries the log without telling an operator
/// anything a single line at startup would not. Saying it once per node, at
/// map time, is the missing half and does not belong here.
pub fn chain_group_for_dial(
    binding: Option<&DedicatedIpBinding>,
    outbound_dispatcher: Option<&OutboundDispatcher>,
    chain_group: &ClientChainGroup,
    resolver: &Arc<dyn Resolver>,
    remote: &dyn std::fmt::Display,
) -> Option<Arc<ClientChainGroup>> {
    let binding = binding?;
    if outbound_dispatcher.is_none() && chain_group.is_direct_only() {
        return Some(chain_group_for(binding, resolver));
    }
    log::debug!(
        "dedicated egress {binding:?} skipped for {remote}: outbound routing is not a direct path"
    );
    None
}

fn build_chain(egress: &DedicatedEgress, resolver: &Arc<dyn Resolver>) -> ClientChainGroup {
    let entry = match egress {
        DedicatedEgress::Source(addr) => {
            InitialHopEntry::Direct(Box::new(SocketConnectorImpl::direct_tcp_from_source(*addr)))
        }
        DedicatedEgress::Upstream(upstream) => {
            let location = NetLocation::new(address_of(upstream.addr), upstream.port);
            let protocol = match upstream.protocol {
                UpstreamProtocol::Socks5 => ClientProxyConfig::Socks {
                    username: upstream.username.clone(),
                    password: upstream.password.clone(),
                },
                UpstreamProtocol::Http => ClientProxyConfig::Http {
                    username: upstream.username.clone(),
                    password: upstream.password.clone(),
                    resolve_hostname: false,
                },
            };
            let config = ClientConfig {
                address: location.clone(),
                protocol,
                ..Default::default()
            };
            // Both `from_config` calls only fail on shapes neither arm above
            // produces: the socket one on a QUIC transport (this config is
            // plain TCP) and the proxy one on the direct protocol.
            let socket = SocketConnectorImpl::from_config(&config, Some(&location))
                .expect("upstream proxy socket config is plain TCP");
            let proxy = ProxyConnectorImpl::from_config(config, resolver.clone())
                .expect("upstream proxy config is never direct");
            InitialHopEntry::Proxy {
                socket: Box::new(socket),
                proxy: Box::new(proxy),
            }
        }
    };

    ClientChainGroup::new(vec![ClientProxyChain::new(vec![entry], vec![])])
}

fn address_of(addr: IpAddr) -> Address {
    match addr {
        IpAddr::V4(ip) => Address::Ipv4(ip),
        IpAddr::V6(ip) => Address::Ipv6(ip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(ip: &str, mode: Option<&str>) -> DedicatedIp {
        DedicatedIp {
            assignment_id: Some(1),
            ip: ip.to_string(),
            mode: mode.map(ToString::to_string),
            protocol: None,
            port: None,
            username: None,
            password: None,
            expires_at: None,
        }
    }

    fn proxy_wire(ip: &str, protocol: &str, port: Option<u16>) -> DedicatedIp {
        DedicatedIp {
            protocol: Some(protocol.to_string()),
            port,
            username: Some("u".to_string()),
            password: Some("p".to_string()),
            ..wire(ip, Some("proxy"))
        }
    }

    fn resolver() -> Arc<dyn Resolver> {
        Arc::new(crate::resolver::NativeResolver::new())
    }

    // ------------------------------------------------------------ 源地址绑定

    #[test]
    fn egress_mode_binds_the_source_address() {
        let binding = binding_from_wire(&wire("198.51.100.7", Some("egress")), "n", 1).unwrap();
        assert_eq!(
            *binding,
            DedicatedEgress::Source("198.51.100.7".parse().unwrap())
        );
    }

    /// A panel that predates upstream pools sends no mode at all.
    #[test]
    fn missing_mode_defaults_to_source_binding() {
        let binding = binding_from_wire(&wire("198.51.100.7", None), "n", 1).unwrap();
        assert!(matches!(*binding, DedicatedEgress::Source(_)));
    }

    #[test]
    fn ipv6_sources_are_accepted() {
        let binding = binding_from_wire(&wire("2001:db8::1", Some("egress")), "n", 1).unwrap();
        assert_eq!(
            *binding,
            DedicatedEgress::Source("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn an_unparseable_address_is_dropped_rather_than_failing_the_user() {
        assert!(binding_from_wire(&wire("not-an-ip", None), "n", 1).is_none());
        assert!(binding_from_wire(&wire("", None), "n", 1).is_none());
    }

    // ------------------------------------------------------------ 上游代理

    #[test]
    fn proxy_mode_carries_the_upstream_the_node_dials_through() {
        let binding = binding_from_wire(&proxy_wire("203.0.113.9", "socks5", Some(1080)), "n", 1)
            .expect("binding");
        assert_eq!(
            *binding,
            DedicatedEgress::Upstream(UpstreamProxy {
                protocol: UpstreamProtocol::Socks5,
                addr: "203.0.113.9".parse().unwrap(),
                port: 1080,
                username: Some("u".to_string()),
                password: Some("p".to_string()),
            })
        );
    }

    /// The binding is printed whenever a dial cannot honour it, so its
    /// `Debug` is a log-facing surface, not a developer convenience. It used
    /// to print the upstream's password verbatim on every such dial.
    #[test]
    fn debug_output_identifies_the_upstream_without_its_credentials() {
        let mut wire = proxy_wire("198.51.100.7", "socks5", Some(1080));
        wire.username = Some("operator".to_string());
        wire.password = Some("hunter2".to_string());
        let binding =
            binding_from_wire(&wire, "node", 7).expect("a complete proxy wire builds a binding");
        let rendered = format!("{binding:?}");

        for secret in ["hunter2", "operator"] {
            assert!(
                !rendered.contains(secret),
                "credentials must not reach the log: {rendered}"
            );
        }
        assert!(rendered.contains("198.51.100.7"), "{rendered}");
        assert!(rendered.contains("1080"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
    }

    /// An upstream dialled anonymously fails differently from one dialled
    /// with a wrong password, so the redaction has to keep saying which it is.
    #[test]
    fn debug_output_distinguishes_an_upstream_without_credentials() {
        let mut wire = proxy_wire("198.51.100.7", "socks5", Some(1080));
        wire.username = None;
        wire.password = None;
        let binding = binding_from_wire(&wire, "node", 7).expect("credentials are optional");

        assert!(format!("{binding:?}").contains("\"none\""));
    }

    #[test]
    fn an_http_upstream_is_accepted_too() {
        let binding =
            binding_from_wire(&proxy_wire("203.0.113.9", "http", Some(8080)), "n", 1).unwrap();
        assert!(matches!(
            *binding,
            DedicatedEgress::Upstream(UpstreamProxy {
                protocol: UpstreamProtocol::Http,
                ..
            })
        ));
    }

    #[test]
    fn an_upstream_without_a_port_is_dropped() {
        assert!(binding_from_wire(&proxy_wire("203.0.113.9", "socks5", None), "n", 1).is_none());
        assert!(binding_from_wire(&proxy_wire("203.0.113.9", "socks5", Some(0)), "n", 1).is_none());
    }

    #[test]
    fn an_upstream_with_an_unsupported_protocol_is_dropped() {
        assert!(
            binding_from_wire(
                &proxy_wire("203.0.113.9", "shadowsocks", Some(1080)),
                "n",
                1
            )
            .is_none()
        );
        let mut no_protocol = proxy_wire("203.0.113.9", "socks5", Some(1080));
        no_protocol.protocol = None;
        assert!(binding_from_wire(&no_protocol, "n", 1).is_none());
    }

    /// Half a credential means the row was truncated somewhere. Dialing with
    /// it authenticates as nobody, which is worse than not dialing.
    #[test]
    fn a_half_filled_upstream_credential_is_dropped() {
        let mut no_password = proxy_wire("203.0.113.9", "socks5", Some(1080));
        no_password.password = None;
        assert!(binding_from_wire(&no_password, "n", 1).is_none());

        let mut no_username = proxy_wire("203.0.113.9", "socks5", Some(1080));
        no_username.username = None;
        assert!(binding_from_wire(&no_username, "n", 1).is_none());
    }

    #[test]
    fn an_upstream_with_no_credentials_at_all_is_allowed() {
        let mut anonymous = proxy_wire("203.0.113.9", "socks5", Some(1080));
        anonymous.username = None;
        anonymous.password = None;
        let binding = binding_from_wire(&anonymous, "n", 1).expect("binding");
        assert_eq!(
            *binding,
            DedicatedEgress::Upstream(UpstreamProxy {
                protocol: UpstreamProtocol::Socks5,
                addr: "203.0.113.9".parse().unwrap(),
                port: 1080,
                username: None,
                password: None,
            })
        );
    }

    /// An unknown mode cannot be guessed at: binding the source address would
    /// be flatly wrong for anything proxy-shaped.
    #[test]
    fn an_unknown_mode_is_dropped_rather_than_assumed_to_be_a_source_bind() {
        assert!(binding_from_wire(&wire("198.51.100.7", Some("teleport")), "n", 1).is_none());
    }

    // ------------------------------------------------------------ 链路缓存

    #[test]
    fn the_same_egress_reuses_one_chain() {
        let resolver = resolver();
        let source = DedicatedEgress::Source("127.0.0.2".parse().unwrap());
        let first = chain_group_for(&source, &resolver);
        let second = chain_group_for(&source, &resolver);
        assert!(Arc::ptr_eq(&first, &second));

        let other = chain_group_for(
            &DedicatedEgress::Source("127.0.0.3".parse().unwrap()),
            &resolver,
        );
        assert!(!Arc::ptr_eq(&first, &other));
    }

    /// Two buyers on the same upstream host but different credentials must not
    /// share a chain, or one would dial as the other.
    #[test]
    fn upstreams_are_keyed_by_their_credentials_too() {
        let resolver = resolver();
        let base = UpstreamProxy {
            protocol: UpstreamProtocol::Socks5,
            addr: "127.0.0.7".parse().unwrap(),
            port: 1080,
            username: Some("alice".to_string()),
            password: Some("secret".to_string()),
        };
        let mut other = base.clone();
        other.username = Some("bob".to_string());

        let first = chain_group_for(&DedicatedEgress::Upstream(base.clone()), &resolver);
        let same = chain_group_for(&DedicatedEgress::Upstream(base), &resolver);
        let different = chain_group_for(&DedicatedEgress::Upstream(other), &resolver);

        assert!(Arc::ptr_eq(&first, &same));
        assert!(!Arc::ptr_eq(&first, &different));
    }

    /// UDP through a bought SOCKS5/HTTP proxy is not something shoes can do:
    /// neither client hop carries UDP-over-TCP. The chain must refuse rather
    /// than fall through to a direct dial, which would put the node's own
    /// address on the wire -- exactly what the buyer paid to avoid.
    #[tokio::test]
    async fn an_upstream_chain_refuses_udp_instead_of_leaking_the_node_address() {
        use crate::address::{Address, NetLocation, ResolvedLocation};

        let resolver = resolver();
        let chain = chain_group_for(
            &DedicatedEgress::Upstream(UpstreamProxy {
                protocol: UpstreamProtocol::Socks5,
                addr: "127.0.0.9".parse().unwrap(),
                port: 1080,
                username: None,
                password: None,
            }),
            &resolver,
        );

        let target = ResolvedLocation::with_resolved(
            NetLocation::new(Address::Ipv4("127.0.0.1".parse().unwrap()), 9),
            "127.0.0.1:9".parse().unwrap(),
        );
        match chain.connect_udp_bidirectional(&resolver, target).await {
            Ok(_) => panic!("an upstream proxy has no UDP to offer"),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::Unsupported),
        }
    }

    /// The chain is what the dial path actually uses, so prove UDP leaves from
    /// the bought address through *it*, not just through the socket helper.
    #[tokio::test]
    async fn a_source_chain_sends_udp_from_the_bound_address() {
        use crate::address::{Address, NetLocation, ResolvedLocation};
        use crate::socket_util::new_udp_socket_bound;
        use std::future::poll_fn;
        use std::pin::Pin;

        let probe = new_udp_socket_bound(false, None, Some("127.0.0.1".parse().unwrap())).unwrap();
        let probe_addr = probe.local_addr().unwrap();

        let source: IpAddr = "127.0.0.8".parse().unwrap();
        let target = ResolvedLocation::with_resolved(
            NetLocation::new(
                Address::Ipv4("127.0.0.1".parse().unwrap()),
                probe_addr.port(),
            ),
            probe_addr,
        );

        let resolver = resolver();
        let mut stream = chain_group_for(&DedicatedEgress::Source(source), &resolver)
            .connect_udp_bidirectional(&resolver, target)
            .await
            .expect("udp dial through the egress chain");

        poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, b"ping"))
            .await
            .expect("write");

        let mut buf = [0u8; 8];
        let (len, observed) = probe.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"ping");
        assert_eq!(observed.ip(), source);
    }
}
