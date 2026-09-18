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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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

/// Why a `dedicated_ip` the panel published is not honoured on this node.
///
/// Every variant is a row the buyer is being billed for: refusing one means
/// their traffic keeps leaving from the node's shared address, so the reason
/// has to survive as a value that reaches the log once, rather than as a
/// `None` nobody ever sees.
///
/// Only values from the panel's closed vocabulary are carried in a variant --
/// a mode or protocol name is worth telling an operator and there are a
/// handful of them. Per-user values (the address, the credentials) are
/// deliberately absent: rejections are deduplicated by reason, and a payload
/// that differs per user would make every bad row its own reason and bring
/// back the flood this type exists to end. The reported user id is the handle
/// for finding the offending row in the panel.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EgressRejection {
    /// `dedicated_ip.ip` is not an address.
    UnparseableAddress,
    /// The assignment's term is over; see `binding_from_wire`.
    Expired,
    /// The panel's `ingress_egress` also promises the buyer *arrives* on the
    /// address, which this backend does not implement.
    IngressEgressUnimplemented,
    /// A `dedicated_ip.mode` this build predates.
    UnknownMode(String),
    /// A `dedicated_ip.protocol` no client hop here speaks.
    UnsupportedUpstreamProtocol(String),
    /// `dedicated_ip.port` is missing or zero on an upstream.
    UnusableUpstreamPort,
    /// Half of an upstream credential, which is a truncated row.
    HalfFilledCredential,
    /// This node type cannot carry a binding at all; holds its panel name.
    NodeKindCannotBind(&'static str),
}

impl EgressRejection {
    /// The half of the log line that says what is wrong and what it costs.
    fn describe(&self) -> String {
        match self {
            Self::UnparseableAddress => {
                "dedicated_ip.ip is not an IP address, so there is nothing to bind".to_string()
            }
            Self::Expired => {
                "the assignment's dedicated_ip.expires_at has passed, so the address may already \
                 be re-sold and is no longer bound"
                    .to_string()
            }
            Self::IngressEgressUnimplemented => {
                "dedicated_ip.mode `ingress_egress` also requires the client to arrive on that \
                 address, which this build does not enforce; binding only the egress would \
                 deliver something other than what was sold, so the whole binding is refused"
                    .to_string()
            }
            Self::UnknownMode(mode) => format!(
                "dedicated_ip.mode `{mode}` is not known to this build, and binding the source \
                 address would be wrong for anything proxy-shaped"
            ),
            Self::UnsupportedUpstreamProtocol(protocol) => format!(
                "dedicated_ip.protocol `{protocol}` is not a proxy this node can dial through"
            ),
            Self::UnusableUpstreamPort => {
                "dedicated_ip.port is missing or zero, so the upstream proxy cannot be dialed"
                    .to_string()
            }
            Self::HalfFilledCredential => {
                "dedicated_ip carries half a credential, which authenticates as nobody".to_string()
            }
            Self::NodeKindCannotBind(node_type) => format!(
                "a `{node_type}` node cannot bind a dedicated egress: its QUIC session scope \
                 keeps only whether the connection authenticated, not which user it was, so the \
                 dial has nothing to bind against"
            ),
        }
    }
}

/// The binding this row asks for, or the reason the node will not honour it.
///
/// A rejected row is dropped rather than failing the sync: losing one user's
/// dedicated egress is a far smaller problem than a whole node refusing to
/// load its user list because of one malformed row. The caller is expected to
/// hand the reason to `report_rejections` so the drop is not silent.
///
/// `now` is the unix time the pull was normalized at, matching how
/// `panel_user_active` ages out a user.
pub fn binding_from_wire(
    wire: &DedicatedIp,
    now: i64,
) -> Result<DedicatedIpBinding, EgressRejection> {
    // The panel sells the address for a term and returns it to the pool when
    // the term ends, so an expired assignment is not this buyer's address any
    // more. This matters most exactly when it cannot be checked with the
    // panel: a node restarted onto its last-known-good snapshot with the
    // panel unreachable would otherwise keep binding an address that has
    // since been re-sold, putting two customers on one "exclusive" IP.
    // Checked before the rest of the row parses, because a lapsed assignment
    // is over whatever shape it has. A zero or negative value is the panel's
    // "no term", the same reading `panel_user_active` gives `expires_at`.
    if let Some(expires_at) = wire.expires_at
        && expires_at > 0
        && expires_at <= now
    {
        return Err(EgressRejection::Expired);
    }

    // A missing `ip` lands here rather than at deserialization on purpose: see
    // the field's note in `types.rs`. `UnparseableAddress` covers it because
    // the operator's problem is identical either way -- the row names no
    // address to bind.
    let addr = wire
        .ip
        .as_deref()
        .unwrap_or("")
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| EgressRejection::UnparseableAddress)?;

    let egress = match wire.mode.as_deref().map(str::trim) {
        // The historical default, and what a panel that predates upstream
        // pools sends.
        None | Some("") | Some("egress") => DedicatedEgress::Source(addr),
        Some("proxy") => upstream_from_wire(wire, addr)?,
        // A named contract value, not an unknown one: the panel means an
        // address the buyer both arrives on and leaves from, and this backend
        // constrains neither inbound listener nor accepted peer address to it.
        Some("ingress_egress") => return Err(EgressRejection::IngressEgressUnimplemented),
        // Forward compatibility: a mode this build predates cannot be guessed
        // at. Binding the source address would be wrong for anything
        // proxy-shaped, so drop it and say which mode it was.
        Some(other) => return Err(EgressRejection::UnknownMode(other.to_string())),
    };

    Ok(Arc::new(egress))
}

fn upstream_from_wire(
    wire: &DedicatedIp,
    addr: IpAddr,
) -> Result<DedicatedEgress, EgressRejection> {
    let protocol = match wire.protocol.as_deref().map(str::trim) {
        Some("socks5") | Some("socks") => UpstreamProtocol::Socks5,
        Some("http") => UpstreamProtocol::Http,
        other => {
            return Err(EgressRejection::UnsupportedUpstreamProtocol(
                other.unwrap_or("").to_string(),
            ));
        }
    };

    let port = match wire.port {
        Some(port) if port > 0 => port,
        _ => return Err(EgressRejection::UnusableUpstreamPort),
    };

    // A username with no password is a truncated credential, not an anonymous
    // proxy. Dialing anyway would authenticate as nobody and most likely leak
    // the node's own address on the retry path.
    let username = non_empty(wire.username.as_deref());
    let password = non_empty(wire.password.as_deref());
    if username.is_some() != password.is_some() {
        return Err(EgressRejection::HalfFilledCredential);
    }

    Ok(DedicatedEgress::Upstream(UpstreamProxy {
        protocol,
        addr,
        port,
        username,
        password,
    }))
}

/// What was last reported for each node, so a reason that is still there on
/// the next pull stays quiet.
///
/// Normalization runs on nearly every pull because a busy node's user list
/// changes constantly, so warning per rejected row turned one bad panel row
/// into a permanent flood that buried everything else in the log -- which is
/// how a rejection ends up as good as silent. Keyed by node, so the map is
/// bounded by the node count rather than by the user count, and the entry is
/// dropped when the node comes back clean so an operator who fixes a row and
/// later breaks it again is told a second time.
static REPORTED_REJECTIONS: LazyLock<RwLock<HashMap<String, BTreeSet<EgressRejection>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Say once, per node, every distinct reason a dedicated egress was refused on
/// this pull, and return the reasons actually reported.
///
/// The return value is what a test can assert on: whether the second pull with
/// the same bad row says anything is the whole point of this function, and it
/// is not observable from the log.
/// Nodes already told that their own routing makes every binding inert.
static ROUTING_OVERRIDE_REPORTED: LazyLock<RwLock<HashSet<String>>> =
    LazyLock::new(|| RwLock::new(HashSet::new()));

/// Says once per node that this node's own configuration, not the panel, is
/// what stops every dedicated egress on it from applying.
///
/// Nothing was rejected here: the bindings are valid and the buyers are real.
/// A dispatcher takes over the dial, and one `default_out` or a single
/// `route_rules` entry anywhere in the backend YAML builds a dispatcher for
/// every node -- so an operator adding one routing rule silently stops
/// delivering an exit IP that every one of these users pays for.
///
/// It has to be said at this level. The per-dial skip is `debug!`, and the
/// release build sets `release_max_level_info`, which compiles that call out
/// of the binary entirely: without this line the most likely way for the
/// feature to be inert is invisible in every official image. Once per node
/// rather than per dial, because the condition is a static property of the
/// configuration and identical for every connection.
///
/// Returns whether it reported, which is what a test can assert on.
pub fn report_local_routing_override(node_tag: &str, bound_users: usize) -> bool {
    let mut reported = ROUTING_OVERRIDE_REPORTED
        .write()
        .unwrap_or_else(|e| e.into_inner());
    if bound_users == 0 {
        // Say it again if the condition returns after the node comes back
        // clean, the same way a rejection reason is re-reported.
        reported.remove(node_tag);
        return false;
    }
    if !reported.insert(node_tag.to_string()) {
        return false;
    }
    warn!(
        "node `{node_tag}` has local outbound routing configured, so the dedicated egress sold to \
         {bound_users} user(s) on it does not apply: their traffic leaves from this node's own \
         address until the routing is removed"
    );
    true
}

pub fn report_rejections(
    node_tag: &str,
    rejections: &[(u64, EgressRejection)],
) -> Vec<EgressRejection> {
    // One representative user id and a count per reason: the id is enough to
    // find the row in the panel, and the count says whether this is one stale
    // assignment or the whole node's worth of buyers getting nothing.
    let mut current: BTreeMap<EgressRejection, (u64, usize)> = BTreeMap::new();
    for (uid, rejection) in rejections {
        let entry = current.entry(rejection.clone()).or_insert((*uid, 0));
        entry.1 += 1;
    }

    let reasons: BTreeSet<EgressRejection> = current.keys().cloned().collect();
    let mut reported = REPORTED_REJECTIONS
        .write()
        .unwrap_or_else(|e| e.into_inner());
    let previous = if reasons.is_empty() {
        reported.remove(node_tag)
    } else {
        reported.insert(node_tag.to_string(), reasons)
    }
    .unwrap_or_default();
    drop(reported);

    let fresh: Vec<(EgressRejection, u64, usize)> = current
        .into_iter()
        .filter(|(rejection, _)| !previous.contains(rejection))
        .map(|(rejection, (uid, count))| (rejection, uid, count))
        .collect();

    for (rejection, uid, count) in &fresh {
        let others = match count - 1 {
            0 => String::new(),
            others => format!(" and {others} other user(s)"),
        };
        warn!(
            "node `{}` refuses the dedicated egress bought by user {}{}: {}. Reported once until this node reports a pull without it.",
            node_tag,
            uid,
            others,
            rejection.describe()
        );
    }
    fresh
        .into_iter()
        .map(|(rejection, _, _)| rejection)
        .collect()
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
const EGRESS_CHAIN_CACHE_LIMIT: usize = 4096;

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
    if !chains.contains_key(egress) && chains.len() >= EGRESS_CHAIN_CACHE_LIMIT {
        // A chain held only by the cache is safe to rebuild on its next dial.
        // Preserve chains cloned by in-flight connections; if more than the
        // limit are genuinely concurrent, correctness wins and the map may
        // temporarily exceed the soft ceiling until a later miss reaps them.
        chains.retain(|_, chain| Arc::strong_count(chain) > 1);
    }
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
/// anything a single line at startup would not. The other half -- saying it
/// once per node, before any connection arrives -- is `report_rejections`,
/// called from normalization.
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

    /// A fixed "now" for rows with no term, so nothing here depends on the
    /// clock. Tests about expiry place their `expires_at` either side of it.
    const NOW: i64 = 1_800_000_000;

    /// Every other test in this module hand-builds a `DedicatedIp`, which
    /// proves what the binding logic does with a value but says nothing about
    /// whether the panel's bytes ever become that value. The deserialization
    /// boundary is the one place the two repositories actually meet, and a
    /// renamed field or a changed type there would leave every test in this
    /// file green while production nodes hand buyers the shared address.
    ///
    /// So these two cases pin whole rows captured from a live panel
    /// (`GET /api/v1/server/UniProxy/user`), byte for byte, one per delivery
    /// method. Update them by capturing again, never by editing to taste.
    mod panel_wire {
        use super::*;
        use crate::v2board::types::UserList;

        /// These rows carry real timestamps, so they get a clock of their own
        /// rather than the module's synthetic `NOW` -- which happens to sit
        /// after the captured term and would read a live row as lapsed.
        const BEFORE_CAPTURED_TERM: i64 = 1_790_000_000;

        /// `node_egress`: the panel binds the buyer's outbound source address
        /// on this node. A term is set, so `expires_at` is a number.
        #[test]
        fn a_node_egress_row_from_the_panel_binds_the_source_address() {
            let body = r#"{"users":[{"id":40034,"uuid":"11111111-2222-4333-8444-555555555555","dedicated_ip":{"assignment_id":34,"ip":"198.51.100.77","mode":"egress","expires_at":1790859302}}]}"#;

            let list: UserList = serde_json::from_str(body).expect("the panel's row must parse");
            let wire = list.users[0]
                .dedicated_ip
                .as_ref()
                .expect("the row carries a dedicated_ip");

            assert_eq!(wire.ip.as_deref(), Some("198.51.100.77"));
            assert_eq!(wire.mode.as_deref(), Some("egress"));
            assert_eq!(wire.expires_at, Some(1_790_859_302));

            match &*binding_from_wire(wire, BEFORE_CAPTURED_TERM).expect("a live egress row binds")
            {
                DedicatedEgress::Source(addr) => {
                    assert_eq!(addr, &"198.51.100.77".parse::<IpAddr>().unwrap());
                }
                other => panic!("egress mode must bind a source address, got {other:?}"),
            }
        }

        /// `upstream_proxy`: the panel dials out through a bought proxy, and
        /// the credentials on the row are the *node's*, never the buyer's.
        /// `expires_at` is null here because a one-time purchase never lapses
        /// -- the shape a term-based row cannot exercise.
        #[test]
        fn an_upstream_proxy_row_from_the_panel_carries_the_dial_target() {
            let body = r#"{"users":[{"id":40034,"uuid":"11111111-2222-4333-8444-555555555555","dedicated_ip":{"assignment_id":35,"ip":"203.0.113.88","mode":"proxy","protocol":"socks5","port":3128,"username":"proxy-user","password":"s3cr3t-pass","expires_at":null}}]}"#;

            let list: UserList = serde_json::from_str(body).expect("the panel's row must parse");
            let wire = list.users[0]
                .dedicated_ip
                .as_ref()
                .expect("the row carries a dedicated_ip");

            // A one-time purchase: no term, so nothing to expire against.
            assert_eq!(wire.expires_at, None);

            match &*binding_from_wire(wire, BEFORE_CAPTURED_TERM).expect("a live proxy row binds") {
                DedicatedEgress::Upstream(upstream) => {
                    assert_eq!(upstream.protocol, UpstreamProtocol::Socks5);
                    assert_eq!(upstream.addr, "203.0.113.88".parse::<IpAddr>().unwrap());
                    assert_eq!(upstream.port, 3128);
                    assert_eq!(upstream.username.as_deref(), Some("proxy-user"));
                    assert_eq!(upstream.password.as_deref(), Some("s3cr3t-pass"));
                }
                other => panic!("proxy mode must dial an upstream, got {other:?}"),
            }
        }

        /// A buyer with no assignment gets no key at all -- not a null. The
        /// panel filters nulls out of the user row, and a `None` here is what
        /// makes "everyone else keeps the shared egress" the default.
        #[test]
        fn a_row_without_an_assignment_omits_the_key_entirely() {
            let body = r#"{"users":[{"id":40035,"uuid":"22222222-2222-4333-8444-555555555555"}]}"#;

            let list: UserList = serde_json::from_str(body).expect("a plain row must parse");
            assert!(list.users[0].dedicated_ip.is_none());
        }

        /// One malformed row must cost exactly one binding. The whole list is
        /// what feeds every user on the node, so a row the panel should never
        /// send still has to leave the others untouched -- the tolerance the
        /// contract asks for is worthless if it is applied after a failure
        /// that already dropped everyone.
        ///
        /// Also captured rather than written: a panel whose
        /// `v2_dedicated_ip_assignment.ip_snapshot` was blanked really does
        /// publish `"ip": null` next to a healthy row, which is how a
        /// required `String` here used to take an entire node offline.
        #[test]
        fn a_malformed_row_does_not_take_the_rest_of_the_list_down() {
            let body = r#"{"users":[
                {"id":40035,"uuid":"00000001-2222-4333-8444-555555555555","dedicated_ip":{"assignment_id":38,"ip":null,"mode":"egress","expires_at":1790859961}},
                {"id":40036,"uuid":"00000002-2222-4333-8444-555555555555","dedicated_ip":{"assignment_id":39,"ip":"198.51.100.91","mode":"egress","expires_at":1790859961}}
            ]}"#;

            let list: UserList =
                serde_json::from_str(body).expect("a null ip must not fail the whole list");
            assert_eq!(list.users.len(), 2);
            // The bad row loses its binding here, at the same place every
            // other malformed value loses it.
            assert!(
                binding_from_wire(
                    list.users[0].dedicated_ip.as_ref().unwrap(),
                    BEFORE_CAPTURED_TERM
                )
                .is_err()
            );
            assert!(
                binding_from_wire(
                    list.users[1].dedicated_ip.as_ref().unwrap(),
                    BEFORE_CAPTURED_TERM
                )
                .is_ok()
            );
        }
    }

    fn wire(ip: &str, mode: Option<&str>) -> DedicatedIp {
        DedicatedIp {
            assignment_id: Some(1),
            ip: Some(ip.to_string()),
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
        let binding = binding_from_wire(&wire("198.51.100.7", Some("egress")), NOW).unwrap();
        assert_eq!(
            *binding,
            DedicatedEgress::Source("198.51.100.7".parse().unwrap())
        );
    }

    /// A panel that predates upstream pools sends no mode at all.
    #[test]
    fn missing_mode_defaults_to_source_binding() {
        let binding = binding_from_wire(&wire("198.51.100.7", None), NOW).unwrap();
        assert!(matches!(*binding, DedicatedEgress::Source(_)));
    }

    #[test]
    fn ipv6_sources_are_accepted() {
        let binding = binding_from_wire(&wire("2001:db8::1", Some("egress")), NOW).unwrap();
        assert_eq!(
            *binding,
            DedicatedEgress::Source("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn an_unparseable_address_is_dropped_rather_than_failing_the_user() {
        assert!(binding_from_wire(&wire("not-an-ip", None), NOW).is_err());
        assert!(binding_from_wire(&wire("", None), NOW).is_err());
    }

    // ------------------------------------------------------------ 上游代理

    #[test]
    fn proxy_mode_carries_the_upstream_the_node_dials_through() {
        let binding = binding_from_wire(&proxy_wire("203.0.113.9", "socks5", Some(1080)), NOW)
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
            binding_from_wire(&wire, NOW).expect("a complete proxy wire builds a binding");
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
        let binding = binding_from_wire(&wire, NOW).expect("credentials are optional");

        assert!(format!("{binding:?}").contains("\"none\""));
    }

    #[test]
    fn an_http_upstream_is_accepted_too() {
        let binding =
            binding_from_wire(&proxy_wire("203.0.113.9", "http", Some(8080)), NOW).unwrap();
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
        assert!(binding_from_wire(&proxy_wire("203.0.113.9", "socks5", None), NOW).is_err());
        assert!(binding_from_wire(&proxy_wire("203.0.113.9", "socks5", Some(0)), NOW).is_err());
    }

    #[test]
    fn an_upstream_with_an_unsupported_protocol_is_dropped() {
        assert!(
            binding_from_wire(&proxy_wire("203.0.113.9", "shadowsocks", Some(1080)), NOW).is_err()
        );
        let mut no_protocol = proxy_wire("203.0.113.9", "socks5", Some(1080));
        no_protocol.protocol = None;
        assert!(binding_from_wire(&no_protocol, NOW).is_err());
    }

    /// Half a credential means the row was truncated somewhere. Dialing with
    /// it authenticates as nobody, which is worse than not dialing.
    #[test]
    fn a_half_filled_upstream_credential_is_dropped() {
        let mut no_password = proxy_wire("203.0.113.9", "socks5", Some(1080));
        no_password.password = None;
        assert!(binding_from_wire(&no_password, NOW).is_err());

        let mut no_username = proxy_wire("203.0.113.9", "socks5", Some(1080));
        no_username.username = None;
        assert!(binding_from_wire(&no_username, NOW).is_err());
    }

    #[test]
    fn an_upstream_with_no_credentials_at_all_is_allowed() {
        let mut anonymous = proxy_wire("203.0.113.9", "socks5", Some(1080));
        anonymous.username = None;
        anonymous.password = None;
        let binding = binding_from_wire(&anonymous, NOW).expect("binding");
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
        assert!(binding_from_wire(&wire("198.51.100.7", Some("teleport")), NOW).is_err());
    }

    /// `ingress_egress` is a contract value the panel really sends, and it
    /// sells more than an exit address: the buyer is also promised they arrive
    /// on it. This backend constrains nothing about inbound, so honouring the
    /// egress half alone would hand the buyer something other than what they
    /// bought while the panel counts the assignment as delivered. It has to be
    /// refused, and refused under its own name rather than as "unknown", or
    /// the day someone implements it they will find nothing that says why.
    #[test]
    fn ingress_egress_is_refused_under_its_own_name_not_downgraded_to_an_egress_bind() {
        assert_eq!(
            binding_from_wire(&wire("198.51.100.7", Some("ingress_egress")), NOW),
            Err(EgressRejection::IngressEgressUnimplemented)
        );
    }

    // ------------------------------------------------------------ 到期

    /// The pool re-sells an address once its term ends. A node that keeps
    /// binding it -- most easily after a restart onto a last-known-good
    /// snapshot with the panel unreachable -- puts the lapsed buyer on an
    /// address someone else now pays to have to themselves, which is the one
    /// property the product is.
    #[test]
    fn an_expired_assignment_stops_binding() {
        let mut expired = wire("198.51.100.7", Some("egress"));
        expired.expires_at = Some(NOW - 1);
        assert_eq!(
            binding_from_wire(&expired, NOW),
            Err(EgressRejection::Expired)
        );

        // Expiry is the term ending, not a grace period: the second it is
        // reached the address is the pool's again.
        expired.expires_at = Some(NOW);
        assert_eq!(
            binding_from_wire(&expired, NOW),
            Err(EgressRejection::Expired)
        );
    }

    #[test]
    fn an_assignment_still_in_its_term_binds() {
        let mut live = wire("198.51.100.7", Some("egress"));
        live.expires_at = Some(NOW + 1);
        assert!(binding_from_wire(&live, NOW).is_ok());
    }

    /// The same reading `panel_user_active` gives a user's own `expires_at`:
    /// a panel that does not date an assignment sends 0, not a timestamp in
    /// 1970, and must not have every one of its buyers cut off.
    #[test]
    fn a_zero_or_negative_expiry_means_no_term_at_all() {
        let mut undated = wire("198.51.100.7", Some("egress"));
        undated.expires_at = Some(0);
        assert!(binding_from_wire(&undated, NOW).is_ok());

        undated.expires_at = Some(-1);
        assert!(binding_from_wire(&undated, NOW).is_ok());
    }

    /// An upstream assignment is sold on the same terms as a bound one.
    #[test]
    fn an_expired_upstream_assignment_stops_dialing_too() {
        let mut expired = proxy_wire("203.0.113.9", "socks5", Some(1080));
        expired.expires_at = Some(NOW - 1);
        assert_eq!(
            binding_from_wire(&expired, NOW),
            Err(EgressRejection::Expired)
        );
    }

    // ------------------------------------------------------------ 拒绝上报

    /// Normalization runs on nearly every pull, so a reason reported per pull
    /// is a permanent flood and a flood is as good as silence. Report each
    /// distinct reason once per node instead.
    /// The condition this reports is the likeliest way for the whole feature
    /// to be inert, and the per-dial skip that used to be the only trace of
    /// it is `debug!` -- which the release build compiles out. So the node
    /// has to say it, and say it where an official image still prints it.
    #[test]
    fn local_routing_that_overrides_every_binding_is_reported_once_per_node() {
        let node = "routing-override-node";

        assert!(
            report_local_routing_override(node, 3),
            "an operator has to learn that three buyers are getting nothing"
        );
        assert!(
            !report_local_routing_override(node, 3),
            "every pull repeating it would bury the log it belongs in"
        );

        // The routing came out, or the last buyer left: nothing to say.
        assert!(!report_local_routing_override(node, 0));
        assert!(
            report_local_routing_override(node, 1),
            "the condition coming back is news again"
        );
        report_local_routing_override(node, 0);
    }

    #[test]
    fn a_reason_is_reported_once_per_node_not_once_per_pull() {
        let node = "report-once-per-node";
        let pull = [
            (1, EgressRejection::IngressEgressUnimplemented),
            (2, EgressRejection::IngressEgressUnimplemented),
            (3, EgressRejection::Expired),
        ];

        // Two users share a reason: an operator needs the reason, not one line
        // per buyer.
        assert_eq!(
            report_rejections(node, &pull),
            vec![
                EgressRejection::Expired,
                EgressRejection::IngressEgressUnimplemented,
            ]
        );
        assert!(report_rejections(node, &pull).is_empty());

        // A reason that is new on a later pull is still worth saying.
        let mut grown = pull.to_vec();
        grown.push((4, EgressRejection::UnparseableAddress));
        assert_eq!(
            report_rejections(node, &grown),
            vec![EgressRejection::UnparseableAddress]
        );
    }

    /// Reporting once must not mean reporting once ever: an operator who fixes
    /// the panel row and later breaks it again gets told the second time too.
    #[test]
    fn a_reason_is_reported_again_after_the_node_comes_back_clean() {
        let node = "report-again-after-clean";
        let pull = [(1, EgressRejection::Expired)];

        assert_eq!(
            report_rejections(node, &pull),
            vec![EgressRejection::Expired]
        );
        assert!(report_rejections(node, &[]).is_empty());
        assert_eq!(
            report_rejections(node, &pull),
            vec![EgressRejection::Expired]
        );
    }

    /// Nodes do not silence each other: one node's bad row says nothing about
    /// the next node's.
    #[test]
    fn reporting_is_remembered_per_node() {
        let pull = [(1, EgressRejection::Expired)];
        assert_eq!(
            report_rejections("report-node-one", &pull),
            vec![EgressRejection::Expired]
        );
        assert_eq!(
            report_rejections("report-node-two", &pull),
            vec![EgressRejection::Expired]
        );
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
