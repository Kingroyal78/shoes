# V2Board Server Remediation Plan

This plan covers only the dedicated V2Board node-server product: panel
configuration and users, inbound wire protocols, authenticated policy, routing,
traffic/alive reporting, and lifecycle management. Client/outbound behavior,
TUN, and generic utility listeners are outside the plan.

## Shadowsocks Plugin Contract: Implemented

V2Board and shoes now use the versioned `plugin-config`/`status` contract.
Legacy `/config` `obfs` fields remain irrelevant and must not be used to infer
operator intent. The strict manifest distinguishes a required `plugin: null`
transition from an active allowlisted plugin and supplies an exact
`config_revision`.

The server runtime implements in-process simple-obfs, v2ray-plugin, GOST,
ShadowTLS, Restls, and Kcptun adapters with generation apply/rollback, opaque
ETag handling, readiness ACK, and restart last-known-good state. The current
operational and verification rules are documented in
[v2board-shadowsocks-plugin-runtime.md](v2board-shadowsocks-plugin-runtime.md).

## Delivery Rules

Every active work item follows the same gates:

1. Add a failing unit or protocol test before changing behavior.
2. Reject invalid protocol input without panics, unbounded buffering, or
   forwarding unauthenticated traffic.
3. Exercise the server with an independent reference client; a shoes client is
   useful regression coverage but is not sufficient interoperability proof.
4. Verify V2Board user authentication, routes, `speed_limit`, `device_limit`,
   alive reporting, traffic accounting, hot reload, and rollback where the
   protocol owns a long-lived session.
5. Update the runtime matrix only after both positive and negative cases pass.

## Track A: Existing Advertised Protocols

These items repair protocols already advertised by the V2Board backend. They
take priority over adding new node families.

Implementation snapshot:

- A1 is implemented and passes padded/unpadded H2/H3 real Docker policy tests.
- A2 strict binary framing is implemented; an external RFC 6455
  conformance/fuzz run remains.
- A3 bounded pre-authentication task pause/resume is implemented and passes a
  real session-ticket/accepted-0-RTT Packet test with an independent wire
  encoder.
- A4 optional direct fallback is implemented and passes a dedicated real
  V2Board/TLS fallback network E2E.
- A5 optional bounded static masquerade is implemented and passes a real
  TLS/QUIC/H3 response/authentication test. Reverse proxying is not part of
  this slice.

### A1. NaiveProxy Padding Negotiation

Status: implemented and Docker-tested in padded and unpadded H2/H3 modes.

H2 and H3 now treat padding as opt-in: an unpadded client receives a normal
unpadded CONNECT tunnel, while a supported client offer enables Naive framing.

Implementation:

- Remove the missing-padding rejection from
  `src/naiveproxy/naive_hyper_service.rs` and
  `src/naiveproxy/naive_h3_service.rs`.
- Centralize negotiation in one helper used by H2 and H3.
- Select `PaddingType::None` when the request has no `padding` header. Do not
  add padding response headers and do not wrap the stream.
- When `padding` is present, return the server padding header and wrap exactly
  the first eight reads/writes as required by the Naive padding format.
- Treat unsupported extension values conservatively; never silently select a
  padding type the client did not offer.

Tests:

- Unit tests for absent, present, malformed, and unsupported padding offers.
- Real unpadded H2 and H3 CONNECT clients that upload and download data.
- Existing padding-aware H2/H3 tests unchanged.
- Wrong-auth, route, speed/device, accounting, and dual-stack cases in both
  padded and unpadded modes.

Done when ordinary H2/H3 CONNECT clients and Naive padding-aware clients share
the same listener successfully. This gate is complete in the real V2Board
Docker policy suite.

### A2. RFC 6455 WebSocket Framing

Status: strict binary proxy framing implemented; external conformance evidence
pending. Risk remains medium because VMess, VLESS, and Trojan share the stream.

The partial parser has been replaced with an explicit RFC 6455 connection state
machine:

- Enforce masked client-to-server frames and unmasked server-to-client frames.
  If legacy compatibility is required, expose an explicit local
  `allow_unmasked_client_frames` escape hatch that defaults to `false`; never
  call compatibility mode RFC-compliant.
- Validate RSV bits, reserved opcodes, canonical payload lengths, continuation
  sequencing, control-frame `FIN`, and the 125-byte control-frame limit.
- Preserve binary-message streaming and continuation frames while allowing
  Ping/Pong/Close frames to be interleaved with fragmented data.
- Validate text messages as streaming UTF-8 across continuation frames without
  buffering a whole message; use Close 1007 for invalid payload data.
- Echo Ping application data in Pong and accept solicited or unsolicited Pong
  frames with arbitrary valid payloads.
- Add closing states (`Open`, `CloseSent`, `CloseReceived`, `Closed`). Validate
  close codes and UTF-8 reasons, echo a received Close, flush it promptly, stop
  accepting application writes, and wait for the peer Close before closing TCP.
- Queue and flush control frames independently of application writes so Pong
  and Close are not delayed until the proxy writes payload data.
- Bound parser/control buffers and fail protocol errors with Close 1002 rather
  than continuing to parse attacker-controlled bytes.

Tests:

- Raw-frame unit tests for masking, fragmentation, extended lengths,
  interleaved controls, Pong payloads, simultaneous Close, invalid close
  payloads, RSV/opcode errors, and oversized controls.
- A WebSocket conformance harness around `WebsocketStream`; run an RFC 6455
  fuzzing suite against that harness.
- Existing VMess/VLESS/Trojan WebSocket payload, early-data, TLS, policy, and
  accounting cases.
- A compatibility test only if the opt-in unmasked mode is retained.

The existing proxy interoperability test and focused raw-frame unit tests pass.
This item is fully closed when the strict server profile also passes the
selected external RFC 6455 conformance/fuzz suite.

### A3. TUIC v5 Pre-Authentication Tasks and Real 0-RTT

Status: bounded pause/resume implementation, focused tests, and real resumed
accepted-0-RTT proof complete. This remains a security-sensitive path because
authentication, QUIC stream ownership, replay, and UDP session state meet here.

`auth_connection()` now returns the authenticated user and bounded paused task
streams rather than discarding non-AUTH unidirectional streams:

- Parse only the TUIC version and command header before authentication.
- Store a bounded `PendingUniTask` containing the command type, partially read
  stream, and parser state. Do not allocate for the declared payload or forward
  it; the fixed parser buffer may retain only a small lookahead prefix.
- Keep the existing three-second authentication deadline and add an explicit
  maximum pending-task count. Close the connection when the bound is exceeded.
- On successful authentication, create the authenticated connection scope
  first, then resume all paused tasks through the same Packet/Dissociate
  processor used for live streams.
- On failed or timed-out authentication, reset every pending stream and ensure
  no target socket, traffic record, or alive record was created.
- Keep bidirectional streams and datagrams naturally QUIC-buffered until
  authentication. Audit them for the same “no forwarding before auth”
  invariant.
- Document that accepted QUIC 0-RTT data is replayable; do not perform
  non-idempotent control-plane actions before authentication.

Tests:

- A Quinn resumption client: establish once, obtain a session ticket, reconnect
  with early data, send a Packet task before AUTH, then authenticate and verify
  the first UDP packet is delivered.
- Pre-auth Packet and Dissociate ordering, multiple paused streams, queue
  limit, auth timeout, wrong password, and rejected-0-RTT fallback.
- Assert zero target traffic and zero accounting before authentication.
- Repeat V1/V2Node TCP, UDP, device/speed, traffic/alive, and reload rollback.

The bounded parser-state queue, no-payload-sized-allocation and
no-forward-before-auth invariants, and post-authentication resumption have
focused coverage. The network test establishes a real Quinn session ticket,
confirms accepted 0-RTT, proves zero target traffic before AUTH, verifies
first-packet delivery after AUTH, and verifies invalid AUTH never forwards. Its
TUIC wire encoder does not call the server parser.

### A4. Trojan Probe Fallback

Status: optional direct fallback implemented with focused unit coverage;
dedicated network E2E pending.

The Trojan handler can forward malformed or unauthenticated “other protocol”
traffic to an explicitly configured TLS-decoded fallback endpoint. Without
that local setting, the listener remains fail-closed.

Implementation:

- Add an optional per-node local fallback destination because the current
  UniProxy Trojan payload does not provide one.
- Preserve all bytes already read while detecting the Trojan header and prepend
  them when forwarding to the fallback.
- Route wrong passwords, malformed requests, and non-Trojan HTTP through the
  fallback without creating an authenticated user scope or traffic record.
- Apply bounded sniff/read state and require a different port from the listener
  to protect against fallback loops.
- Keep valid Trojan CONNECT and UDP behavior unchanged.

Tests:

- An HTTPS probe receives the same response as the configured fallback.
- Wrong password and malformed Trojan headers reach fallback but create no
  V2Board traffic/alive state.
- Valid Trojan TCP/UDP still receives policy and accounting.

Buffered-byte replay, no-user behavior, no-fallback rejection, and valid Trojan
TCP/UDP regression behavior have focused coverage. The dedicated V2Board/TLS
network E2E verifies a 16,541-byte TLS-decoded probe reaches the decoy exactly,
the no-fallback path stays closed, and no traffic/alive state is attributed.

### A5. Hysteria2 HTTP/3 Masquerade Hardening

Status: optional bounded static response implemented. Reverse-proxy masquerade
is not implemented or claimed.

The server can retain its empty 404 behavior or serve an explicitly configured
static H3 response for ordinary and failed-auth requests:

- Add a local static response for ordinary H3 requests and failed
  authentication; never expose different network behavior for a wrong
  Hysteria password.
- Continue serving ordinary H3 requests on the connection until successful
  `/auth` or timeout, with bounded request counts and body sizes.
- Ensure proxy streams and datagrams are processed only after status 233 has
  been sent for a valid user.
- Test bandwidth negotiation values, authentication failure, and ordinary H3
  request behavior against the Hysteria 2 specification.

The static response/configuration slice is implemented with bounded request and
body handling. A real TLS/QUIC/H3 test covers GET, HEAD, failed authentication,
multiple requests, authentication-window expiry, and successful authentication
on a fresh connection. Reverse proxying requires a separate design and
acceptance decision.

## Track B: Features Currently Rejected

These are not current release blockers because shoes fails them closed. Add
them only after Track A is green, one independently releasable slice at a time.

### B1. Multiplexing and gRPC Multi-Mode

- Introduce an authenticated logical-stream scope so every multiplexed stream
  inherits the user and route policy while bytes are counted exactly once.
- Share device admission at the physical connection level and speed limiting
  at the node/user level.
- Implement gRPC multi-mode and V2Ray/sing-box inbound mux on that common
  accounting layer rather than adding protocol-specific accounting shortcuts.
- Stress test concurrent streams, cancellation, half-close, reload, and
  traffic totals.

### B2. XHTTP Advanced Server Behavior and HTTP/3

- Pin an Xray-core interoperability version and turn each accepted setting into
  a typed runtime field with an explicit server-side effect.
- Implement `xmux`, download streams, padding controls, stream-up timing, and
  header limits as separate slices with a matching Xray client test.
- Add HTTP/3 only after the H2 state machine and policy/accounting hooks can be
  reused over QUIC; do not treat “QUIC listener starts” as XHTTP compatibility.
- Preserve current fail-closed validation for every unimplemented field.

### B3. TLS ECH and Certificate Providers

- Separate certificate loading from listener construction behind a reloadable
  TLS identity provider.
- Add atomic certificate rotation before ACME or remote providers.
- Implement server ECH only when UniProxy/V2Node provides the complete server
  key/config material; public client ECH settings alone are insufficient.
- Add expiry, rollback, SNI, ALPN, and failed-renewal tests. Never replace a
  working certificate with an invalid update.

### B4. VLESS Encryption and Remaining Cipher Variants

- Treat VLESS ML-KEM/AEAD as a cryptographic project: pin the Xray protocol
  version, use reviewed primitives, define replay-cache limits, and obtain
  independent Xray interoperability vectors before enabling the panel field.
- Add Shadowsocks 2022 ChaCha multi-user support separately from obfs, including
  key derivation, duplicate-key rejection, TCP/UDP vectors, and reference-client
  E2E.
- Keep non-empty `encryption_settings` rejected for every protocol until that
  protocol owns and tests the exact schema.

### B5. Additional QUIC Transports

Do not create a generic “QUIC=true” switch. For each protocol, define stream and
datagram framing, authentication ordering, ALPN, 0-RTT policy, reload behavior,
and accounting first. Enable it only when V2Board exposes a stable server
contract and a reference client test exists.

## Track C: Additional V2Board Node Families

Each family is a separate project, not a mapper-only change. Before coding,
freeze the UniProxy config/user/traffic/alive fixtures and decide whether to
embed an upstream engine or implement a native audited engine. Do not write new
cryptographic wire protocols merely to avoid a process boundary.

### C1. Mieru

- Use the [official Mieru implementation and protocol documentation](https://github.com/enfein/mieru)
  as the wire and interoperability baseline.
- Add `NodeType::Mieru`, config fields for port bindings, multiplexing,
  handshake mode, traffic pattern, and MTU, plus username/password users.
- Prefer a maintained upstream engine with server hooks. If only the Go engine
  is viable, define a supervised sidecar protocol that reports authenticated
  user, source IP, destination, connection lifecycle, and directional bytes.
- Support TCP/UDP and multiple port/range bindings atomically.
- Apply routes, speed/device limits, alive, accounting, and hot reload per user.
- Verify with the official Mieru client and malformed/replay inputs.

### C2. TrustTunnel

- Reuse the
  [official Rust implementation and protocol specification](https://github.com/TrustTunnel/TrustTunnel/blob/master/PROTOCOL.md)
  as a version-pinned library where its API permits hooks; do not fork the wire
  protocol first.
- Map V2Board TCP plus optional QUIC, username/password, settings, congestion
  controller, CWND, BBR profile, and local TLS identity.
- Bridge authenticated TCP/UDP streams into the existing route, limiter,
  alive, and traffic scopes. Decide explicitly whether ICMP is in product
  scope; reject it if it cannot be accounted safely.
- Test official HTTP/1.1, H2, and H3 clients, wrong auth, policy, accounting,
  and reload across both listener types.

### C3. MTProxy

- Use [Telegram's official MTProxy implementation](https://github.com/TelegramMessenger/MTProxy)
  or a protocol engine with equivalent test coverage; isolate it behind a
  supervised adapter rather than reimplementing MTProto cryptography casually.
- Map each V2Board user secret and enforce enabled state, quota,
  `max_connections`, secret modes (classic/secure/TLS), and `allow_ad_tag`.
- Obtain and refresh Telegram proxy configuration safely without blocking the
  last working runtime.
- Export per-secret traffic and source-IP lifecycle into V2Board `/push` and
  `/alive`.
- Verify classic and random-padding modes with official Telegram tooling; add
  TLS-mode coverage only against an implementation that actually supports it.

### C4. Hysteria1

Hysteria1 is upstream legacy. Keep it rejected by default. If product demand
requires it:

- isolate it behind a separately versioned compatibility module or pinned
  upstream engine;
- freeze v1 auth, TCP/UDP, bandwidth, and obfs vectors before implementation;
- run the archived official v1 client in E2E;
- do not share Hysteria2 framing code based only on similar names.

### C5. WireGuard

Treat WireGuard as a separate Linux network-backend project:

- Create and configure kernel WireGuard interfaces through netlink; do not
  reimplement the
  [WireGuard protocol](https://www.wireguard.com/protocol/).
- Reconcile panel-provided server keys, address pools, IPv4/IPv6 peers,
  allowed IPs, MTU, keepalive, routes, nftables, and `tc` limits atomically.
- Diff peer updates without recreating healthy interfaces, and roll back failed
  changes.
- Read kernel per-peer cumulative counters and implement the dedicated
  `/traffic-cumulative` acknowledgement/retry model. Do not send normal
  `/push`.
- Implement `/status` with readiness, applied revision/features, version, and
  online peer/handshake data.
- Test in Linux network namespaces with real WireGuard peers, counter resets,
  process restarts, key rotation, address exhaustion, dual-stack, firewall,
  rate limiting, and rollback.

## Track D: Legacy V2Board API Styles

Deepbwork, Trojan Tidalab, and Shadowsocks Tidalab are control-plane adapters,
not new wire protocols. Add a `PanelApiStyle` abstraction only if deployments
still use them:

- capture config/user/push/alive fixtures and authentication rules;
- normalize them into the same runtime model and user tracker;
- keep protocol builders independent of API style;
- run identical protocol and policy E2E against every enabled style.

## Intentional Non-Goals

The dedicated server should continue to fail closed for outbound/DNS route
actions (`route`, `route_ip`, `dns`, and `default_out`) because they require a
general outbound engine outside the product boundary. VMess/VLESS domain socket
support remains blocked by the current V2Board database schema. Neither item
should delay the inbound remediation tracks above.

## Recommended Execution Order

1. NaiveProxy opt-in padding.
2. WebSocket RFC 6455 state machine.
3. TUIC paused pre-authentication tasks and real 0-RTT tests.
4. Trojan fallback and Hysteria2 masquerade hardening.
5. Multiplexing/gRPC multi-mode, then XHTTP advanced behavior.
6. TLS identity/ECH and cryptographic protocol extensions.
7. Mieru and TrustTunnel after their engine-integration spikes.
8. MTProxy if Telegram node demand justifies the adapter.
9. Hysteria1 only as an explicitly accepted legacy target.
10. WireGuard as a separately designed Linux backend.

After each numbered item, rerun the full server matrix and update
`docs/v2board-runtime-support.md`; do not wait for the entire roadmap before
shipping a completed slice.
