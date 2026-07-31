# V2Board Alignment Audit

This is the requirement-level audit for using `shoes` as a dedicated V2Board
node server. The audit covers inbound protocol handling, V2Board configuration
and users, policy, routing, traffic/alive reporting, and server lifecycle.
Client/outbound implementations, local utility listeners, TUN, and client-side
H2MUX/AnyTLS behavior are explicitly outside the acceptance boundary.

Passing a Docker download/traffic case proves a common server data path, not
every mandatory control-frame or 0-RTT behavior in the protocol specification.

## Audit Baselines

The server review uses the local V2Board API/controllers as the product
contract, then checks wire behavior against the applicable primary protocol
documents:

- [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html) for WebSocket
  framing and control frames.
- [TUIC v5 specification](https://github.com/tuic-protocol/tuic/blob/master/SPEC.md)
  for authentication, task ordering, streams, and datagrams.
- [AnyTLS protocol v2](https://github.com/anytls/anytls-go/blob/main/docs/protocol.md)
  for session settings, padding updates, and logical streams.
- [Hysteria 2 protocol](https://v2.hysteria.network/docs/developers/Protocol/)
  for QUIC authentication, TCP, UDP, and bandwidth negotiation.
- [NaiveProxy protocol notes](https://github.com/klzgrad/naiveproxy/blob/master/README.md)
  for HTTP/2 interoperability and padding negotiation.
- [Trojan protocol](https://trojan-gfw.github.io/trojan/protocol.html) for
  authenticated requests and non-Trojan fallback behavior.

Interoperability fixtures and the sibling `sing-box`/`singlink` implementation
are supporting evidence, not substitutes for those contracts.

## Authoritative V2Board Surface

Local V2Board accepts these UniProxy node models in
`/root/cate/v2board/app/Services/ServerService.php`:

| V2Board node type | Evidence | Current shoes status |
| --- | --- | --- |
| `shadowsocks` | `ServerService::SERVER_MODELS` | Plain legacy AEAD and 2022 AES are E2E verified. The legacy `/config` obfs fields remain null by design; server plugin intent and all six allowlisted adapters use the separate versioned `plugin-config`/`status` contract. |
| `vmess` / `v2ray` alias | `UniProxyController::__construct` normalizes `v2ray` to `vmess` | Common inbound transports are E2E verified; the shared WebSocket server implements strict binary framing, with external conformance-suite evidence still pending. |
| `vless` | `ServerService::SERVER_MODELS` | Common inbound transports, TLS, Reality, and Vision are E2E verified; the shared WebSocket server implements strict binary framing, with external conformance-suite evidence still pending. |
| `trojan` | `ServerService::SERVER_MODELS` | TLS, WebSocket, gRPC, and HTTPUpgrade data paths are E2E verified. An optional different-port direct probe fallback preserves buffered input; a dedicated V2Board/TLS network E2E verifies exact replay, fail-closed behavior, and accounting isolation. |
| `hysteria` / `hysteria2` alias | `ServerService::SERVER_MODELS`, `UniProxyController::__construct` | Hysteria2 supported for V1 `version=2` and V2Node `protocol=hysteria2`, including panel `up_mbps/down_mbps`, Salamander/Gecko obfs, and an optional static H3 masquerade; reverse-proxy masquerade is not implemented. Hysteria1 and unknown obfs are rejected. |
| `tuic` | `ServerService::SERVER_MODELS` | Authenticated native-datagram paths are E2E verified for V1 and V2Node. Pre-authentication unidirectional task headers are bounded and resumed after authentication. A real Quinn session-ticket test with an independent wire encoder proves accepted 0-RTT, no pre-auth forwarding, post-auth first-packet delivery, and invalid-auth zero forwarding. |
| `anytls` | `ServerService::SERVER_MODELS` | Supported for V1 UniProxy AnyTLS TLS/raw TCP with V2Board user accounting and E2E coverage. |
| `mtproxy` | `ServerService::SERVER_MODELS` | Not implemented in V2Board runtime. |
| `mieru` | `ServerService::SERVER_MODELS` | Not implemented in V2Board runtime. |
| `trusttunnel` / aliases | `ServerService::SERVER_MODELS`, `UniProxyController::__construct` | Not implemented in V2Board runtime. |
| `naiveproxy` / aliases | `ServerService::SERVER_MODELS`, `UniProxyController::__construct` | Optional-padding and unpadded H2/H3 plus dual-stack paths pass the real V2Board Docker policy suite. |
| `v2node` | `ServerService::SERVER_MODELS`, V2 `/api/v2/server/config` | Supported as a V2 config source for current runtime protocols: VMess, VLESS, Shadowsocks, Trojan, AnyTLS, TUIC, Hysteria2, and NaiveProxy. |
| `wireguard` / `wg` alias | `ServerService::SERVER_MODELS`, `UniProxyController::__construct` | Not implemented; also requires `/status` and `/traffic-cumulative`, not normal `/push`. |

The sibling `sing-box`/`singlink` V2Board service is a useful reference, but
not a completion proof for this project. Its mapper still covers families and
API styles outside the current `shoes` runtime slice, including `mieru`,
`deepbwork`, `trojan_tidalab`, and `shadowsocks_tidalab`.

V2Board UniProxy endpoints that a production backend must account for:

| Endpoint | V2Board behavior | Current shoes status |
| --- | --- | --- |
| `/config` | Returns per-node protocol config, `base_config`, routes, ETag/304. | Supported for current V1 UniProxy node types. |
| `/user` | Returns active users, updates `LAST_CHECK_AT`, supports JSON/msgpack and ETag/304. | Supported for current V1 UniProxy node types. |
| `/push` | Reports per-user traffic, updates `ONLINE_USER`/`LAST_PUSH_AT`; disabled for WireGuard. | Supported for current V1 UniProxy node types; accepted traffic is persisted as consumed before `/alive` is attempted. |
| `/alive` | Reports alive IPs into `ALIVE_IP_USER_<uid>` and updates counts by `device_limit_mode`. | Supported for current V1 UniProxy node types. |
| `/alivelist` | Returns aggregate alive counts for device-limit admission. | Supported for current V1 UniProxy node types; backend caches the panel view per configured local node. |
| `/status` | WireGuard-only node status cache update. | Not implemented. |
| `/traffic-cumulative` | WireGuard-only cumulative traffic delta dispatch. | Not implemented. |

V2Board registers both `UniProxy` and `uniproxy` route spellings under the V1
`/api/v1/server` prefix. The backend control-plane HTTP client uses `UniProxy`,
which is accepted; this use of "client" does not expand the protocol acceptance
boundary to proxy outbounds.
`v2node` is present in the model list but does not have a V1 UniProxy `/config`
case in this checkout; this backend fetches its node config from the V2 server
API and continues using V1 UniProxy for users, traffic, alive, and alivelist.
V2 `/api/v2/server/config` ETag values are normalized before being sent back
as `If-None-Match`, matching the local V2Board controller's raw-hash 304
comparison.

## Current Supported Slice

The current runtime model accepts these local node types:

- `shadowsocks`, with `ss` as local config alias.
- `vmess`, with `v2ray` as local config alias.
- `vless`.
- `trojan`.
- `anytls`.
- `tuic`.
- `hysteria` for Hysteria2 only.
- `naiveproxy` for TCP/TLS H2, QUIC/TLS H3, and V1 TCP+H3 dual stack.
- `v2node` as a config source for the protocols above.

For those node types, the Docker E2E suite verifies:

- UniProxy `/config` and `/user` JSON/msgpack API compatibility, ETag/304.
- VMess TCP, V2Ray HTTP transport over plaintext HTTP/1.1 and TLS HTTP/2, XHTTP over TLS HTTP/2, TCP HTTP header obfuscation, WebSocket, TLS, gRPC, gRPC authority, HTTPUpgrade, HTTPUpgrade custom headers, and `security=none`.
- VLESS TCP, V2Ray HTTP transport over plaintext HTTP/1.1, TLS HTTP/2, and Reality HTTP/2, XHTTP over TLS HTTP/2 and Reality HTTP/2, WebSocket, TLS, gRPC, HTTPUpgrade, Vision TLS, Reality, and Vision Reality.
- Shadowsocks legacy AEAD and Shadowsocks 2022 AES-128/AES-256. The old raw
  `/config` `obfs=http` case is obsolete; plugin verification now uses the
  versioned plugin contract and a real Mihomo client matrix.
- Trojan TLS, WebSocket, gRPC, and HTTPUpgrade.
- AnyTLS TLS/raw TCP with V2Board UUID password, panel padding scheme, route enforcement, speed/device admission, alive, and traffic accounting.
- TUIC QUIC/TLS authenticated/native operation with V2Board UUID as TUIC UUID/password, route enforcement, speed/device admission, alive, traffic accounting, wrong-password rejection, and UDP reload rollback, including V2Node TUIC user policy coverage. Focused tests cover bounded pre-authentication task pause/resume, but the Docker suite does not exercise a real resumed session-ticket Packet command in early data.
- Hysteria2 QUIC/TLS with V2Board UUID as password, route enforcement, panel `up_mbps/down_mbps`, Salamander/Gecko obfs, speed/device admission, alive, traffic accounting, and explicit rejection of Hysteria1/unsupported Hysteria2 obfs, including V2Node Hysteria2 user policy coverage.
- NaiveProxy TCP/TLS and QUIC/H3 with padded and `--no-padding` modes, V2Board username/password authentication, route enforcement, speed/device admission, alive, traffic accounting, wrong-password rejection, and V1 `enable_quic=1` dual-stack behavior.
- V2Node VMess TCP/WebSocket/HTTP plaintext/HTTP over TLS/gRPC/HTTPUpgrade/XHTTP over TLS, VLESS TCP/WebSocket/TLS/HTTP plaintext/HTTP over TLS/gRPC/HTTPUpgrade/XHTTP over TLS/XHTTP over Reality/Vision TLS/Reality, Shadowsocks legacy AEAD across all V2Board Admin ciphers plus 2022 AES-128/AES-256, Trojan TLS/WebSocket/gRPC/HTTPUpgrade, TUIC TLS, Hysteria2 TLS, AnyTLS TLS/Reality, NaiveProxy TCP/TLS, and NaiveProxy H3 through `/api/v2/server/config` plus V1 UniProxy user and traffic reporting.
- V2Board `network_settings.acceptProxyProtocol=true` for supported V1 protocol tables and V2Node configs that expose `network_settings`, including PROXY protocol v1/v2 before TLS/Reality/transport parsing.
- XHTTP HTTP/1 CORS preflight behavior, including `OPTIONS`, Origin echo, requested method/header reflection, and credentials headers when V2Board cookie placement is configured.
- Per-user `speed_limit`, `device_limit`, V2Board `/alivelist` global admission, alive reports, stat/user/server traffic rows.
- Dynamic speed limit effective `/user` values, traffic-triggered hot-sync enforcement, plan/user rule priority.
- `rate != 1` accounting, user-state filtering, parent/child node status cache ownership, thresholds, base_config hot update, route blocking, pending replay including connection-drop persistence and `/push`-success/`/alive`-failure recovery, and reload rollback.
- Explicit unsupported-option failures cover unsupported networks, invalid XHTTP modes and unsupported server-side XHTTP advanced fields, HTTP/XHTTP on non-VMess/VLESS protocols, gRPC `multiMode`, VLESS ML-KEM, non-empty VLESS/V2Node `encryption_settings`, Reality/TLS ECH, Reality `xver`, Hysteria1, unsupported Hysteria2 obfs values, invalid Naive ALPN/TLS/congestion-control modes, and unsupported ciphers. Shadowsocks plugin intent now uses the separate strict schema-v1 plugin contract.

## Important Non-Completion Findings

The historical default and unsupported-option matrices predate the versioned
Shadowsocks plugin contract. Their legacy obfs cases are no longer valid
acceptance evidence and must be replaced by plugin-config/status and real
adapter interoperability cases.

Remaining claim-limiting server findings and evidence gaps:

- Shadowsocks plugin state now comes from the strict versioned contract, not
  the legacy null obfs fields. All six allowlisted adapters are integrated;
  TCP Brutal remains an explicit fail-closed server-mux limitation.
- WebSocket strict proxy framing is implemented, including fragmented text
  UTF-8 validation and the active/passive Close handshake, and is covered by
  raw-frame unit tests plus the existing binary proxy E2E. An external RFC 6455
  conformance/fuzz suite is still required before making a broader
  whole-protocol certification claim.
- TUIC v5 now bounds and pauses non-AUTH unidirectional task headers and resumes
  them after successful authentication without pre-auth forwarding. A real
  Quinn session ticket and independent wire encoder prove accepted early data,
  post-auth first-packet delivery, and invalid-auth zero forwarding.
- NaiveProxy padding negotiation is repaired; padded and unpadded H2/H3 modes
  pass the real V2Board Docker policy suite.
- Trojan optional fallback preserves buffered TLS-decoded bytes and isolates
  invalid traffic from authenticated accounting. Its dedicated V2Board/TLS
  network E2E verifies 16,541-byte exact replay and fail-closed behavior.
- Hysteria2 has an optional bounded static ordinary-H3 masquerade. Reverse-proxy
  masquerade remains outside the implemented slice.

Documented server-scope gaps compared with sibling `sing-box`/`singlink`:

- Missing node families or subfeatures: Hysteria1,
  Mieru, MTProxy, TrustTunnel, and WireGuard.
- Missing legacy API styles outside V2Node: Deepbwork,
  Trojan Tidalab, and Shadowsocks Tidalab.
- V2Board Shadowsocks obfs and GOST fields exist in the Admin/schema layer, but
  this checkout's UniProxy `/config` response for `shadowsocks` does not expose
  operator intent, so the node cannot implement or reject it without a V2Board
  API payload change.
- Missing transport/settings support inside the current supported protocols:
  panel-driven QUIC transport outside TUIC,
  XHTTP HTTP/3, V2Board inbound multiplex, custom TLS ECH, and certificate
  providers. XHTTP `xmux`, `downloadSettings`, explicit `xPadding*`,
  `scStreamUpServerSecs`, and `serverMaxHeaderBytes` are not implemented as
  runtime behaviors and are now explicit sync failures.
- VMess/VLESS `domainsocket` cannot be included in the current Docker
  unsupported default set because local V2Board's Admin validator accepts the
  string while the database column is `varchar(11)`, so the fixture is rejected
  by MySQL before UniProxy can expose it to shoes.
- Route parity is intentionally narrower for outbound/DNS actions: `route`,
  `route_ip`, `dns`, and `default_out` are not treated as silently supported.
  `regexp:`, configured `geosite:`, configured `geoip:`, and `protocol`
  matchers are supported for block routes. Protocol sniffing covers TCP
  `http`, `tls`, `bittorrent`, and `ssh`, plus UDP `quic`. Unsupported route
  actions fail sync and preserve the previous runtime.

The implemented AnyTLS slice intentionally follows V2Board V1 UniProxy
`v2_server_anytls`: the panel exposes `server_port`, `server_name`, and
`padding_scheme` only. This backend supplies certificates from local config and
meters each authenticated AnyTLS logical stream inside the AnyTLS session because
the protocol handler owns multiplexed forwarding and returns
`TcpServerSetupResult::AlreadyHandled`.

V2Node runtime support is implemented through V2Board's separate V2 API, whose
payload includes protocol, TLS, Reality, cipher/encryption, TUIC, Hysteria2,
and network settings that are not available from every V1 UniProxy table. The
supported V2Node slice currently resolves to the same inbound protocol builders
used by VMess, VLESS, Shadowsocks, Trojan, AnyTLS, TUIC, Hysteria2, and
compatible NaiveProxy payloads. Current local V2Board Admin validation does not
allow operators to create V2Node `protocol=naive` rows through the Admin API,
so Naive V2Node support is compatibility coverage for manually seeded, legacy,
or future-compatible payloads.

## Remaining Verification and Implementation Order

Shadowsocks plugin integration is now an active, versioned server contract.
Its lifecycle and production checks are in
[v2board-shadowsocks-plugin-runtime.md](v2board-shadowsocks-plugin-runtime.md).
The detailed strategy and completion criteria for other server findings remain
in [v2board-server-remediation-plan.md](v2board-server-remediation-plan.md).

The active order is:

1. Run an external RFC 6455 conformance/fuzz suite against the strict server
   profile.
2. Keep Hysteria2 masquerade static unless a separately specified reverse-proxy
   feature is accepted.
3. Implement currently rejected features one fail-closed slice at a time.
4. Add V2Board node families, with WireGuard remaining a separate
   Linux networking backend.
