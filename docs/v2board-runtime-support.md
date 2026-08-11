# V2Board Runtime Support Matrix

This document tracks the server-side production surface that the current V2Board backend accepts from the panel at runtime. Local YAML validation only checks static process settings; protocol support is validated during `sync-once` or `run`.

The acceptance boundary is inbound/server behavior plus the V2Board control plane, policy, routing, and accounting. Generic local-YAML client/outbound implementations, TUN, utility proxy listeners, and client-side H2MUX or AnyTLS behavior are not evaluated or advertised here.

## Node Models

The local config accepts the supported node types `shadowsocks`, `vmess`, `vless`, `trojan`, `anytls`, `tuic`, `hysteria`, `naiveproxy`, and `v2node`. It also accepts the aliases `ss`, `v2ray`, `hysteria2`, and `naive`, which are normalized to `shadowsocks`, `vmess`, `hysteria`, and `naiveproxy` before calling UniProxy.

Local V2Board currently exposes additional server models through `ServerService::models()` and UniProxy aliases. These are not implemented in this backend yet: `mtproxy`, `mieru`, `trusttunnel`, and `wireguard`/`wg`. Hysteria2 is implemented only for V1 Hysteria `version=2` and V2Node `protocol=hysteria2`; Hysteria1 is rejected. NaiveProxy supports TCP/TLS H2, QUIC/TLS H3, and the V1 `enable_quic=1` TCP+H3 dual-stack shape emitted by V2Board.

WireGuard is not a normal `/push` UniProxy backend in this V2Board checkout; it uses `/status` and `/traffic-cumulative`. `v2node` uses the V2 server API for `/config`; this backend supports that config source for currently supported runtime protocols and still uses V1 UniProxy for users, traffic, and alive reporting. The runtime accepts compatible V2Node `protocol=naive` payloads, but the current local V2Board Admin validator only permits `shadowsocks`, `vmess`, `vless`, `trojan`, `tuic`, `hysteria2`, and `anytls` when operators create V2Node rows through the Admin API.

## Transports

| Transport | Status | Notes |
| --- | --- | --- |
| TCP | Supported | Plain TCP and V2Ray TCP HTTP header obfuscation are supported for non-TLS VMess/VLESS nodes. |
| HTTP | Supported with limits | V2Ray HTTP transport is supported for VMess/VLESS nodes. Plain nodes use HTTP/1.1; TLS and VLESS Reality nodes use HTTP/2 with ALPN `h2`. |
| XHTTP/splitHTTP | Supported with limits | Supported for VMess/VLESS nodes with V2Board `network=xhttp` and `network=splithttp`. `path`, `host`/`Host`, `mode`, session/seq/uplink-data placement including cookie placement, post size, buffered posts, `noSSEHeader`, and HTTP `OPTIONS` CORS preflight are honored. Client-side fields such as `noGRPCHeader` and `extra.headers` are tolerated because the inbound accepts both request shapes. TLS and Reality use HTTP/2 with ALPN `h2`; HTTP/3 is not implemented. Non-empty `xmux`, `downloadSettings`, explicit `xPadding*` settings, `scStreamUpServerSecs`, and `serverMaxHeaderBytes` are rejected during sync instead of being silently ignored. |
| WebSocket | Supported; external conformance evidence pending | Path, headers, and V2Board sing-box early-data are honored. Missing early-data settings default to `maxEarlyData=2048` and `earlyDataHeaderName=Sec-WebSocket-Protocol` for V2Board compatibility. The server proxy profile enforces client masking, RSV/opcode and canonical-length rules, fragmented-message sequencing, interleaved control frames, streaming text UTF-8 validation, Ping/Pong payloads, and passive/active Close handshakes. Protocol errors use Close 1002 and invalid UTF-8 uses 1007. Unit and binary proxy E2E tests pass; an external RFC 6455 conformance/fuzz suite is still pending. |
| HTTPUpgrade | Supported | Expects `GET`, matching path/host/headers, `Connection: upgrade`, and `Upgrade: websocket`. Real WebSocket requests with `Sec-WebSocket-Key` are rejected. |
| gRPC | Supported with limits | Single-stream h2 gRPC transport with standard v2ray `Hunk{data}` framing. `serviceName` and `authority` are honored. `multiMode` is rejected. |
| QUIC | Supported for TUIC, Hysteria2, and NaiveProxy H3 | V2Board V1 TUIC/Hysteria2/NaiveProxy and V2Node `protocol=tuic`/`protocol=hysteria2`/`protocol=naive` listen on QUIC/UDP with TLS and ALPN `h3` where the protocol requires it. |
| NaiveProxy TCP/H3 | Supported | V2Board V1 NaiveProxy `network=tcp` uses TCP/TLS HTTP/2; V1 `enable_quic=1` omits `network` and starts TCP+H3 dual-stack; V2Node `protocol=naive network=udp` starts pure H3. TCP ALPN is `h2`/`http/1.1`; H3 ALPN is `h3`. Padding is opt-in: absent negotiation produces an ordinary unpadded CONNECT tunnel, while supported offers retain Naive framing. Padded and unpadded H2/H3 downloads pass the real Docker policy suite. |
| PROXY protocol | Supported with trust-boundary limits | `network_settings.acceptProxyProtocol=true` enables HAProxy PROXY protocol v1/v2 before TLS, Reality, WebSocket, HTTPUpgrade, gRPC, or proxy authentication on TCP listeners. The header source IP is used for `device_limit` and alive accounting. Enable it only behind a trusted load balancer because direct clients can forge source IPs. `LOCAL`/`UNKNOWN` keep the kernel peer. TUIC and Hysteria2 reject this setting because their listeners are UDP/QUIC. |
| KCP/domain socket and non-supported QUIC | Not supported | Rejected when UniProxy exposes the value. Current `v2board-docker` has an Admin validator that accepts VMess `domainsocket`, but the VMess/VLESS `network varchar(11)` schema cannot store the 12-character value, so this path is schema-blocked before runtime sync in the local Docker environment. |
| Shadowsocks sing-mux/h2mux | Supported except TCP Brutal | Enabled only by the authoritative plugin manifest. Padding is negotiated strictly. Every logical TCP/fixed-UDP/packet-address UDP stream retains the authenticated user and original peer address and enters the normal device-limit, routing, speed-limit, alive, and traffic-accounting path. TCP Brutal candidates are rejected and the last-known-good runtime is retained. |

## Security

| Security | Status | Notes |
| --- | --- | --- |
| None | Supported | Valid for non-Trojan nodes. |
| TLS | Supported | Certificates come from panel `tls_settings.cert_file/key_file`, per-node `v2board.nodes[].tls`, or top-level `tls`. Automatic certificate modes and TLS ECH are rejected when UniProxy exposes them. VMess/Trojan/AnyTLS/TUIC/Hysteria2 UniProxy payloads do not expose certificate/ECH settings, so those node types must use local certificate files. TUIC and Hysteria2 automatically advertise ALPN `h3`. |
| Reality | Supported with limits | V2Board-reachable through VLESS `tls=2`/`reality` and V2Node protocols whose V2 config payload exposes `tls=2`. Requires `private_key`, at least one `short_id`/`short_ids` value, and either `dest` or `server_name`/`server_port`; the destination must be a hostname for a reachable TLS 1.3 handshake server. Optional `reality_config.MaxTimeDiff` is honored as milliseconds or Go-style duration text. `xver`, ECH, and automatic certificate issuance modes are rejected. Some client-side/display fields such as `public_key`, `fingerprint`, and `server_names` are parsed but not used by the inbound builder. |

## Protocols

| Protocol | Status | Notes |
| --- | --- | --- |
| VMess | Supported | Multi-user, AEAD/security from panel, TCP/HTTP/XHTTP/WebSocket/HTTPUpgrade/gRPC, optional TLS. V2Ray HTTP transport supports plaintext HTTP/1.1 and TLS HTTP/2. XHTTP is supported as a distinct splitHTTP transport, not as plain HTTP transport. |
| VLESS | Supported with limits | Multi-user, encryption must be `none`. VLESS supports TCP/HTTP/XHTTP/WebSocket/HTTPUpgrade/gRPC, with V2Ray HTTP over plaintext HTTP/1.1, TLS HTTP/2, or Reality HTTP/2. XHTTP is supported over TLS HTTP/2 and Reality HTTP/2; Vision `xtls-rprx-vision` is supported only with plain TCP wrapped by TLS or Reality. ML-KEM encryption modes and non-empty `encryption_settings` are rejected. |
| Trojan | Supported with optional local fallback | Multi-user and requires TLS in the V2Board UniProxy runtime. The V2Board Trojan table does not expose Reality or a decoy destination. Optional local `trojan_fallback` sends malformed or unauthenticated TLS-decoded traffic directly to a different-port decoy with all already-read bytes preserved and without an authenticated accounting scope. Without it, invalid traffic remains fail-closed. A real V2Board/TLS network E2E verifies 16,541-byte exact replay, fail-closed behavior, and no user traffic/alive state. |
| Shadowsocks legacy AEAD | Supported | V2Board Admin ciphers only: `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, and `chacha20-ietf-poly1305`. Multi-user probing is O(n); `runtime.max_legacy_shadowsocks_users` is enforced and duplicate credentials are rejected. Shadowsocks requires plain TCP transport; V2Node Shadowsocks with WS/gRPC/HTTP/HTTPUpgrade/XHTTP transport is rejected. Plugin intent is obtained from the strict plugin-config contract, not legacy `/config` obfs fields. Non-empty V2Node Shadowsocks `encryption_settings` is rejected instead of being ignored. |
| Shadowsocks 2022 AES | Supported | `2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm` only. Uses UniProxy `server_key`; official V2Board derives it from node `created_at`. Per-user `link_secret`/`secret` is preferred, with V2Board-compatible UUID-prefix fallback. Duplicate PSKs are rejected. |
| Shadowsocks 2022 chacha20 | Not supported | `2022-blake3-chacha20-poly1305` is rejected for V2Board multi-user. |
| Shadowsocks plugin runtime | Supported through schema v1 | The versioned `plugin-config`/`status` contract drives in-process simple-obfs HTTP/TLS, v2ray-plugin WS/WSS/HTTPUpgrade/Mux.Cool, GOST WS/WSS/smux, ShadowTLS v1/v2/v3, Restls, and Kcptun UDP/KCP/FEC/Snappy/smux v1/v2. Plugin-null transitions, opaque ETag, exact revision ACK, readiness, rollback, and restart LKG are enforced. See `v2board-shadowsocks-plugin-runtime.md`. |
| Shadowsocks `jls` plugin | Rejected | The panel can store and emit a `jls` manifest, but this backend has no JLS listener, so the candidate is rejected by name, the last-known-good runtime is kept, and `shadowsocks-plugin-jls-v1` is never advertised. The panel's publication gate keeps such a node hidden. |
| Restls script beyond the interoperable range | Rejected | The script grammar allows a record target up to 32767 and 254 responses, but the reference client stops carrying traffic above 31 responses whatever server it talks to: the reference Restls server fails from 32, this backend from 33. The accepted range is therefore a last record target of 16364 and 31 responses, matching what the panel treats as v1-safe; a wider script is rejected by name and the last-known-good runtime is kept. |
| AnyTLS | Supported with limits | V2Board V1 UniProxy `v2_server_anytls` is supported as TLS/raw TCP. When a V2Node config resolves to `protocol=anytls`, TLS, Reality, and PROXY protocol are supported through `/api/v2/server/config`, but only over plain TCP transport. V2Node AnyTLS with WS/gRPC/HTTP/HTTPUpgrade/XHTTP transport is rejected. Users authenticate with their V2Board UUID, `padding_scheme` is honored, and V2Board speed limit/device limit/alive/traffic accounting is applied per AnyTLS logical stream. The V1 AnyTLS table does not expose Reality, transport, PROXY protocol, or certificate settings; certificates must come from local config. |
| TUIC | Supported, including real accepted 0-RTT Packet evidence | V2Board V1 UniProxy `v2_server_tuic` and V2Node `protocol=tuic` are supported over QUIC/TLS. Users authenticate with the V2Board UUID as both TUIC UUID and password. Authenticated native-datagram TCP/UDP, congestion control, policy, and accounting paths pass E2E. Non-AUTH unidirectional task headers received before authentication are retained with bounded parser state and no payload-sized allocation; a small payload prefix may remain as bounded parser lookahead. Tasks resume only after the authenticated connection scope exists, and no task is forwarded before authentication. A wire encoder independent from the server parser obtains a real Quinn session ticket and proves accepted 0-RTT, no pre-auth target forwarding, post-auth first-packet delivery, and invalid-auth zero forwarding. Fragmented UDP reassembly limits each logical packet to 65,535 bytes and each connection cache to 4 MiB. The current panel APIs omit `udp_relay_mode`. TUIC does not support Reality or PROXY protocol. |
| Hysteria2 | Supported with optional static masquerade | V2Board V1 UniProxy `v2_server_hysteria` is supported only when `version=2`; V2Node `protocol=hysteria2` is supported. Users authenticate with the V2Board UUID as password. Traffic accounting, `speed_limit`, `device_limit`, panel `up_mbps/down_mbps`, Salamander and Gecko obfs, alive, TCP forwarding, UDP forwarding, route decisions, and reload rollback use the authenticated QUIC connection scope. Fragmented UDP reassembly limits each logical packet to 65,535 bytes and each connection cache to 4 MiB. Optional local `hysteria2_masquerade` provides a bounded static status/content-type/body response for ordinary and failed-auth H3 requests; HEAD omits the body and body-forbidden statuses are rejected. A real TLS/QUIC/H3 test covers durable ordinary/failed-auth responses, the authentication window, and successful auth on a fresh connection. It is not a reverse proxy; without it, the prior empty-404 authentication-window behavior remains. Hysteria1, unknown Hysteria2 obfs types, Reality, and PROXY protocol are rejected. |
| NaiveProxy | Supported | V2Board V1 UniProxy `v2_server_naiveproxy` and compatible V2Node `protocol=naive` payloads are supported as TCP/TLS HTTP/2 CONNECT and QUIC/TLS HTTP/3 CONNECT. Users authenticate with `/user` `username`/`password` when present, falling back to `user-<id>`/UUID. V2Board speed limit/device limit/alive/traffic accounting applies to authenticated streams. Padding is negotiated only when offered; requests without the header use a normal unpadded tunnel. V1 `enable_quic=1` starts TCP+H3 dual-stack. V1 `quic_congestion_control` and V2Node `congestion_control` accept V2Board values `cubic`, `reno`, `new_reno`, `bbr`, `bbr_standard`, `bbr2`, and `bbr2_variant` for H3; `bbr_standard`/`bbr2*` map to Quinn BBR. Current local V2Board Admin does not expose `protocol=naive` for new V2Node rows, so this V2Node path covers manual, legacy, or future-compatible payloads. |
| V2Node config source | Supported with limits | `/api/v2/server/config` is supported for V2Node VMess, VLESS, Shadowsocks, Trojan, AnyTLS, TUIC, Hysteria2, and NaiveProxy. Users, traffic, alive, and device-limit admission continue through V1 UniProxy using `node_type=v2node`. Empty `encryption_settings` defaults are tolerated; non-empty values are rejected unless the protocol explicitly implements them. |

## User Policy

`speed_limit` and `device_limit` are read from the V2Board user API. They are not local YAML settings.

- `speed_limit` is Mbps. `0` or missing is unlimited.
- Hysteria2 `up_mbps`/`down_mbps` are node-level Mbps limits from the panel and are shared across concurrent connections for the same local node. `up_mbps` limits server-to-client/user download traffic, and `down_mbps` limits client-to-server/user upload traffic.
- Hysteria2 `obfs=salamander` and `obfs=gecko` are supported when V2Board supplies `obfs_password`; unknown obfs types are rejected.
- `device_limit` counts currently connected distinct source IPs for the node/user and also consults the V2Board `/alivelist` aggregate count cached for that same local node before admitting a new distinct local IP. `0` or missing is unlimited.
- `node_report_min_traffic` gates traffic push payloads.
- `device_online_min_traffic` gates alive IP push payloads; it does not change `device_limit` enforcement.
- Active long-lived connections flush traffic periodically, so traffic and alive reports are not delayed until disconnect.
- Connection teardown/drop synchronously persists newly recorded pending traffic, so graceful shutdown and runtime task aborts leave restart-replayable traffic in `traffic-pending.json`.
- After V2Board accepts a `/push` payload, the consumed pending traffic is persisted before `/alive` is attempted. A later `/alive` failure in the same cycle will not replay already accepted traffic after restart.

V2Board `device_limit_mode` affects the panel's cross-node alive aggregation returned by `/alivelist`. The backend reports alive IPs in V2Board's `ip_nodeId` format and caches the panel's aggregate count per configured local node for new-connection admission. UniProxy does not expose `device_limit_mode` or per-user alive IP details to nodes, so existing local connections are tracked exactly, while cross-node admission follows the aggregate count V2Board returns. Multiple nodes in one process do not overwrite each other's cached `/alivelist` view.

Policy changes affect new connections after the next successful user/config sync. Existing long-lived connections continue until the client disconnects; traffic and alive accounting still flush periodically while they are open.

## Routes

V2Board `route_id` rules are applied before the default direct outbound:

- `block`: supported for domain keyword matchers, `domain:` suffix matchers, `full:` exact hostname matchers, `regexp:` hostname regex matchers, and configured `geosite:` local rule sets.
- `block_ip`: supported for IPv4/IPv6 address/CIDR matchers and configured `geoip:` local rule sets.
- `block_port`: supported for single ports and inclusive ranges written as `start-end` or `start:end`.
- `protocol`: supported for TCP `http`, `tls`, `bittorrent`, and `ssh` first-payload sniffing, plus UDP `quic` first-datagram sniffing.
- `geosite:`/`geoip:` labels must be mapped under `v2board.route_rule_sets`; missing files or invalid entries fail sync.
- `dns`, `route`, `route_ip`, and `default_out`: rejected because V2Board stores Xray outbound/DNS JSON in `action_value`, which has no equivalent local outbound model.

Unsupported route actions fail node sync. If a previous runtime is already serving, reload keeps the previous runtime instead of silently allowing traffic with ignored routes.

## Local E2E Coverage

The sibling `v2board-docker`联调 scripts currently validate:

- VMess TCP, V2Ray HTTP transport over plaintext and TLS, XHTTP over TLS HTTP/2 including `packet-up` and `auto` with header session/seq/uplink-data placement, TCP HTTP header obfuscation, WebSocket, TLS, gRPC, gRPC authority, HTTPUpgrade, and HTTPUpgrade custom headers.
- HTTPUpgrade rejects real WebSocket handshakes carrying `Sec-WebSocket-Key`.
- VMess `security=none` from V2Board `networkSettings.security`.
- VLESS TCP, V2Ray HTTP transport over plaintext/TLS/Reality, XHTTP over TLS/Reality HTTP/2 including `packet-up`, `stream-up`, `stream-one`, `splithttp` alias, query/cookie placement, WebSocket, TLS, gRPC, HTTPUpgrade, Vision over TLS, Reality, and Vision over Reality.
- Shadowsocks legacy AEAD and Shadowsocks 2022 AES-128/AES-256.
  The legacy `shadowsocks_obfs_http` case is obsolete; plugin acceptance now
  uses the versioned plugin-config/status contract.
- Trojan over TLS, WebSocket, gRPC, and HTTPUpgrade.
- AnyTLS over TLS/raw TCP with panel padding scheme.
- TUIC over QUIC/TLS, including V2Board UUID/password authentication, traffic accounting, `speed_limit`, `device_limit`, wrong-password rejection, and the same user policy checks through V2Node TUIC with `server_type=v2node`.
- Hysteria2 over QUIC/TLS, including V1 Hysteria `version=2`, V2Board UUID/password authentication, traffic accounting, per-user `speed_limit`/`device_limit`, panel `up_mbps/down_mbps`, Salamander and Gecko obfs, V2Node Hysteria2 user policy, and explicit rejection of Hysteria1 and unsupported Hysteria2 obfs values.
- NaiveProxy TCP/TLS and QUIC/H3, including padded and unpadded H2/H3 downloads, V2Board username/password authentication, wrong-password rejection, per-user `speed_limit`, `device_limit`, alive, traffic accounting, V1 TCP+H3 dual stack, and V2Node H3 user policy.
- V2Node VMess TCP/WebSocket/HTTP plaintext/HTTP over TLS/gRPC/HTTPUpgrade/XHTTP over TLS, VLESS TCP/WebSocket/TLS/HTTP plaintext/HTTP over TLS/gRPC/HTTPUpgrade/XHTTP over TLS/splitHTTP alias over TLS/XHTTP over Reality/Vision TLS/Reality, Shadowsocks legacy AEAD across all V2Board Admin ciphers plus 2022 AES-128/AES-256, Trojan TLS/WebSocket/gRPC/HTTPUpgrade, AnyTLS TLS, TUIC TLS, Hysteria2 TLS, NaiveProxy TCP/TLS, NaiveProxy H3, and AnyTLS Reality via `/api/v2/server/config`, with V1 UniProxy user and traffic reporting.
- VMess per-user `speed_limit` and `device_limit`, including the same checks through V2Node VMess with `server_type=v2node` reporting.
- Dynamic user `direct_limit` speed rules from V2Board's effective `/user` payload and runtime enforcement.
- Global dynamic speed trigger path: shoes pushes real proxy traffic, V2Board queue drain plus `traffic:update` records the dynamic traffic bucket, `/user` returns the lower effective `speed_limit`, and the same shoes process hot-syncs the change for new connections.
- Dynamic speed rule priority: global inherited users, enabled plan override, user whitelist bypass, user direct limit override, and plan-rule effective speed enforcement by shoes.
- Node `rate != 1` traffic accounting: `v2_user` is multiplied by rate, while `v2_stat_user` and `v2_stat_server` keep raw bytes.
- V2Board `route_id` domain keyword/suffix/full/regexp/geosite, IP/CIDR/geoip, port, `action=protocol`, and `action=block` with `protocol:` matchers, plus sync failure for unsupported outbound route actions.
- UniProxy `/config` and `/user` JSON API ETag/304 behavior, and `/user` msgpack responses.
- V2Board user filtering for `expired_at`, `banned`, and exhausted `transfer_enable`, plus backend-side filtering when `/user` payloads explicitly include `enabled=false`, expired `expires_at`, or expired `expires_on`.
- V2Board alive push into `ALIVE_IP_USER_<uid>` cache and `/alivelist`.
- Cross-node `device_limit_mode` alive aggregation for mode `0` and `1`.
- Global `/alivelist` device-limit admission for new connections.
- Parent/child node status cache behavior: operator-facing `LAST_CHECK_AT`, `LAST_PUSH_AT`, and `ONLINE_USER` use `parent_id`, while traffic statistics remain attributed to the serving child node.
- Nonzero V2Board reporting thresholds: high `node_report_min_traffic` suppresses sub-threshold pushes, pending traffic flushes when the threshold is lowered, high `device_online_min_traffic` suppresses alive reports, and a reachable nonzero alive threshold reports expected IPs.
- Live V2Board `base_config.pull_interval` and `base_config.push_interval` hot update without restarting shoes.
- PROXY protocol v1/v2 positive matrix cases for VLESS WebSocket and V2Node VMess WebSocket/AnyTLS TLS, with a local TCP bridge that writes the PROXY header before forwarding client traffic.
- Explicit sync failures for unsupported panel options that are actually exposed by UniProxy or V2Node config: unsupported VMess/VLESS networks, invalid XHTTP modes and unsupported server-side XHTTP advanced features, XHTTP on non-VMess/VLESS V2Node protocols, gRPC `multiMode`, VLESS ML-KEM encryption, non-empty VLESS/V2Node `encryption_settings`, V2Node Shadowsocks/AnyTLS non-plain TCP transports, Reality `xver`/ECH/missing destination/missing `short_id`, VLESS TLS ECH, Hysteria1, unsupported Hysteria2 obfs values, invalid Naive ALPN/TLS/congestion-control modes including V2Node Naive `congestion_control`, and non-V2Board Shadowsocks ciphers. The raw `/config` unknown-obfs case is quarantined because the panel strips that legacy field; the strict plugin manifest separately rejects unknown plugin intent.
- TLS certificate sourcing from V1 VLESS and V2Node VLESS panel `tls_settings.cert_file/key_file`, plus local per-node `v2board.nodes[].tls` fallback/override.
- Pending `traffic-pending.json` replay after restart, including connection-drop persistence and the crash-consistency boundary where `/push` succeeds but `/alive` fails before the cycle completes.
- Runtime reload rollback when a changed panel node cannot bind its new listener.
- TUIC-specific UDP reload rollback when a changed panel node cannot bind its new QUIC listener.
- V2Board `v2_user`, `v2_stat_user`, and `v2_stat_server` traffic rows after queue drain and `traffic:update`.

Vision E2E cases use a local HTTPS payload target to exercise TLS-in-TLS traffic. TUIC and Hysteria2 cases require `singlink` to include `with_quic`; Reality cases require `with_utls`.

Current audit snapshot:

- The historical raw matrices' `shadowsocks_obfs_http` and `ss_unknown_obfs`
  cases are obsolete because they exercise legacy fields that are not the
  plugin control plane. They must not be counted for or against plugin
  readiness.
- Plugin acceptance uses strict manifest, revision/ACK, lifecycle, negative
  parser, and real adapter-interoperability cases described in
  `v2board-shadowsocks-plugin-runtime.md`.
- NaiveProxy H2/H3 policy suite passes in both padding-aware and `--no-padding`
  modes against the real V2Board Docker fixtures.
- WebSocket framing has focused unit coverage and the existing binary proxy E2E
  passes, but an external RFC conformance/fuzz suite has not yet run.
- TUIC pre-authentication task pause/resume has focused unit coverage and a
  real session-ticket/accepted-0-RTT QUIC-stream test with an independent wire
  encoder. The existing V2Board policy E2E separately covers accounting.
- Trojan fallback passes its dedicated real V2Board/TLS network E2E, including
  exact replay and no authenticated traffic/alive state.
- Hysteria2 static masquerade passes a real TLS/QUIC/H3 network test; its
  existing policy E2E continues to cover the authenticated proxy data plane.

## Sync Behavior

Unsupported panel options fail the node sync. If a node already has a running runtime, the previous runtime keeps serving. During startup, `shoes run` refuses to continue only when every configured node fails initial sync.
