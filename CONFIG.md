# V2Board Backend Configuration

`shoes` uses one YAML file. Unknown fields are rejected.

The sample below shows the full production shape. Remove or comment the top-level `tls` block unless those certificate files exist; `shoes validate` checks that configured TLS paths are readable.

This reference documents the V2Board node-server configuration used in production: inbound listeners, panel integration, and the local outbound routing layer (`outbounds`, `default_out`, `route_rules`, `rule_providers`). Generic local-YAML client configurations, TUN, utility SOCKS/HTTP listeners, and client-side protocol options are outside this backend's acceptance boundary; legacy examples for those code paths are not production configuration guidance.

```yaml
v2board:
  api_host: "http://127.0.0.1"
  api_key: "replace-with-v2board-server-token"
  api_timeout_secs: 30
  error_body_limit_bytes: 4096
  user_list_body_limit_bytes: 10485760
  nodes:
    - tag: "vless-1"
      node_id: 1
      node_type: "vless"
      listen: "0.0.0.0"
      # Optional per-node API and timing overrides.
      # api_host: "https://panel.example.com"
      # api_key: "per-node-server-token"
      # pull_interval_secs: 30
      # push_interval_secs: 30
      # tls:
      #   cert_file: "/etc/shoes/tls/fullchain.pem"
      #   key_file: "/etc/shoes/tls/privkey.pem"
      # Trojan only; must use a different port from the node listener.
      # trojan_fallback: "127.0.0.1:8443"
      # Hysteria2 only; optional static HTTP/3 masquerade, not a reverse proxy.
      # hysteria2_masquerade:
      #   status_code: 404
      #   content_type: "text/html; charset=utf-8"
      #   body: "<html><body>Not Found</body></html>"

runtime:
  data_dir: "/var/lib/shoes"
  pull_interval_secs: 60
  push_interval_secs: 60
  node_report_min_traffic: 0
  device_online_min_traffic: 0
  max_legacy_shadowsocks_users: 10000
  tcp_fast_open: false

tls:
  cert_file: "/etc/shoes/tls/fullchain.pem"
  key_file: "/etc/shoes/tls/privkey.pem"

log:
  level: "info"

# Optional local outbounds for node-side routing. V2Board is not involved;
# outbound credentials live in this file, so keep it private (chmod 0600).
outbounds:
  - tag: "unlock"
    type: "vless"
    server: "203.0.113.10"
    port: 443
    user_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    udp: true
    tls:
      enabled: true
      sni: "unlock.example.com"
      allow_insecure: false
      # cert_file: "/etc/shoes/ca/unlock-ca.pem"
      alpn: ["h2", "http/1.1"]
    transport:
      type: "ws"
      path: "/unlock"
      host: "unlock.example.com"
  - tag: "socks-hop"
    type: "socks5"
    server: "127.0.0.1"
    port: 1080
  - tag: "via-socks"
    chain: ["socks-hop", "unlock"]
  - tag: "direct"
    type: "direct"

default_out: "direct"

# route_rules:
#   - "DOMAIN-SUFFIX,netflix.com,unlock"
#   - "MATCH,direct"

# rule_providers:
#   - tag: "netflix"
#     path: "/etc/shoes/rules/netflix.yaml"
#     reload_interval_secs: 300
```

## `v2board`

- `api_host`: V2Board panel base URL.
- `api_key`: V2Board `server_token`.
- `api_timeout_secs`: HTTP timeout.
- `error_body_limit_bytes`: max error body logged from panel failures.
- `user_list_body_limit_bytes`: max user list response size.
- `route_rule_sets`: optional local files for V2Board `geosite:`/`geoip:` route matchers. `geosite` files are plain text with one domain matcher per line: bare keyword, `keyword:`, `domain:`, `full:`, or `regexp:`. `geoip` files are plain text with one IP/CIDR matcher per line. Blank lines and lines starting with `#` are ignored.
- `nodes`: list of V2Board nodes managed by this process.

Each node:

- `tag`: unique runtime name.
- `node_id`: V2Board server ID.
- `node_type`: `shadowsocks`, `vmess`, `vless`, `trojan`, `anytls`, `tuic`, `hysteria`, `naiveproxy`, or `v2node`. The aliases `ss`, `v2ray`, `hysteria2`, and `naive` are accepted and normalized to `shadowsocks`, `vmess`, `hysteria`, and `naiveproxy`.
- `v2node` uses `/api/v2/server/config` for node settings and V1 UniProxy for users, traffic, and alive reporting. The runtime protocol is taken from the panel `protocol` field.
- Other V2Board models such as `mieru`, `mtproxy`, `trusttunnel`, and `wireguard` are not production-supported by this backend yet and are rejected during config parsing or sync.
- `listen`: local listen IP, default `0.0.0.0`.
- `api_host`, `api_key`: optional per-node override.
- `pull_interval_secs`, `push_interval_secs`: optional per-node override.
- `tls`: optional per-node TLS certificate files. This overrides top-level `tls`.
- `trojan_fallback`: optional `host:port` direct decoy destination for Trojan
  nodes. It must use a different port from the node listener. Malformed or
  unauthenticated TLS-decoded bytes are replayed there without creating a
  V2Board authenticated-user scope.
- `hysteria2_masquerade`: optional static HTTP/3 response for Hysteria2 ordinary
  and failed-auth requests. It accepts `status_code`, `content_type`, and
  `body`; `status_code` defaults to `404`, `content_type` defaults to
  `text/html; charset=utf-8`, and `body` is required. Informational and
  body-forbidden statuses are rejected, the content type is limited to 256
  bytes, and the body is limited to 64 KiB. It does not proxy requests to
  another server.

## `runtime`

- `data_dir`: stores `traffic-pending.json` plus owner-only MessagePack
  `v2board-lkg-<node-type>-<node-id>.mpk` last-known-good snapshots. Legacy
  `.json` snapshots are validated, migrated with read-back verification, and
  removed only after the `.mpk` replacement is durable.
  Snapshots are atomically replaced with mode `0600` on Unix and include
  credentials, so this directory must be private to the shoes service account.
  A validated snapshot is restored before the first panel request, allowing
  listeners to return after restart while V2Board is temporarily unavailable.
  Connection teardown synchronously persists newly recorded pending traffic
  for restart replay. Traffic accepted by V2Board `/push` is persisted as
  consumed before `/alive` is attempted, so an `/alive` failure does not replay
  already accepted traffic after restart.
- `pull_interval_secs`: local fallback config/user pull interval. V2Board `base_config.pull_interval` takes precedence after a node sync unless the node has `pull_interval_secs`.
- `push_interval_secs`: local fallback traffic/alive push interval. V2Board `base_config.push_interval` takes precedence after a node sync unless the node has `push_interval_secs`.
- `node_report_min_traffic`: local fallback for the minimum bytes before a user traffic record is pushed. V2Board `base_config.node_report_min_traffic` takes precedence after a node sync.
- `device_online_min_traffic`: local fallback for the minimum bytes in a push cycle before alive IPs are reported. V2Board `base_config.device_online_min_traffic` takes precedence after a node sync.
- `max_legacy_shadowsocks_users`: startup guard for legacy Shadowsocks multi-user authentication, which is O(n).
- `tcp_fast_open`: must remain `false`. It is reserved for future support and currently fails validation if enabled, so the runtime never silently starts without applying it.

## `tls`

- `cert_file`: PEM certificate chain used by TLS-enabled V2Board nodes.
- `key_file`: PEM private key used by TLS-enabled V2Board nodes.
- Node-level `v2board.nodes[].tls` overrides the global TLS files.
- Panel `tls_settings.cert_file` and `tls_settings.key_file` are also accepted when present.

## `log`

- `level`: `error`, `warn`, `info`, `debug`, `trace`, or `off`.
- `file`: optional log file path. `-l/--log-file` can add more destinations.

## `outbounds`

Optional local outbounds used for node-side routing. The panel is not
involved: outbounds, routes, and rule files live in the local YAML only.
Outbound credentials are stored in this file, so keep it private with mode
`0600` (same convention as the `runtime.data_dir` LKG snapshots) and never
log it.

Each outbound is a flat entry; `tag` is required and must be unique:

- `tag`: unique runtime name, referenced by `route_rules`, `default_out`,
  and other outbounds' `chain` lists.
- `chain`: optional list of outbound tags. When present, the outbound
  forwards through those hops and its `type`/`server`/credential fields are
  ignored. Every hop must be a configured outbound tag, chains must be
  non-empty, and cycles are rejected. Chain hops are assembled into the
  generic engine's `ClientChainHop` by the runtime; each leaf outbound
  converts to a single `ClientConfig`.
- `type`: `direct`, `http`, `socks`/`socks5`, `ss`/`shadowsocks`, `snell`,
  `vless`, `trojan`, `vmess`, `anytls`, `naive`/`naiveproxy`, `shadowtls`,
  or `ws`/`websocket` (the last is rejected: `ws` is a transport, not an
  outbound). A bare `- tag: direct` (no fields) is also accepted.
- `server`, `port`: upstream address. Required for every non-direct type.
- Credentials, required per type: `user_id` for `vless`/`vmess`;
  `cipher`+`password` for `ss`/`snell`; `password` for `trojan`/`anytls`;
  `username`+`password` for `naiveproxy`; `cipher`+`user_id` for `vmess`;
  `username`/`password` optional for `socks`/`http`. `shadowtls` uses
  `password` for both the ShadowTLS handshake secret and the inner
  Shadowsocks password, with `cipher` selecting the inner cipher.
  `snell` rejects `2022-blake3-*` ciphers. `ss` supports the legacy AEAD
  ciphers `aes-128-gcm`/`aes-192-gcm`/`aes-256-gcm`/`chacha20-ietf-poly1305`
  and the 2022 ciphers with a base64 `password`.
- `udp`: enable UDP forwarding where the protocol supports it; default
  `true` (no-op for `http`, `socks`, `trojan`, `naiveproxy`).
- `tls`: optional client TLS settings:
  - `enabled`: default is inferred. `trojan`, `anytls`, and `naiveproxy`
    imply TLS when `enabled` is absent (same rule as the inbound side);
    `vless`/`vmess` need an explicit `enabled: true` — a `transport` alone
    does not enable TLS.
  - `sni`: SNI hostname; defaults to the `server` hostname.
  - `allow_insecure`: skip server certificate verification; default `false`.
  - `cert_file`: PEM file with the private CA that signed the upstream
    server certificate. It is read and embedded in the client TLS config,
    so it must be readable (checked by `shoes validate`) and must be kept
    private. Do not reuse the server-side `tls.cert_file`/`key_file`
    (inbound certificate files) here — those are for the node listeners,
    not for outbound verification.
  - `alpn`: list of ALPN protocols, e.g. `["h2", "http/1.1"]`; default empty.
- `reality`: optional, `vless` only. `public_key` and `server_name` are
  required, `short_id` is optional hex (default all zeros) and is validated
  like the inbound Reality short ids. Reality replaces the TLS layer:
  combining it with `tls` or `transport` is rejected.
- `transport`: optional transport settings. Only `type: ws` is supported
  for now (`grpc`, `httpupgrade`, and `xhttp` are rejected by validate).
  `path` defaults to `/`; `host` is sent as the `Host` header.

Assembly order (flat YAML → generic engine nesting): credentials build the
inner protocol, then `reality` or `tls` wraps it, then `ws` wraps that —
`tls + ws + vless` becomes
`Websocket { protocol: Tls { protocol: Vless } }`.

## `default_out`

Optional fallback outbound tag used when no `route_rules` entry matches. It
must reference a configured outbound tag. When absent, behavior is
identical to today: direct. An explicit `MATCH` rule takes precedence over
`default_out` because rules are matched in order and `MATCH` is the last
resort of the rule list.

## `route_rules`

Optional CRS (Clash/sing-box style) one-liners, matched in order with
first match wins. Each line is
`<TYPE>,<value>[,<value>...],<outbound tag>`. Supported types: `DOMAIN-SUFFIX`,
`DOMAIN`, `DOMAIN-KEYWORD`, `DOMAIN-REGEX`, `IP-CIDR`, `IP-CIDR6`, `GEOSITE`,
`GEOIP`, `PROTOCOL` (sniffed `http`/`tls`/`bittorrent`/`ssh`/`quic`), and
`MATCH` (explicit catch-all with no value). `GEOSITE`/`GEOIP` reference the
`v2board.route_rule_sets` local files by label. Every line is parsed by
`shoes validate`; rule-set expansion and compilation happen at runtime, not
during validate.

## `rule_providers`

Optional external CRS rule files, hot-reloaded by mtime polling. Each entry:

- `tag`: unique provider name used in diagnostics.
- `path`: file containing one CRS one-liner per line. Must exist and parse;
  checked by `shoes validate` (via `check_provider_files`).
- `reload_interval_secs`: mtime poll interval; default `300`.

## Protocol Notes

`shoes validate` checks the local YAML shape and readable TLS files. Panel-driven protocol compatibility is checked during `sync-once` or `run`, after the V2Board node config and users have been fetched.

All support statements below describe inbound/server behavior. They do not claim that the corresponding outbound/client implementation is complete.

Supported V2Board transports are:

- TCP, including V2Ray TCP HTTP header obfuscation for non-TLS VMess/VLESS nodes.
- V2Ray HTTP transport for VMess/VLESS nodes. Plain nodes use HTTP/1.1; TLS and VLESS Reality nodes use HTTP/2 and automatically advertise ALPN `h2`. `host`, `Host`, `path`, `method`, and response `headers` are honored.
- XHTTP/splitHTTP transport for VMess/VLESS nodes. `network=xhttp` and `network=splithttp` are accepted. `path`, `host`/`Host`, and `mode` are honored; `mode` accepts `auto`, `packet-up`, `stream-up`, and `stream-one`. Server-relevant `extra` fields are honored for `noGRPCHeader`, `noSSEHeader`, `scMaxEachPostBytes`, `scMaxBufferedPosts`, `sessionIDPlacement`, `sessionIDKey`, `seqPlacement`, `seqKey`, `uplinkDataPlacement`, and `uplinkDataKey`. TLS and Reality XHTTP use HTTP/2 with ALPN `h2`. XHTTP over HTTP/3, xmux, client padding obfuscation, and `downloadSettings` are not server behavior switches in this runtime.
- WebSocket with strict server-side proxy framing. `path`, `headers`, `maxEarlyData`, and `earlyDataHeaderName` are honored. If V2Board omits early-data settings, shoes defaults to the sing-box subscription behavior: `maxEarlyData=2048` and `earlyDataHeaderName=Sec-WebSocket-Protocol`. The frame layer enforces client masking, RSV/opcode and canonical-length rules, fragmentation/control interleaving, streaming text UTF-8 validation, Ping/Pong payload behavior, and passive/active Close handshakes. Protocol errors use Close 1002 and invalid UTF-8 uses 1007. An external RFC 6455 conformance/fuzz run remains pending.
- HTTPUpgrade. `path`, `host`, and custom `headers` are honored. The handler expects a plain HTTP upgrade request with `Connection: upgrade` and `Upgrade: websocket`; real WebSocket handshakes with `Sec-WebSocket-Key` are rejected.
- gRPC over h2, single-stream mode only. `serviceName` and `authority` are honored. `multiMode` is rejected.
- TUIC over QUIC/UDP. V2Board V1 TUIC and V2Node `protocol=tuic` are accepted only as QUIC listeners with TLS and ALPN `h3`. Authenticated native-datagram operation is covered. Pre-authentication unidirectional task headers are paused with bounded parser state and no payload-sized allocation; a small payload prefix may remain as bounded parser lookahead, but nothing is forwarded before successful authentication. A real Quinn session-ticket test proves an accepted 0-RTT Packet is withheld before AUTH, delivered afterward, and not delivered after invalid AUTH.
- Hysteria2 over QUIC/UDP. V2Board V1 Hysteria nodes require `version=2`; V2Node requires `protocol=hysteria2`. Salamander and Gecko obfs are supported when `obfs_password` is present. An optional local static HTTP/3 masquerade can serve ordinary and failed-auth requests; reverse-proxy masquerade is not implemented. Hysteria1 is rejected.
- NaiveProxy over TCP/TLS HTTP/2 and QUIC/TLS HTTP/3. V2Board V1 `network=tcp` runs H2, V1 `enable_quic=1` starts the V2Board-compatible TCP+H3 dual-stack listener, and compatible V2Node `protocol=naive network=udp` payloads run pure H3. TCP ALPN is `h2`/`http/1.1`; H3 ALPN is `h3`. Padding is negotiated only when the client offers it; a missing header selects a normal unpadded CONNECT tunnel.
- `network_settings.acceptProxyProtocol=true` enables HAProxy PROXY protocol v1/v2 parsing before TLS, Reality, WebSocket, HTTPUpgrade, gRPC, or proxy authentication on TCP listeners. When enabled, every inbound connection must start with a valid PROXY header. The header source IP is used for V2Board `device_limit` and alive accounting. Only enable this listener behind a trusted load balancer or reverse proxy because clients that can connect directly can forge the source IP. TUIC and Hysteria2 reject this setting because their listeners are UDP/QUIC.

TLS is supported for VMess, VLESS, Trojan, AnyTLS, TUIC, Hysteria2, and NaiveProxy. Trojan, AnyTLS, TUIC, Hysteria2, and NaiveProxy are treated as TLS even when the panel payload omits a `tls` field. TLS certificates can come from top-level `tls`, per-node `v2board.nodes[].tls`, or panel `tls_settings.cert_file`/`key_file` when UniProxy exposes those fields. VMess, Trojan, V2Board V1 AnyTLS, V2Board V1 TUIC, V2Board V1 Hysteria2, and V2Board V1 NaiveProxy UniProxy payloads currently omit TLS certificate/ECH settings, so use local certificate files for those node types. Automatic certificate modes and TLS ECH are not implemented; use file/local certificate mode.

Trojan valid-user TCP/UDP proxying is supported. Because the current UniProxy
Trojan response does not expose a decoy destination, configure the optional
local `v2board.nodes[].trojan_fallback`. Malformed or unauthenticated traffic
after TLS is forwarded there with all already-read bytes preserved and without
creating V2Board traffic/alive state. Without this explicit setting, invalid
traffic remains fail-closed. The fallback bypasses V2Board outbound routing and
connects directly, and its port must differ from the Trojan listener port.

Reality inbound is supported for V2Board VLESS nodes when the panel provides `tls: reality` or `tls: 2`. Required production inputs are `private_key`, at least one hex `short_id`/`short_ids` value, and either `dest` or `server_name`/`server_port`. The `dest`/`server_name` target must be a hostname that resolves to a reachable TLS 1.3 handshake server. `reality_config.MaxTimeDiff` is honored when present, accepting millisecond numbers or Go-style duration strings such as `60s` and `1m30s`; otherwise the runtime uses the existing 60000 ms default. `xver`, ECH settings, and automatic certificate issuance modes are rejected. `public_key`, `fingerprint`, `server_names`, and Reality certificate file fields may be present in panel settings but are not used by the inbound builder. V2Board Trojan nodes do not expose Reality settings through UniProxy, so Trojan runs as TLS only in this backend.

VLESS Vision `xtls-rprx-vision` is supported only with plain TCP transport wrapped by TLS or Reality. VLESS ML-KEM encryption modes and non-empty `encryption_settings` are rejected.

Shadowsocks legacy AEAD supports V2Board Admin ciphers `aes-128-gcm`,
`aes-192-gcm`, `aes-256-gcm`, and `chacha20-ietf-poly1305`. It supports
multiple users by probing the first encrypted length chunk; this is O(n), so
`max_legacy_shadowsocks_users` is enforced at startup. Duplicate legacy user
credentials are rejected. Shadowsocks requires plain TCP transport; V2Node
Shadowsocks with `network=ws`, `grpc`, `http`, `httpupgrade`, or `xhttp` is
rejected.

For a V1 Shadowsocks node, shoes also fetches the strict schema-v1
`/UniProxy/plugin-config` manifest. `plugin: null` exposes raw Shadowsocks.
An active profile starts the loopback raw upstream and the public plugin edge
as one runtime generation. Supported in-process server adapters are
simple-obfs HTTP/TLS, v2ray-plugin WebSocket/WSS/HTTPUpgrade/Mux.Cool, GOST
WebSocket/WSS/smux, ShadowTLS v1/v2/v3, Restls, and Kcptun. TLS-enabled
v2ray/GOST adapters use the node or global local certificate files; plugin
secrets never belong in local YAML. See
`docs/v2board-shadowsocks-plugin-runtime.md`.

Shadowsocks 2022 multi-user is supported for `2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm`. The UniProxy config response must include a base64 `server_key`; official V2Board derives it from the node `created_at` value and does not require a local shoes setting. Per-user PSKs come from `link_secret`/`secret` when present; otherwise the runtime derives the same UUID-prefix fallback used by V2Board subscription builders. Duplicate 2022 user PSKs are rejected at sync time. `2022-blake3-chacha20-poly1305` is rejected for V2Board multi-user.

AnyTLS is supported for V2Board V1 UniProxy `v2_server_anytls` as TLS/raw TCP, and for V2Node AnyTLS as plain TCP with TLS or Reality. User passwords are the V2Board user UUIDs, matching V2Board subscription builders. Panel `padding_scheme` is honored. V2Node AnyTLS with WS/gRPC/HTTP/HTTPUpgrade/XHTTP transport is rejected because this runtime does not implement AnyTLS over V2Ray transports. Because the V1 AnyTLS table does not expose certificate, transport, or Reality settings, certificates must be supplied by local `tls` config.

TUIC is supported for V2Board V1 UniProxy `v2_server_tuic` and V2Node `protocol=tuic`. The runtime uses the V2Board user UUID as both TUIC UUID and password, matching V2Board subscription behavior. TUIC always listens on QUIC/UDP with TLS and ALPN `h3`; V2Board V1 TUIC nodes must provide certificates through top-level or per-node local `tls`, while V2Node TUIC can also use panel `tls_settings.cert_file`/`key_file` when present. With `zero_rtt_handshake`, non-AUTH unidirectional task headers received before authentication are kept with bounded parser state and no payload-sized allocation; a small payload prefix may remain as bounded parser lookahead, but nothing is forwarded before authentication. Tasks resume in the authenticated connection scope. A real Quinn session-ticket test verifies accepted 0-RTT Packet delivery across this boundary with a wire encoder independent from the server parser. Incomplete UDP fragments are limited to a 65,535-byte logical packet and a 4 MiB per-connection cache. `congestion_control` accepts `cubic`, `new_reno`/`newreno`/`reno`, and `bbr`; unknown values fail sync. The current local V2Board node config APIs omit `udp_relay_mode` even though subscription builders use it; authenticated native datagram operation is covered. `disable_sni`/`insecure` are client-side settings with no server-side effect. `network_settings.acceptProxyProtocol=true` is rejected for TUIC.

Hysteria2 is supported for V2Board V1 UniProxy `v2_server_hysteria` only when `version=2`, and for V2Node `protocol=hysteria2`. The runtime uses the V2Board user UUID as the Hysteria2 password, matching V2Board subscription behavior. Hysteria2 always listens on QUIC/UDP with TLS and ALPN `h3`; V2Board V1 Hysteria2 nodes must provide certificates through top-level or per-node local `tls`, while V2Node Hysteria2 can also use panel `tls_settings.cert_file`/`key_file` when present. Panel `up_mbps` limits server-to-client/user download traffic, and `down_mbps` limits client-to-server/user upload traffic; both use V2Board Mbps units and are shared across concurrent connections for the same local node. Hysteria2 `obfs=salamander` and `obfs=gecko` are supported for V1 Hysteria2 and V2Node Hysteria2 when `obfs_password` is present. Incomplete UDP fragments are limited to a 65,535-byte logical packet and a 4 MiB per-connection cache. Optional local `v2board.nodes[].hysteria2_masquerade` supplies a bounded static status/content-type/body response for ordinary and failed-auth H3 requests and can continue serving bounded requests for the connection lifetime; HEAD sends headers without a body, and body-forbidden response statuses are rejected. It is not a reverse proxy. Without that setting, the existing empty-404 authentication-window behavior remains. Hysteria1, unknown Hysteria2 obfs types, Reality, and PROXY protocol are rejected.

NaiveProxy is supported for V2Board V1 UniProxy `v2_server_naiveproxy` and compatible V2Node `protocol=naive` payloads. The runtime uses V2Board `/user` `username` and `password` when present, falling back to `user-<id>` and the user UUID to match the UniProxy payload. It listens behind TLS with HTTP/2 CONNECT or HTTP/3 CONNECT and applies V2Board speed limits, device limits, alive, route, and traffic accounting to authenticated streams. Padding is opt-in: no `padding` request header produces a normal unpadded tunnel and no padding response header, while a supported offered type enables Naive framing. Both padded and unpadded H2/H3 downloads pass the real V2Board Docker policy suite. V1 `quic_congestion_control` and V2Node `congestion_control` are honored for H3; accepted values are `cubic`, `reno`, `new_reno`, `bbr`, `bbr_standard`, `bbr2`, and `bbr2_variant`. QUIC congestion settings on TCP-only nodes, custom ALPN values outside the selected transport, Reality, and PROXY protocol on QUIC are rejected.

V2Board `v2node` is supported as a V2 config source for currently supported runtime protocols: VMess, VLESS, Shadowsocks, Trojan, AnyTLS, TUIC, Hysteria2, and NaiveProxy. This includes Reality when V2Board exposes `tls=2` through the V2 config payload. Users, traffic, alive, and device-limit behavior still use the V1 UniProxy endpoints with `node_type=v2node`.

Per-user `speed_limit` and `device_limit` come from the V2Board user API, not from the local YAML. `speed_limit` is the panel's effective value, including V2Board dynamic speed-limit rules after they are reflected by `/UniProxy/user`; it is interpreted as Mbps and enforced with a shared per-node/per-user token bucket with a short burst. `device_limit` counts currently connected distinct source IPs for that node/user and checks the V2Board `/alivelist` aggregate count cached for the same local node before admitting a new distinct local IP; `0` or missing means unlimited. V2Board does not expose `device_limit_mode` or per-user alive IP detail to UniProxy nodes, so cross-node admission follows the aggregate alive count returned by the panel. Nodes configured in the same process keep separate cached `/alivelist` views.

V2Board `route_id` rules are honored for `block`, `block_ip`, `block_port`, and `protocol`. Domain `block` supports keyword matchers, `domain:` suffix matchers, `full:` exact hostname matchers, `regexp:` hostname regex matchers, and configured `geosite:` local rule sets. `block_ip` supports IP/CIDR and configured `geoip:` local rule sets. `block_port` supports ports and inclusive ranges written as `start-end` or `start:end`. `protocol` supports TCP `http`, `tls`, `bittorrent`, and `ssh` first-payload sniffing, plus UDP `quic` first-datagram sniffing. `geosite:`/`geoip:` labels must be mapped under `v2board.route_rule_sets`; missing files or invalid entries fail sync. `dns`, `route`, `route_ip`, and `default_out` are rejected during sync because they require Xray outbound/DNS models that this backend does not expose.

V2Node `encryption_settings` is accepted only when empty (`{}`, `[]`, or
blank). Non-empty values are rejected for VMess, VLESS, Trojan, AnyTLS, TUIC,
Hysteria2, NaiveProxy, and Shadowsocks until each protocol's semantics are
implemented. V2Board Shadowsocks sing-mux/h2mux is enabled only by an
authoritative `multiplex.enabled=true` plugin manifest. Every logical stream
inherits the authenticated user and original peer address and passes through
the normal device, speed, routing, and traffic-accounting path. Padding is
strictly negotiated. TCP Brutal is rejected until its server scheduler is
implemented.

Unsupported panel fields fail during sync and the previous runtime is kept if one exists. Initial startup refuses to run if every configured node fails its first sync. Policy changes, user-state changes, and speed-limit changes apply to new connections after the next successful sync; already established connections are not force-disconnected.
