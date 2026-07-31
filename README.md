# shoes

`shoes` is a dedicated V2Board node server backend.

It talks to V2Board UniProxy APIs, pulls node configuration and users, starts local proxy listeners, records authenticated user traffic, and pushes traffic/alive data back to the panel.

The production acceptance boundary is server-side only: V2Board control-plane integration, inbound protocol handling, user policy, routing, and accounting. Generic local-YAML clients, outbound proxy chaining, TUN, SOCKS/HTTP utility listeners, and client-side H2MUX/AnyTLS behavior are legacy code surfaces and are not production claims of this backend.

## Supported Scope

Current backend API:

- `/api/v1/server/UniProxy/config`
- `/api/v1/server/UniProxy/user`
- `/api/v1/server/UniProxy/push`
- `/api/v1/server/UniProxy/alive`
- `/api/v1/server/UniProxy/plugin-config` and `/status` for the versioned
  Shadowsocks plugin runtime
- `/api/v2/server/config` for `v2node` configuration, with V1 UniProxy still used for users, traffic, and alive reporting.

Current node support:

- `vless`: TCP, V2Ray HTTP transport over plaintext HTTP/1.1, TLS HTTP/2, or Reality HTTP/2, XHTTP over TLS or Reality HTTP/2, strict server-side WebSocket binary framing, HTTPUpgrade, single-stream gRPC, optional TLS or Reality, multi-user
- `vmess`: TCP, V2Ray HTTP transport over plaintext HTTP/1.1 or TLS HTTP/2, XHTTP transport, TCP HTTP header obfuscation, strict server-side WebSocket binary framing, HTTPUpgrade, single-stream gRPC, optional TLS, AEAD, multi-user. Local config also accepts the V2Board alias `v2ray`.
- `trojan`: TCP, strict server-side WebSocket binary framing, HTTPUpgrade, single-stream gRPC over TLS, multi-user, and an optional local direct fallback for malformed or unauthenticated TLS-decoded probes
- `shadowsocks`: plain TCP legacy AEAD multi-user with startup threshold guard
  and Shadowsocks 2022 AES multi-user. The versioned V2Board plugin contract
  additionally drives in-process server adapters for simple-obfs HTTP/TLS,
  v2ray-plugin WebSocket/WSS/HTTPUpgrade/Mux.Cool, GOST
  WebSocket/WSS/smux, ShadowTLS v1/v2/v3, Restls, and Kcptun. Local config also
  accepts the alias `ss`.
- `anytls`: V2Board V1 UniProxy AnyTLS over TLS/raw TCP, multi-user, panel `padding_scheme`, V2Board user UUID as password.
- `tuic`: V2Board V1 UniProxy TUIC and V2Node `protocol=tuic` over QUIC/TLS, multi-user, V2Board user UUID as both TUIC UUID and password, ALPN `h3`, V2Board speed/device/alive/traffic accounting, and `cubic`/`new_reno`/`bbr` congestion control. Non-AUTH unidirectional task headers received before authentication are kept with bounded parser state, without payload-sized allocation or forwarding; a small payload prefix may remain as bounded parser lookahead. Tasks resume only inside the authenticated connection scope. Authenticated native-datagram operation and a real session-ticket/accepted-0-RTT QUIC-stream Packet are covered.
- `hysteria2`: V2Board V1 Hysteria `version=2` and V2Node `protocol=hysteria2` over QUIC/TLS, multi-user, V2Board user UUID as password, ALPN `h3`, panel `up_mbps/down_mbps`, Salamander and Gecko obfs, V2Board speed/device/alive/traffic accounting, and an optional bounded static HTTP/3 masquerade response for ordinary or failed-auth requests. Reverse-proxy masquerade is not implemented. Hysteria1 and unknown Hysteria2 obfs types are rejected.
- `naiveproxy`: V2Board V1 NaiveProxy over TCP/TLS HTTP/2 CONNECT and QUIC/TLS HTTP/3 CONNECT with optional NaiveProxy padding, multi-user username/password auth, V2Board speed/device/alive/traffic accounting. Requests without a `padding` offer use an ordinary unpadded CONNECT tunnel; padded clients negotiate only an offered supported padding type. V1 `enable_quic=1` starts the V2Board-compatible TCP+H3 dual-stack listener; V1 `quic_congestion_control` and V2Node `congestion_control` accept V2Board values, with `bbr_standard`/`bbr2`/`bbr2_variant` mapped to Quinn BBR. V2Node `protocol=naive` is supported for manually seeded, legacy, or future V2 payloads, including H3 user policy; the current local V2Board Admin validator does not expose `naive` as a V2Node protocol.
- `v2node`: V2 config source for supported VMess, VLESS, Shadowsocks, Trojan, AnyTLS, TUIC, Hysteria2, and compatible NaiveProxy payloads, including Reality where V2Board exposes it.

V2Board `network_settings.acceptProxyProtocol=true` is supported for TCP-based protocol tables and V2Node configs that expose `network_settings`. It parses HAProxy PROXY protocol v1/v2 before TLS, Reality, WebSocket, HTTPUpgrade, gRPC, or proxy authentication, and uses the header source IP for `device_limit` and alive accounting. Enable it only behind a trusted load balancer or reverse proxy. TUIC and Hysteria2 reject PROXY protocol because their listeners are QUIC/UDP.

Unsupported fields that reach shoes normally fail explicitly instead of being silently ignored. The following server features are not production-supported:

- QUIC transport for V2Board protocols other than TUIC, Hysteria2, and NaiveProxy H3
- VMess/VLESS unsupported networks such as KCP and domain socket when they reach UniProxy
- XHTTP invalid modes/placements, unsupported server-side advanced features such as `xmux`, `downloadSettings`, explicit `xPadding*`, `scStreamUpServerSecs`, `serverMaxHeaderBytes`, and XHTTP on non-VMess/VLESS protocols
- gRPC `multiMode`
- TCP Brutal inside the Shadowsocks server-multiplex profile; ordinary
  authenticated sing-mux/h2mux and its padding mode are supported
- TLS/Reality ECH, Reality `xver`, and automatic certificate issuance modes when UniProxy exposes them
- VLESS ML-KEM encryption modes and non-empty `encryption_settings`
- V2Node non-empty `encryption_settings` for protocols that do not implement those settings yet
- Shadowsocks 2022 `2022-blake3-chacha20-poly1305`
- Hysteria1 and unknown Hysteria2 obfs
- V2Board node families not yet wired into this runtime: MTProxy, Mieru, TrustTunnel, and WireGuard

Remaining inbound protocol evidence and feature limits:

- WebSocket now enforces the RFC 6455 server-side proxy profile: client masking, RSV/opcode and canonical-length rules, fragmentation/control interleaving, streaming UTF-8 validation for text messages, Ping/Pong payloads, and both passive and active Close handshakes. Protocol errors use Close 1002 and invalid UTF-8 uses 1007. Unit tests and the existing binary proxy E2E pass; an external RFC conformance/fuzz suite is still pending.
- TUIC pre-authentication task pause/resume is implemented with bounded parser state, no payload-sized pre-authentication allocation, and no forwarding before authentication. A real Quinn session ticket with accepted 0-RTT proves the early Packet is withheld before AUTH, delivered after AUTH, and never delivered after invalid AUTH; its wire encoder is independent of the server parser.
- NaiveProxy padded and unpadded H2/H3 downloads pass the real V2Board Docker policy suite.
- Trojan fallback is opt-in through local configuration, direct-only, and must use a different port from its node listener. A real V2Board/TLS network E2E verifies 16,541-byte exact probe replay, fail-closed behavior without fallback, and absence of user traffic/alive accounting.
- Hysteria2 supports an optional bounded static HTTP/3 masquerade response. A real TLS/QUIC/H3 test covers GET, HEAD, failed auth, durable requests, the authentication window, and successful auth on a fresh connection. It is not a reverse proxy.
- TUIC and Hysteria2 incomplete UDP fragments are bounded to a 65,535-byte logical packet and a 4 MiB per-connection fragment cache.

Shadowsocks plugin intent is read only from the strict, versioned
`plugin-config` endpoint. Legacy `/config` obfs fields are not used to infer a
plugin. Unknown schema versions, plugin types, fields, incoherent revisions,
and unsupported runtime combinations fail closed while the last-known-good
generation remains active.

Per-user `speed_limit` and `device_limit` from the V2Board user API are enforced for authenticated users. `device_limit` also consults the V2Board `/alivelist` aggregate count cached for that local node before admitting new distinct local IPs, so multiple nodes in one process do not overwrite each other's panel-side admission view. `speed_limit=0` and `device_limit=0` mean unlimited.

See [docs/v2board-runtime-support.md](docs/v2board-runtime-support.md) for the
server-side production acceptance matrix and
[docs/v2board-shadowsocks-plugin-runtime.md](docs/v2board-shadowsocks-plugin-runtime.md)
for the plugin lifecycle, exact option surface, and deployment requirements.
[docs/v2board-alignment-audit.md](docs/v2board-alignment-audit.md) records the
server-only audit boundary and open conformance findings.
Redistribution notices for protocol-derived code are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Run

```bash
shoes run -c /etc/shoes/config.yml
```

The default config path is `/etc/shoes/config.yml`.

Useful commands:

```bash
shoes validate -c config/config.yml.example
shoes sync-once -c /etc/shoes/config.yml
shoes --version
```

## Config

See [CONFIG.md](CONFIG.md) and [config/config.yml.example](config/config.yml.example).

The files under [examples](examples/README.md) are legacy generic-engine fixtures, not V2Board production guidance.

Minimum config:

```yaml
v2board:
  api_host: "http://127.0.0.1"
  api_key: "replace-with-v2board-server-token"
  nodes:
    - tag: "vless-1"
      node_id: 1
      node_type: "vless"
      listen: "0.0.0.0"
```

## Docker

Build:

```bash
docker build -t shoes-v2board .
```

Validate the bundled example config inside the image:

```bash
docker run --rm shoes-v2board validate -c /etc/shoes/config.yml.example
```

Run with a real production config mounted at `/etc/shoes/config.yml`:

```bash
docker run --rm \
  --network host \
  -v /etc/shoes/config.yml:/etc/shoes/config.yml:ro \
  -v shoes-data:/var/lib/shoes \
  shoes-v2board
```

Host networking is the simplest production mode because V2Board controls listener ports. If you do not use host networking, publish every panel-managed node port explicitly.

For local panel testing, run the sibling `v2board-docker` environment first,
then point `api_host` at a panel URL reachable from the container. The real E2E
scripts cover the server protocol and policy paths listed in
[docs/v2board-docker-e2e.md](docs/v2board-docker-e2e.md). Plugin tests must use
the versioned `plugin-config` contract rather than the obsolete legacy
`obfs`/`obfs_settings` fields.
