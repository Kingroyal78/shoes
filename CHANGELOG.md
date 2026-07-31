# Changelog

> Product scope note: `shoes` is now documented and accepted as a dedicated
> V2Board node server. Historical entries below also describe the inherited
> generic local-YAML client/outbound, TUN, and utility-listener engine; those
> entries are release history, not current production support claims. See
> [README.md](README.md) and
> [docs/v2board-runtime-support.md](docs/v2board-runtime-support.md) for the
> current server-only support boundary.

## Unreleased

### V2Board Server Protocol Remediation

- NaiveProxy padding negotiation is now opt-in for both HTTP/2 and HTTP/3:
  ordinary CONNECT requests run unpadded, while supported client offers retain
  Naive padding. The real V2Board Docker policy suite covers padded and
  unpadded H2/H3 downloads.
- The server-side WebSocket binary proxy profile now validates RFC 6455 masking,
  RSV/opcodes, canonical lengths, fragmentation and control frames, Ping/Pong,
  streaming text UTF-8, and passive/active Close behavior. Invalid UTF-8 uses
  Close 1007. An external conformance/fuzz suite is still pending.
- TUIC pre-authentication unidirectional tasks are paused with bounded parser
  state and no payload-sized allocation, then resumed only inside the
  authenticated connection scope. Bounded parser lookahead may retain a small
  payload prefix, but no task is forwarded before authentication. Independent
  wire encoding plus a real Quinn session ticket verifies accepted 0-RTT,
  no pre-auth forwarding, post-auth delivery, and invalid-auth rejection.
- Trojan nodes can opt into a local direct fallback for malformed or
  unauthenticated TLS-decoded probes. Already-read bytes are preserved, invalid
  traffic does not create authenticated accounting state, and the fallback
  must use a different port from the listener. A real V2Board/TLS network E2E
  covers exact replay, fail-closed behavior, and accounting isolation.
- Hysteria2 nodes can opt into a bounded static HTTP/3 masquerade response.
  HEAD responses omit the body and body-forbidden statuses are rejected.
  A real TLS/QUIC/H3 test covers ordinary and failed-auth requests, repeated
  requests, the authentication window, and fresh-connection authentication.
  Reverse-proxy masquerade is not implemented.
- TUIC and Hysteria2 fragmented UDP reassembly now limits each logical packet
  to 65,535 bytes and each connection's incomplete-fragment cache to 4 MiB.
- Shadowsocks obfs remains deferred because the current V1 UniProxy response
  removes `obfs` and `obfs_settings`; implementation requires a V2Board
  control-plane contract first.

## v0.2.7

### Improvements

#### H2MUX Stability
- Added connection-level activity tracking that counts HTTP/2 control frames (PING, SETTINGS) as activity, ensuring keepalives properly reset idle detection
- Removed application-level idle timeout in favor of PING-based dead connection detection, matching sing-mux behavior for better compatibility
- Added drain timeout for graceful session shutdown
- Updated window sizes to match Go http2 defaults (256KB per stream, 1MB per connection)

#### AnyTLS Memory Leak Fixes
- Stream handler tasks are now tracked and aborted when session closes, preventing memory leaks from orphaned tasks
- Added 5-minute stream handler timeout to prevent hung streams (slow DNS, stuck connections) from leaking memory
- Reduced allocations in padding frame generation

#### TUN Connection Tracking
- Refactored TCP connection state machine with explicit states (Normal, Close, Closing, Closed) for proper lifecycle management
- Improved connection teardown handling following shadowsocks-rust patterns

## v0.2.6

### New Features

#### H2MUX (sing-box Compatible HTTP/2 Multiplexing)

H2MUX multiplexes multiple proxy streams over a single HTTP/2 connection, reducing connection overhead and improving performance for many concurrent streams. This is compatible with sing-box's h2mux implementation.

**Client configuration (VMess, VLESS, Trojan):**
```yaml
client_chain:
  address: "example.com:443"
  protocol:
    type: tls
    protocol:
      type: vmess
      cipher: aes-128-gcm
      user_id: "uuid"
      h2mux:
        max_connections: 4    # Maximum connections to maintain
        min_streams: 4        # Min streams before opening new connection
        max_streams: 0        # Max streams per connection (0 = unlimited)
        padding: true         # Enable padding for traffic obfuscation
```

**Server support:** H2MUX is auto-detected on the server side for VMess, VLESS, Trojan, Shadowsocks, and Snell protocols. No server configuration changes are needed.

#### H2MUX Client Compatibility

The Go H2MUX library contained a bug that prevents data upload from finishing successfully, see [https://github.com/SagerNet/sing-mux/pull/8](https://github.com/SagerNet/sing-mux/pull/8)

sing-box now contains this fix, but other clients (eg mihomo) that depend on sing-mux without this change can have issues.

#### DNS Resolution Timeout

DNS servers now support a configurable timeout to prevent hanging on unresponsive DNS servers.

```yaml
- dns_group: my-dns
  servers:
    - url: "tls://dns.example.com"
      timeout_secs: 10      # Default: 5. Set to 0 to disable.
```

### Improvements

- **DNS connection timeout**: DNS-over-TLS/HTTPS connections now respect a 5-second connection timeout, preventing hangs when DNS servers are unreachable
- **Reality server**: Improved shutdown handling with proper flush after every forward operation

## v0.2.5

### New Features

#### AnyTLS Protocol

**Server:**
```yaml
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: cert.pem
      key: key.pem
      protocol:
        type: anytls
        users:
          - name: user1
            password: secret123
        udp_enabled: true
        padding_scheme: ["stop=8", "0=30-30"]  # Optional custom padding
        fallback: "127.0.0.1:80"               # Optional fallback
```

**Client:**
```yaml
client_chain:
  address: "example.com:443"
  protocol:
    type: tls
    protocol:
      type: anytls
      password: secret123
```

#### NaiveProxy Protocol

**Server:**
```yaml
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: cert.pem
      key: key.pem
      alpn_protocols: ["h2"]
      protocol:
        type: naiveproxy
        users:
          - username: user1
            password: secret123
        padding: true
        fallback: "/var/www/html"  # Optional static file fallback
```

**Client:**
```yaml
client_chain:
  address: "example.com:443"
  protocol:
    type: tls
    alpn_protocols: ["h2"]
    protocol:
      type: naiveproxy
      username: user1
      password: secret123
```

#### Mixed Port (HTTP + SOCKS5)
Auto-detects HTTP or SOCKS5 protocol.

```yaml
- address: "0.0.0.0:7890"
  protocol:
    type: mixed
    username: user
    password: pass
    udp_enabled: true  # Enable SOCKS5 UDP ASSOCIATE
```

#### TUN/VPN Support
Layer 3 VPN mode using TUN devices for transparent proxying. Supports Linux, Android, and iOS.

```yaml
- device_name: "tun0"
  address: "10.0.0.1"
  netmask: "255.255.255.0"
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  icmp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "proxy.example.com:443"
        protocol:
          type: vless
          user_id: "uuid"
```

**Platform support:**
- Linux: Creates TUN device with specified name/address (requires root)
- Android: Use `device_fd` from `VpnService.Builder.establish()`
- iOS: Use `device_fd` from `NEPacketTunnelProvider.packetFlow`

#### SOCKS5 UDP ASSOCIATE
Full UDP support for SOCKS5 servers including UDP ASSOCIATE command. Enable with `udp_enabled: true` (default).

```yaml
protocol:
  type: socks
  udp_enabled: true  # Default: true
```

#### VLESS Fallback
Route failed authentication attempts to a fallback destination instead of rejecting them.

```yaml
protocol:
  type: vless
  user_id: "uuid"
  fallback: "127.0.0.1:80"  # Serve web content for invalid clients
```

#### Reality `dest_client_chain`
Route Reality fallback (dest) connections through a proxy chain.

```yaml
reality_targets:
  "www.example.com":
    private_key: "..."
    dest: "www.example.com:443"
    dest_client_chain:
      address: "proxy.example.com:1080"
      protocol:
        type: socks
    protocol:
      type: vless
      user_id: "uuid"
```

### Improvements

- **UDP routing**: Comprehensive rewrite of UDP session routing with better multiplexing support
- **Reality**: Improved active probing resistance with TLS 1.3 verification
- **Performance**: Optimized buffer handling and reduced allocations
- **QUIC**: Better buffer sizing based on quic-go recommendations

### Mobile Support

- **iOS FFI**: Added iOS bindings via `NEPacketTunnelProvider` integration
- **Android FFI**: Added Android bindings via `VpnService` integration
- Library now builds as `rlib`, `cdylib`, and `staticlib` for mobile embedding

---

## v0.2.1

## New Features

### Client Chaining (`client_chains`)
Multi-hop proxy chains with load balancing support. Traffic can now be routed through multiple proxies in sequence.

- **Multi-hop chains**: Route traffic through multiple proxies sequentially (e.g., `proxy1 -> proxy2 -> target`)
- **Round-robin chains**: Specify multiple chains and rotate between them for load distribution
- **Pool-based load balancing**: At each hop, use a pool of proxies for load balancing
- New config fields: `client_chain` (singular) and `client_chains` (multiple)
- See `examples/multi_hop_chain.yaml` for usage examples

### TUIC v5 Zero-RTT Handshake
New `zero_rtt_handshake` option for TUIC v5 servers enables 0-RTT (0.5-RTT for server) handshakes for faster connection establishment.

```yaml
protocol:
  type: tuic
  uuid: "..."
  password: "..."
  zero_rtt_handshake: true  # Default: false
```

Note: 0-RTT is vulnerable to replay attacks. Only enable if the latency benefit outweighs security concerns.

Current server-audit correction: non-authentication unidirectional task headers
received before TUIC authentication are paused with bounded parser state and
resumed only after successful authentication. A wire encoder independent of
the server parser now establishes a real Quinn session ticket, reconnects with
accepted early data, proves zero target forwarding before AUTH, verifies
delivery after AUTH, and verifies zero forwarding after invalid AUTH; see
[docs/v2board-alignment-audit.md](docs/v2board-alignment-audit.md).

### Reality Cipher Suites
Both Reality server and client now support specifying TLS 1.3 cipher suites.

```yaml
# Server
reality_targets:
  "example.com":
    cipher_suites: ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
    ...

# Client
protocol:
  type: reality
  cipher_suites: ["TLS_AES_256_GCM_SHA384"]
  ...
```

Valid values: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`

### Reality Client Version Control
Server-side Reality configuration can now restrict client versions:

```yaml
reality_targets:
  "example.com":
    min_client_version: [1, 8, 0]  # [major, minor, patch]
    max_client_version: [2, 0, 0]
    ...
```

## Deprecations

### `client_proxy` / `client_proxies` in Rules
The `client_proxy` and `client_proxies` fields in rule configurations are deprecated in favor of `client_chain` and `client_chains`.

**Migration**: Replace `client_proxy:` with `client_chain:` in your configuration files. The old fields still work but will emit a warning and may be removed in a future version.

Before:
```yaml
rules:
  - masks: "0.0.0.0/0"
    action: allow
    client_proxy: my-proxy-group
```

After:
```yaml
rules:
  - masks: "0.0.0.0/0"
    action: allow
    client_chain: my-proxy-group
```

### VMess `force_aead` / `aead` Fields
The `force_aead` and `aead` fields in VMess configuration are deprecated. AEAD mode is now always enabled, and non-AEAD (legacy) mode is no longer supported.

**Migration**: Remove `force_aead` and `aead` fields from your VMess configurations. They have no effect and will be ignored.

## Removed / Breaking Changes

### VMess Non-AEAD Mode Removed
VMess non-AEAD (legacy) mode is no longer supported. All VMess connections now use AEAD encryption exclusively. This improves security but breaks compatibility with very old VMess clients that don't support AEAD.

## Other Changes

- Hysteria2 and TUIC servers now have authentication timeouts (3 seconds by default) to prevent connection hogging
- Improved fragment packet handling with LRU cache eviction
- TUIC server now sends heartbeat packets to maintain connection liveness
