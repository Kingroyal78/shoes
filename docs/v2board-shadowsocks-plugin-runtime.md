# V2Board Shadowsocks Plugin Runtime

This document describes the server-side integration between shoes and the
V2Board Shadowsocks plugin runtime contract v1. It does not describe client
subscription generation.

## Control plane

For every `node_type: shadowsocks` entry, shoes uses the normal UniProxy
`config`, `user`, `push`, and `alive` endpoints and additionally calls:

```text
GET  /api/v1/server/UniProxy/plugin-config
POST /api/v1/server/UniProxy/status
```

The request uses the configured V2Board server token, node type, and node ID.
Production deployments must use HTTPS. Query strings contain the server token
and must not be written to access logs.

`plugin-config` is decoded with a strict schema-v1 allowlist. Unknown schema
versions, plugin types, fields, malformed secrets, invalid limits, and a
revision mismatch between `/config` and `/plugin-config` are rejected. ETags
are opaque and are returned in `If-None-Match` without normalization.

`plugin: null` is authoritative: shoes removes the old plugin edge and exposes
the raw Shadowsocks listener. A missing `plugin` field is invalid.

Status has an independent retry interval. A `ready: true` ACK is sent only
after the complete generation has bound its listeners, survived the readiness
gate, and become the committed runtime. HTTP 409 forces an unconditional
manifest refresh. A failed candidate keeps the prior applied revision and
runtime.

## Runtime topology

An active plugin profile is applied as one generation:

```text
public plugin listener
        │
        ▼
in-process plugin decoder
        │
        ▼
authenticated raw Shadowsocks handler

127.0.0.1:<server_port> ────────┘
```

The loopback raw listener and public plugin listener share the same raw
Shadowsocks handler and user table. The public edge calls the handler directly
after decoding, so the kernel peer address is retained for `device_limit`,
alive reporting, traffic accounting, and logs. Multiplexed plugin sessions
pass the same peer address to every logical stream.

The graph starts all listeners, checks that workers remain alive, and probes
TCP listeners before committing. A partial start is aborted. If a replacement
uses the same bind address, shoes stops the old generation, starts and probes
the candidate, and restores the exact previous graph if the candidate fails.

The applied server config, users, ETags, and exact plugin manifest are
atomically persisted under `runtime.data_dir` as
`v2board-lkg-<node-type>-<node-id>.json`. On Unix the file mode is `0600`.
Because this snapshot contains user and plugin credentials, the data directory
must be private to the shoes service account. A validated last-known-good
snapshot is restored before the first panel request after restart.

## Adapter matrix

| V2Board plugin | Server modes and effective options |
| --- | --- |
| `obfs` | simple-obfs `http` and `tls`; configured Host/SNI is validated |
| `v2ray-plugin` | WebSocket or WSS; HTTP Upgrade; Mux.Cool; `host`, `path`, `tls`, `mux`, `v2ray_http_upgrade` |
| `gost-plugin` | WebSocket or WSS; smux; `host`, `path`, `tls`, `mux` |
| `shadow-tls` | versions 1, 2, and 3; camouflage host is contacted on port 443; v2/v3 require `password` |
| `restls` | TLS 1.2/1.3 camouflage relay, authenticated record codec, fallback, and bounded Restls script execution |
| `kcptun` | UDP/KCP, legacy and AES-GCM packet protection, Reed-Solomon FEC, optional Snappy framing, smux v1/v2, mode/window/MTU/rate/DSCP/socket settings |

Plugin implementations are in-process Rust services. shoes does not spawn or
supervise external `obfs-server`, `v2ray-plugin`, `gost`, `shadow-tls`,
`restls`, or `kcptun` executables.

Two plugin intents the contract defines are deliberately not implemented here.
A `jls` manifest is rejected by name; shoes has no JLS listener and never
advertises `shadowsocks-plugin-jls-v1`. A Restls script outside the One/Shoes
v1-safe range (last record target above 16364, or more than 127 responses) is
rejected by name; the panel gates those Profiles on
`shadowsocks-plugin-restls-v2`, which shoes does not advertise. In both cases
the candidate is refused whole, the last-known-good runtime keeps serving, the
revision is not acknowledged, and the rejection reason names the cause instead
of reporting a generic schema failure.

For v2ray-plugin or GOST with `tls: true`, configure a readable certificate and
private key in the node-level or top-level local `tls` block. V2Board never
sends private certificate material through the plugin manifest.

ShadowTLS and Restls connect directly to the configured camouflage host on
port 443. Their authentication-failure path relays to that host without
creating an authenticated V2Board user scope.

Kcptun is the only UDP public plugin listener. Its raw Shadowsocks upstream
remains TCP loopback. Session, queue, buffer, packet, FEC, and idle limits are
bounded. Both panel values `smuxver: 1` and `smuxver: 2` are supported.

## Shadowsocks server multiplex

An authoritative manifest with `multiplex.enabled: true` enables sing-mux
H2MUX at the Shadowsocks magic destination. The server requires the client's
padding bit to match `multiplex.padding`. Each logical TCP or UDP stream enters
the normal authenticated setup-result path, so routing, device limits, user
speed limits, alive state, and upload/download accounting are preserved.

TCP Brutal is not silently ignored. A manifest with
`multiplex.brutal.enabled: true` fails candidate application and leaves the
last-known-good generation active until the scheduler is implemented.

## Operational checks

Before rollout:

1. Configure HTTPS between shoes and V2Board and redact query strings at every
   reverse proxy.
2. Make `runtime.data_dir` writable only by the shoes service account.
3. Configure local TLS files for WSS plugin profiles.
4. Ensure public TCP or UDP firewall rules match the plugin `listen_port`;
   never expose the raw loopback upstream.
5. Run `shoes validate`, then `shoes sync-once`.
6. Confirm V2Board records the exact `applied_revision`, runtime feature, and
   active adapter feature before publishing the node.
7. Run the complete external-client gate with an independently built official
   Mihomo binary:

   ```bash
   E2E_MIHOMO_BIN=/path/to/mihomo scripts/e2e_ss_plugins_mihomo.sh
   ```

   This exercises all 18 adapter/mode cases through a mock schema-v1 V2Board
   control plane, validates the readiness ACK/features, and compares a 512 KiB
   payload digest through the full Shadowsocks stack.
8. In staging, repeat a public-endpoint transfer against the real panel and
   confirm user traffic and alive-IP reports before general availability.

Never infer readiness from successful JSON parsing alone. The V2Board
publication gate must remain closed when shoes reports `ready: false`, an old
revision, or a feature set missing the exact active adapter.
