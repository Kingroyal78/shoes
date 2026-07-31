# V2Board Docker E2E

`scripts/selftest_v2board_core.sh` is the local entrypoint for testing `shoes`
against the sibling V2Board docker checkout. It is intentionally conservative:
by default it checks the environment and runs `shoes validate` only. Compose
startup, panel sync, fixture seeding, and client matrix checks must be enabled
explicitly.

The real protocol acceptance scripts seed dedicated panel fixtures, start
`shoes`, start a real protocol client, send HTTP or HTTPS payload traffic
through the proxy, drain V2Board queues, and verify V2Board user/stat/server
traffic records. Most matrix/policy scripts use the sibling
`sing-box`/`singlink` client; NaiveProxy policy and VLESS/VMess XHTTP matrix
coverage use feature-gated shoes E2E clients where the local singlink build has
no matching outbound.

These clients are test drivers for the server. Their presence does not make
client/outbound protocol behavior part of the shoes production acceptance
boundary.

Use these scripts for production-oriented local联调:

| Script | Coverage |
| --- | --- |
| `scripts/e2e_ss_plugins_mihomo.sh` | Production plugin interoperability gate. It starts a schema-v1 mock V2Board control plane, verifies the exact readiness ACK/features, runs shoes as the server and an independently built official Mihomo process as the client, then compares a 512 KiB payload SHA-256 through simple-obfs HTTP/TLS; V2Ray WS/WSS, Mux.Cool and HTTP/HTTPS Upgrade; GOST WS/WSS and smux; ShadowTLS v1/v2/v3; Restls; and Kcptun smux v1/v2. |
| `scripts/v2board_e2e_ss_plugins.sh` | Real-panel Shadowsocks plugin gate. It seeds `v2_server_shadowsocks` fixtures whose `ss_client_settings` blobs are produced by the panel's own `ShadowsocksClientProfileService` (`sscp:v1:`), runs shoes against the live panel, verifies the `plugin-config` manifest revision plus ETag/304 and the exact readiness ACK/features through the Redis capability status, downloads a 512 KiB payload with an external Mihomo process over every plugin type (simple-obfs HTTP/TLS; V2Ray WS/WSS, Mux.Cool and HTTP/HTTPS Upgrade; GOST WS/WSS and smux; ShadowTLS v1/v2/v3; Restls; and Kcptun smux v1/v2), and verifies V2Board `v2_stat_user`/`v2_stat_server` accounting after `traffic:update`. WSS cases use the local self-signed certificate; ShadowTLS/Restls use a local `openssl s_server` camouflage on 127.0.0.1:443. |
| `scripts/v2board_e2e_vmess.sh` | Single VMess/TCP smoke path. |
| `scripts/v2board_e2e_matrix.sh` | 81-case default inbound matrix for VMess, VLESS, Shadowsocks, Trojan, AnyTLS, TUIC, Hysteria2, V2Node variants, transports, TLS/Reality/Vision, and PROXY protocol. The exact default list is authoritative in `E2E_MATRIX_CASES` inside the script. The historical raw `/config` `shadowsocks_obfs_http` case is quarantined because that endpoint intentionally returns null legacy obfs fields; it is not a plugin acceptance case. Plugin acceptance uses the versioned `plugin-config`/`status` contract and `scripts/e2e_ss_plugins_mihomo.sh`. WebSocket cases prove binary proxy payload interoperability but are not an external RFC 6455 conformance suite. The TUIC zero-RTT configuration case does not establish a session ticket and send a pre-authentication QUIC-stream Packet command. Trojan cases do not exercise the optional probe fallback, and Hysteria2 cases do not exercise the optional static ordinary-H3 masquerade. |
| `scripts/v2board_e2e_api_compat.sh` | UniProxy `/config` and `/user` API checks plus V2Node `/api/v2/server/config`: JSON schema, ETag/304, and msgpack user responses. |
| `scripts/v2board_e2e_policy.sh` | VMess policy checks for V1 VMess and V2Node VMess: per-user `speed_limit`, `device_limit`, and V2Board stat/user/server traffic rows, including `server_type=v2node` for V2Node cases. |
| `scripts/v2board_e2e_tuic_policy.sh` | TUIC policy checks for V1 TUIC and V2Node TUIC: wrong password records no traffic, per-user `speed_limit`, `device_limit`, and V2Board stat/user/server traffic rows. |
| `scripts/v2board_e2e_hysteria2_policy.sh` | Hysteria2 policy checks for V1 Hysteria2 and V2Node Hysteria2: wrong password records no traffic, per-user `speed_limit`, node `up_mbps/down_mbps`, Salamander and Gecko obfs, `device_limit`, and V2Board stat/user/server traffic rows. |
| `scripts/v2board_e2e_naiveproxy_policy.sh` | NaiveProxy TCP/TLS and QUIC/H3 policy checks in both padding-aware and `--no-padding` modes: padded and unpadded H2/H3 downloads, wrong password records no traffic, per-user `speed_limit`, `device_limit`, V1 `enable_quic=1` TCP+H3 dual-stack, V2Node `protocol=naive` TCP and UDP/H3 config through `/api/v2/server/config`, V2Node H3 `speed_limit`/`device_limit`, and V2Board stat/user/server traffic rows for both `naiveproxy` and `v2node` server types. |
| `scripts/v2board_e2e_trojan_fallback.sh` | Trojan fallback over a real V2Board-managed TLS listener: exact 16,541-byte TLS-decoded probe replay to a different-port decoy, fail-closed behavior without fallback, and absence of user traffic/stat/Redis/alive accounting. |
| `scripts/v2board_e2e_dynamic_speed.sh` | V2Board dynamic user `direct_limit`: effective `/user` speed and runtime speed enforcement. |
| `scripts/v2board_e2e_dynamic_speed_trigger.sh` | V2Board global dynamic speed trigger: real traffic push, queue drain, `traffic:update`, effective `/user` speed change, and same-process shoes hot-sync enforcement. |
| `scripts/v2board_e2e_dynamic_speed_rules.sh` | V2Board dynamic speed rule priority: global rule, plan override, user whitelist, user direct limit, and plan-rule runtime enforcement. |
| `scripts/v2board_e2e_traffic_accounting.sh` | V2Board node `rate != 1` accounting: user counters multiplied, stat rows raw. |
| `scripts/v2board_e2e_user_state.sh` | V2Board user filtering checks: expired, banned, traffic exhausted, and restored users. |
| `scripts/v2board_e2e_alive.sh` | V2Board alive push checks: `ALIVE_IP_USER_<uid>` cache and `/alivelist`. |
| `scripts/v2board_e2e_device_limit_mode.sh` | Cross-node V2Board `device_limit_mode` alive aggregation checks for mode `0` and `1`. |
| `scripts/v2board_e2e_global_device_limit.sh` | Global `/alivelist` device-limit admission check for new connections. |
| `scripts/v2board_e2e_parent_child_status.sh` | V2Board parent/child node operator status cache ownership and child-node traffic attribution. |
| `scripts/v2board_e2e_thresholds.sh` | V2Board `node_report_min_traffic` and `device_online_min_traffic` threshold behavior, including pending traffic flush. |
| `scripts/v2board_e2e_base_config_hot_update.sh` | Live V2Board `base_config.pull_interval`/`push_interval` hot update without restarting shoes. |
| `scripts/v2board_e2e_tls_sources.sh` | V1 VLESS and V2Node VLESS/TLS certificate source checks for panel `tls_settings.cert_file/key_file` and local per-node `nodes[].tls`. |
| `scripts/v2board_e2e_routes.sh` | V2Board `route_id` checks: domain keyword/regexp/geosite block, geoip/IP, single port, colon range port, protocol HTTP block through both `action=protocol` and `action=block` with `protocol:` matchers, plus sync failure for unsupported `route`, `dns`, `route_ip`, and `default_out` actions. |
| `scripts/v2board_e2e_xhttp_cors.sh` | V2Board VLESS/XHTTP HTTP/1 CORS preflight check for `OPTIONS`, Origin echo, requested method/header reflection, and `Access-Control-Allow-Credentials` when V2Board XHTTP cookie placement is enabled. |
| `scripts/v2board_e2e_unsupported_options.sh` | 44-case fail-closed matrix for unsupported panel options exposed by UniProxy or V2Node config. The historical `ss_unknown_obfs` raw-configuration case is quarantined because V1 UniProxy strips that legacy field before shoes can inspect it. The strict plugin manifest independently rejects unknown plugin types, schema versions, fields, and values. VMess/VLESS `domainsocket` is not in the default Docker run because this checkout's DB column rejects the value before shoes can sync it. |
| `scripts/v2board_e2e_pending.sh` | Pending `traffic-pending.json` replay into V2Board traffic/stat counters. |
| `scripts/v2board_e2e_reload_rollback.sh` | Runtime reload rollback when a changed panel node cannot bind its new listener. |
| `scripts/v2board_e2e_tuic_reload_rollback.sh` | TUIC UDP reload rollback when a changed panel node cannot bind its new QUIC listener. |

## Workspace

The default layout is:

```text
/root/cate/
  shoes/
  v2board/
  v2board-docker/
  sing-box/
```

The script verifies the sibling checkout and its compose file:

```text
/root/cate/v2board-docker/docker-compose.yaml
```

Host dependencies used by the full suite include `docker`, `curl`, `python3`,
Python `msgpack` (`apt-get install python3-msgpack` on Debian), `shellcheck`,
`openssl`, `ss`, Cargo/Rust, and Go when `SINGLINK_BIN` is not prebuilt.

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `V2BOARD_DOCKER_DIR` | `../v2board-docker` | Sibling checkout; expected as `/root/cate/v2board-docker` in this workspace. |
| `V2BOARD_COMPOSE_FILE` | `$V2BOARD_DOCKER_DIR/docker-compose.yaml` | Compose file used when compose startup is enabled. |
| `V2BOARD_PANEL_URL` | `http://127.0.0.1` | URL probed after optional compose startup. |
| `SHOES_CONFIG` | `config/config.yml.example` | Config passed to `validate` and `sync-once`. |
| `SHOES_BIN` | unset | Optional prebuilt `shoes` binary. If unset, V2Board E2E scripts build `target/debug/shoes` from the current source before running. |
| `SINGLINK_BIN` | unset | Optional prebuilt `singlink/sing-box` binary for `v2board_e2e_matrix.sh`. TUIC and Hysteria2 cases require `with_quic`; Reality cases require `with_utls`. If unset, the matrix script builds one from the sibling checkout. |
| `SINGLINK_BUILD_TAGS` | `with_quic,with_utls` | Build tags used by `v2board_e2e_matrix.sh` when `SINGLINK_BIN` is unset. |
| `E2E_SS_OBFS_CLIENT_BIN` | `target/debug/shoes-ss-obfs-e2e-client` | Optional prebuilt Shadowsocks simple-obfs E2E client. If unset, `v2board_e2e_matrix.sh` builds it with `--features e2e-client`. |
| `E2E_MIHOMO_BIN` | `/tmp/mihomo-interop` | Independently built official Mihomo binary used by `e2e_ss_plugins_mihomo.sh`. |
| `E2E_MIHOMO_SOURCE` | unset | Official Mihomo checkout to build when `E2E_MIHOMO_BIN` is absent. Keep the checkout outside this repository; the test runner does not copy its GPL source. |
| `E2E_SS_PLUGIN_CASES` | 18-case comma-separated list defined in `e2e_ss_plugins_mihomo.sh` and `v2board_e2e_ss_plugins.sh` | Override the plugin interoperability cases. Keep the scripts as the authoritative list. The real-panel script uses reserved node/user IDs 9601–9618/19601–19618 with plugin ports 18701–18718. |
| `E2E_PAYLOAD_SIZE` | `524288` | Payload bytes downloaded and hashed in every plugin interoperability case. |
| `E2E_CAMOUFLAGE_HOST` | `127.0.0.1` | ShadowTLS/Restls camouflage host for the local interoperability fixture. |
| `E2E_KEEP_TMP` | `0` | Preserve plugin interoperability logs, configs, payloads, and LKG files on failure analysis when set to `1`. |
| `E2E_RESTLS_SCRIPT` | unset | Optional `restls-script` value passed to Mihomo for the real-panel Restls case; empty means no script in the seeded profile. |
| `E2E_NAIVE_CLIENT_BIN` | `target/debug/shoes-naiveproxy-e2e-client` | Optional prebuilt NaiveProxy E2E client. If unset, `v2board_e2e_naiveproxy_policy.sh` builds it with `--features e2e-client`. |
| `E2E_XHTTP_CLIENT_BIN` | `target/debug/shoes-vless-xhttp-e2e-client` | Optional prebuilt VLESS/VMess XHTTP TLS/Reality E2E client. If unset, `v2board_e2e_matrix.sh` builds it with `--features e2e-client`. |
| `SHOES_E2E_RELEASE` | `0` | Use `cargo run --release --bin shoes` in `selftest_v2board_core.sh` when `SHOES_BIN` is unset. |
| `SHOES_E2E_COMPOSE_UP` | `0` | Run `docker compose up -d` before checks. |
| `SHOES_E2E_COMPOSE_DOWN` | `0` | If this script started compose, run `docker compose down` on exit. |
| `SHOES_E2E_WAIT_FOR_PANEL` | `$SHOES_E2E_COMPOSE_UP` | Probe `V2BOARD_PANEL_URL` before running shoes commands. |
| `SHOES_E2E_PANEL_TIMEOUT_SECS` | `120` | Readiness probe timeout. |
| `SHOES_E2E_VALIDATE` | `1` | Run `shoes validate -c "$SHOES_CONFIG"`. |
| `SHOES_E2E_SYNC_ONCE` | `$SHOES_SYNC_ONCE` or `0` | Run `shoes sync-once -c "$SHOES_CONFIG"`. |
| `SHOES_SYNC_ONCE` | unset | Legacy alias for `SHOES_E2E_SYNC_ONCE`. |
| `SHOES_E2E_SEED` | `0` | Reserved panel fixture hook. Enabling it currently fails with a clear message. |
| `SHOES_E2E_CLIENT_MATRIX` | `0` | Reserved client matrix hook. Enabling it currently fails with a clear message. |
| `SHOES_E2E_NODE_MATRIX` | `vless,vmess,trojan,shadowsocks,anytls,tuic,hysteria,v2node` | Reserved node/protocol matrix list. |
| `SHOES_E2E_CLIENT_MATRIX_LIST` | `sing-box,xray,clash-meta` | Reserved client implementation list. |
| `V2BOARD_REDIS_CONTAINER` | `v2board-docker-redis-1` | Redis container used by the real E2E scripts to clear traffic hash fields. |
| `E2E_MATRIX_CASES` | 81-case comma-separated list defined in `v2board_e2e_matrix.sh` | Override the default inbound protocol matrix. Keep the script as the authoritative list to avoid documentation drift. |
| `E2E_UNSUPPORTED_CASES` | 44-case comma-separated list defined in `v2board_e2e_unsupported_options.sh` | Override the default fail-closed matrix. |
| `E2E_REALITY_DEST_PORT` | `18097` | Local TLS 1.3 camouflage target used by VLESS Reality cases. |
| `E2E_HTTPS_PORT` | `18098` | Local HTTPS payload target used by Vision cases to exercise TLS-in-TLS traffic. |
| `E2E_KEEP_FIXTURES` | `1` | Keep seeded rows by default. Set `0` to remove rows matching the E2E email/name prefixes. |
| `E2E_CURL_MAX_TIME_SECS` | `45` or `60` | Total curl timeout for matrix/policy client requests. |

## Examples

Current server-audit baseline:

- `v2board_e2e_matrix.sh`: the raw `/config` `shadowsocks_obfs_http` case is a
  quarantined legacy-contract check. It has been superseded by the versioned
  plugin manifest and must not be counted as plugin acceptance evidence.
- `v2board_e2e_unsupported_options.sh`: `ss_unknown_obfs` is the matching
  quarantined legacy-field check. Unknown plugin intent is rejected by the
  strict `plugin-config` decoder instead.
- `v2board_e2e_naiveproxy_policy.sh`: passes padded and unpadded H2/H3 download
  and policy cases.
- Focused unit tests cover strict WebSocket binary framing and bounded TUIC
  pre-authentication pause/resume. A separate Rust network test establishes a
  real Quinn ticket and accepted 0-RTT Packet; the Docker suites themselves are
  not an external RFC 6455 conformance run.
- `v2board_e2e_trojan_fallback.sh` passes its dedicated V2Board/TLS fallback
  network case.
- Hysteria2 static masquerade has a real TLS/QUIC/H3 Rust network test; it is
  not yet a separate Docker script.

Validate only:

```bash
scripts/selftest_v2board_core.sh
```

Start the sibling V2Board compose stack, wait for the panel, then validate:

```bash
SHOES_E2E_COMPOSE_UP=1 scripts/selftest_v2board_core.sh
```

Run a single panel sync with a real local config:

```bash
SHOES_CONFIG=/tmp/shoes-v2board.yml \
SHOES_E2E_SYNC_ONCE=1 \
scripts/selftest_v2board_core.sh
```

Use a prebuilt binary instead of `cargo run --bin shoes`:

```bash
SHOES_BIN=target/debug/shoes scripts/selftest_v2board_core.sh
```

Validate the Docker image's bundled example config:

```bash
docker build -t shoes-v2board .
docker run --rm shoes-v2board validate -c /etc/shoes/config.yml.example
```

Run the real VMess/TCP local E2E:

```bash
scripts/v2board_e2e_vmess.sh
```

Run the default production protocol matrix:

```bash
SINGLINK_BIN=/tmp/singlink-e2e-quic-utls \
scripts/v2board_e2e_matrix.sh
```

When `SHOES_BIN` is unset, V2Board E2E scripts rebuild `target/debug/shoes` from the current checkout before running. When `E2E_SS_OBFS_CLIENT_BIN` or `E2E_XHTTP_CLIENT_BIN` are unset, the matrix script rebuilds those helper binaries as well. Set these binary variables only when intentionally testing prebuilt artifacts.

If `SINGLINK_BIN` is omitted, the matrix script builds `singlink` from the sibling `sing-box` checkout with `SINGLINK_BUILD_TAGS=with_quic,with_utls`. Use the same tags when providing a prebuilt binary for the default TUIC, Hysteria2, and Reality cases:

```bash
go -C ../sing-box build -tags with_quic,with_utls -o /tmp/singlink-e2e-quic-utls ./cmd/singlink
```

Run the policy checks:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e \
scripts/v2board_e2e_policy.sh
```

Run the TUIC policy checks:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e-quic \
scripts/v2board_e2e_tuic_policy.sh
```

Run the Hysteria2 policy checks:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e-quic \
scripts/v2board_e2e_hysteria2_policy.sh
```

Run the NaiveProxy policy checks:

```bash
SHOES_BIN=target/debug/shoes \
scripts/v2board_e2e_naiveproxy_policy.sh
```

Run the dynamic speed-limit check:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e \
scripts/v2board_e2e_dynamic_speed.sh
```

Run the traffic-triggered dynamic speed-limit check:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e \
E2E_KEEP_FIXTURES=0 \
scripts/v2board_e2e_dynamic_speed_trigger.sh
```

Run the dynamic speed-limit rule priority check:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e \
E2E_KEEP_FIXTURES=0 \
scripts/v2board_e2e_dynamic_speed_rules.sh
```

Run the traffic accounting check:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e \
scripts/v2board_e2e_traffic_accounting.sh
```

Run the UniProxy API compatibility checks:

```bash
PYTHONPATH=/usr/lib/python3/dist-packages/pip/_vendor \
E2E_KEEP_FIXTURES=0 \
scripts/v2board_e2e_api_compat.sh
```

Run the user-state reload checks:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e \
scripts/v2board_e2e_user_state.sh
```

Run the alive cache checks:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e \
scripts/v2board_e2e_alive.sh
```

Run the cross-node device-limit-mode checks:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e \
scripts/v2board_e2e_device_limit_mode.sh
```

Run the global device-limit admission check:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e \
scripts/v2board_e2e_global_device_limit.sh
```

Run the parent/child status cache checks:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e \
scripts/v2board_e2e_parent_child_status.sh
```

Run the V2Board reporting threshold checks:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e \
scripts/v2board_e2e_thresholds.sh
```

Run the live V2Board base_config interval hot-update check:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e \
scripts/v2board_e2e_base_config_hot_update.sh
```

Run the TLS certificate source checks:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e-utls \
scripts/v2board_e2e_tls_sources.sh
```

Run the V2Board route checks:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e \
scripts/v2board_e2e_routes.sh
```

Run unsupported panel option rejection checks:

```bash
SHOES_BIN=target/debug/shoes \
E2E_KEEP_FIXTURES=0 \
scripts/v2board_e2e_unsupported_options.sh
```

Run the pending traffic replay check:

```bash
SHOES_BIN=target/debug/shoes \
scripts/v2board_e2e_pending.sh
```

Run the reload rollback check:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e \
scripts/v2board_e2e_reload_rollback.sh
```

Run the TUIC UDP reload rollback check:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e-quic \
scripts/v2board_e2e_tuic_reload_rollback.sh
```

Use already built binaries:

```bash
SHOES_BIN=target/debug/shoes \
SINGLINK_BIN=/tmp/singlink-e2e \
scripts/v2board_e2e_vmess.sh
```

The VMess E2E script defaults to:

| Fixture | Value |
| --- | --- |
| V2Board node | `v2_server_vmess.id=9001` |
| V2Board user | `v2_user.id=19001` |
| shoes listen | `127.0.0.1:18081` |
| singlink mixed inbound | `127.0.0.1:18082` |
| local HTTP target | `127.0.0.1:18083` |

The matrix script uses dedicated node/user IDs in the `9101`-`9492` and
`19101`-`19492` ranges, with some intentionally sparse IDs to avoid conflicts
with protocol-specific policy scripts.
Each matrix case writes an isolated
V2Board group with the same ID as its node, so kept fixtures do not pollute
later Shadowsocks 2022 user-key checks.
Vision cases download through a local HTTPS payload target on `E2E_HTTPS_PORT`
so the VLESS Vision stream sees TLS-in-TLS traffic. Reality cases use a
separate local TLS 1.3 camouflage target on `E2E_REALITY_DEST_PORT`; this target
must be distinct because a valid Reality handshake intentionally drops the
camouflage connection after sampling TLS records.
The policy script uses node IDs `9501`, `9502` and user IDs `19501`, `19502`.
The TUIC policy script uses node/user IDs `9551`-`9553`/`19551`-`19553` for V1
TUIC and `9651`-`9652`/`19651`-`19652` for V2Node TUIC.
The Hysteria2 policy script uses node/user IDs `9561`-`9569`/`19561`-`19569`
for V1/V2Node transport coverage and `9661`-`9662`/`19661`-`19662` for V2Node
user policy cases.
The NaiveProxy policy script uses node/user IDs `9571`-`9577`/`19571`-`19577`
for V1 and V2Node transport coverage and `9671`-`9672`/`19671`-`19672` for
V2Node H3 user policy cases.
The user-state script uses node ID `9601` and user ID `19601`.
The alive script uses node ID `9701` and user ID `19701`.
The device-limit-mode script uses nodes `9702`, `9703` and user `19702`.
The pending replay script uses node/user IDs `9801`/`19801`.
The reload rollback script uses node/user IDs `9802`/`19802`.
The TUIC reload rollback script uses node/user IDs `9554`/`19554`.
The API compatibility script uses node/user IDs `9901`/`19901`.
The TLS source script uses node/user IDs `9902`/`19902` and `9903`/`19903`.
The route script uses node/user IDs `9904`/`19904` and route IDs `9904`-`9906`.
The traffic accounting script uses node/user IDs `9907`/`19907`.
The dynamic speed script uses node/user IDs `9908`/`19908`.
The dynamic speed trigger script uses node/user IDs `9915`/`19915`.
The dynamic speed rules script uses node `9916`, plan `9916`, and users
`19916`-`19919`.
The parent/child status script uses parent node `9909`, child node `9910`,
and user `19909`.
The thresholds script uses node/user IDs `9911`/`19911`.

The scripts reset dedicated user traffic, matching stat rows, and Redis traffic
hash fields before each run, then keep the node/user fixtures by default for
repeatability. Set `E2E_KEEP_FIXTURES=0` to remove rows matching the E2E
email/name prefixes after the run. On failure, temporary logs are kept under
`/tmp/shoes-v2board-*-e2e.*`.

Run the container against a real local panel config:

```bash
docker run --rm \
  --network host \
  -v /etc/shoes/config.yml:/etc/shoes/config.yml:ro \
  -v shoes-data:/var/lib/shoes \
  shoes-v2board
```

Use host networking for local E2E unless the test config publishes every
panel-managed node port explicitly.

## Reserved Hooks

`seed_panel_matrix()` and `run_client_matrix()` are present in the entrypoint so
future work can add panel fixture setup and client compatibility checks without
changing the test interface. They are disabled by default and fail intentionally
when enabled until their implementations are added.

Until those hooks are implemented, `SHOES_E2E_SYNC_ONCE=1` verifies only that the
current panel data can be fetched and mapped into a runtime node. It does not
open client connections or prove protocol interoperability.

Use the real E2E scripts above for protocol and policy interoperability. The
reserved hooks remain only for the lightweight `selftest_v2board_core.sh`
entrypoint.
