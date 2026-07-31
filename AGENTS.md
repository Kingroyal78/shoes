# AGENTS.md

`shoes` is a Rust V2Board node-server backend: it pulls node config/users from the
V2Board UniProxy + V2Node APIs, starts inbound listeners (VLESS/VMess/Trojan/
Shadowsocks/AnyTLS/TUIC/Hysteria2/NaiveProxy), and pushes traffic/alive data back.

## Workspace and local test env

Workspace layout at `/root/cate/` (sibling checkouts are used by scripts):
`shoes/` + `v2board/` (panel source, mounts into Docker) + `v2board-docker/`
(compose stack) + `sing-box/` (builds the `singlink` E2E client).

The local V2Board test panel is Docker, driven by `/root/cate/v2board-docker/docker-compose.yaml`.
Compose mounts `../v2board` panel code and `../v2board/.env`; stack is
`www` (panel, port 80), `mysql:5.7.29` (db `v2board`, root password `v2boardisbest`),
`redis:6`. It is currently running and healthy; panel URL is `http://127.0.0.1`.
E2E scripts reach Redis via container name `v2board-docker-redis-1`.

## Commands

- Build: `cargo build` / `cargo build --release --bin shoes`. Requires system
  `pkg-config cmake clang make` (aws-lc-rs, quinn, smoltcp). Edition 2024.
- CLI: `shoes run|validate|sync-once -c config.yml` (default config path
  `/etc/shoes/config.yml`). `validate` rejects unknown fields and checks that
  referenced TLS cert files are readable.
- Lint gate (CI): `cargo fmt -- --check` then `cargo clippy -- -D warnings`.
- Tests: `cargo test`. Some unit tests are real localhost network tests
  (QUIC/H3/TLS: TUIC 0-RTT, Hysteria2 masquerade). `cargo test --features e2e-client`
  additionally runs `tests/tuic_0rtt_preauth.rs`. Run
  `cargo test --release --features e2e-client` if QUIC tests time out in debug.
- Docker image: `docker build -t shoes-v2board .` then
  `docker run --rm --network host -v <config>:/etc/shoes/config.yml:ro shoes-v2board`.
  Use host networking for panel tests; the panel controls listener ports.
- E2E client helper binaries (used by matrix/naiveproxy/ss-obfs scripts) are
  gated behind the `e2e-client` feature in `src/bin/`.

## V2Board E2E testing (the important workflow)

- Entrypoint `scripts/selftest_v2board_core.sh` is intentionally conservative:
  by default it only runs `shoes validate`. Enable compose/sync with
  `SHOES_E2E_COMPOSE_UP=1`, `SHOES_E2E_SYNC_ONCE=1`.
- Real acceptance scripts are `scripts/v2board_e2e_*.sh`; `docs/v2board-docker-e2e.md`
  is the authoritative reference for which env vars/cases each needs. Read it
  before running any E2E.
- Most scripts seed V2Board fixture rows with reserved node/user ID ranges
  (per-script, e.g. VMess 9001/19001, matrix 9101–9492). They reset traffic and
  Redis hashes per run, keep fixtures by default, and clean up when
  `E2E_KEEP_FIXTURES=0`.
- If `SHOES_BIN` is unset, scripts rebuild `target/debug/shoes`. If `SINGLINK_BIN`
  is unset, the matrix script builds `singlink` from sibling `sing-box` with
  `-tags with_quic,with_utls`. Prebuilt binaries exist at `/tmp/singlink-e2e*`
  and `/tmp/mihomo-interop` (for `e2e_ss_plugins_mihomo.sh` and
  `v2board_e2e_ss_plugins.sh`).
- The real-panel Shadowsocks plugin gate `scripts/v2board_e2e_ss_plugins.sh`
  seeds `ss_client_settings` blobs via the panel's own `ShadowsocksClientProfileService`
  (`docker exec -e E2E_PROFILE_B64=… php artisan tinker`), expects the `plugin-config`
  manifest revision and ETag/304, checks the Redis capability status
  (`SERVER_SHADOWSOCKS_CAPABILITY_STATUS_<node_id>`), and verifies Mihomo payload
  digests plus `traffic:update` accounting. WSS uses the local self-signed cert;
  ShadowTLS/Restls camouflage uses a local `openssl s_server` on 127.0.0.1:443.
  Reserved node/user IDs are 9601–9618/19601–19618.
- Host deps beyond docker/compose: `python3-msgpack` (panel API checks),
  `shellcheck`, `openssl`, `ss`. Panel must be reachable at port 80.

## Production boundary (read before changing code)

Only server-side behavior is in scope: inbound protocol handling, V2Board control
plane/policy/routing/accounting. Generic local-YAML clients, outbound proxy
chaining, TUN, SOCKS/HTTP utility listeners, and client-side H2MUX/AnyTLS are
legacy surfaces — do not treat changes there as production work. See
`docs/v2board-alignment-audit.md` and `docs/v2board-runtime-support.md`
(acceptance matrix) for what is claimed vs rejected.

Core server code lives in `src/v2board/` (client.rs, mapper.rs, plugin_api.rs,
tracker.rs, lkg.rs, types.rs) plus per-protocol modules. `src/lib.rs` keeps
`#![allow(dead_code)]` because lib shares code with the binary and mobile FFI.

## Quirks

- jemalloc global allocator is compiled out for MSVC/iOS/Android targets.
- Mobile builds (`scripts/build-android.sh`, `scripts/build-ios.sh`, android/ dir)
  are a separate release surface; `mobile.yml` CI uses `--locked` and cargo-ndk.
- `.gitignore` excludes root-level `/*.yaml`; do not rely on committing top-level
  YAML configs.
- Shadowsocks plugin intent comes only from the versioned `plugin-config` contract,
  never legacy `obfs` fields (see `docs/v2board-shadowsocks-plugin-runtime.md`).
- `docs/v2board-server-remediation-plan.md` tracks open conformance findings.
- `examples/` are legacy generic-engine fixtures, not V2Board production config.
