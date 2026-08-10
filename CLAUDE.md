# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`AGENTS.md` covers the local V2Board test workspace and E2E workflow; read it before running any
`scripts/v2board_e2e_*.sh`. This file focuses on build/test commands and the runtime architecture.

## Commands

Rust edition 2024; CI pins toolchain **1.95.0**. System build deps: `pkg-config cmake clang make`
(aws-lc-rs, quinn, smoltcp).

```bash
cargo build                                  # debug
cargo build --release --bin shoes            # release binary

cargo fmt -- --check                         # CI lint gate 1
cargo clippy --all-targets -- -D warnings    # CI lint gate 2

cargo test                                   # unit tests
cargo test <substring>                       # single test by name
cargo test --features e2e-client             # adds tests/tuic_0rtt_preauth.rs
cargo test --release --features e2e-client   # use if QUIC/H3 tests time out in debug
```

Several unit tests are *real* localhost network tests (QUIC/H3/TLS: TUIC 0-RTT,
Hysteria2 masquerade), so they bind ports and are timing-sensitive.

CLI (default config path `/etc/shoes/config.yml`):

```bash
shoes run       -c config.yml   # start controllers
shoes validate  -c config.yml   # strict parse, rejects unknown fields, checks TLS cert readability
shoes sync-once -c config.yml   # one pull+apply per node, no serving loop
```

Docker: `docker build -t shoes-v2board .`, then run with `--network host` (the panel owns the
listener ports).

E2E client/server helper binaries live in `src/bin/` behind the `e2e-client` feature;
`internal-bench` gates `benches/perf_baseline.rs` and the perf binaries.

### This checkout

Most of the tree is root-owned (`src/v2board/`, `docs/`, `config/`, `benches/`, `README.md`,
`Dockerfile`, and the repo root itself) and unreadable/unwritable as `admin`. Use `sudo` to read or
write those paths — the `Read`/`Edit`/`Write` tools will fail with `EACCES`. The sibling workspace
`AGENTS.md` describes (`/root/cate/{v2board,v2board-docker,sing-box}`) is not reachable here, so the
real panel E2E scripts cannot run in this environment.

## Architecture

### The control plane owns everything

This is not a config-driven proxy. The local YAML supplies only credentials and a node list; V2Board
supplies ports, ciphers, transports, TLS, users, and policy on every pull. Consequences that shape
the whole codebase: listeners are built at runtime rather than at startup, generations must be
swapped atomically under live traffic, and unknown panel fields must **fail closed** instead of being
ignored (`scripts/v2board_e2e_unsupported_options.sh` is the regression gate for that).

### Control loop

`src/main.rs` (CLI/logging/tokio runtime) → `src/app.rs`.

`app.rs` spawns one `NodeController` per `v2board.nodes[]` entry. Each controller owns independent
`pull` / `push` / plugin-`status` tickers whose intervals come from the panel's `base_config` and are
re-created in place when the panel changes them. Controllers are fully independent — a failing node
never blocks another. On startup a controller restores its last-known-good snapshot *before* it ever
contacts the panel, so a dead panel does not mean a dead node.

### Sync pipeline

```
client.rs          ETag-conditional GET /config, /user, /plugin-config (+ /alivelist when device_limit>0)
   ↓ types.rs      ServerConfig / UserInfo / BaseConfig
runtime_model.rs   normalize_node() → RuntimeNodeSpec  (panel dialect → protocol-neutral spec; rejects unsupported)
   ↓ mapper.rs     build_runtime_node() → RuntimeNode  (real handlers, TLS/Reality configs, QUIC endpoints)
runtime_graph.rs   RuntimeGraph → RuntimeGraphSlot::replace()
```

`RuntimeGraph` is one *generation*: possibly several listeners (e.g. the loopback raw-Shadowsocks
ingress plus the public plugin edge) treated as a single unit so a partially-started node is never
acknowledged. `RuntimeGraphSlot::replace` starts the candidate, waits a scheduling turn, checks no
worker died, runs a readiness probe per bind, and only then drains the old generation. When binds
overlap it must stop the old one first and restores the *exact* previous graph on failure.

Two ordering invariants in `NodeController::sync` (both have comments and tests — preserve them):

- ETags and cached payloads are committed only after the runtime replacement succeeds, so a bad
  candidate is re-fetched next pull instead of being masked by a 304.
- If the LKG persist fails, the committed validators are rolled back, so the on-disk recovery point
  cannot freeze indefinitely behind 304s.

### Users-only hot path (memory-critical)

A busy node's user list changes almost every pull. Rebuilding listeners for that leaks unboundedly:
every accepted connection holds an `Arc` to the handler that accepted it, so each superseded
generation stays resident until its last connection closes.

`src/shared_users.rs` + `src/v2board/user_tables.rs` fix this. `NodeUserTables` is created once per
node and handed to every generation; a user-list change becomes a pointer swap inside a container the
live listeners already hold (`refresh_node_users`, taken when `users_changed && !non_user_changed`).
**Invariant:** authentication must borrow the table only for the lookup (`SharedUsers::load`) and
copy out the matched credentials — holding that `Arc` for a connection's lifetime reintroduces the
exact retention this type exists to prevent.

### Accounting

`TrafficRecorder` is defined in `src/tcp/tcp_handler.rs` and implemented by
`src/v2board/tracker.rs`; protocol handlers depend on the trait, not the tracker. The tracker holds
pending traffic, alive-IP sets, and the panel `/alivelist` aggregate used for `device_limit`
admission. The push path drains a snapshot, and **restores it on failure** so nothing is lost; it
persists to `data_dir` (throttled on connection close, unconditionally each push). `reconcile_users`
/ `reconcile_speed_limiters` prune per-user state against panel truth on every apply.

### Shadowsocks plugin runtime

Plugin intent comes *only* from the versioned `/plugin-config` contract — never legacy `obfs` fields.
`plugin_api.rs` holds the strict manifest types (newtyped `ConfigRevision`/`OpaqueEtag`/
`SecretString`) and fails closed on unknown versions, types, fields, or incoherent revisions, leaving
the last-known-good generation live. `map_shadowsocks_plugin_nodes` cross-checks `/config` against
the manifest, then builds the multi-listener graph; the applied feature set is ACKed back via
`/plugin-config/status`, and a `RevisionMismatch` schedules a forced refresh. Adapters are in
`src/ss_plugins/` (obfs, v2ray, gost, shadow_tls, restls, kcptun, transport).

### Protocol layer

TCP-family protocols implement `TcpServerHandler` (`setup_server_stream[_with_peer_addr]` →
`TcpServerSetupResult`) and are composed as handler stacks (PROXY protocol → TLS/Reality →
WebSocket/HTTPUpgrade/gRPC/XHTTP → protocol → optional mux). QUIC-family protocols (TUIC,
Hysteria2, NaiveProxy H3) bypass that trait and appear as distinct `RuntimeNodeKind` variants in
`mapper.rs` holding their own `quinn` server config and user tables. Per-protocol modules:
`vless/`, `vmess/`, `anytls/`, `naiveproxy/`, `snell/`, `shadowsocks/`, `reality/`, `websocket/`,
`h2mux/`, `xudp/`, `uot/`, plus `trojan_handler.rs`, `tuic_server.rs`, `hysteria2_server.rs`.

### Two config surfaces — do not conflate

- `src/backend_config.rs` — **production**. `AppConfig` = the V2Board backend YAML (`v2board`,
  `runtime`, `tls`, `log`, `outbounds`, `route_rules`, `rule_providers`). Documented in `CONFIG.md`,
  example in `config/config.yml.example`, JSON Schema in `config/config.schema.json`.
- `src/config/` — the legacy generic-engine config types. Its *types* (`BindLocation`, `TcpConfig`,
  server/transport/rule types) are still the runtime vocabulary the mapper builds into, so the module
  is live even though the generic YAML entrypoint is not the production path. `examples/*.yaml` are
  legacy fixtures, not V2Board guidance.

### Production boundary

Only server-side behavior is in scope: inbound protocol handling, V2Board control plane, policy,
routing, accounting. Generic local-YAML clients, outbound proxy chaining, TUN, SOCKS/HTTP utility
listeners, and client-side H2MUX/AnyTLS are legacy surfaces — changes there are not production work.
`docs/v2board-runtime-support.md` is the acceptance matrix (claimed vs rejected);
`docs/v2board-alignment-audit.md` and `docs/v2board-server-remediation-plan.md` track open findings.

## Conventions and quirks

- `src/lib.rs` carries `#![allow(dead_code)]` because the lib crate shares code with the binary and
  the mobile FFI; server code looks unused in lib builds. `src/main.rs` re-declares the module tree.
- `#[cfg(feature = "internal-bench")]` flips several modules from private to `pub` — keep both arms
  in sync when adding modules.
- jemalloc is the global allocator except on MSVC/iOS/Android.
- Mobile (`src/ffi/`, `android/`, `scripts/build-{android,ios}.sh`) is a separate release surface;
  `mobile.yml` builds with `--locked` and cargo-ndk.
- `.gitignore` excludes root-level `/*.yaml`, so top-level YAML configs cannot be committed.
- Release artifacts are Linux-only (gnu/musl × x86_64/aarch64); tagged builds also push multi-arch
  GHCR images.
