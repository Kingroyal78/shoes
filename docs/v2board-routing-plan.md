# V2Board Node Outbound Routing Plan

Status: plan (M0). Target: production-facing outbound routing for the shoes
V2Board node backend, mirroring xray/sing-box routing semantics while keeping
the existing V2Board contract intact.

## Background

Node servers are blocked by many websites (streaming, bot protection, CDN
geofences) when their IP is a known datacenter range. The operator needs the
node to send some destinations through an upstream proxy (unlock node) while
keeping everything else direct, without involving the panel: outbounds and
rules live in the local config file.

## Existing facts (verified in current code)

- Full client (outbound) protocol stack exists and is shared code, not legacy
  dead weight: `ClientProxyConfig` (`src/config/types/client.rs:311`,
  `#[serde(tag = "type", rename_all = "lowercase")]`) supports `direct`, `http`,
  `socks`/`socks5`, `shadowsocks` (legacy AEAD + 2022), `snell`, `vless`,
  `trojan`, `vmess`, `reality` (wrapping inner protocol), `shadowtls`,
  `tls` (wrapping inner protocol), `websocket`/`ws`, `portforward`, `anytls`,
  `naiveproxy`. Chaining is expressed by nesting `protocol: Box<ClientProxyConfig>`
  (reality/shadowtls/tls/ws wrap the inner protocol).
- `src/tcp/chain_builder.rs` already builds `ClientProxyChain` (multi-hop) and
  `ClientChainGroup` (round-robin groups); `src/tcp/socket_connector_impl.rs` /
  `proxy_connector_impl.rs` provide pooled socket+protocol connectors with
  UDP-over-TCP support (`InitialHopEntry::supports_udp`).
- `src/client_proxy_selector.rs` implements the rule engine used by every
  inbound handler: `ConnectMatcher` variants `Location(NetLocationMask)` (IP/CIDR),
  `DomainKeyword`, `DomainFull`, `DomainSuffix`, `DomainRegex`, `Protocol(SniffedProtocol)`
  (http/tls/bittorrent/ssh/quic sniffing), with LRU decision cache.
  `ConnectDecision::Allow { chain_group, remote_location }` / `Block` already
  exists; the V2Board path ignores `chain_group` today.
- Rule semantics (verified in `match_rule`): matchers inside one rule are OR;
  rules are matched in order, first match wins. CRS rules are single-matcher,
  so they are order-preserving by construction.
- `src/dns/` has a full resolver stack: hickory-backed caching resolver,
  composite resolver, parsed DNS config, and `proxy_runtime.rs` (DNS through a
  proxy) — reusable as-is.
- Existing local rule-set files (`v2board.route_rule_sets` geosite/geoip) are
  plain text, one matcher per line (`keyword:`/`domain:`/`full:`/`regexp:`;
  IP/CIDR) — plain text is already the project's rule-set format.
- Every inbound handler dials the destination with a bare TCP/UDP connect
  (e.g. `vless_server_handler.rs:159`, `anytls_server_handler.rs:292`); there
  is no outbound abstraction on the node path.

## Decisions

1. **Rule-set format: CRS (Clash/sing-box textual rules), not xray geosite dat.**
   Performance facts: xray matches a geosite category by linearly scanning its
   entry list with suffix comparison — O(category size × name length); a CRS
   rule compiles into a deterministic structure (domain suffix set → reversed
   domain trie O(name length); IP CIDR → radix tree O(32/128 bits)) that is
   independent of rule count. CRS also gives exact single-rule granularity,
   per-file hot reload (mtime), and needs no protobuf/binary toolchain.
   `GEOSITE,<name>` keeps working with the existing plain-text category files
   and compiles into the same trie.
2. **Outbounds reuse the existing client protocol stack** (see facts above).
   Zero new protocol implementations. The config layer is new; the dial layer
   is `ClientChainGroup` already built by `chain_builder.rs`.
3. **Rule primitives reuse `ConnectMatcher`** — CRS maps 1:1
   (`DOMAIN-SUFFIX`→`DomainSuffix`, `DOMAIN`→`DomainFull`, `DOMAIN-KEYWORD`→`DomainKeyword`,
   `DOMAIN-REGEX`→`DomainRegex`, `IP-CIDR`→`Location(NetLocationMask)`,
   `PROTOCOL`→`Protocol(SniffedProtocol)`).
4. **Performance: compile rule sets into aggregate indexes** (suffix trie,
   IP radix, keyword/regex buckets) grouped by matcher type, bucket-internal
   order preserved (rule order semantics). Single-matcher rules (the vast
   majority, including all CRS rules) hit the index in O(len)/O(bits);
   multi-matcher OR rules keep the existing linear path. This resolves the
   existing `TODO: Replace linear rule matching with radix set/trie`
   (`client_proxy_selector.rs:257`). LRU decision cache stays.
5. **Config-friendly surface**: flat outbound YAML (V2Board admin/Clash habits:
   `type/server/port/credentials/tls/transport` at one level) converted into
   the nested `ClientProxyConfig` internally; rules are CRS one-liners; external
   rule files via `rule_providers`. No panel involvement: `default_out`
   defaults to `direct`, which makes behavior identical to today when the
   whole block is absent.

## Configuration design (local file only)

```yaml
v2board:
  api_host: "http://127.0.0.1"
  api_key: "panel-token"
  nodes:
    - tag: "ss-1"
      node_id: 1
      node_type: "shadowsocks"

outbounds:
  - tag: "unlock"
    type: "vless"            # ClientProxyConfig tag incl. aliases (socks5/ss/ws/...)
    server: "203.0.113.10"
    port: 443
    user_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    udp: true                # default true, same as client stack
    tls:                     # optional; trojan/anytls/tuic/hysteria2/naive imply TLS when absent (same rule as inbound)
      enabled: true
      sni: "unlock.example.com"
      allow_insecure: false
      cert_file: "/etc/shoes/ca/unlock-ca.pem"   # private CA pinning; readable-checked by validate
      alpn: ["h2", "http/1.1"]
    reality:                 # optional, vless only
      public_key: "base64..."
      short_id: "abc123"
      server_name: "unlock.example.com"
    transport:               # optional: ws/grpc/httpupgrade/xhttp
      type: "ws"
      path: "/unlock"
      host: "unlock.example.com"
  - tag: "direct"
    type: "direct"
  - tag: "via-socks"         # chain example: this outbound forwards through socks hop
    chain: ["socks-hop", "unlock"]   # optional; overrides type/server when present

default_out: "direct"        # fallback outbound; default "direct"; absent == today's behavior

route_rules:                 # CRS one-liners; first match wins
  - "DOMAIN-SUFFIX,netflix.com,unlock"
  - "DOMAIN,netflix.com,unlock"
  - "GEOSITE,netflix,unlock"              # references v2board.route_rule_sets.geosite files
  - "IP-CIDR,103.102.0.0/24,unlock"
  - "IP-CIDR6,2001:db8::/32,unlock"
  - "PROTOCOL,http,unlock"                # sniffed http/tls/bittorrent/ssh/quic
  - "MATCH,direct"                        # explicit catch-all; default_out is the implicit one

rule_providers:              # external CRS files, hot-reloaded
  - tag: "netflix"
    path: "/etc/shoes/rules/netflix.yaml"  # list of CRS one-liners
    reload_interval_secs: 300
```

Validation (`shoes validate` and startup):
- Compile every rule line; unknown syntax/type/value fails with file+line.
- Every referenced outbound tag must exist; `default_out` must exist or be
  omitted; `chain` cycles are rejected; `chain` hops must exist.
- `rule_providers` files must exist, parse, and compile; tags must be unique.
- TLS `cert_file`/`key_file` paths must be readable (existing rule).
- Credentials stay in the local file; recommend mode 0600 (same convention as
  `runtime.data_dir` LKG snapshots); never logged.

## Architecture

```
inbound handlers (all protocols, TCP + UDP)
        │  target location (+ sniffed protocol where available)
        ▼
OutboundDispatcher (new, src/v2board/outbound/)
  1. selector.judge(target)          → Compiler-built indexes + LRU cache
       │  decision: outbound tag (or block / default_out)
       ▼
  2. chain_group for tag             → ClientChainGroup (chain_builder)
       ▼
  3. dial (TCP: chain.connect; UDP: supports_udp / UDP-over-TCP)
```

- Compiler (new): CRS line → `ConnectMatcher` + tag; groups single-matcher
  rules into per-type indexes (suffix trie, IP radix, keyword list, regex
  bucket); keeps multi-matcher OR rules linear; emits `Arc<CompiledRules>`
  swapped atomically on reload (same pattern as the existing LKG snapshot
  replacement).
- DNS: only when an IP-class rule exists and the target is a hostname —
  resolve through `src/dns/` (hickory caching, TTL-aware; optional
  `proxy_runtime` when the resolver must go through an outbound). Reuse the
  existing `resolve_rule_hostnames` option. No fake-ip (client-side concept,
  meaningless on a node).
- Hot reload: `rule_providers` mtime poll on a small tokio task
  (`reload_interval_secs`), plus config-file reload on the existing pull loop;
  compiled rules swapped under `Arc`; in-flight connections unaffected.
- Per-connection decision caching: existing LRU `RoutingCache` (threshold 16)
  keyed by target; UDP dials skip DNS (targets are IPs).

## Performance design

- Compile: one pass at startup and per reload; O(total rules) build; trie/radix
  build cost is negligible for tens of thousands of rules.
- Query path: LRU hit O(1) → index lookup O(name length) / O(32|128 bits) →
  miss falls back to rule scan only for the rare multi-matcher rules.
  Compared with the current linear scan (the codebase's own TODO), lookup cost
  is constant in rule count (10x–100x on large rule sets).
- Memory: trie + radix for ~10k rules ≈ a few MiB, built once.
- DNS: only when IP rules exist and target is a hostname; TTL-aware cache;
  per-flow decisions cached (mux streams judge per flow).
- No locks on the hot path: `Arc<CompiledRules>` + existing connector pools.

## Milestones

| Phase | Scope | Acceptance |
| --- | --- | --- |
| M0 | This document | Review |
| M1 | `OutboundDispatcher` + `Direct` outbound; refactor handler dial points (vless/anytls/shadowsocks/ss_plugins TCP first; then trojan/naive/http/xhttp/grpc) | Full regression (fmt/clippy/2255 tests/18+18 plugin E2E) unchanged |
| M2 | Rule compiler: CRS parse + per-type indexes + GEOSITE/geoip references; wire `route_rules`/`default_out` into selector; enable `chain_group` | New unit tests: order semantics, index vs linear equivalence |
| M3 | `outbounds` config → `ClientChainGroup` (all `ClientProxyConfig` types, flat→nested converter, chain hops) | `shoes validate` accepts full config; local socks5/vless upstream link test |
| M4 | DNS integration (hickory cache, optional proxy runtime, hostname→IP rule path) | Route-by-IP case over hostname target |
| M5 | UDP outbound routing (tuic/hysteria2/quic UDP dials through dispatcher; UDP-over-TCP where supported) | UDP rule E2E |
| M6 | Hot reload (mtime + config reload, `Arc` swap) | Reload test with changed rule file |
| M7 | Docs (CONFIG.md/schema/example), real-panel E2E: seed route fixtures on live V2Board, mihomo client through the node, verify direct/proxy split by destination; performance benchmark (trie vs linear) | Full acceptance + gates green |

## Risks and rejected alternatives

- Rejected: expose the generic engine `ClientConfig` nesting directly
  (protocol/transport three-level nesting is not operator-friendly).
- Rejected: xray geosite `.dat` files (linear-match cost, coarse categories,
  binary toolchain; see Decisions 1).
- Rejected: fake-ip DNS (client-side concept; node-side destination is what
  the client requested).
- Rejected: panel-driven outbounds (V2Board exposes no outbound model; local
  file keeps the V2Board contract untouched — same precedent as
  `trojan_fallback`).
- Fail-closed: dial errors reject the connection (same as Block); unknown
  tags/cycles fail validation, not runtime.
- Scope note: this is a new production-facing server-side surface. The legacy
  generic local-YAML client chains stay outside the production boundary
  (AGENTS.md); we reuse their protocol implementations only.
