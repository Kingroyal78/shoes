#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Declarative case matrix for the Shadowsocks plugin E2E.

`v2board_e2e_ss_plugins.sh` used to carry two hand-written case ladders: one
building the profile V2Board stores, one building the Mihomo client config.
Every new option combination had to be added to both, and a mismatch between
them shows up as a confusing interop failure rather than a clear one.

This module is the single source of truth for a case. `PROFILE_OPTIONS` are
what the panel stores (and therefore what reaches the backend manifest through
the plugin option allowlist); `CLIENT_OPTIONS` are what Mihomo needs, including
client-only keys such as `skip-cert-verify` that never appear in the manifest.
Keys shared by both are written once and projected into each side.

Groups let the shell driver select a slice:
  base      the original 18-case set, unchanged
  hosthdr   WebSocket Host header folding
  restls    Restls script and version-hint coverage
  shadowtls ShadowTLS ALPN and client fingerprints
  kcptun    Kcptun cipher, mode and framing sweeps
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field

CAMOUFLAGE_PLACEHOLDER = "@camouflage@"

# Options every WebSocket-family case shares.
WS_BASE = {
    "mode": "websocket",
    "host": "interop.test",
    "path": "/interop",
}

KCPTUN_BASE = {
    "key": "shoes-kcptun-interop",
    "crypt": "aes-128",
    "mode": "manual",
    "conn": 1,
    "autoexpire": 0,
    "scavengettl": 60,
    "mtu": 1350,
    "ratelimit": 0,
    "sndwnd": 256,
    "rcvwnd": 512,
    "datashard": 4,
    "parityshard": 2,
    "dscp": 0,
    "nocomp": False,
    "acknodelay": True,
    "nodelay": 1,
    "interval": 10,
    "resend": 2,
    "nc": 1,
    "sockbuf": 4194304,
    "smuxver": 1,
    "smuxbuf": 4194304,
    "framesize": 8192,
    "streambuf": 1048576,
    "keepalive": 1,
}

# Profile option names that Mihomo spells differently.
CLIENT_KEY_RENAMES = {
    "v2ray_http_upgrade": "v2ray-http-upgrade",
    "version_hint": "version-hint",
    "restls_script": "restls-script",
    "skip_cert_verify": "skip-cert-verify",
}

# Profile-only keys: stored by the panel for the client payload, never part of
# the Mihomo plugin-opts block written here.
PROFILE_ONLY_KEYS = {"fingerprint", "v2ray_http_upgrade_fast_open"}


@dataclass(frozen=True)
class Case:
    name: str
    kind: str
    group: str
    options: dict = field(default_factory=dict)
    """Plugin options as stored in the profile."""
    client_extra: dict = field(default_factory=dict)
    """Extra or overriding Mihomo plugin-opts."""
    profile_extra: dict = field(default_factory=dict)
    """Top-level profile keys outside `plugin`, e.g. client_fingerprint."""
    camouflage_tls: str = "auto"
    """TLS version the local camouflage server must offer: auto, tls12, tls13.

    A Restls `version_hint` describes the handshake shape the client produces.
    Pointed at a camouflage host that will not speak that version, the whole
    chain stalls silently instead of failing, so the fixture has to match the
    case rather than the other way round.
    """

    def profile_options(self, camouflage_host: str, restls_script: str) -> dict:
        return _resolve(self.options, camouflage_host, restls_script)

    def client_options(self, camouflage_host: str, restls_script: str) -> dict:
        merged = {}
        for key, value in self.options.items():
            if key in PROFILE_ONLY_KEYS:
                continue
            merged[CLIENT_KEY_RENAMES.get(key, key)] = value
        merged.update(self.client_extra)
        return _resolve(merged, camouflage_host, restls_script)


def _resolve(values: dict, camouflage_host: str, restls_script: str) -> dict:
    resolved = {}
    for key, value in values.items():
        if value == CAMOUFLAGE_PLACEHOLDER:
            value = camouflage_host
        elif key in ("restls_script", "restls-script") and value is None:
            value = restls_script
        resolved[key] = value
    return resolved


def _ws(name: str, kind: str, group: str, *, tls=False, mux=False, upgrade=False, headers=None, extra=None) -> Case:
    options = dict(WS_BASE)
    options.update(
        {
            "tls": tls,
            "fingerprint": "",
            "skip_cert_verify": tls,
            "mux": mux,
        }
    )
    if kind == "v2ray-plugin":
        options["v2ray_http_upgrade"] = upgrade
        options["v2ray_http_upgrade_fast_open"] = False
    if headers is not None:
        options["headers"] = headers
    if extra:
        options.update(extra)
    client_extra = {}
    if headers is not None:
        client_extra["headers"] = headers
    return Case(name=name, kind=kind, group=group, options=options, client_extra=client_extra)


def _shadowtls(name: str, group: str, version: int, *, alpn=None, fingerprint="chrome") -> Case:
    options = {
        "host": CAMOUFLAGE_PLACEHOLDER,
        "version": version,
        # The camouflage certificate is self-signed, and in subscription mode
        # the client config is whatever the panel stored, so this has to live
        # in the profile rather than only in the hand-written config.
        "skip_cert_verify": True,
    }
    if version > 1:
        options["password"] = "shadowtls-interop-password"
    if alpn is not None:
        options["alpn"] = alpn
    # Mihomo always wants the password field present, and never verifies the
    # camouflage certificate in this fixture.
    client_extra = {"password": "shadowtls-interop-password", "skip-cert-verify": True}
    return Case(
        name=name,
        kind="shadow-tls",
        group=group,
        options=options,
        client_extra=client_extra,
        profile_extra={"client_fingerprint": fingerprint},
    )


def _restls(
    name: str,
    group: str,
    *,
    version_hint="tls13",
    script=None,
    fingerprint="chrome",
) -> Case:
    options = {
        "host": CAMOUFLAGE_PLACEHOLDER,
        "password": "restls-interop-password",
        "version_hint": version_hint,
        "restls_script": script,
        "skip_cert_verify": True,
    }
    return Case(
        name=name,
        kind="restls",
        group=group,
        options=options,
        client_extra={"skip-cert-verify": True},
        profile_extra={"client_fingerprint": fingerprint},
        camouflage_tls=version_hint,
    )


def _kcptun(name: str, group: str, **overrides) -> Case:
    options = dict(KCPTUN_BASE)
    options.update(overrides)
    return Case(name=name, kind="kcptun", group=group, options=options)


def _build_cases() -> list[Case]:
    cases: list[Case] = [
        Case("obfs-http", "obfs", "base", {"mode": "http", "host": "interop.test"}),
        Case("obfs-tls", "obfs", "base", {"mode": "tls", "host": "interop.test"}),
        _ws("v2ray-ws", "v2ray-plugin", "base"),
        _ws("v2ray-wss", "v2ray-plugin", "base", tls=True),
        _ws("v2ray-ws-mux", "v2ray-plugin", "base", mux=True),
        _ws("v2ray-wss-mux", "v2ray-plugin", "base", tls=True, mux=True),
        _ws("v2ray-http-upgrade", "v2ray-plugin", "base", upgrade=True),
        _ws("v2ray-https-upgrade", "v2ray-plugin", "base", tls=True, upgrade=True),
        _ws("gost-ws", "gost-plugin", "base"),
        _ws("gost-wss", "gost-plugin", "base", tls=True),
        _ws("gost-ws-mux", "gost-plugin", "base", mux=True),
        _ws("gost-wss-mux", "gost-plugin", "base", tls=True, mux=True),
        _shadowtls("shadowtls-v1", "base", 1),
        _shadowtls("shadowtls-v2", "base", 2),
        _shadowtls("shadowtls-v3", "base", 3),
        _restls("restls", "base"),
        _kcptun("kcptun-v1", "base", smuxver=1),
        _kcptun("kcptun-v2", "base", smuxver=2),
    ]

    # The panel folds a WebSocket `headers.Host` into the manifest's
    # `options.host`, after stripping whitespace, a port and IPv6 brackets. A
    # header that cannot normalize to a host must leave the validated
    # `options.host` in place. Both sides must still carry traffic.
    for kind, prefix in (("v2ray-plugin", "v2ray"), ("gost-plugin", "gost")):
        cases += [
            _ws(f"{prefix}-ws-hosthdr", kind, "hosthdr", headers={"Host": "front.interop.test"}),
            _ws(f"{prefix}-wss-hosthdr", kind, "hosthdr", tls=True, headers={"Host": "front.interop.test"}),
            _ws(f"{prefix}-ws-hosthdr-port", kind, "hosthdr", headers={"Host": "front.interop.test:8443"}),
        ]
    # A Host header that cannot normalize to a host is kept out of the manifest,
    # so the backend listens on the validated `options.host` while the client
    # still sends the unusable header verbatim. The two then disagree and the
    # WebSocket handshake is refused, even though the node is ACKed and
    # published. Kept in its own group: it documents a real gap in the panel's
    # header validation rather than a passing combination.
    cases.append(
        _ws(
            "v2ray-ws-hosthdr-unusable",
            "v2ray-plugin",
            "hosthdr-known-broken",
            headers={"Host": "front.interop.test/websocket"},
        )
    )

    # Restls: both version hints, and scripts inside the v1-safe range the
    # backend implements (last record target <= 16364, responses <= 127).
    cases += [
        _restls("restls-tls12", "restls", version_hint="tls12"),
        _restls("restls-script-simple", "restls", script="100"),
        _restls("restls-script-range", "restls", script="600?100<1"),
        _restls("restls-script-multi", "restls", script="250?100<1,650~1000<2"),
        _restls("restls-script-edge", "restls-known-broken", script="16364<127"),
        # Bisect the boundary: which of the two limits the backend actually
        # trips on. Both values are inside the range the panel treats as
        # v1-safe and the backend documents as supported.
        _restls("restls-script-target-max", "restls-probe", script="16364<1"),
        _restls("restls-script-resp-max", "restls-probe", script="100<127"),
        _restls("restls-script-mid", "restls-probe", script="8192<64"),
        _restls("restls-script-resp-32", "restls-probe", script="100<32"),
        _restls("restls-script-resp-40", "restls-probe", script="100<40"),
        _restls("restls-script-resp-48", "restls-probe", script="100<48"),
        _restls("restls-script-resp-64", "restls-probe", script="100<64"),
        _restls("restls-fp-ios", "restls", fingerprint="ios"),
        _restls("restls-fp-firefox", "restls", fingerprint="firefox"),
    ]

    # ShadowTLS: ALPN and the client fingerprints the panel accepts.
    cases += [
        _shadowtls("shadowtls-v3-alpn", "shadowtls", 3, alpn=["h2", "http/1.1"]),
        _shadowtls("shadowtls-v2-alpn", "shadowtls", 2, alpn=["http/1.1"]),
        _shadowtls("shadowtls-v3-fp-firefox", "shadowtls", 3, fingerprint="firefox"),
        _shadowtls("shadowtls-v3-fp-safari", "shadowtls", 3, fingerprint="safari"),
        _shadowtls("shadowtls-v3-fp-ios", "shadowtls", 3, fingerprint="ios"),
        _shadowtls("shadowtls-v3-fp-random", "shadowtls", 3, fingerprint="random"),
    ]

    # Kcptun: every cipher the panel allows, every mode, and the framing knobs
    # that differ between implementations. `mtu` stays at the shared default,
    # which clears the per-cipher minimum for all of them.
    for crypt in (
        "aes",
        "aes-192",
        "aes-128-gcm",
        "salsa20",
        "blowfish",
        "twofish",
        "cast5",
        "3des",
        "tea",
        "xtea",
        "xor",
        "none",
        "null",
    ):
        cases.append(_kcptun(f"kcptun-crypt-{crypt}", "kcptun", crypt=crypt))
    for mode in ("fast3", "fast2", "fast", "normal"):
        cases.append(_kcptun(f"kcptun-mode-{mode}", "kcptun", mode=mode))
    cases += [
        _kcptun("kcptun-nocomp", "kcptun", nocomp=True),
        _kcptun("kcptun-shards", "kcptun", datashard=20, parityshard=10),
        _kcptun("kcptun-framing", "kcptun", framesize=4096, streambuf=524288, smuxbuf=2097152),
        _kcptun("kcptun-nodelay-off", "kcptun", nodelay=0, nc=0, resend=0, acknodelay=False),
    ]

    return cases


CASES = {case.name: case for case in _build_cases()}

FEATURES = {
    "obfs": "shadowsocks-plugin-obfs-v1",
    "v2ray-plugin": "shadowsocks-plugin-v2ray-v1",
    "gost-plugin": "shadowsocks-plugin-gost-v1",
    "shadow-tls": "shadowsocks-plugin-shadow-tls-v1",
    "restls": "shadowsocks-plugin-restls-v1",
    "kcptun": "shadowsocks-plugin-kcptun-v1",
}


def _case(name: str) -> Case:
    try:
        return CASES[name]
    except KeyError:
        raise SystemExit(f"unknown case: {name}") from None


def _yaml_scalar(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value))


def _yaml_opts(options: dict, indent: str) -> str:
    lines = []
    for key, value in options.items():
        if isinstance(value, dict):
            lines.append(f"{indent}{key}:")
            for sub_key, sub_value in value.items():
                lines.append(f"{indent}  {sub_key}: {_yaml_scalar(sub_value)}")
        elif isinstance(value, list):
            lines.append(f"{indent}{key}:")
            for item in value:
                lines.append(f"{indent}  - {_yaml_scalar(item)}")
        else:
            lines.append(f"{indent}{key}: {_yaml_scalar(value)}")
    return "\n".join(lines)


def _from_subscription(case: Case, args) -> int:
    """Drive Mihomo with the panel's own subscription payload.

    The hand-written client config proves the two runtimes interoperate. It
    does not prove the panel describes the node the way this client needs, and
    that description is dialect-dependent. Here the proxy entry is taken from
    the subscription verbatim -- only the listener and rules around it are
    ours -- so a wrong or missing key in the panel payload fails the transfer
    instead of being papered over.
    """
    import yaml  # local: only the subscription path needs it

    from pathlib import Path

    document = yaml.safe_load(Path(args.subscription).read_text())
    if not isinstance(document, dict):
        print("subscription is not a YAML mapping", file=sys.stderr)
        return 1

    proxies = document.get("proxies") or []
    if len(proxies) != 1:
        print(
            f"expected exactly one proxy in the subscription, got {len(proxies)}",
            file=sys.stderr,
        )
        return 1

    proxy = dict(proxies[0])
    problems = []
    if proxy.get("type") != "ss":
        problems.append(f"type={proxy.get('type')!r}, want 'ss'")
    if str(proxy.get("server")) != args.server:
        problems.append(f"server={proxy.get('server')!r}, want {args.server!r}")
    if int(proxy.get("port", 0)) != args.plugin_port:
        problems.append(f"port={proxy.get('port')!r}, want {args.plugin_port}")
    if proxy.get("plugin") != case.kind:
        problems.append(f"plugin={proxy.get('plugin')!r}, want {case.kind!r}")
    if problems:
        print(
            "subscription proxy does not describe this node: " + "; ".join(problems),
            file=sys.stderr,
        )
        return 1

    proxy["name"] = "e2e"
    config = {
        "mixed-port": args.mixed_port,
        "bind-address": "127.0.0.1",
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "proxies": [proxy],
        "rules": ["MATCH,e2e"],
    }
    print(yaml.safe_dump(config, sort_keys=False, allow_unicode=True), end="")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    listing = sub.add_parser("list", help="print case names, one per line")
    listing.add_argument("--group", action="append", default=None)
    listing.add_argument("--joined", action="store_true", help="print one comma-separated line")

    for name in ("kind", "feature", "group", "flags"):
        single = sub.add_parser(name)
        single.add_argument("case")

    profile = sub.add_parser("profile", help="print the profile JSON to seed")
    profile.add_argument("case")
    profile.add_argument("--plugin-port", type=int, required=True)
    profile.add_argument("--endpoint-host", default="127.0.0.1")
    profile.add_argument("--camouflage-host", default="127.0.0.1")
    profile.add_argument("--restls-script", default="")

    from_sub = sub.add_parser(
        "from-subscription",
        help="turn a panel subscription into a Mihomo config, verbatim",
    )
    from_sub.add_argument("case")
    from_sub.add_argument("--subscription", required=True, help="fetched subscription YAML")
    from_sub.add_argument("--plugin-port", type=int, required=True)
    from_sub.add_argument("--mixed-port", type=int, required=True)
    from_sub.add_argument("--server", default="127.0.0.1")

    mihomo = sub.add_parser("mihomo", help="print the Mihomo client config")
    mihomo.add_argument("case")
    mihomo.add_argument("--plugin-port", type=int, required=True)
    mihomo.add_argument("--mixed-port", type=int, required=True)
    mihomo.add_argument("--password", required=True)
    mihomo.add_argument("--cipher", default="aes-128-gcm")
    mihomo.add_argument("--server", default="127.0.0.1")
    mihomo.add_argument("--camouflage-host", default="127.0.0.1")
    mihomo.add_argument("--restls-script", default="")

    args = parser.parse_args()

    if args.command == "list":
        names = [
            case.name
            for case in CASES.values()
            if args.group is None or case.group in args.group
        ]
        print(",".join(names) if args.joined else "\n".join(names))
        return 0

    case = _case(args.case)

    if args.command == "kind":
        print(case.kind)
        return 0
    if args.command == "group":
        print(case.group)
        return 0
    if args.command == "feature":
        print(FEATURES[case.kind])
        return 0

    if args.command == "flags":
        # The camouflage plugins terminate a real TLS handshake against a local
        # openssl s_server; the WebSocket plugins terminate TLS in shoes itself
        # and need the certificate in the shoes config instead. Both are
        # properties of the case definition, never of the case name.
        camouflage = case.kind in ("shadow-tls", "restls")
        server_tls = bool(case.options.get("tls"))
        print(f"CASE_KIND={case.kind}")
        print(f"CASE_FEATURE={FEATURES[case.kind]}")
        print(f"CASE_GROUP={case.group}")
        print(f"CASE_NEEDS_CAMOUFLAGE={int(camouflage)}")
        print(f"CASE_NEEDS_SERVER_TLS={int(server_tls)}")
        print(f"CASE_NEEDS_CERT={int(camouflage or server_tls)}")
        print(f"CASE_CAMOUFLAGE_TLS={case.camouflage_tls}")
        return 0

    if args.command == "profile":
        profile_json = {
            "version": 1,
            "plugin": {
                "type": case.kind,
                "endpoint_host": args.endpoint_host,
                "endpoint_port": args.plugin_port,
                "options": case.profile_options(args.camouflage_host, args.restls_script),
            },
        }
        profile_json.update(case.profile_extra)
        print(json.dumps(profile_json, separators=(",", ":")))
        return 0

    if args.command == "from-subscription":
        return _from_subscription(case, args)

    options = case.client_options(args.camouflage_host, args.restls_script)
    print(
        f"""\
mixed-port: {args.mixed_port}
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: info
ipv6: false
proxies:
  - name: e2e
    type: ss
    server: {args.server}
    port: {args.plugin_port}
    cipher: {args.cipher}
    password: {args.password}
    plugin: {case.kind}
    plugin-opts:
{_yaml_opts(options, "      ")}
rules:
  - MATCH,e2e"""
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
