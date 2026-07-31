#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Small black-box V2Board control-plane fixture for SS plugin interoperability.

This fixture is original test code for shoes. It does not copy or embed client
or protocol implementation code; the interoperability runner uses a separately
built Mihomo process as the peer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse


def plugin_for_case(
    case: str,
    raw_port: int,
    plugin_port: int,
    camouflage_host: str,
    restls_script: str,
) -> dict[str, Any] | None:
    upstream = {"host": "127.0.0.1", "port": raw_port}
    common = {"listen_port": plugin_port, "upstream": upstream}
    if case == "raw":
        return None
    if case in {"obfs-http", "obfs-tls"}:
        return {
            "type": "obfs",
            **common,
            "options": {
                "mode": case.removeprefix("obfs-"),
                "host": "interop.test",
            },
        }
    if case in {
        "v2ray-ws",
        "v2ray-wss",
        "v2ray-ws-mux",
        "v2ray-wss-mux",
        "v2ray-http-upgrade",
        "v2ray-https-upgrade",
    }:
        return {
            "type": "v2ray-plugin",
            **common,
            "options": {
                "mode": "websocket",
                "host": "interop.test",
                "path": "/interop",
                "tls": case in {
                    "v2ray-wss",
                    "v2ray-wss-mux",
                    "v2ray-https-upgrade",
                },
                "mux": case in {"v2ray-ws-mux", "v2ray-wss-mux"},
                "v2ray_http_upgrade": case in {
                    "v2ray-http-upgrade",
                    "v2ray-https-upgrade",
                },
            },
        }
    if case in {"gost-ws", "gost-wss", "gost-ws-mux", "gost-wss-mux"}:
        return {
            "type": "gost-plugin",
            **common,
            "options": {
                "mode": "websocket",
                "host": "interop.test",
                "path": "/interop",
                "tls": case in {"gost-wss", "gost-wss-mux"},
                "mux": case in {"gost-ws-mux", "gost-wss-mux"},
            },
        }
    if case in {"shadowtls-v1", "shadowtls-v2", "shadowtls-v3"}:
        version = int(case[-1])
        options: dict[str, Any] = {
            "host": camouflage_host,
            "version": version,
        }
        if version > 1:
            options["password"] = "shadowtls-interop-password"
        return {
            "type": "shadow-tls",
            **common,
            "options": options,
        }
    if case == "restls":
        return {
            "type": "restls",
            **common,
            "options": {
                "host": camouflage_host,
                "password": "restls-interop-password",
                "restls_script": restls_script,
            },
        }
    if case in {"kcptun-v1", "kcptun-v2"}:
        return {
            "type": "kcptun",
            **common,
            "options": {
                "key": "shoes-kcptun-interop",
                "crypt": "aes-128",
                "mode": "manual",
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
                "sockbuf": 4 * 1024 * 1024,
                "smuxver": int(case[-1]),
                "smuxbuf": 4 * 1024 * 1024,
                "framesize": 8192,
                "streambuf": 1024 * 1024,
                "keepalive": 1,
            },
        }
    raise ValueError(f"unsupported interop case: {case}")


class PanelState:
    def __init__(self, args: argparse.Namespace):
        revision_digest = hashlib.sha256(args.case.encode()).hexdigest()
        self.revision = f"sha256:{revision_digest}"
        self.etag = f'"plugin-{revision_digest[:16]}"'
        self.case = args.case
        self.raw_port = args.raw_port
        self.plugin = plugin_for_case(
            args.case,
            args.raw_port,
            args.plugin_port,
            args.camouflage_host,
            args.restls_script,
        )
        self.lock = threading.Lock()
        self.last_status: dict[str, Any] = {}

    def config(self) -> dict[str, Any]:
        return {
            "server_port": self.raw_port,
            "cipher": "aes-128-gcm",
            "obfs": None,
            "obfs_settings": None,
            "routes": [],
            "config_revision": self.revision,
            "base_config": {
                "push_interval": 5,
                "pull_interval": 5,
                "node_report_min_traffic": 0,
                "device_online_min_traffic": 0,
            },
        }

    def manifest(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "node_type": "shadowsocks",
            "node_id": 1,
            "server_port": self.raw_port,
            "cipher": "aes-128-gcm",
            "server_key": None,
            "obfs": None,
            "obfs_settings": None,
            "multiplex": None,
            "plugin": self.plugin,
            "routes": [],
            "config_revision": self.revision,
            "base_config": {
                "push_interval": 5,
                "pull_interval": 5,
                "node_report_min_traffic": 0,
                "device_online_min_traffic": 0,
            },
        }


class PanelHandler(BaseHTTPRequestHandler):
    server: "PanelServer"

    def log_message(self, format_string: str, *args: Any) -> None:
        print(
            f"{self.client_address[0]} {format_string % args}",
            flush=True,
        )

    def send_json(
        self,
        status: int,
        value: Any,
        *,
        etag: str | None = None,
    ) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if etag is not None:
            self.send_header("ETag", etag)
        self.end_headers()
        self.wfile.write(body)

    def validate_query(self) -> bool:
        query = parse_qs(urlparse(self.path).query)
        if (
            query.get("token") != ["interop-token"]
            or query.get("node_id") != ["1"]
            or query.get("node_type") != ["shadowsocks"]
        ):
            self.send_json(403, {"error": "invalid test credentials"})
            return False
        return True

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/test/status":
            with self.server.state.lock:
                status = dict(self.server.state.last_status)
            self.send_json(200, status)
            return
        if not self.validate_query():
            return
        if parsed.path.endswith("/config"):
            self.send_json(
                200,
                self.server.state.config(),
                etag=f'"config-{self.server.state.revision[-16:]}"',
            )
            return
        if parsed.path.endswith("/plugin-config"):
            if self.headers.get("If-None-Match") == self.server.state.etag:
                self.send_response(304)
                self.send_header("ETag", self.server.state.etag)
                self.end_headers()
            else:
                self.send_json(
                    200,
                    self.server.state.manifest(),
                    etag=self.server.state.etag,
                )
            return
        if parsed.path.endswith("/user"):
            self.send_json(
                200,
                [
                    {
                        "id": 1,
                        "uuid": "interop-password",
                        "speed_limit": 0,
                        "device_limit": 0,
                        "enabled": True,
                    }
                ],
                etag='"users-v1"',
            )
            return
        if parsed.path.endswith("/alivelist"):
            self.send_json(200, {"alive": {}})
            return
        self.send_json(404, {"error": "unknown test endpoint"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if not self.validate_query():
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            self.send_json(400, {"error": "invalid JSON"})
            return
        if parsed.path.endswith("/status"):
            with self.server.state.lock:
                self.server.state.last_status = body
            self.send_json(200, {"data": True})
            return
        if parsed.path.endswith(("/push", "/alive")):
            self.send_json(200, {"data": True})
            return
        self.send_json(404, {"error": "unknown test endpoint"})


class PanelServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], state: PanelState):
        super().__init__(address, PanelHandler)
        self.state = state


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--raw-port", type=int, required=True)
    parser.add_argument("--plugin-port", type=int, required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--camouflage-host", default="localhost")
    parser.add_argument("--restls-script", default="")
    args = parser.parse_args()
    state = PanelState(args)
    server = PanelServer(("127.0.0.1", args.port), state)
    print(
        f"mock panel case={args.case} port={args.port} revision={state.revision}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
