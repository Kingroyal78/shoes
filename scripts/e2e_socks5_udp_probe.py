#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Send a datagram through a SOCKS5 proxy and require it back unchanged.

The plugin matrix proves a TCP payload survives the plugin edge. UDP takes a
different path through the backend -- UDP-over-TCP, whose version the panel
chooses and the backend has to agree with -- and a mismatch there is invisible
to a TCP-only check: the node still serves web traffic while every datagram is
dropped.

Exits 0 when the echo comes back byte for byte, non-zero otherwise, so the
shell driver can treat it like any other assertion.
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys


def udp_associate(sock: socket.socket) -> tuple[str, int]:
    """Open a UDP association and return the relay address to send to."""
    sock.sendall(b"\x05\x01\x00")
    greeting = sock.recv(2)
    if greeting != b"\x05\x00":
        raise SystemExit(f"SOCKS5 greeting refused: {greeting!r}")

    # UDP ASSOCIATE, no expectation about the source we will send from.
    sock.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))
    header = sock.recv(4)
    if len(header) != 4 or header[1] != 0x00:
        raise SystemExit(f"UDP ASSOCIATE refused: {header!r}")

    atyp = header[3]
    if atyp == 0x01:
        host = socket.inet_ntoa(sock.recv(4))
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, sock.recv(16))
    elif atyp == 0x03:
        length = sock.recv(1)[0]
        host = sock.recv(length).decode()
    else:
        raise SystemExit(f"unsupported bound address type: {atyp}")
    port = struct.unpack("!H", sock.recv(2))[0]

    # A relay that binds the wildcard address is telling us the port, not where
    # to send; the association lives on the proxy we are already talking to.
    if host in ("0.0.0.0", "::"):
        host = sock.getpeername()[0]
    return host, port


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy-port", type=int, required=True)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--payload-size", type=int, default=1024)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--attempts", type=int, default=3)
    args = parser.parse_args()

    payload = os.urandom(args.payload_size)
    request = (
        b"\x00\x00\x00\x01"
        + socket.inet_aton(args.target_host)
        + struct.pack("!H", args.target_port)
        + payload
    )

    with socket.create_connection(("127.0.0.1", args.proxy_port), timeout=args.timeout) as control:
        relay_host, relay_port = udp_associate(control)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagrams:
            datagrams.settimeout(args.timeout)
            # The association can take a moment to be usable, and a lost
            # datagram is not a failure of the thing under test.
            for attempt in range(args.attempts):
                datagrams.sendto(request, (relay_host, relay_port))
                try:
                    reply, _ = datagrams.recvfrom(65535)
                except socket.timeout:
                    if attempt + 1 == args.attempts:
                        raise SystemExit("no datagram came back through the proxy")
                    continue

                if len(reply) < 10 or reply[:3] != b"\x00\x00\x00":
                    raise SystemExit(f"malformed SOCKS5 UDP reply header: {reply[:10]!r}")
                echoed = reply[10:] if reply[3] == 0x01 else reply[reply.index(payload[:8]) :]
                if echoed != payload:
                    raise SystemExit(
                        f"datagram came back changed: sent {len(payload)} bytes, "
                        f"got {len(echoed)}"
                    )
                print(f"udp round trip ok: {len(payload)} bytes")
                return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
