"""Threaded TLS camouflage server for the Shadowsocks plugin E2E.

`openssl s_server` handles one connection at a time: a second handshake while
another connection is open never completes. ShadowTLS and Restls relay a real
handshake to this server for every connection they accept, so under a full
matrix run the second one stalls until the client gives up -- a 45 second
timeout that looks exactly like a backend defect and is not one.
"""

import http.server
import socketserver
import ssl
import sys

port = int(sys.argv[1])
certfile, keyfile, version = sys.argv[2], sys.argv[3], sys.argv[4]

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
if version == "tls12":
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
elif version == "tls13":
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certfile, keyfile)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"<html><body>camouflage</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def get_request(self):
        sock, addr = super().get_request()
        return context.wrap_socket(sock, server_side=True), addr

    def handle_error(self, request, client_address):
        # A probe that speaks no TLS is ordinary traffic here, not a failure.
        pass


with Server(("127.0.0.1", port), Handler) as server:
    server.serve_forever()
