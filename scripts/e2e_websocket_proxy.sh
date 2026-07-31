#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/scripts"

# shellcheck source=scripts/v2board_e2e_common.sh
source "${SCRIPT_DIR}/v2board_e2e_common.sh"

trap e2e_on_error ERR

E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_HTTP_TARGET_PORT="${E2E_HTTP_TARGET_PORT:-18214}"
E2E_WEBSOCKET_PROXY_PORT="${E2E_WEBSOCKET_PROXY_PORT:-18213}"
E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB:-128}"
E2E_SHOES_LOG_LEVEL="${E2E_SHOES_LOG_LEVEL:-info}"
E2E_CLIENT_TIMEOUT_SECS="${E2E_CLIENT_TIMEOUT_SECS:-30}"
E2E_BASIC_PROXY_BIN="${E2E_BASIC_PROXY_BIN:-${ROOT_DIR}/target/debug/shoes-basic-proxy-e2e-server}"
E2E_BASIC_PROXY_BIN_EXPLICIT="${E2E_BASIC_PROXY_BIN_EXPLICIT:-0}"

TMP_DIR=""
HTTP_PID=""
PROXY_PID=""
PAYLOAD_SHA256=""

usage() {
  cat <<'EOF'
Usage:
  scripts/e2e_websocket_proxy.sh

Runs a real WebSocket transport check:
  - shoes serves WebSocket at /ws with a SOCKS5 inner protocol.
  - a Go client performs a real WebSocket Upgrade and masked binary frames.
  - the client speaks SOCKS5 inside WebSocket and downloads a deterministic HTTP payload.
EOF
}

cleanup() {
  local status=$?
  set +e

  if [[ -n "${PROXY_PID}" ]] && kill -0 "${PROXY_PID}" 2>/dev/null; then
    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true
  fi
  if [[ -n "${HTTP_PID}" ]] && kill -0 "${HTTP_PID}" 2>/dev/null; then
    kill "${HTTP_PID}" 2>/dev/null || true
    wait "${HTTP_PID}" 2>/dev/null || true
  fi

  if [[ "${status}" -ne 0 && -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    e2e_warn "temporary logs kept for failure analysis: ${TMP_DIR}"
  elif [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    rm -rf "${TMP_DIR}"
  fi

  exit "${status}"
}

trap cleanup EXIT

parse_args() {
  if (($# == 0)); then
    return
  fi
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    *)
      e2e_die "unknown argument: $1"
      ;;
  esac
}

wait_for_tcp_port() {
  local port="$1"
  local label="$2"
  local timeout="${3:-15}"
  local start
  local now

  start="$(date +%s)"
  while true; do
    if ss -ltn | awk '{print $4}' | grep -Eq "(^|:)${port}$"; then
      return
    fi
    if [[ -n "${HTTP_PID}" ]] && ! kill -0 "${HTTP_PID}" 2>/dev/null; then
      e2e_die "${label} process exited before listening on ${port}"
    fi
    if [[ -n "${PROXY_PID}" ]] && ! kill -0 "${PROXY_PID}" 2>/dev/null; then
      e2e_die "${label} process exited before listening on ${port}"
    fi
    now="$(date +%s)"
    if ((now - start >= timeout)); then
      e2e_die "${label} did not listen on port ${port} within ${timeout}s"
    fi
    sleep 0.2
  done
}

resolve_binaries() {
  e2e_section "binaries"
  e2e_require_command cargo
  e2e_require_command go
  e2e_require_command python3
  e2e_require_command ss

  if ! e2e_bool "${E2E_BASIC_PROXY_BIN_EXPLICIT}"; then
    e2e_run cargo build \
      --manifest-path "${ROOT_DIR}/Cargo.toml" \
      --features e2e-client \
      --bin shoes-basic-proxy-e2e-server
  fi
  [[ -x "${E2E_BASIC_PROXY_BIN}" ]] \
    || e2e_die "E2E_BASIC_PROXY_BIN is not executable: ${E2E_BASIC_PROXY_BIN}"
}

start_http_target() {
  e2e_section "http target"
  e2e_assert_port_free "${E2E_HTTP_TARGET_PORT}" "websocket proxy http target"

  mkdir -p "${TMP_DIR}/www"
  PAYLOAD_PATH="${TMP_DIR}/www/payload.bin"
  PAYLOAD_SHA256="$(
    PAYLOAD_PATH="${PAYLOAD_PATH}" E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB}" python3 <<'PY'
import hashlib
import os
from pathlib import Path

path = Path(os.environ["PAYLOAD_PATH"])
size = int(os.environ["E2E_PAYLOAD_KIB"]) * 1024
data = bytes(((i * 13 + 41) % 256 for i in range(size)))
path.write_bytes(data)
print(hashlib.sha256(data).hexdigest())
PY
  )"

  python3 -m http.server "${E2E_HTTP_TARGET_PORT}" \
    --bind "${E2E_BIND_HOST}" \
    --directory "${TMP_DIR}/www" \
    >"${TMP_DIR}/http-target.log" 2>&1 &
  HTTP_PID=$!
  wait_for_tcp_port "${E2E_HTTP_TARGET_PORT}" "websocket proxy http target"
}

build_go_client() {
  e2e_section "websocket client"
  mkdir -p "${TMP_DIR}/go-client"

  cat >"${TMP_DIR}/go-client/go.mod" <<'GO'
module shoes_ws_e2e

go 1.22

require github.com/gorilla/websocket v1.5.3
GO

  cat >"${TMP_DIR}/go-client/main.go" <<'GO'
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type wsBytes struct {
	conn    *websocket.Conn
	buffer  []byte
	timeout time.Duration
}

func (r *wsBytes) writeBinary(data []byte) {
	_ = r.conn.SetWriteDeadline(time.Now().Add(r.timeout))
	if err := r.conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		fatalf("write websocket binary frame: %v", err)
	}
}

func (r *wsBytes) fill(n int) {
	for len(r.buffer) < n {
		_ = r.conn.SetReadDeadline(time.Now().Add(r.timeout))
		messageType, reader, err := r.conn.NextReader()
		if err != nil {
			fatalf("read websocket frame: %v", err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			fatalf("read websocket frame payload: %v", err)
		}
		if messageType != websocket.BinaryMessage {
			continue
		}
		r.buffer = append(r.buffer, data...)
	}
}

func (r *wsBytes) readN(n int) []byte {
	r.fill(n)
	out := append([]byte(nil), r.buffer[:n]...)
	r.buffer = r.buffer[n:]
	return out
}

func (r *wsBytes) readUntil(delim []byte) []byte {
	for {
		if idx := bytes.Index(r.buffer, delim); idx >= 0 {
			end := idx + len(delim)
			out := append([]byte(nil), r.buffer[:end]...)
			r.buffer = r.buffer[end:]
			return out
		}
		r.fill(len(r.buffer) + 1)
	}
}

func main() {
	wsURL := flag.String("ws", "", "WebSocket URL")
	target := flag.String("target", "", "SOCKS target host:port")
	expectedSHA256 := flag.String("sha256", "", "expected payload sha256")
	timeoutSeconds := flag.Int("timeout", 30, "timeout in seconds")
	flag.Parse()

	if *wsURL == "" || *target == "" || *expectedSHA256 == "" {
		fatalf("missing required arguments")
	}

	timeout := time.Duration(*timeoutSeconds) * time.Second
	dialer := websocket.Dialer{HandshakeTimeout: timeout}
	conn, response, err := dialer.Dial(*wsURL, http.Header{})
	if err != nil {
		status := ""
		if response != nil {
			status = response.Status
		}
		fatalf("websocket dial failed: %v %s", err, status)
	}
	defer conn.Close()

	stream := &wsBytes{conn: conn, timeout: timeout}
	stream.writeBinary([]byte{0x05, 0x01, 0x00})
	method := stream.readN(2)
	if !bytes.Equal(method, []byte{0x05, 0x00}) {
		fatalf("unexpected SOCKS method response: %x", method)
	}

	host, portString, err := net.SplitHostPort(*target)
	if err != nil {
		fatalf("parse target: %v", err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil || port < 1 || port > 65535 {
		fatalf("invalid target port: %s", portString)
	}

	request := []byte{0x05, 0x01, 0x00}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is4() {
			request = append(request, 0x01)
			request = append(request, addr.AsSlice()...)
		} else {
			request = append(request, 0x04)
			request = append(request, addr.AsSlice()...)
		}
	} else {
		if len(host) > 255 {
			fatalf("target host too long")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, []byte(host)...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	request = append(request, portBytes[:]...)
	stream.writeBinary(request)

	reply := stream.readN(4)
	if !bytes.Equal(reply[:3], []byte{0x05, 0x00, 0x00}) {
		fatalf("unexpected SOCKS connect response: %x", reply)
	}
	switch reply[3] {
	case 0x01:
		stream.readN(4 + 2)
	case 0x03:
		length := int(stream.readN(1)[0])
		stream.readN(length + 2)
	case 0x04:
		stream.readN(16 + 2)
	default:
		fatalf("unexpected SOCKS bind address type: %d", reply[3])
	}

	httpRequest := fmt.Sprintf(
		"GET /payload.bin HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		*target,
	)
	stream.writeBinary([]byte(httpRequest))

	headers := stream.readUntil([]byte("\r\n\r\n"))
	headerText := string(headers)
	if !strings.HasPrefix(headerText, "HTTP/1.0 200 ") && !strings.HasPrefix(headerText, "HTTP/1.1 200 ") {
		fatalf("unexpected HTTP response headers: %q", headerText)
	}
	contentLength := -1
	for _, line := range strings.Split(headerText, "\r\n") {
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			contentLength, err = strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				fatalf("invalid Content-Length: %v", err)
			}
		}
	}
	if contentLength < 0 {
		fatalf("missing Content-Length")
	}

	body := stream.readN(contentLength)
	sum := sha256.Sum256(body)
	actualSHA256 := hex.EncodeToString(sum[:])
	if actualSHA256 != *expectedSHA256 {
		fatalf("sha256 mismatch: got %s want %s", actualSHA256, *expectedSHA256)
	}

	fmt.Printf("websocket socks download ok bytes=%d target=%s\n", len(body), *target)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
GO

  (
    cd "${TMP_DIR}/go-client"
    GOWORK=off go mod tidy
    GOWORK=off go build -o "${TMP_DIR}/websocket-socks-client" .
  )
}

start_proxy() {
  e2e_section "websocket-socks proxy"
  e2e_assert_port_free "${E2E_WEBSOCKET_PROXY_PORT}" "websocket-socks proxy"
  RUST_LOG="${E2E_SHOES_LOG_LEVEL}" "${E2E_BASIC_PROXY_BIN}" \
    --listen "${E2E_BIND_HOST}:${E2E_WEBSOCKET_PROXY_PORT}" \
    --protocol websocket-socks \
    >"${TMP_DIR}/websocket-socks-proxy.log" 2>&1 &
  PROXY_PID=$!
  wait_for_tcp_port "${E2E_WEBSOCKET_PROXY_PORT}" "websocket-socks proxy"
}

run_check() {
  e2e_section "download"
  "${TMP_DIR}/websocket-socks-client" \
    --ws "ws://${E2E_BIND_HOST}:${E2E_WEBSOCKET_PROXY_PORT}/ws" \
    --target "${E2E_BIND_HOST}:${E2E_HTTP_TARGET_PORT}" \
    --sha256 "${PAYLOAD_SHA256}" \
    --timeout "${E2E_CLIENT_TIMEOUT_SECS}"
}

main() {
  parse_args "$@"
  TMP_DIR="$(mktemp -d /tmp/shoes-websocket-proxy-e2e.XXXXXX)"

  resolve_binaries
  start_http_target
  build_go_client
  start_proxy
  run_check

  e2e_section "websocket proxy interop passed"
}

main "$@"
