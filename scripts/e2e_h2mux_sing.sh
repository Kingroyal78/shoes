#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/scripts"

# shellcheck source=scripts/v2board_e2e_common.sh
source "${SCRIPT_DIR}/v2board_e2e_common.sh"

trap e2e_on_error ERR

E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_HTTP_TARGET_PORT="${E2E_HTTP_TARGET_PORT:-18216}"
E2E_H2MUX_PORT="${E2E_H2MUX_PORT:-18215}"
E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB:-128}"
E2E_SHOES_LOG_LEVEL="${E2E_SHOES_LOG_LEVEL:-info}"
E2E_CLIENT_TIMEOUT_SECS="${E2E_CLIENT_TIMEOUT_SECS:-30}"
E2E_BASIC_PROXY_BIN="${E2E_BASIC_PROXY_BIN:-${ROOT_DIR}/target/debug/shoes-basic-proxy-e2e-server}"
E2E_BASIC_PROXY_BIN_EXPLICIT="${E2E_BASIC_PROXY_BIN_EXPLICIT:-0}"

TMP_DIR=""
HTTP_PID=""
H2MUX_PID=""
PAYLOAD_SHA256=""

usage() {
  cat <<'EOF'
Usage:
  scripts/e2e_h2mux_sing.sh

Runs real h2mux interop checks:
  - shoes exposes a raw h2mux session using the production h2mux server handler.
  - a Go client built against github.com/sagernet/sing-mux opens TCP streams.
  - both unpadded and padded h2mux sessions download a deterministic HTTP payload.
EOF
}

cleanup() {
  local status=$?
  set +e

  if [[ -n "${H2MUX_PID}" ]] && kill -0 "${H2MUX_PID}" 2>/dev/null; then
    kill "${H2MUX_PID}" 2>/dev/null || true
    wait "${H2MUX_PID}" 2>/dev/null || true
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
    if [[ -n "${H2MUX_PID}" ]] && ! kill -0 "${H2MUX_PID}" 2>/dev/null; then
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
  e2e_assert_port_free "${E2E_HTTP_TARGET_PORT}" "h2mux http target"

  mkdir -p "${TMP_DIR}/www"
  PAYLOAD_PATH="${TMP_DIR}/www/payload.bin"
  PAYLOAD_SHA256="$(
    PAYLOAD_PATH="${PAYLOAD_PATH}" E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB}" python3 <<'PY'
import hashlib
import os
from pathlib import Path

path = Path(os.environ["PAYLOAD_PATH"])
size = int(os.environ["E2E_PAYLOAD_KIB"]) * 1024
data = bytes(((i * 19 + 5) % 256 for i in range(size)))
path.write_bytes(data)
print(hashlib.sha256(data).hexdigest())
PY
  )"

  python3 -m http.server "${E2E_HTTP_TARGET_PORT}" \
    --bind "${E2E_BIND_HOST}" \
    --directory "${TMP_DIR}/www" \
    >"${TMP_DIR}/http-target.log" 2>&1 &
  HTTP_PID=$!
  wait_for_tcp_port "${E2E_HTTP_TARGET_PORT}" "h2mux http target"
}

build_go_client() {
  e2e_section "sing-mux client"
  mkdir -p "${TMP_DIR}/go-client"

  cat >"${TMP_DIR}/go-client/go.mod" <<'GO'
module shoes_h2mux_e2e

go 1.22

require github.com/sagernet/sing-mux v0.3.5
GO

  cat >"${TMP_DIR}/go-client/main.go" <<'GO'
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	mux "github.com/sagernet/sing-mux"
	M "github.com/sagernet/sing/common/metadata"
)

type fixedDialer struct {
	server  string
	timeout time.Duration
}

func (d fixedDialer) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	dialer := net.Dialer{Timeout: d.timeout}
	return dialer.DialContext(ctx, "tcp", d.server)
}

func (d fixedDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func main() {
	server := flag.String("server", "", "raw h2mux server address")
	target := flag.String("target", "", "target host:port")
	expectedSHA256 := flag.String("sha256", "", "expected payload sha256")
	padding := flag.Bool("padding", false, "enable h2mux padding")
	timeoutSeconds := flag.Int("timeout", 30, "timeout in seconds")
	flag.Parse()

	if *server == "" || *target == "" || *expectedSHA256 == "" {
		fatalf("missing required arguments")
	}

	timeout := time.Duration(*timeoutSeconds) * time.Second
	client, err := mux.NewClient(mux.Options{
		Dialer:         fixedDialer{server: *server, timeout: timeout},
		Protocol:       "h2mux",
		MaxConnections: 1,
		MinStreams:     1,
		Padding:        *padding,
	})
	if err != nil {
		fatalf("create sing-mux client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	destination := M.ParseSocksaddr(*target)
	if !destination.IsValid() {
		fatalf("invalid target: %s", *target)
	}
	conn, err := client.DialContext(ctx, "tcp", destination)
	if err != nil {
		fatalf("open h2mux stream: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	request := fmt.Sprintf(
		"GET /payload.bin HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		*target,
	)
	if _, err := conn.Write([]byte(request)); err != nil {
		fatalf("write HTTP request over h2mux: %v", err)
	}

	response, err := http.ReadResponse(bufioReader(conn), nil)
	if err != nil {
		fatalf("read HTTP response over h2mux: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		fatalf("unexpected HTTP status: %s", response.Status)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		fatalf("read HTTP body: %v", err)
	}
	sum := sha256.Sum256(body)
	actualSHA256 := hex.EncodeToString(sum[:])
	if actualSHA256 != *expectedSHA256 {
		fatalf("sha256 mismatch: got %s want %s", actualSHA256, *expectedSHA256)
	}

	fmt.Printf("h2mux download ok padding=%v bytes=%d target=%s\n", *padding, len(body), *target)
}

func bufioReader(conn net.Conn) *bufio.Reader {
	return bufio.NewReader(conn)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
GO

  (
    cd "${TMP_DIR}/go-client"
    GOWORK=off go mod tidy
    GOWORK=off go build -o "${TMP_DIR}/sing-mux-client" .
  )
}

start_h2mux_server() {
  e2e_section "h2mux server"
  e2e_assert_port_free "${E2E_H2MUX_PORT}" "h2mux server"
  RUST_LOG="${E2E_SHOES_LOG_LEVEL}" "${E2E_BASIC_PROXY_BIN}" \
    --listen "${E2E_BIND_HOST}:${E2E_H2MUX_PORT}" \
    --protocol h2mux \
    >"${TMP_DIR}/h2mux-server.log" 2>&1 &
  H2MUX_PID=$!
  wait_for_tcp_port "${E2E_H2MUX_PORT}" "h2mux server"
}

run_client() {
  local padding="$1"
  e2e_section "download padding=${padding}"
  "${TMP_DIR}/sing-mux-client" \
    --server "${E2E_BIND_HOST}:${E2E_H2MUX_PORT}" \
    --target "${E2E_BIND_HOST}:${E2E_HTTP_TARGET_PORT}" \
    --sha256 "${PAYLOAD_SHA256}" \
    --timeout "${E2E_CLIENT_TIMEOUT_SECS}" \
    --padding="${padding}"
}

main() {
  parse_args "$@"
  TMP_DIR="$(mktemp -d /tmp/shoes-h2mux-e2e.XXXXXX)"

  resolve_binaries
  start_http_target
  build_go_client
  start_h2mux_server
  run_client false
  run_client true

  e2e_section "h2mux sing-mux interop passed"
}

main "$@"
