#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/scripts"

# shellcheck source=scripts/v2board_e2e_common.sh
source "${SCRIPT_DIR}/v2board_e2e_common.sh"

trap e2e_on_error ERR

SING_BOX_DIR="${SING_BOX_DIR:-${ROOT_DIR}/../sing-box}"
E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_HTTP_TARGET_PORT="${E2E_HTTP_TARGET_PORT:-18219}"
E2E_PROXY_PORT="${E2E_PROXY_PORT:-18218}"
E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB:-128}"
E2E_SHOES_LOG_LEVEL="${E2E_SHOES_LOG_LEVEL:-info}"
E2E_CLIENT_TIMEOUT_SECS="${E2E_CLIENT_TIMEOUT_SECS:-30}"
E2E_SS_PASSWORD="${E2E_SS_PASSWORD:-shoes-e2e-password}"
E2E_SS_2022_AES128_PASSWORD="${E2E_SS_2022_AES128_PASSWORD:-c2hvZXMtZTJlLWtleS0xNg==}"
E2E_BASIC_PROXY_BIN="${E2E_BASIC_PROXY_BIN:-${ROOT_DIR}/target/debug/shoes-basic-proxy-e2e-server}"
E2E_BASIC_PROXY_BIN_EXPLICIT="${E2E_BASIC_PROXY_BIN_EXPLICIT:-0}"

TMP_DIR=""
HTTP_PID=""
PROXY_PID=""
PAYLOAD_SHA256=""

usage() {
  cat <<'EOF'
Usage:
  scripts/e2e_shadowsocks_trojan_sing.sh

Runs real-client Shadowsocks and Trojan protocol checks:
  - github.com/sagernet/sing-shadowsocks legacy AEAD client downloads through shoes.
  - github.com/sagernet/sing-shadowsocks 2022 client downloads through shoes.
  - sing-box transport/trojan client downloads through shoes raw Trojan.

Environment:
  SING_BOX_DIR                       Local sing-box/singlink checkout for Trojan client package.
  E2E_BASIC_PROXY_BIN                Optional prebuilt shoes-basic-proxy-e2e-server.
  E2E_PROXY_PORT                     Shoes proxy port. Default: 18218.
  E2E_HTTP_TARGET_PORT               HTTP target port. Default: 18219.
  E2E_PAYLOAD_KIB                    HTTP payload size. Default: 128.
EOF
}

cleanup() {
  local status=$?
  set +e

  stop_proxy
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
  e2e_require_dir "${SING_BOX_DIR}" "sing-box checkout"
  e2e_require_file "${SING_BOX_DIR}/go.mod" "sing-box go.mod"

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
  e2e_assert_port_free "${E2E_HTTP_TARGET_PORT}" "Shadowsocks/Trojan HTTP target"

  mkdir -p "${TMP_DIR}/www"
  PAYLOAD_PATH="${TMP_DIR}/www/payload.bin"
  PAYLOAD_SHA256="$(
    PAYLOAD_PATH="${PAYLOAD_PATH}" E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB}" python3 <<'PY'
import hashlib
import os
from pathlib import Path

path = Path(os.environ["PAYLOAD_PATH"])
size = int(os.environ["E2E_PAYLOAD_KIB"]) * 1024
data = bytes(((i * 29 + 11) % 256 for i in range(size)))
path.write_bytes(data)
print(hashlib.sha256(data).hexdigest())
PY
  )"

  python3 -m http.server "${E2E_HTTP_TARGET_PORT}" \
    --bind "${E2E_BIND_HOST}" \
    --directory "${TMP_DIR}/www" \
    >"${TMP_DIR}/http-target.log" 2>&1 &
  HTTP_PID=$!
  wait_for_tcp_port "${E2E_HTTP_TARGET_PORT}" "Shadowsocks/Trojan HTTP target"
}

build_go_client() {
  e2e_section "sing client"
  mkdir -p "${TMP_DIR}/go-client"

  cat >"${TMP_DIR}/go-client/go.mod" <<GO
module shoes_ss_trojan_e2e

go 1.25

require (
	github.com/sagernet/sing-shadowsocks v0.2.9
	github.com/singlink/singlink v0.0.0
)

replace github.com/singlink/singlink => ${SING_BOX_DIR}
GO

  cat >"${TMP_DIR}/go-client/main.go" <<'GO'
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowimpl"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/singlink/singlink/transport/trojan"
)

func main() {
	mode := flag.String("mode", "", "ss or trojan")
	server := flag.String("server", "", "proxy server host:port")
	target := flag.String("target", "", "target host:port")
	methodName := flag.String("method", "", "Shadowsocks method")
	password := flag.String("password", "", "proxy password")
	expectedSHA256 := flag.String("sha256", "", "expected payload sha256")
	timeoutSeconds := flag.Int("timeout", 30, "timeout in seconds")
	flag.Parse()

	if *mode == "" || *server == "" || *target == "" || *password == "" || *expectedSHA256 == "" {
		fatalf("missing required arguments")
	}

	timeout := time.Duration(*timeoutSeconds) * time.Second
	tcp, err := net.DialTimeout("tcp", *server, timeout)
	if err != nil {
		fatalf("dial proxy: %v", err)
	}

	destination := M.ParseSocksaddr(*target)
	if !destination.IsValid() {
		fatalf("invalid target: %s", *target)
	}

	var conn net.Conn
	switch *mode {
	case "ss":
		if *methodName == "" {
			fatalf("missing Shadowsocks method")
		}
		method, err := shadowimpl.FetchMethod(*methodName, *password, nil)
		if err != nil {
			fatalf("create Shadowsocks method: %v", err)
		}
		conn = method.DialEarlyConn(tcp, destination)
	case "trojan":
		conn = trojan.NewClientConn(tcp, trojan.Key(*password), destination)
	default:
		fatalf("unknown mode: %s", *mode)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	body := download(conn, *target)
	sum := sha256.Sum256(body)
	actualSHA256 := hex.EncodeToString(sum[:])
	if actualSHA256 != *expectedSHA256 {
		fatalf("sha256 mismatch: got %s want %s", actualSHA256, *expectedSHA256)
	}

	fmt.Printf("%s download ok bytes=%d target=%s\n", *mode, len(body), *target)
}

func download(conn net.Conn, target string) []byte {
	request := fmt.Sprintf(
		"GET /payload.bin HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: shoes-ss-trojan-e2e/1\r\nAccept: */*\r\n\r\n",
		target,
	)
	if _, err := conn.Write([]byte(request)); err != nil {
		fatalf("write HTTP request: %v", err)
	}

	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		fatalf("read HTTP response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		fatalf("unexpected HTTP status: %s", response.Status)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		fatalf("read HTTP body: %v", err)
	}
	return body
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
GO

  e2e_run go -C "${TMP_DIR}/go-client" mod tidy
  e2e_run go -C "${TMP_DIR}/go-client" build -o "${TMP_DIR}/shoes-ss-trojan-e2e-client" .
}

start_proxy() {
  local protocol="$1"

  stop_proxy
  e2e_assert_port_free "${E2E_PROXY_PORT}" "${protocol} proxy"
  RUST_LOG="${E2E_SHOES_LOG_LEVEL}" "${E2E_BASIC_PROXY_BIN}" \
    --listen "${E2E_BIND_HOST}:${E2E_PROXY_PORT}" \
    --protocol "${protocol}" \
    >"${TMP_DIR}/${protocol}-proxy.log" 2>&1 &
  PROXY_PID=$!
  wait_for_tcp_port "${E2E_PROXY_PORT}" "${protocol} proxy"
}

stop_proxy() {
  if [[ -n "${PROXY_PID}" ]] && kill -0 "${PROXY_PID}" 2>/dev/null; then
    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true
  fi
  PROXY_PID=""
}

run_client() {
  local mode="$1"
  local method="$2"
  local password="$3"
  local label="$4"

  "${TMP_DIR}/shoes-ss-trojan-e2e-client" \
    --mode "${mode}" \
    --server "${E2E_BIND_HOST}:${E2E_PROXY_PORT}" \
    --target "${E2E_BIND_HOST}:${E2E_HTTP_TARGET_PORT}" \
    --method "${method}" \
    --password "${password}" \
    --sha256 "${PAYLOAD_SHA256}" \
    --timeout "${E2E_CLIENT_TIMEOUT_SECS}" \
    | tee "${TMP_DIR}/${label}-client.log"
}

run_checks() {
  e2e_section "shadowsocks aes-128-gcm"
  start_proxy shadowsocks-aes128
  run_client ss aes-128-gcm "${E2E_SS_PASSWORD}" shadowsocks-aes128

  e2e_section "shadowsocks chacha20-ietf-poly1305"
  start_proxy shadowsocks-chacha20
  run_client ss chacha20-ietf-poly1305 "${E2E_SS_PASSWORD}" shadowsocks-chacha20

  e2e_section "shadowsocks 2022 aes-128-gcm"
  start_proxy shadowsocks-2022-aes128
  run_client ss 2022-blake3-aes-128-gcm "${E2E_SS_2022_AES128_PASSWORD}" shadowsocks-2022-aes128

  e2e_section "trojan"
  start_proxy trojan
  run_client trojan "" "${E2E_SS_PASSWORD}" trojan
}

main() {
  parse_args "$@"
  TMP_DIR="$(mktemp -d /tmp/shoes-ss-trojan-e2e.XXXXXX)"

  resolve_binaries
  start_http_target
  build_go_client
  run_checks

  e2e_section "Shadowsocks/Trojan sing interop passed"
}

main "$@"
