#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/scripts"

# shellcheck source=scripts/v2board_e2e_common.sh
source "${SCRIPT_DIR}/v2board_e2e_common.sh"

trap e2e_on_error ERR

MIHOMO_DIR="${MIHOMO_DIR:-${ROOT_DIR}/../mihomo-1.19.24}"
E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_SNELL_PORT="${E2E_SNELL_PORT:-18190}"
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18191}"
E2E_UDP_ECHO_PORT="${E2E_UDP_ECHO_PORT:-18192}"
E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB:-128}"
E2E_UDP_PAYLOAD_SIZE="${E2E_UDP_PAYLOAD_SIZE:-4096}"
E2E_SNELL_PASSWORD="${E2E_SNELL_PASSWORD:-secretpass}"
E2E_SHOES_LOG_LEVEL="${E2E_SHOES_LOG_LEVEL:-info}"
E2E_SNELL_SERVER_BIN_EXPLICIT=0
if [[ -n "${E2E_SNELL_SERVER_BIN:-}" ]]; then
  E2E_SNELL_SERVER_BIN_EXPLICIT=1
fi
E2E_SNELL_SERVER_BIN="${E2E_SNELL_SERVER_BIN:-${ROOT_DIR}/target/debug/shoes-snell-e2e-server}"

TMP_DIR=""
HTTP_PID=""
UDP_ECHO_PID=""
SNELL_PID=""

usage() {
  cat <<'EOF'
Usage:
  scripts/e2e_snell_mihomo.sh

Runs Snell v3 TCP and UDP-over-TCP interop against shoes using the mihomo Snell
client implementation from a local checkout.

Environment:
  MIHOMO_DIR                 Local mihomo checkout. Default: ../mihomo-1.19.24.
  E2E_SNELL_SERVER_BIN       Optional prebuilt shoes-snell-e2e-server.
  E2E_SNELL_PORT             Snell server TCP port. Default: 18190.
  E2E_HTTP_PORT              HTTP target TCP port. Default: 18191.
  E2E_UDP_ECHO_PORT          UDP echo target port. Default: 18192.
  E2E_PAYLOAD_KIB            HTTP payload size. Default: 128.
  E2E_UDP_PAYLOAD_SIZE       UDP datagram size. Default: 4096.
EOF
}

cleanup() {
  local status=$?
  set +e
  for pid in "${SNELL_PID}" "${HTTP_PID}" "${UDP_ECHO_PID}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  if [[ "${status}" -ne 0 && -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    e2e_warn "temporary logs kept for failure analysis: ${TMP_DIR}"
  elif [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    rm -rf "${TMP_DIR}"
  fi
  exit "${status}"
}

trap cleanup EXIT

parse_args() {
  case "${1:-}" in
    "")
      ;;
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
    for pid in "${SNELL_PID}" "${HTTP_PID}"; do
      if [[ -n "${pid}" ]] && ! kill -0 "${pid}" 2>/dev/null; then
        e2e_die "${label} process exited before listening on ${port}"
      fi
    done
    now="$(date +%s)"
    if ((now - start >= timeout)); then
      e2e_die "${label} did not listen on TCP port ${port} within ${timeout}s"
    fi
    sleep 0.2
  done
}

wait_for_udp_port() {
  local port="$1"
  local label="$2"
  local timeout="${3:-15}"
  local start
  local now

  start="$(date +%s)"
  while true; do
    if ss -lun | awk '{print $4}' | grep -Eq "(^|:)${port}$"; then
      return
    fi
    if [[ -n "${UDP_ECHO_PID}" ]] && ! kill -0 "${UDP_ECHO_PID}" 2>/dev/null; then
      e2e_die "${label} process exited before listening on UDP ${port}"
    fi
    now="$(date +%s)"
    if ((now - start >= timeout)); then
      e2e_die "${label} did not listen on UDP port ${port} within ${timeout}s"
    fi
    sleep 0.2
  done
}

check_environment() {
  e2e_section "environment"
  e2e_require_command cargo
  e2e_require_command go
  e2e_require_command python3
  e2e_require_command ss
  e2e_require_dir "${MIHOMO_DIR}" "mihomo checkout"
  e2e_require_file "${MIHOMO_DIR}/go.mod" "mihomo go.mod"

  e2e_assert_port_free "${E2E_SNELL_PORT}" "Snell server"
  e2e_assert_port_free "${E2E_HTTP_PORT}" "HTTP target"
  e2e_assert_udp_port_free "${E2E_UDP_ECHO_PORT}" "UDP echo target"
}

build_binaries() {
  e2e_section "binaries"
  if ((E2E_SNELL_SERVER_BIN_EXPLICIT == 0)); then
    e2e_run cargo build \
      --manifest-path "${ROOT_DIR}/Cargo.toml" \
      --features e2e-client \
      --bin shoes-snell-e2e-server
  elif [[ ! -x "${E2E_SNELL_SERVER_BIN}" ]]; then
    e2e_die "E2E_SNELL_SERVER_BIN is not executable: ${E2E_SNELL_SERVER_BIN}"
  fi
  [[ -x "${E2E_SNELL_SERVER_BIN}" ]] || e2e_die "E2E_SNELL_SERVER_BIN is not executable: ${E2E_SNELL_SERVER_BIN}"

  cat >"${TMP_DIR}/snell_e2e_client.go" <<'GO'
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/transport/snell"
)

func main() {
	server := flag.String("server", "", "Snell server host:port")
	psk := flag.String("psk", "", "Snell PSK")
	mode := flag.String("mode", "tcp", "tcp or udp")
	target := flag.String("target", "", "target host:port")
	output := flag.String("output", "", "TCP body output path")
	udpPayloadSize := flag.Int("udp-payload-size", 4096, "UDP payload size")
	timeout := flag.Duration("timeout", 15*time.Second, "overall network timeout")
	flag.Parse()

	if *server == "" || *psk == "" || *target == "" {
		fatal(errors.New("missing --server, --psk, or --target"))
	}

	switch *mode {
	case "tcp":
		if *output == "" {
			fatal(errors.New("missing --output for tcp mode"))
		}
		fatal(runTCP(*server, *psk, *target, *output, *timeout))
	case "udp":
		fatal(runUDP(*server, *psk, *target, *udpPayloadSize, *timeout))
	default:
		fatal(fmt.Errorf("unknown mode %q", *mode))
	}
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func dialSnell(server string, psk string, timeout time.Duration) (*snell.Snell, error) {
	conn, err := net.DialTimeout("tcp", server, timeout)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return snell.StreamConn(conn, []byte(psk), snell.Version3), nil
}

func runTCP(server string, psk string, target string, output string, timeout time.Duration) error {
	host, port, err := splitHostPort(target)
	if err != nil {
		return err
	}
	conn, err := dialSnell(server, psk, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := snell.WriteHeader(conn, host, uint(port), snell.Version3); err != nil {
		return err
	}
	request := fmt.Sprintf("GET /payload.bin HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: shoes-snell-e2e-client/1\r\nAccept: */*\r\n\r\n", target)
	if _, err := conn.Write([]byte(request)); err != nil {
		return err
	}
	response, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	body, err := httpBody(response)
	if err != nil {
		return err
	}
	if err := os.WriteFile(output, body, 0o644); err != nil {
		return err
	}
	fmt.Printf("snell tcp download ok bytes=%d target=%s\n", len(body), target)
	return nil
}

func runUDP(server string, psk string, target string, payloadSize int, timeout time.Duration) error {
	if payloadSize < 0 {
		return errors.New("negative UDP payload size")
	}
	conn, err := dialSnell(server, psk, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := snell.WriteUDPHeader(conn, snell.Version3); err != nil {
		return err
	}

	packetConn := snell.PacketConn(conn)
	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}
	payload := deterministicPayload(payloadSize)
	if _, err := packetConn.WriteTo(payload, targetAddr); err != nil {
		return err
	}

	reply := make([]byte, payloadSize+1024)
	n, source, err := packetConn.ReadFrom(reply)
	if err != nil {
		return err
	}
	if !bytes.Equal(reply[:n], payload) {
		return fmt.Errorf("UDP echo mismatch: got %d bytes from %s, want %d", n, source, len(payload))
	}
	fmt.Printf("snell udp echo ok bytes=%d source=%s\n", n, source)
	return nil
}

func splitHostPort(value string) (string, uint64, error) {
	host, portString, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func httpBody(response []byte) ([]byte, error) {
	parts := bytes.SplitN(response, []byte("\r\n\r\n"), 2)
	if len(parts) != 2 {
		return nil, errors.New("HTTP response missing header terminator")
	}
	statusLine, _, _ := strings.Cut(string(parts[0]), "\r\n")
	if !strings.Contains(statusLine, " 200 ") {
		return nil, fmt.Errorf("unexpected HTTP status line: %s", statusLine)
	}
	return parts[1], nil
}

func deterministicPayload(size int) []byte {
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte((i*31 + 17) % 251)
	}
	return payload
}
GO

  e2e_run go -C "${MIHOMO_DIR}" build -o "${TMP_DIR}/snell-e2e-client" "${TMP_DIR}/snell_e2e_client.go"
}

start_http_target() {
  e2e_section "start HTTP target"
  mkdir -p "${TMP_DIR}/www"
  python3 - "${TMP_DIR}/www/payload.bin" "${E2E_PAYLOAD_KIB}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
size = int(sys.argv[2]) * 1024
path.write_bytes(bytes((i * 13 + 7) % 251 for i in range(size)))
PY
  python3 -m http.server "${E2E_HTTP_PORT}" \
    --bind "${E2E_BIND_HOST}" \
    --directory "${TMP_DIR}/www" \
    >"${TMP_DIR}/http.log" 2>&1 &
  HTTP_PID=$!
  wait_for_tcp_port "${E2E_HTTP_PORT}" "HTTP target" 10
}

start_udp_echo_target() {
  e2e_section "start UDP echo target"
  cat >"${TMP_DIR}/udp_echo.py" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((host, port))
while True:
    data, addr = sock.recvfrom(65535)
    sock.sendto(data, addr)
PY
  python3 "${TMP_DIR}/udp_echo.py" "${E2E_BIND_HOST}" "${E2E_UDP_ECHO_PORT}" >"${TMP_DIR}/udp-echo.log" 2>&1 &
  UDP_ECHO_PID=$!
  wait_for_udp_port "${E2E_UDP_ECHO_PORT}" "UDP echo target" 10
}

start_snell_server() {
  e2e_section "start shoes Snell server"
  RUST_LOG="${E2E_SHOES_LOG_LEVEL}" "${E2E_SNELL_SERVER_BIN}" \
    --listen "${E2E_BIND_HOST}:${E2E_SNELL_PORT}" \
    --cipher aes-128-gcm \
    --password "${E2E_SNELL_PASSWORD}" \
    --udp-enabled true \
    >"${TMP_DIR}/snell-server.log" 2>&1 &
  SNELL_PID=$!
  wait_for_tcp_port "${E2E_SNELL_PORT}" "shoes Snell server" 10
}

run_tcp_case() {
  e2e_section "snell tcp"
  "${TMP_DIR}/snell-e2e-client" \
    --server "${E2E_BIND_HOST}:${E2E_SNELL_PORT}" \
    --psk "${E2E_SNELL_PASSWORD}" \
    --mode tcp \
    --target "${E2E_BIND_HOST}:${E2E_HTTP_PORT}" \
    --output "${TMP_DIR}/download.bin" \
    --timeout 15s
  cmp "${TMP_DIR}/www/payload.bin" "${TMP_DIR}/download.bin"
}

run_udp_case() {
  e2e_section "snell udp"
  "${TMP_DIR}/snell-e2e-client" \
    --server "${E2E_BIND_HOST}:${E2E_SNELL_PORT}" \
    --psk "${E2E_SNELL_PASSWORD}" \
    --mode udp \
    --target "${E2E_BIND_HOST}:${E2E_UDP_ECHO_PORT}" \
    --udp-payload-size "${E2E_UDP_PAYLOAD_SIZE}" \
    --timeout 15s
}

main() {
  parse_args "$@"
  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/shoes-snell-mihomo-e2e.XXXXXX")"
  check_environment
  build_binaries
  start_http_target
  start_udp_echo_target
  start_snell_server
  run_tcp_case
  run_udp_case
  e2e_section "snell mihomo interop passed"
}

main "$@"
