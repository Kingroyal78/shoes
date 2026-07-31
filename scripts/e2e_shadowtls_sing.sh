#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/scripts"

# shellcheck source=scripts/v2board_e2e_common.sh
source "${SCRIPT_DIR}/v2board_e2e_common.sh"

trap e2e_on_error ERR

SING_BOX_DIR="${SING_BOX_DIR:-${ROOT_DIR}/../sing-box}"
E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_SHADOWTLS_PORT="${E2E_SHADOWTLS_PORT:-18200}"
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18201}"
E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB:-128}"
E2E_SHADOWTLS_PASSWORD="${E2E_SHADOWTLS_PASSWORD:-shadowtls-secret}"
E2E_TLS_SERVER_NAME="${E2E_TLS_SERVER_NAME:-example.com}"
E2E_SHOES_LOG_LEVEL="${E2E_SHOES_LOG_LEVEL:-info}"
E2E_CLIENT_TIMEOUT_SECS="${E2E_CLIENT_TIMEOUT_SECS:-30}"
E2E_SHADOWTLS_SERVER_BIN="${E2E_SHADOWTLS_SERVER_BIN:-${ROOT_DIR}/target/debug/shoes-shadowtls-e2e-server}"
E2E_SHADOWTLS_SERVER_BIN_EXPLICIT="${E2E_SHADOWTLS_SERVER_BIN_EXPLICIT:-0}"

TMP_DIR=""
HTTP_PID=""
SHADOWTLS_PID=""

usage() {
  cat <<'EOF'
Usage:
  scripts/e2e_shadowtls_sing.sh

Runs a real ShadowTLS v3 interop check:
  - shoes runs a local ShadowTLS v3 server with a SOCKS5 inner protocol.
  - a Go client built against github.com/sagernet/sing-shadowtls performs the
    real v3 TLS session-id authentication handshake.
  - the client speaks SOCKS5 over the ShadowTLS stream and downloads a local
    deterministic HTTP payload.
EOF
}

cleanup() {
  local status=$?
  set +e

  if [[ -n "${SHADOWTLS_PID}" ]] && kill -0 "${SHADOWTLS_PID}" 2>/dev/null; then
    kill "${SHADOWTLS_PID}" 2>/dev/null || true
    wait "${SHADOWTLS_PID}" 2>/dev/null || true
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
    if [[ -n "${SHADOWTLS_PID}" ]] && ! kill -0 "${SHADOWTLS_PID}" 2>/dev/null; then
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
  e2e_require_command openssl
  e2e_require_command python3
  e2e_require_command ss
  e2e_require_dir "${SING_BOX_DIR}" "sing-box checkout"

  if ! e2e_bool "${E2E_SHADOWTLS_SERVER_BIN_EXPLICIT}"; then
    e2e_run cargo build \
      --manifest-path "${ROOT_DIR}/Cargo.toml" \
      --features e2e-client \
      --bin shoes-shadowtls-e2e-server
  fi
  [[ -x "${E2E_SHADOWTLS_SERVER_BIN}" ]] \
    || e2e_die "E2E_SHADOWTLS_SERVER_BIN is not executable: ${E2E_SHADOWTLS_SERVER_BIN}"
}

generate_tls_files() {
  e2e_section "tls fixture"
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -days 1 \
    -nodes \
    -subj "/CN=${E2E_TLS_SERVER_NAME}" \
    -addext "subjectAltName=DNS:${E2E_TLS_SERVER_NAME}" \
    -keyout "${TMP_DIR}/tls.key" \
    -out "${TMP_DIR}/tls.crt" \
    >/dev/null 2>&1
}

prepare_http_target() {
  e2e_section "http target"
  e2e_assert_port_free "${E2E_HTTP_PORT}" "shadowtls e2e http target"

  mkdir -p "${TMP_DIR}/www"
  PAYLOAD_PATH="${TMP_DIR}/www/payload.bin"
  PAYLOAD_SHA256="$(
    PAYLOAD_PATH="${PAYLOAD_PATH}" E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB}" python3 <<'PY'
import hashlib
import os
from pathlib import Path

path = Path(os.environ["PAYLOAD_PATH"])
size = int(os.environ["E2E_PAYLOAD_KIB"]) * 1024
data = bytes(((i * 31 + 7) % 256 for i in range(size)))
path.write_bytes(data)
print(hashlib.sha256(data).hexdigest())
PY
  )"

  python3 -m http.server "${E2E_HTTP_PORT}" \
    --bind "${E2E_BIND_HOST}" \
    --directory "${TMP_DIR}/www" \
    >"${TMP_DIR}/http.log" 2>&1 &
  HTTP_PID=$!
  wait_for_tcp_port "${E2E_HTTP_PORT}" "shadowtls e2e http target"
}

build_go_client() {
  e2e_section "sing-shadowtls client"
  cat >"${TMP_DIR}/shadowtls_e2e_client.go" <<'GO'
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	shadowtls "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/logger"
)

func main() {
	server := flag.String("server", "", "ShadowTLS server address")
	password := flag.String("password", "", "ShadowTLS password")
	sni := flag.String("sni", "", "TLS server name")
	target := flag.String("target", "", "SOCKS target address")
	expectedSHA256 := flag.String("sha256", "", "expected response body sha256")
	timeoutSeconds := flag.Int("timeout", 30, "timeout in seconds")
	flag.Parse()

	if *server == "" || *password == "" || *sni == "" || *target == "" || *expectedSHA256 == "" {
		fatalf("missing required arguments")
	}

	timeout := time.Duration(*timeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", *server)
	if err != nil {
		fatalf("dial shadowtls server: %v", err)
	}
	defer rawConn.Close()

	tlsConfig := &tls.Config{
		ServerName:         *sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	client, err := shadowtls.NewClient(shadowtls.ClientConfig{
		Version:      3,
		Password:     *password,
		TLSHandshake: shadowtls.DefaultTLSHandshakeFunc(*password, tlsConfig),
		Logger:       logger.NOP(),
	})
	if err != nil {
		fatalf("create shadowtls client: %v", err)
	}

	conn, err := client.DialContextConn(ctx, rawConn)
	if err != nil {
		fatalf("shadowtls handshake: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := socksConnect(conn, *target); err != nil {
		fatalf("socks connect: %v", err)
	}

	host, _, _ := net.SplitHostPort(*target)
	request := fmt.Sprintf("GET /payload.bin HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	if _, err := io.WriteString(conn, request); err != nil {
		fatalf("write http request: %v", err)
	}

	response, err := io.ReadAll(conn)
	if err != nil {
		fatalf("read http response: %v", err)
	}
	body, err := parseHTTPBody(response)
	if err != nil {
		fatalf("parse http response: %v", err)
	}
	sum := sha256.Sum256(body)
	actual := hex.EncodeToString(sum[:])
	if !strings.EqualFold(actual, *expectedSHA256) {
		fatalf("sha256 mismatch: got %s expected %s", actual, *expectedSHA256)
	}

	fmt.Printf("shadowtls tcp download ok bytes=%d target=%s\n", len(body), *target)
}

func socksConnect(conn net.Conn, target string) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	handshake := make([]byte, 2)
	if _, err := io.ReadFull(conn, handshake); err != nil {
		return err
	}
	if handshake[0] != 0x05 || handshake[1] != 0x00 {
		return fmt.Errorf("unexpected SOCKS method response %v", handshake)
	}

	host, portString, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := net.LookupPort("tcp", portString)
	if err != nil {
		return err
	}

	request := []byte{0x05, 0x01, 0x00}
	if ip4 := net.ParseIP(host).To4(); ip4 != nil {
		request = append(request, 0x01)
		request = append(request, ip4...)
	} else {
		if len(host) > 255 {
			return fmt.Errorf("SOCKS domain too long")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, []byte(host)...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	request = append(request, portBytes[:]...)
	if _, err := conn.Write(request); err != nil {
		return err
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x05 || header[1] != 0x00 {
		return fmt.Errorf("unexpected SOCKS connect response header %v", header)
	}
	switch header[3] {
	case 0x01:
		_, err = io.CopyN(io.Discard, conn, 4+2)
	case 0x03:
		length := make([]byte, 1)
		if _, err = io.ReadFull(conn, length); err != nil {
			return err
		}
		_, err = io.CopyN(io.Discard, conn, int64(length[0])+2)
	case 0x04:
		_, err = io.CopyN(io.Discard, conn, 16+2)
	default:
		err = fmt.Errorf("unexpected SOCKS address type %d", header[3])
	}
	return err
}

func parseHTTPBody(response []byte) ([]byte, error) {
	sep := []byte("\r\n\r\n")
	index := bytes.Index(response, sep)
	if index < 0 {
		return nil, fmt.Errorf("missing HTTP header terminator")
	}
	statusEnd := bytes.Index(response, []byte("\r\n"))
	if statusEnd < 0 {
		return nil, fmt.Errorf("missing HTTP status line")
	}
	statusLine := string(response[:statusEnd])
	if !strings.Contains(statusLine, " 200 ") {
		return nil, fmt.Errorf("unexpected HTTP status line %q", statusLine)
	}
	return response[index+len(sep):], nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
GO

  e2e_run go -C "${SING_BOX_DIR}" build \
    -o "${TMP_DIR}/shadowtls-e2e-client" \
    "${TMP_DIR}/shadowtls_e2e_client.go"
}

start_shadowtls_server() {
  e2e_section "shadowtls server"
  e2e_assert_port_free "${E2E_SHADOWTLS_PORT}" "shadowtls server"

  RUST_LOG="${E2E_SHOES_LOG_LEVEL}" "${E2E_SHADOWTLS_SERVER_BIN}" \
    --listen "${E2E_BIND_HOST}:${E2E_SHADOWTLS_PORT}" \
    --server-name "${E2E_TLS_SERVER_NAME}" \
    --password "${E2E_SHADOWTLS_PASSWORD}" \
    --cert "${TMP_DIR}/tls.crt" \
    --key "${TMP_DIR}/tls.key" \
    >"${TMP_DIR}/shadowtls-server.log" 2>&1 &
  SHADOWTLS_PID=$!
  wait_for_tcp_port "${E2E_SHADOWTLS_PORT}" "shadowtls server"
}

run_client() {
  e2e_section "interop"
  e2e_run "${TMP_DIR}/shadowtls-e2e-client" \
    --server "${E2E_BIND_HOST}:${E2E_SHADOWTLS_PORT}" \
    --password "${E2E_SHADOWTLS_PASSWORD}" \
    --sni "${E2E_TLS_SERVER_NAME}" \
    --target "${E2E_BIND_HOST}:${E2E_HTTP_PORT}" \
    --sha256 "${PAYLOAD_SHA256}" \
    --timeout "${E2E_CLIENT_TIMEOUT_SECS}"
}

main() {
  parse_args "$@"
  TMP_DIR="$(mktemp -d /tmp/shoes-shadowtls-sing-e2e.XXXXXX)"

  resolve_binaries
  generate_tls_files
  prepare_http_target
  build_go_client
  start_shadowtls_server
  run_client

  e2e_section "shadowtls sing interop passed"
}

main "$@"
