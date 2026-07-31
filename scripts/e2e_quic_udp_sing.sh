#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/scripts"

# shellcheck source=scripts/v2board_e2e_common.sh
source "${SCRIPT_DIR}/v2board_e2e_common.sh"

trap e2e_on_error ERR

SING_BOX_DIR="${SING_BOX_DIR:-${ROOT_DIR}/../sing-box}"
SINGLINK_BIN_EXPLICIT=0
if [[ -n "${SINGLINK_BIN:-}" ]]; then
  SINGLINK_BIN_EXPLICIT=1
fi
SINGLINK_BIN="${SINGLINK_BIN:-}"
SINGLINK_BUILD_TAGS="${SINGLINK_BUILD_TAGS:-with_quic}"

E2E_QUIC_SERVER_BIN_EXPLICIT=0
if [[ -n "${E2E_QUIC_SERVER_BIN:-}" ]]; then
  E2E_QUIC_SERVER_BIN_EXPLICIT=1
fi
E2E_QUIC_SERVER_BIN="${E2E_QUIC_SERVER_BIN:-${ROOT_DIR}/target/debug/shoes-quic-e2e-server}"

E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_TLS_SERVER_NAME="${E2E_TLS_SERVER_NAME:-localhost}"
E2E_TUIC_PORT="${E2E_TUIC_PORT:-18240}"
E2E_HYSTERIA2_PORT="${E2E_HYSTERIA2_PORT:-18241}"
E2E_TUIC_PROXY_PORT="${E2E_TUIC_PROXY_PORT:-18242}"
E2E_HYSTERIA2_PROXY_PORT="${E2E_HYSTERIA2_PROXY_PORT:-18243}"
E2E_UDP_ECHO_PORT="${E2E_UDP_ECHO_PORT:-18244}"
E2E_UDP_PAYLOAD_SIZE="${E2E_UDP_PAYLOAD_SIZE:-4096}"
E2E_SHOES_LOG_LEVEL="${E2E_SHOES_LOG_LEVEL:-info}"
E2E_SINGLINK_LOG_LEVEL="${E2E_SINGLINK_LOG_LEVEL:-info}"
E2E_CLIENT_TIMEOUT_SECS="${E2E_CLIENT_TIMEOUT_SECS:-15}"
E2E_TUIC_UUID="${E2E_TUIC_UUID:-d685aef3-b3c4-4932-9a9d-d0c2f6727dfa}"
E2E_TUIC_PASSWORD="${E2E_TUIC_PASSWORD:-tuic-secret}"
E2E_HYSTERIA2_PASSWORD="${E2E_HYSTERIA2_PASSWORD:-hysteria2-secret}"

TMP_DIR=""
TUIC_PID=""
HYSTERIA2_PID=""
UDP_ECHO_PID=""
SINGLINK_PID=""

usage() {
  cat <<'EOF'
Usage:
  scripts/e2e_quic_udp_sing.sh

Runs real-client UDP echo checks through singlink against shoes QUIC servers:
  - TUIC v5 with native UDP relay
  - Hysteria2 UDP relay

Environment:
  SING_BOX_DIR                 Local sing-box/singlink checkout. Default: ../sing-box.
  SINGLINK_BIN                 Optional prebuilt singlink binary.
  E2E_QUIC_SERVER_BIN          Optional prebuilt shoes-quic-e2e-server binary.
  E2E_TUIC_PORT                shoes TUIC UDP port. Default: 18240.
  E2E_HYSTERIA2_PORT           shoes Hysteria2 UDP port. Default: 18241.
  E2E_TUIC_PROXY_PORT          singlink mixed proxy port for TUIC. Default: 18242.
  E2E_HYSTERIA2_PROXY_PORT     singlink mixed proxy port for Hysteria2. Default: 18243.
  E2E_UDP_ECHO_PORT            local UDP echo target port. Default: 18244.
  E2E_UDP_PAYLOAD_SIZE         largest UDP payload size. Default: 4096.
EOF
}

cleanup() {
  local status=$?
  set +e
  stop_singlink
  for pid in "${TUIC_PID}" "${HYSTERIA2_PID}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  if [[ -n "${UDP_ECHO_PID}" ]] && kill -0 "${UDP_ECHO_PID}" 2>/dev/null; then
    kill "${UDP_ECHO_PID}" 2>/dev/null || true
    wait "${UDP_ECHO_PID}" 2>/dev/null || true
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
    for pid in "${SINGLINK_PID}"; do
      if [[ -n "${pid}" ]] && ! kill -0 "${pid}" 2>/dev/null; then
        e2e_die "${label} process exited before listening on TCP ${port}"
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
    for pid in "${TUIC_PID}" "${HYSTERIA2_PID}" "${UDP_ECHO_PID}"; do
      if [[ -n "${pid}" ]] && ! kill -0 "${pid}" 2>/dev/null; then
        e2e_die "${label} process exited before listening on UDP ${port}"
      fi
    done
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
  e2e_require_command openssl
  e2e_require_command python3
  e2e_require_command ss
  if ((SINGLINK_BIN_EXPLICIT == 0)); then
    e2e_require_dir "${SING_BOX_DIR}" "sing-box checkout"
    e2e_require_file "${SING_BOX_DIR}/go.mod" "sing-box go.mod"
  fi

  e2e_assert_udp_port_free "${E2E_TUIC_PORT}" "shoes TUIC"
  e2e_assert_udp_port_free "${E2E_HYSTERIA2_PORT}" "shoes Hysteria2"
  e2e_assert_port_free "${E2E_TUIC_PROXY_PORT}" "singlink TUIC proxy"
  e2e_assert_port_free "${E2E_HYSTERIA2_PROXY_PORT}" "singlink Hysteria2 proxy"
  e2e_assert_udp_port_free "${E2E_UDP_ECHO_PORT}" "UDP echo target"
}

build_binaries() {
  e2e_section "binaries"
  if ((E2E_QUIC_SERVER_BIN_EXPLICIT == 0)); then
    e2e_run cargo build \
      --manifest-path "${ROOT_DIR}/Cargo.toml" \
      --features e2e-client \
      --bin shoes-quic-e2e-server
  elif [[ ! -x "${E2E_QUIC_SERVER_BIN}" ]]; then
    e2e_die "E2E_QUIC_SERVER_BIN is not executable: ${E2E_QUIC_SERVER_BIN}"
  fi
  [[ -x "${E2E_QUIC_SERVER_BIN}" ]] \
    || e2e_die "E2E_QUIC_SERVER_BIN is not executable: ${E2E_QUIC_SERVER_BIN}"

  if [[ -z "${SINGLINK_BIN}" ]]; then
    SINGLINK_BIN="${TMP_DIR}/singlink"
    if [[ -n "${SINGLINK_BUILD_TAGS}" ]]; then
      e2e_run go -C "${SING_BOX_DIR}" build -tags "${SINGLINK_BUILD_TAGS}" -o "${SINGLINK_BIN}" ./cmd/singlink
    else
      e2e_run go -C "${SING_BOX_DIR}" build -o "${SINGLINK_BIN}" ./cmd/singlink
    fi
  fi
  [[ -x "${SINGLINK_BIN}" ]] || e2e_die "SINGLINK_BIN is not executable: ${SINGLINK_BIN}"
}

generate_tls() {
  e2e_section "tls"
  e2e_run openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -keyout "${TMP_DIR}/tls.key" \
    -out "${TMP_DIR}/tls.crt" \
    -days 1 \
    -subj "/CN=${E2E_TLS_SERVER_NAME}" \
    -addext "subjectAltName=DNS:${E2E_TLS_SERVER_NAME},IP:${E2E_BIND_HOST}" \
    >"${TMP_DIR}/openssl.log" 2>&1
}

start_shoes_quic_servers() {
  e2e_section "shoes quic"
  RUST_LOG="${E2E_SHOES_LOG_LEVEL}" "${E2E_QUIC_SERVER_BIN}" \
    --listen "${E2E_BIND_HOST}:${E2E_TUIC_PORT}" \
    --protocol tuic \
    --uuid "${E2E_TUIC_UUID}" \
    --password "${E2E_TUIC_PASSWORD}" \
    --cert "${TMP_DIR}/tls.crt" \
    --key "${TMP_DIR}/tls.key" \
    --zero-rtt-handshake true \
    >"${TMP_DIR}/tuic-shoes.log" 2>&1 &
  TUIC_PID=$!
  wait_for_udp_port "${E2E_TUIC_PORT}" "shoes TUIC"

  RUST_LOG="${E2E_SHOES_LOG_LEVEL}" "${E2E_QUIC_SERVER_BIN}" \
    --listen "${E2E_BIND_HOST}:${E2E_HYSTERIA2_PORT}" \
    --protocol hysteria2 \
    --password "${E2E_HYSTERIA2_PASSWORD}" \
    --cert "${TMP_DIR}/tls.crt" \
    --key "${TMP_DIR}/tls.key" \
    >"${TMP_DIR}/hysteria2-shoes.log" 2>&1 &
  HYSTERIA2_PID=$!
  wait_for_udp_port "${E2E_HYSTERIA2_PORT}" "shoes Hysteria2"
}

start_udp_echo() {
  e2e_section "udp echo target"
  E2E_BIND_HOST="${E2E_BIND_HOST}" \
    E2E_UDP_ECHO_PORT="${E2E_UDP_ECHO_PORT}" \
    python3 >"${TMP_DIR}/udp-echo.log" 2>&1 <<'PY' &
import os
import socket
import sys

host = os.environ["E2E_BIND_HOST"]
port = int(os.environ["E2E_UDP_ECHO_PORT"])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((host, port))
print(f"udp echo listening on {host}:{port}", flush=True)

while True:
    data, addr = sock.recvfrom(65535)
    sock.sendto(data, addr)
PY
  UDP_ECHO_PID=$!
  wait_for_udp_port "${E2E_UDP_ECHO_PORT}" "UDP echo target"
}

write_singlink_config() {
  local protocol="$1"
  local server_port="$2"
  local proxy_port="$3"
  local outbound_tag="${protocol}-out"
  local outbound_json=""

  case "${protocol}" in
    tuic)
      outbound_json=$(cat <<JSON
{
  "type": "tuic",
  "tag": "${outbound_tag}",
  "server": "${E2E_BIND_HOST}",
  "server_port": ${server_port},
  "uuid": "${E2E_TUIC_UUID}",
  "password": "${E2E_TUIC_PASSWORD}",
  "congestion_control": "cubic",
  "udp_relay_mode": "native",
  "zero_rtt_handshake": true,
  "network": "udp",
  "tls": {
    "enabled": true,
    "server_name": "${E2E_TLS_SERVER_NAME}",
    "certificate_path": "${TMP_DIR}/tls.crt",
    "alpn": ["h3"]
  }
}
JSON
)
      ;;
    hysteria2)
      outbound_json=$(cat <<JSON
{
  "type": "hysteria2",
  "tag": "${outbound_tag}",
  "server": "${E2E_BIND_HOST}",
  "server_port": ${server_port},
  "password": "${E2E_HYSTERIA2_PASSWORD}",
  "up_mbps": 100,
  "down_mbps": 100,
  "network": "udp",
  "tls": {
    "enabled": true,
    "server_name": "${E2E_TLS_SERVER_NAME}",
    "certificate_path": "${TMP_DIR}/tls.crt",
    "alpn": ["h3"]
  }
}
JSON
)
      ;;
    *)
      e2e_die "unknown protocol for singlink config: ${protocol}"
      ;;
  esac

  cat >"${TMP_DIR}/${protocol}.singlink.json" <<JSON
{
  "log": {"level": "${E2E_SINGLINK_LOG_LEVEL}", "timestamp": true},
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "${E2E_BIND_HOST}",
      "listen_port": ${proxy_port}
    }
  ],
  "outbounds": [
    ${outbound_json}
  ],
  "route": {"final": "${outbound_tag}"}
}
JSON
}

start_singlink() {
  local protocol="$1"
  local proxy_port="$2"

  stop_singlink
  "${SINGLINK_BIN}" -c "${TMP_DIR}/${protocol}.singlink.json" check \
    >"${TMP_DIR}/${protocol}.singlink-check.log" 2>&1
  e2e_assert_port_free "${proxy_port}" "singlink ${protocol}"
  "${SINGLINK_BIN}" -c "${TMP_DIR}/${protocol}.singlink.json" run \
    >"${TMP_DIR}/${protocol}.singlink.log" 2>&1 &
  SINGLINK_PID=$!
  wait_for_tcp_port "${proxy_port}" "singlink ${protocol}"
}

stop_singlink() {
  if [[ -n "${SINGLINK_PID}" ]] && kill -0 "${SINGLINK_PID}" 2>/dev/null; then
    kill "${SINGLINK_PID}" 2>/dev/null || true
    wait "${SINGLINK_PID}" 2>/dev/null || true
  fi
  SINGLINK_PID=""
}

run_udp_probe() {
  local protocol="$1"
  local proxy_port="$2"

  E2E_BIND_HOST="${E2E_BIND_HOST}" \
    E2E_PROXY_PORT="${proxy_port}" \
    E2E_UDP_ECHO_PORT="${E2E_UDP_ECHO_PORT}" \
    E2E_UDP_PAYLOAD_SIZE="${E2E_UDP_PAYLOAD_SIZE}" \
    E2E_CLIENT_TIMEOUT_SECS="${E2E_CLIENT_TIMEOUT_SECS}" \
    E2E_PROTOCOL="${protocol}" \
    python3 <<'PY'
import os
import socket
import struct
import sys

proxy_host = os.environ["E2E_BIND_HOST"]
proxy_port = int(os.environ["E2E_PROXY_PORT"])
target_host = os.environ["E2E_BIND_HOST"]
target_port = int(os.environ["E2E_UDP_ECHO_PORT"])
payload_max = int(os.environ["E2E_UDP_PAYLOAD_SIZE"])
timeout = float(os.environ["E2E_CLIENT_TIMEOUT_SECS"])
protocol = os.environ["E2E_PROTOCOL"]


def recv_exact(sock, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("unexpected EOF from SOCKS control connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_socks_addr(sock, atyp):
    if atyp == 0x01:
        addr = socket.inet_ntoa(recv_exact(sock, 4))
    elif atyp == 0x03:
        length = recv_exact(sock, 1)[0]
        addr = recv_exact(sock, length).decode("idna")
    elif atyp == 0x04:
        addr = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    else:
        raise RuntimeError(f"unsupported SOCKS address type in reply: {atyp}")
    port = struct.unpack("!H", recv_exact(sock, 2))[0]
    return addr, port


def parse_udp_packet(packet):
    if len(packet) < 10:
        raise RuntimeError(f"truncated SOCKS UDP response: {len(packet)} bytes")
    if packet[0:2] != b"\x00\x00":
        raise RuntimeError("invalid SOCKS UDP RSV field")
    if packet[2] != 0:
        raise RuntimeError("fragmented SOCKS UDP responses are not supported by this probe")
    atyp = packet[3]
    offset = 4
    if atyp == 0x01:
        offset += 4
    elif atyp == 0x03:
        if len(packet) <= offset:
            raise RuntimeError("truncated SOCKS domain address")
        offset += 1 + packet[offset]
    elif atyp == 0x04:
        offset += 16
    else:
        raise RuntimeError(f"unsupported SOCKS UDP address type: {atyp}")
    offset += 2
    if len(packet) < offset:
        raise RuntimeError("truncated SOCKS UDP address")
    return packet[offset:]


def udp_request(payload):
    target_ip = socket.inet_aton(target_host)
    return b"\x00\x00\x00\x01" + target_ip + struct.pack("!H", target_port) + payload


def deterministic_payload(size):
    return bytes(((index * 31 + 17) % 256 for index in range(size)))


with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as control:
    control.settimeout(timeout)
    control.sendall(b"\x05\x01\x00")
    if recv_exact(control, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS proxy did not accept no-auth method")

    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    version, reply, _reserved, atyp = recv_exact(control, 4)
    if version != 5 or reply != 0:
        raise RuntimeError(f"SOCKS UDP ASSOCIATE failed: version={version} reply={reply}")
    udp_host, udp_port = read_socks_addr(control, atyp)
    if udp_host in ("0.0.0.0", "::"):
        udp_host = proxy_host

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(timeout)
        for size in (1, 128, payload_max):
            payload = deterministic_payload(size)
            udp.sendto(udp_request(payload), (udp_host, udp_port))
            response, _addr = udp.recvfrom(65535)
            echoed = parse_udp_packet(response)
            if echoed != payload:
                raise RuntimeError(
                    f"UDP echo mismatch for {protocol} size={size}: got {len(echoed)} bytes"
                )
            print(f"{protocol} udp echo ok bytes={size}", flush=True)
PY
}

run_case() {
  local protocol="$1"
  local server_port="$2"
  local proxy_port="$3"

  e2e_section "${protocol} udp"
  write_singlink_config "${protocol}" "${server_port}" "${proxy_port}"
  start_singlink "${protocol}" "${proxy_port}"
  run_udp_probe "${protocol}" "${proxy_port}"
  stop_singlink
}

main() {
  parse_args "$@"
  TMP_DIR="$(mktemp -d)"
  check_environment
  build_binaries
  generate_tls
  start_udp_echo
  start_shoes_quic_servers
  run_case "tuic" "${E2E_TUIC_PORT}" "${E2E_TUIC_PROXY_PORT}"
  run_case "hysteria2" "${E2E_HYSTERIA2_PORT}" "${E2E_HYSTERIA2_PROXY_PORT}"
  e2e_section "done"
}

main "$@"
