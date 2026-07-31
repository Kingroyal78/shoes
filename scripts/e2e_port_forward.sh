#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/scripts"

# shellcheck source=scripts/v2board_e2e_common.sh
source "${SCRIPT_DIR}/v2board_e2e_common.sh"

trap e2e_on_error ERR

E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_FORWARD_PORT="${E2E_FORWARD_PORT:-18250}"
E2E_TARGET_A_PORT="${E2E_TARGET_A_PORT:-18251}"
E2E_TARGET_B_PORT="${E2E_TARGET_B_PORT:-18252}"
E2E_SHOES_LOG_LEVEL="${E2E_SHOES_LOG_LEVEL:-info}"
E2E_CLIENT_MAX_TIME_SECS="${E2E_CLIENT_MAX_TIME_SECS:-10}"

E2E_BASIC_PROXY_BIN_EXPLICIT=0
if [[ -n "${E2E_BASIC_PROXY_BIN:-}" ]]; then
  E2E_BASIC_PROXY_BIN_EXPLICIT=1
fi
E2E_BASIC_PROXY_BIN="${E2E_BASIC_PROXY_BIN:-${ROOT_DIR}/target/debug/shoes-basic-proxy-e2e-server}"

TMP_DIR=""
TARGET_A_PID=""
TARGET_B_PID=""
FORWARD_PID=""

usage() {
  cat <<'EOF'
Usage:
  scripts/e2e_port_forward.sh

Runs real TCP checks for the PortForward inbound handler:
  - two target HTTP servers
  - round-robin forwarding across targets
  - raw HTTP request with client write-side half-close
EOF
}

cleanup() {
  local status=$?
  set +e
  for pid in "${FORWARD_PID}" "${TARGET_A_PID}" "${TARGET_B_PID}"; do
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
    for pid in "${FORWARD_PID}" "${TARGET_A_PID}" "${TARGET_B_PID}"; do
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

check_environment() {
  e2e_section "environment"
  e2e_require_command cargo
  e2e_require_command curl
  e2e_require_command python3
  e2e_require_command ss

  e2e_assert_port_free "${E2E_FORWARD_PORT}" "PortForward server"
  e2e_assert_port_free "${E2E_TARGET_A_PORT}" "target A"
  e2e_assert_port_free "${E2E_TARGET_B_PORT}" "target B"
}

build_binary() {
  e2e_section "binary"
  if ((E2E_BASIC_PROXY_BIN_EXPLICIT == 0)); then
    e2e_run cargo build \
      --manifest-path "${ROOT_DIR}/Cargo.toml" \
      --features e2e-client \
      --bin shoes-basic-proxy-e2e-server
  elif [[ ! -x "${E2E_BASIC_PROXY_BIN}" ]]; then
    e2e_die "E2E_BASIC_PROXY_BIN is not executable: ${E2E_BASIC_PROXY_BIN}"
  fi
  [[ -x "${E2E_BASIC_PROXY_BIN}" ]] \
    || e2e_die "E2E_BASIC_PROXY_BIN is not executable: ${E2E_BASIC_PROXY_BIN}"
}

start_http_target() {
  local label="$1"
  local port="$2"
  local body="$3"
  local pid_var="$4"
  local dir="${TMP_DIR}/www-${label}"

  mkdir -p "${dir}"
  printf '%s' "${body}" >"${dir}/payload.txt"
  python3 -m http.server "${port}" \
    --bind "${E2E_BIND_HOST}" \
    --directory "${dir}" \
    >"${TMP_DIR}/target-${label}.log" 2>&1 &
  printf -v "${pid_var}" '%s' "$!"
  wait_for_tcp_port "${port}" "target ${label}"
}

start_forwarder() {
  e2e_section "port forward"
  RUST_LOG="${E2E_SHOES_LOG_LEVEL}" "${E2E_BASIC_PROXY_BIN}" \
    --listen "${E2E_BIND_HOST}:${E2E_FORWARD_PORT}" \
    --protocol port-forward \
    --target "${E2E_BIND_HOST}:${E2E_TARGET_A_PORT}" \
    --target "${E2E_BIND_HOST}:${E2E_TARGET_B_PORT}" \
    >"${TMP_DIR}/port-forward.log" 2>&1 &
  FORWARD_PID=$!
  wait_for_tcp_port "${E2E_FORWARD_PORT}" "PortForward server"
}

curl_payload() {
  curl -fsS \
    --http1.1 \
    --max-time "${E2E_CLIENT_MAX_TIME_SECS}" \
    "http://${E2E_BIND_HOST}:${E2E_FORWARD_PORT}/payload.txt"
}

assert_body() {
  local label="$1"
  local expected="$2"
  local body

  body="$(curl_payload)"
  if [[ "${body}" != "${expected}" ]]; then
    e2e_die "${label}: expected ${expected}, got ${body}"
  fi
  e2e_log "${label}: ${body}"
}

assert_half_close_body() {
  E2E_BIND_HOST="${E2E_BIND_HOST}" \
    E2E_FORWARD_PORT="${E2E_FORWARD_PORT}" \
    E2E_EXPECTED_BODY="target-a" \
    E2E_CLIENT_MAX_TIME_SECS="${E2E_CLIENT_MAX_TIME_SECS}" \
    python3 <<'PY'
import os
import socket

host = os.environ["E2E_BIND_HOST"]
port = int(os.environ["E2E_FORWARD_PORT"])
expected = os.environ["E2E_EXPECTED_BODY"].encode()
timeout = float(os.environ["E2E_CLIENT_MAX_TIME_SECS"])

with socket.create_connection((host, port), timeout=timeout) as sock:
    sock.settimeout(timeout)
    request = (
        f"GET /payload.txt HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    sock.sendall(request)
    sock.shutdown(socket.SHUT_WR)
    chunks = []
    while True:
        chunk = sock.recv(65535)
        if not chunk:
            break
        chunks.append(chunk)

response = b"".join(chunks)
header, sep, body = response.partition(b"\r\n\r\n")
if not sep:
    raise RuntimeError("HTTP response missing header terminator")
if body != expected:
    raise RuntimeError(f"half-close request expected {expected!r}, got {body!r}")
print(f"half-close request: {body.decode()}", flush=True)
PY
}

main() {
  parse_args "$@"
  TMP_DIR="$(mktemp -d)"
  check_environment
  build_binary
  e2e_section "targets"
  start_http_target "a" "${E2E_TARGET_A_PORT}" "target-a" TARGET_A_PID
  start_http_target "b" "${E2E_TARGET_B_PORT}" "target-b" TARGET_B_PID
  start_forwarder
  e2e_section "round robin"
  assert_body "request 1" "target-a"
  assert_body "request 2" "target-b"
  assert_body "request 3" "target-a"
  assert_body "request 4" "target-b"
  assert_half_close_body
  e2e_section "done"
}

main "$@"
