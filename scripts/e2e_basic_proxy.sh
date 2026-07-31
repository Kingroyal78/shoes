#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/scripts"

# shellcheck source=scripts/v2board_e2e_common.sh
source "${SCRIPT_DIR}/v2board_e2e_common.sh"

trap e2e_on_error ERR

E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_HTTP_TARGET_PORT="${E2E_HTTP_TARGET_PORT:-18209}"
E2E_SOCKS_PORT="${E2E_SOCKS_PORT:-18210}"
E2E_HTTP_PROXY_PORT="${E2E_HTTP_PROXY_PORT:-18211}"
E2E_MIXED_PORT="${E2E_MIXED_PORT:-18212}"
E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB:-128}"
E2E_SHOES_LOG_LEVEL="${E2E_SHOES_LOG_LEVEL:-info}"
E2E_CLIENT_MAX_TIME_SECS="${E2E_CLIENT_MAX_TIME_SECS:-30}"
E2E_BASIC_PROXY_BIN="${E2E_BASIC_PROXY_BIN:-${ROOT_DIR}/target/debug/shoes-basic-proxy-e2e-server}"
E2E_BASIC_PROXY_BIN_EXPLICIT="${E2E_BASIC_PROXY_BIN_EXPLICIT:-0}"

TMP_DIR=""
HTTP_PID=""
PROXY_PID=""

usage() {
  cat <<'EOF'
Usage:
  scripts/e2e_basic_proxy.sh

Runs real-client checks for basic inbound proxy handlers:
  - SOCKS5 proxy via curl --socks5-hostname
  - HTTP proxy via curl -x
  - Mixed proxy with both SOCKS5 and HTTP detection on the same listener
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
  e2e_require_command curl
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
  e2e_assert_port_free "${E2E_HTTP_TARGET_PORT}" "basic proxy http target"

  mkdir -p "${TMP_DIR}/www"
  PAYLOAD_PATH="${TMP_DIR}/www/payload.bin"
  PAYLOAD_PATH="${PAYLOAD_PATH}" E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB}" python3 <<'PY'
import os
from pathlib import Path

path = Path(os.environ["PAYLOAD_PATH"])
size = int(os.environ["E2E_PAYLOAD_KIB"]) * 1024
path.write_bytes(bytes(((i * 17 + 23) % 256 for i in range(size))))
PY

  python3 -m http.server "${E2E_HTTP_TARGET_PORT}" \
    --bind "${E2E_BIND_HOST}" \
    --directory "${TMP_DIR}/www" \
    >"${TMP_DIR}/http-target.log" 2>&1 &
  HTTP_PID=$!
  wait_for_tcp_port "${E2E_HTTP_TARGET_PORT}" "basic proxy http target"
}

start_proxy() {
  local protocol="$1"
  local port="$2"

  stop_proxy
  e2e_assert_port_free "${port}" "${protocol} proxy"
  RUST_LOG="${E2E_SHOES_LOG_LEVEL}" "${E2E_BASIC_PROXY_BIN}" \
    --listen "${E2E_BIND_HOST}:${port}" \
    --protocol "${protocol}" \
    >"${TMP_DIR}/${protocol}-proxy.log" 2>&1 &
  PROXY_PID=$!
  wait_for_tcp_port "${port}" "${protocol} proxy"
}

stop_proxy() {
  if [[ -n "${PROXY_PID}" ]] && kill -0 "${PROXY_PID}" 2>/dev/null; then
    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true
  fi
  PROXY_PID=""
}

curl_socks() {
  local port="$1"
  local label="$2"
  local output="${TMP_DIR}/${label}.bin"

  e2e_run curl \
    -fsS \
    --max-time "${E2E_CLIENT_MAX_TIME_SECS}" \
    --noproxy "" \
    --socks5-hostname "${E2E_BIND_HOST}:${port}" \
    -o "${output}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_TARGET_PORT}/payload.bin"
  cmp "${TMP_DIR}/www/payload.bin" "${output}"
  e2e_log "${label} socks download ok bytes=$(wc -c <"${output}")"
}

curl_http_proxy() {
  local port="$1"
  local label="$2"
  local output="${TMP_DIR}/${label}.bin"

  e2e_run curl \
    -fsS \
    --max-time "${E2E_CLIENT_MAX_TIME_SECS}" \
    --noproxy "" \
    -x "http://${E2E_BIND_HOST}:${port}" \
    -o "${output}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_TARGET_PORT}/payload.bin"
  cmp "${TMP_DIR}/www/payload.bin" "${output}"
  e2e_log "${label} http download ok bytes=$(wc -c <"${output}")"
}

run_checks() {
  e2e_section "socks"
  start_proxy socks "${E2E_SOCKS_PORT}"
  curl_socks "${E2E_SOCKS_PORT}" "socks"

  e2e_section "http"
  start_proxy http "${E2E_HTTP_PROXY_PORT}"
  curl_http_proxy "${E2E_HTTP_PROXY_PORT}" "http"

  e2e_section "mixed"
  start_proxy mixed "${E2E_MIXED_PORT}"
  curl_socks "${E2E_MIXED_PORT}" "mixed-socks"
  curl_http_proxy "${E2E_MIXED_PORT}" "mixed-http"
}

main() {
  parse_args "$@"
  TMP_DIR="$(mktemp -d /tmp/shoes-basic-proxy-e2e.XXXXXX)"

  resolve_binaries
  start_http_target
  run_checks

  e2e_section "basic proxy interop passed"
}

main "$@"
