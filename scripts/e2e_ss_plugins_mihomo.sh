#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHOES_BIN="${E2E_SHOES_BIN:-${ROOT_DIR}/target/debug/shoes}"
MIHOMO_BIN="${E2E_MIHOMO_BIN:-/tmp/mihomo-interop}"
MIHOMO_SOURCE="${E2E_MIHOMO_SOURCE:-}"
CASES="${E2E_SS_PLUGIN_CASES:-obfs-http,obfs-tls,v2ray-ws,v2ray-wss,v2ray-ws-mux,v2ray-wss-mux,v2ray-http-upgrade,v2ray-https-upgrade,gost-ws,gost-wss,gost-ws-mux,gost-wss-mux,shadowtls-v1,shadowtls-v2,shadowtls-v3,restls,kcptun-v1,kcptun-v2}"
PAYLOAD_SIZE="${E2E_PAYLOAD_SIZE:-524288}"
CURL_MAX_TIME="${E2E_CURL_MAX_TIME:-30}"
KEEP_TMP="${E2E_KEEP_TMP:-0}"
CAMOUFLAGE_HOST="${E2E_CAMOUFLAGE_HOST:-127.0.0.1}"
CAMOUFLAGE_TLS_VERSION="${E2E_CAMOUFLAGE_TLS_VERSION:-auto}"
RESTLS_SCRIPT="${E2E_RESTLS_SCRIPT:-}"

TMP_DIR=""
PIDS=()

log() {
  printf '[ss-plugin-interop] %s\n' "$*"
}

die() {
  log "FAIL: $*"
  if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    while IFS= read -r file; do
      printf '\n--- %s ---\n' "${file}"
      tail -200 "${file}" || true
    done < <(find "${TMP_DIR}" -type f -name '*.log' -print | sort)
  fi
  exit 1
}

cleanup_case() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
  done
  for pid in "${PIDS[@]:-}"; do
    wait "${pid}" 2>/dev/null || true
  done
  PIDS=()
}

cleanup() {
  cleanup_case
  if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" && "${KEEP_TMP}" != "1" ]]; then
    rm -rf -- "${TMP_DIR}"
  elif [[ -n "${TMP_DIR}" ]]; then
    log "preserved ${TMP_DIR}"
  fi
}
trap cleanup EXIT INT TERM

free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_http() {
  local url="$1"
  local attempt
  for attempt in $(seq 1 100); do
    if curl --silent --show-error --fail --max-time 1 "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

wait_tcp() {
  local port="$1"
  local attempt
  for attempt in $(seq 1 100); do
    if python3 - "${port}" <<'PY'
import socket
import sys
try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2):
        pass
except OSError:
    raise SystemExit(1)
PY
    then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

wait_ready() {
  local panel_port="$1"
  local case_name="$2"
  local attempt
  for attempt in $(seq 1 160); do
    if curl --silent --show-error --fail --max-time 1 \
      "http://127.0.0.1:${panel_port}/test/status" \
      | python3 -c '
import hashlib
import json
import sys
case = sys.argv[1]
status = json.load(sys.stdin)
if case.startswith("v2ray-"):
    kind = "v2ray"
elif case.startswith("gost-"):
    kind = "gost"
elif case.startswith("shadowtls-"):
    kind = "shadow-tls"
elif case.startswith("kcptun-"):
    kind = "kcptun"
elif case.startswith("obfs-"):
    kind = "obfs"
else:
    kind = "restls"
expected_revision = "sha256:" + hashlib.sha256(case.encode()).hexdigest()
expected_feature = f"shadowsocks-plugin-{kind}-v1"
valid = (
    status.get("ready") is True
    and status.get("applied_revision") == expected_revision
    and "shadowsocks-plugin-runtime-v1" in status.get("applied_features", [])
    and expected_feature in status.get("applied_features", [])
    and str(status.get("version", "")).startswith("shoes/")
)
raise SystemExit(0 if valid else 1)
' "${case_name}" \
      2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

write_shoes_config() {
  local output="$1"
  local panel_port="$2"
  local data_dir="$3"
  local tls_cert="${4:-}"
  local tls_key="${5:-}"
  python3 - \
    "${output}" \
    "${panel_port}" \
    "${data_dir}" \
    "${tls_cert}" \
    "${tls_key}" <<'PY'
import json
import os
import pathlib
import sys
output, panel_port, data_dir, tls_cert, tls_key = sys.argv[1:]
tls = ""
if tls_cert:
    tls = f"""\
tls:
  cert_file: "{tls_cert}"
  key_file: "{tls_key}"
"""
pathlib.Path(output).write_text(f"""\
v2board:
  api_host: "http://127.0.0.1:{panel_port}"
  api_key: "interop-token"
  api_timeout_secs: 3
  nodes:
    - tag: "ss-plugin-interop"
      node_id: 1
      node_type: "shadowsocks"
      listen: "127.0.0.1"
runtime:
  data_dir: "{data_dir}"
  pull_interval_secs: 5
  push_interval_secs: 5
  max_legacy_shadowsocks_users: 16
log:
  level: "debug"
""" + tls)
PY
}

write_mihomo_config() {
  local output="$1"
  local case_name="$2"
  local plugin_port="$3"
  local mixed_port="$4"
  local camouflage_host="$5"
  python3 - \
    "${output}" \
    "${case_name}" \
    "${plugin_port}" \
    "${mixed_port}" \
    "${camouflage_host}" <<'PY'
import json
import os
import pathlib
import sys

output, case, plugin_port, mixed_port, camouflage_host = sys.argv[1:]
plugin = ""
plugin_opts = []
if case.startswith("obfs-"):
    plugin = "obfs"
    plugin_opts = [
        f"mode: {case.removeprefix('obfs-')}",
        "host: interop.test",
    ]
elif case.startswith("v2ray-"):
    plugin = "v2ray-plugin"
    plugin_opts = [
        "mode: websocket",
        "host: interop.test",
        "path: /interop",
        f"tls: {'true' if case in ('v2ray-wss', 'v2ray-wss-mux', 'v2ray-https-upgrade') else 'false'}",
        f"skip-cert-verify: {'true' if case in ('v2ray-wss', 'v2ray-wss-mux', 'v2ray-https-upgrade') else 'false'}",
        f"mux: {'true' if case in ('v2ray-ws-mux', 'v2ray-wss-mux') else 'false'}",
        f"v2ray-http-upgrade: {'true' if case in ('v2ray-http-upgrade', 'v2ray-https-upgrade') else 'false'}",
    ]
elif case.startswith("gost-"):
    plugin = "gost-plugin"
    plugin_opts = [
        "mode: websocket",
        "host: interop.test",
        "path: /interop",
        f"tls: {'true' if case in ('gost-wss', 'gost-wss-mux') else 'false'}",
        f"skip-cert-verify: {'true' if case in ('gost-wss', 'gost-wss-mux') else 'false'}",
        f"mux: {'true' if case in ('gost-ws-mux', 'gost-wss-mux') else 'false'}",
    ]
elif case.startswith("kcptun-"):
    plugin = "kcptun"
    plugin_opts = [
        "key: shoes-kcptun-interop",
        "crypt: aes-128",
        "mode: manual",
        "conn: 1",
        "autoexpire: 0",
        "scavengettl: 60",
        "mtu: 1350",
        "ratelimit: 0",
        "sndwnd: 256",
        "rcvwnd: 512",
        "datashard: 4",
        "parityshard: 2",
        "dscp: 0",
        "nocomp: false",
        "acknodelay: true",
        "nodelay: 1",
        "interval: 10",
        "resend: 2",
        "nc: 1",
        "sockbuf: 4194304",
        f"smuxver: {case[-1]}",
        "smuxbuf: 4194304",
        "framesize: 8192",
        "streambuf: 1048576",
        "keepalive: 1",
    ]
elif case.startswith("shadowtls-"):
    plugin = "shadow-tls"
    plugin_opts = [
        f"host: {camouflage_host}",
        f"version: {case[-1]}",
        "password: shadowtls-interop-password",
        "skip-cert-verify: true",
    ]
elif case == "restls":
    plugin = "restls"
    plugin_opts = [
        f"host: {camouflage_host}",
        "password: restls-interop-password",
        "version-hint: tls13",
        f"restls-script: {json.dumps(os.environ.get('E2E_RESTLS_SCRIPT', ''))}",
        "skip-cert-verify: true",
    ]
else:
    raise SystemExit(f"unsupported Mihomo case: {case}")

opts_yaml = "\n".join(f"      {line}" for line in plugin_opts)
pathlib.Path(output).write_text(f"""\
mixed-port: {mixed_port}
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: debug
ipv6: false
proxies:
  - name: interop
    type: ss
    server: 127.0.0.1
    port: {plugin_port}
    cipher: aes-128-gcm
    password: interop-password
    plugin: {plugin}
    plugin-opts:
{opts_yaml}
rules:
  - MATCH,interop
""")
PY
}

run_case() {
  local case_name="$1"
  local case_dir="${TMP_DIR}/${case_name}"
  local panel_port raw_port plugin_port target_port mixed_port
  mkdir -p "${case_dir}/data" "${case_dir}/mihomo" "${case_dir}/www"
  panel_port="$(free_port)"
  raw_port="$(free_port)"
  plugin_port="$(free_port)"
  target_port="$(free_port)"
  mixed_port="$(free_port)"

  python3 - "${case_dir}/www/payload.bin" "${PAYLOAD_SIZE}" <<'PY'
import pathlib
import sys
path, size = sys.argv[1], int(sys.argv[2])
payload = bytes((index * 31 + 17) & 0xff for index in range(size))
pathlib.Path(path).write_bytes(payload)
PY
  sha256sum "${case_dir}/www/payload.bin" | cut -d' ' -f1 >"${case_dir}/expected.sha256"

  python3 "${ROOT_DIR}/scripts/e2e_ss_plugins_mock_panel.py" \
    --port "${panel_port}" \
    --raw-port "${raw_port}" \
    --plugin-port "${plugin_port}" \
    --case "${case_name}" \
    --camouflage-host "${CAMOUFLAGE_HOST}" \
    --restls-script "${RESTLS_SCRIPT}" \
    >"${case_dir}/panel.log" 2>&1 &
  PIDS+=("$!")
  wait_http "http://127.0.0.1:${panel_port}/test/status" \
    || die "${case_name}: mock panel did not start"

  python3 -m http.server "${target_port}" \
    --bind 127.0.0.1 \
    --directory "${case_dir}/www" \
    >"${case_dir}/target.log" 2>&1 &
  PIDS+=("$!")
  wait_http "http://127.0.0.1:${target_port}/payload.bin" \
    || die "${case_name}: target server did not start"

  local needs_certificate=0
  if [[ "${case_name}" == *wss* \
    || "${case_name}" == "v2ray-https-upgrade" \
    || "${case_name}" == shadowtls-* \
    || "${case_name}" == "restls" ]]; then
    needs_certificate=1
  fi
  if [[ "${needs_certificate}" == "1" ]]; then
    command -v openssl >/dev/null || die "${case_name}: openssl is required"
    openssl req -x509 -newkey rsa:2048 -nodes \
      -subj "/CN=localhost" \
      -days 1 \
      -keyout "${case_dir}/camouflage.key" \
      -out "${case_dir}/camouflage.crt" \
      >"${case_dir}/openssl-cert.log" 2>&1
  fi
  if [[ "${case_name}" == shadowtls-* || "${case_name}" == "restls" ]]; then
    local -a tls_version_args=()
    case "${CAMOUFLAGE_TLS_VERSION}" in
      auto) ;;
      tls12) tls_version_args=(-tls1_2) ;;
      tls13) tls_version_args=(-tls1_3) ;;
      *) die "invalid E2E_CAMOUFLAGE_TLS_VERSION=${CAMOUFLAGE_TLS_VERSION}" ;;
    esac
    openssl s_server \
      -accept "127.0.0.1:443" \
      -cert "${case_dir}/camouflage.crt" \
      -key "${case_dir}/camouflage.key" \
      "${tls_version_args[@]}" \
      -www \
      -quiet \
      >"${case_dir}/camouflage.log" 2>&1 &
    PIDS+=("$!")
    wait_tcp 443 || die "${case_name}: local TLS camouflage server did not start"
  fi

  if [[ "${case_name}" == *wss* || "${case_name}" == "v2ray-https-upgrade" ]]; then
    write_shoes_config \
      "${case_dir}/shoes.yml" \
      "${panel_port}" \
      "${case_dir}/data" \
      "${case_dir}/camouflage.crt" \
      "${case_dir}/camouflage.key"
  else
    write_shoes_config "${case_dir}/shoes.yml" "${panel_port}" "${case_dir}/data"
  fi
  "${SHOES_BIN}" run -c "${case_dir}/shoes.yml" \
    >"${case_dir}/shoes.log" 2>&1 &
  PIDS+=("$!")
  wait_ready "${panel_port}" "${case_name}" \
    || die "${case_name}: shoes did not ACK a ready plugin generation"

  write_mihomo_config \
    "${case_dir}/mihomo.yml" \
    "${case_name}" \
    "${plugin_port}" \
    "${mixed_port}" \
    "${CAMOUFLAGE_HOST}"
  "${MIHOMO_BIN}" -d "${case_dir}/mihomo" -f "${case_dir}/mihomo.yml" \
    >"${case_dir}/mihomo.log" 2>&1 &
  PIDS+=("$!")
  wait_tcp "${mixed_port}" || die "${case_name}: Mihomo mixed listener did not start"

  curl --silent --show-error --fail --max-time "${CURL_MAX_TIME}" \
    --noproxy "" \
    --proxy "socks5h://127.0.0.1:${mixed_port}" \
    "http://127.0.0.1:${target_port}/payload.bin" \
    --output "${case_dir}/actual.bin" \
    || die "${case_name}: Mihomo download through shoes failed"
  local expected actual
  expected="$(cat "${case_dir}/expected.sha256")"
  actual="$(sha256sum "${case_dir}/actual.bin" | cut -d' ' -f1)"
  [[ "${actual}" == "${expected}" ]] \
    || die "${case_name}: payload digest mismatch expected=${expected} actual=${actual}"
  log "PASS ${case_name}: ${PAYLOAD_SIZE} bytes, sha256=${actual}"
  cleanup_case
}

main() {
  command -v cargo >/dev/null || die "cargo is required"
  command -v curl >/dev/null || die "curl is required"
  command -v python3 >/dev/null || die "python3 is required"
  command -v sha256sum >/dev/null || die "sha256sum is required"
  TMP_DIR="$(mktemp -d /tmp/shoes-ss-plugin-interop.XXXXXX)"

  if [[ -z "${E2E_SHOES_BIN:-}" ]]; then
    log "building current shoes source"
    cargo build --manifest-path "${ROOT_DIR}/Cargo.toml" --bin shoes
  elif [[ ! -x "${SHOES_BIN}" ]]; then
    die "E2E_SHOES_BIN is not executable: ${SHOES_BIN}"
  fi
  if [[ ! -x "${MIHOMO_BIN}" ]]; then
    [[ -n "${MIHOMO_SOURCE}" && -d "${MIHOMO_SOURCE}" ]] \
      || die "set E2E_MIHOMO_BIN to an official binary or E2E_MIHOMO_SOURCE to an official checkout"
    command -v go >/dev/null || die "go is required to build Mihomo"
    MIHOMO_BIN="${TMP_DIR}/mihomo"
    log "building external Mihomo client from ${MIHOMO_SOURCE}"
    (
      cd "${MIHOMO_SOURCE}"
      CGO_ENABLED=0 go build -o "${MIHOMO_BIN}" .
    )
  fi
  log "external client: $("${MIHOMO_BIN}" -v | head -1)"
  if git -C "${MIHOMO_SOURCE}" rev-parse --verify HEAD >/dev/null 2>&1; then
    log "Mihomo source commit: $(git -C "${MIHOMO_SOURCE}" rev-parse HEAD)"
  fi

  IFS=',' read -r -a case_list <<<"${CASES}"
  local case_name
  for case_name in "${case_list[@]}"; do
    log "running ${case_name}"
    run_case "${case_name}"
  done
  log "all requested real-process interoperability cases passed"
}

main "$@"
