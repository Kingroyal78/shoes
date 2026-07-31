#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/scripts"

# shellcheck source=scripts/v2board_e2e_common.sh
source "${SCRIPT_DIR}/v2board_e2e_common.sh"

trap e2e_on_error ERR

V2BOARD_DIR="${V2BOARD_DIR:-${ROOT_DIR}/../v2board}"
V2BOARD_DOCKER_DIR="${V2BOARD_DOCKER_DIR:-${ROOT_DIR}/../v2board-docker}"
V2BOARD_PANEL_URL="${V2BOARD_PANEL_URL:-http://127.0.0.1}"
V2BOARD_MYSQL_CONTAINER="${V2BOARD_MYSQL_CONTAINER:-v2board-docker-mysql-1}"
V2BOARD_WWW_CONTAINER="${V2BOARD_WWW_CONTAINER:-v2board-docker-www-1}"
V2BOARD_REDIS_CONTAINER="${V2BOARD_REDIS_CONTAINER:-v2board-docker-redis-1}"
V2BOARD_MYSQL_USER="${V2BOARD_MYSQL_USER:-root}"
V2BOARD_MYSQL_PASSWORD="${V2BOARD_MYSQL_PASSWORD:-v2boardisbest}"
V2BOARD_MYSQL_DATABASE="${V2BOARD_MYSQL_DATABASE:-v2board}"

SING_BOX_DIR="${SING_BOX_DIR:-${ROOT_DIR}/../sing-box}"
SINGLINK_BIN="${SINGLINK_BIN:-}"
SINGLINK_BUILD_TAGS="${SINGLINK_BUILD_TAGS:-with_quic,with_utls}"
SHOES_BIN_EXPLICIT=0
if [[ -n "${SHOES_BIN:-}" ]]; then
  SHOES_BIN_EXPLICIT=1
fi
SHOES_BIN="${SHOES_BIN:-}"
E2E_SS_OBFS_CLIENT_BIN_EXPLICIT=0
if [[ -n "${E2E_SS_OBFS_CLIENT_BIN:-}" ]]; then
  E2E_SS_OBFS_CLIENT_BIN_EXPLICIT=1
fi
E2E_SS_OBFS_CLIENT_BIN="${E2E_SS_OBFS_CLIENT_BIN:-${ROOT_DIR}/target/debug/shoes-ss-obfs-e2e-client}"
E2E_XHTTP_CLIENT_BIN_EXPLICIT=0
if [[ -n "${E2E_XHTTP_CLIENT_BIN:-}" ]]; then
  E2E_XHTTP_CLIENT_BIN_EXPLICIT=1
fi
E2E_XHTTP_CLIENT_BIN="${E2E_XHTTP_CLIENT_BIN:-${ROOT_DIR}/target/debug/shoes-vless-xhttp-e2e-client}"

E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18083}"
E2E_REALITY_DEST_PORT="${E2E_REALITY_DEST_PORT:-18097}"
E2E_HTTPS_PORT="${E2E_HTTPS_PORT:-18098}"
E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB:-128}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-5}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-5}"
E2E_WAIT_TIMEOUT_SECS="${E2E_WAIT_TIMEOUT_SECS:-45}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_SHOES_LOG_LEVEL="${E2E_SHOES_LOG_LEVEL:-info}"
E2E_MATRIX_CASES="${E2E_MATRIX_CASES:-vmess_tcp,vmess_ws,vmess_ws_path_ed,vmess_tls,vmess_grpc,vmess_grpc_authority,vmess_httpupgrade,vmess_httpupgrade_headers,vmess_http,vmess_http_tls,vmess_xhttp_tls,vmess_xhttp_auto_tls,vmess_tcp_http_header,vmess_zero_security,vless_tcp,vless_ws,vless_tls,vless_grpc,vless_httpupgrade,vless_http,vless_http_tls,vless_xhttp_tls,vless_xhttp_stream_up_tls,vless_xhttp_stream_one_tls,vless_splithttp_tls,vless_xhttp_reality,vless_http_reality,vless_vision_tls,vless_reality,vless_vision_reality,shadowsocks_aead,shadowsocks_aead_aes192,shadowsocks_aead_aes256,shadowsocks_aead_chacha20,shadowsocks_obfs_http,shadowsocks_2022_aes128,shadowsocks_2022_aes256,trojan_tls,trojan_ws,trojan_grpc,trojan_httpupgrade,anytls_tls,tuic_tls,tuic_tls_newreno_zero_rtt,hysteria2_tls,vless_ws_proxy_protocol_v1,v2node_anytls_tls_proxy_protocol_v2,v2node_vmess_ws_proxy_protocol_v1,v2node_vmess_tcp,v2node_vmess_ws,v2node_vmess_http,v2node_vmess_http_tls,v2node_vmess_grpc,v2node_vmess_httpupgrade,v2node_vmess_xhttp_tls,v2node_vless_tcp,v2node_vless_ws,v2node_vless_tls,v2node_vless_http,v2node_vless_http_tls,v2node_vless_grpc,v2node_vless_httpupgrade,v2node_vless_xhttp_tls,v2node_vless_splithttp_tls,v2node_vless_xhttp_reality,v2node_vless_vision_tls,v2node_vless_reality,v2node_shadowsocks_aead,v2node_shadowsocks_aead_aes192,v2node_shadowsocks_aead_aes256,v2node_shadowsocks_aead_chacha20,v2node_shadowsocks_2022_aes128,v2node_shadowsocks_2022_aes256,v2node_trojan_tls,v2node_trojan_ws,v2node_trojan_grpc,v2node_trojan_httpupgrade,v2node_tuic_tls,v2node_hysteria2_tls,v2node_anytls_tls,v2node_anytls_reality}"
E2E_CURL_CONNECT_TIMEOUT_SECS="${E2E_CURL_CONNECT_TIMEOUT_SECS:-5}"
E2E_CURL_MAX_TIME_SECS="${E2E_CURL_MAX_TIME_SECS:-45}"

TMP_DIR=""
HTTP_PID=""
REALITY_DEST_PID=""
HTTPS_PID=""
SHOES_PID=""
SINGLINK_PID=""
PROXY_PROTOCOL_PID=""
SERVER_TOKEN=""

CASE_NAME=""
CASE_NODE_TYPE=""
CASE_CLIENT_TYPE=""
CASE_V2_PROTOCOL=""
CASE_NODE_ID=""
CASE_USER_ID=""
CASE_GROUP_ID=""
CASE_UUID=""
CASE_NODE_PORT=""
CASE_PROXY_PORT=""
CASE_NETWORK=""
CASE_WS_PATH=""
CASE_CLIENT_WS_PATH=""
CASE_HTTPUPGRADE_HOST=""
CASE_HTTPUPGRADE_PATH=""
CASE_HTTPUPGRADE_HEADER_NAME=""
CASE_HTTPUPGRADE_HEADER_VALUE=""
CASE_HTTP_HOST=""
CASE_HTTP_PATH=""
CASE_HTTP_METHOD=""
CASE_XHTTP_HOST=""
CASE_XHTTP_PATH=""
CASE_XHTTP_MODE=""
CASE_XHTTP_SESSION_PLACEMENT=""
CASE_XHTTP_SESSION_KEY=""
CASE_XHTTP_SEQ_PLACEMENT=""
CASE_XHTTP_SEQ_KEY=""
CASE_XHTTP_UPLINK_DATA_PLACEMENT=""
CASE_XHTTP_UPLINK_DATA_KEY=""
CASE_TCP_HTTP_HEADER=""
CASE_GRPC_SERVICE_NAME=""
CASE_GRPC_AUTHORITY=""
CASE_TLS=""
CASE_TLS_SERVER_NAME="example.org"
CASE_FLOW=""
CASE_REALITY=""
CASE_REALITY_PRIVATE_KEY="gJ5Wl_Qx8b_57LrIe-d7BkjqOq2fLZTu1Q-fKlRKrUw"
CASE_REALITY_PUBLIC_KEY="LN1mo2a7LNrrH3kij2fb_H3uYZosvLvNUOKpVkbHyQ8"
CASE_REALITY_SHORT_ID="a1b2c3d4"
CASE_VMESS_SECURITY="auto"
CASE_SS_CIPHER=""
CASE_SS_CLIENT_PASSWORD=""
CASE_SS_OBFS=""
CASE_SS_OBFS_SETTINGS=""
CASE_SS_OBFS_HOST=""
CASE_SS_OBFS_PATH=""
CASE_ANYTLS_PADDING_SCHEME=""
CASE_TUIC_CONGESTION_CONTROL=""
CASE_TUIC_UDP_RELAY_MODE=""
CASE_TUIC_ZERO_RTT=0
CASE_ACCEPT_PROXY_PROTOCOL=0
CASE_PROXY_PROTOCOL_VERSION=""
CASE_PROXY_PROTOCOL_BRIDGE_PORT=""
CASE_PROXY_PROTOCOL_SOURCE_IP=""
CASE_PROXY_PROTOCOL_SOURCE_PORT=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_matrix.sh

Runs a local production-oriented V2Board interop matrix against sibling
    v2board-docker. Default cases:
  vmess_tcp, vmess_ws, vmess_ws_path_ed, vmess_tls, vmess_grpc, vmess_grpc_authority,
  vmess_httpupgrade, vmess_httpupgrade_headers, vmess_http, vmess_http_tls,
  vmess_xhttp_tls, vmess_xhttp_auto_tls, vmess_tcp_http_header, vmess_zero_security,
  vless_tcp, vless_ws, vless_tls, vless_grpc, vless_httpupgrade,
  vless_http, vless_http_tls, vless_xhttp_tls, vless_xhttp_stream_up_tls,
  vless_xhttp_stream_one_tls, vless_splithttp_tls, vless_xhttp_reality, vless_http_reality,
  vless_vision_tls, vless_reality, vless_vision_reality,
  shadowsocks_aead, shadowsocks_aead_aes192, shadowsocks_aead_aes256,
  shadowsocks_aead_chacha20, shadowsocks_obfs_http,
  shadowsocks_2022_aes128, shadowsocks_2022_aes256,
  trojan_tls, trojan_ws, trojan_grpc, trojan_httpupgrade,
  anytls_tls, tuic_tls, tuic_tls_newreno_zero_rtt, hysteria2_tls,
  vless_ws_proxy_protocol_v1, v2node_anytls_tls_proxy_protocol_v2,
  v2node_vmess_ws_proxy_protocol_v1,
  v2node_vmess_tcp, v2node_vmess_ws, v2node_vmess_http, v2node_vmess_http_tls,
  v2node_vmess_grpc, v2node_vmess_httpupgrade, v2node_vmess_xhttp_tls,
  v2node_vless_tcp, v2node_vless_ws, v2node_vless_tls, v2node_vless_http,
  v2node_vless_http_tls, v2node_vless_grpc, v2node_vless_httpupgrade,
  v2node_vless_xhttp_tls, v2node_vless_splithttp_tls,
  v2node_vless_xhttp_reality, v2node_vless_vision_tls,
  v2node_vless_reality,
  v2node_shadowsocks_aead, v2node_shadowsocks_aead_aes192,
  v2node_shadowsocks_aead_aes256, v2node_shadowsocks_aead_chacha20,
  v2node_shadowsocks_2022_aes128, v2node_shadowsocks_2022_aes256,
  v2node_trojan_tls, v2node_trojan_ws, v2node_trojan_grpc,
  v2node_trojan_httpupgrade, v2node_tuic_tls, v2node_hysteria2_tls,
  v2node_anytls_tls, v2node_anytls_reality

Environment:
  E2E_MATRIX_CASES          Comma-separated case list.
  SHOES_BIN                 Optional prebuilt shoes binary.
  SINGLINK_BIN              Optional prebuilt singlink/sing-box binary.
  E2E_SS_OBFS_CLIENT_BIN    Optional prebuilt SS obfs E2E client.
  E2E_XHTTP_CLIENT_BIN      Optional prebuilt VLESS/VMess XHTTP E2E client.
  SINGLINK_BUILD_TAGS       Tags used when building singlink. Default: with_quic,with_utls.
  E2E_REALITY_DEST_PORT     Local TLS target for Reality camouflage. Default: 18097.
  E2E_HTTPS_PORT            Local HTTPS target for Vision payloads. Default: 18098.
  E2E_KEEP_FIXTURES         Keep seeded V2Board fixtures. Default: 1.
  E2E_WAIT_TIMEOUT_SECS     Wait time for traffic rows/user counters. Default: 45.
  E2E_SHOES_LOG_LEVEL       shoes log level in generated config. Default: info.
EOF
}

cleanup() {
  local status=$?
  set +e
  stop_case_services
  if [[ -n "${HTTP_PID}" ]] && kill -0 "${HTTP_PID}" 2>/dev/null; then
    kill "${HTTP_PID}" 2>/dev/null || true
    wait "${HTTP_PID}" 2>/dev/null || true
  fi
  if [[ -n "${REALITY_DEST_PID}" ]] && kill -0 "${REALITY_DEST_PID}" 2>/dev/null; then
    kill "${REALITY_DEST_PID}" 2>/dev/null || true
    wait "${REALITY_DEST_PID}" 2>/dev/null || true
  fi
  if [[ -n "${HTTPS_PID}" ]] && kill -0 "${HTTPS_PID}" 2>/dev/null; then
    kill "${HTTPS_PID}" 2>/dev/null || true
    wait "${HTTPS_PID}" 2>/dev/null || true
  fi

  if [[ "${status}" -ne 0 ]] && ! e2e_env_bool E2E_KEEP_FIXTURES 1; then
    maybe_cleanup_fixtures || true
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

mysql_exec() {
  docker exec -i "${V2BOARD_MYSQL_CONTAINER}" \
    mysql \
    -u"${V2BOARD_MYSQL_USER}" \
    -p"${V2BOARD_MYSQL_PASSWORD}" \
    "${V2BOARD_MYSQL_DATABASE}"
}

mysql_query() {
  docker exec "${V2BOARD_MYSQL_CONTAINER}" \
    mysql \
    -N \
    -B \
    -u"${V2BOARD_MYSQL_USER}" \
    -p"${V2BOARD_MYSQL_PASSWORD}" \
    "${V2BOARD_MYSQL_DATABASE}" \
    -e "$1" 2>/dev/null
}

discover_server_token() {
  if [[ -n "${V2BOARD_SERVER_TOKEN:-}" ]]; then
    printf '%s\n' "${V2BOARD_SERVER_TOKEN}"
    return
  fi

  e2e_require_file "${V2BOARD_DIR}/config/v2board.php" "V2Board config"
  sed -n "s/.*'server_token'[[:space:]]*=>[[:space:]]*'\\([^']*\\)'.*/\\1/p" \
    "${V2BOARD_DIR}/config/v2board.php" \
    | head -n 1
}

wait_for_listen_port() {
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

    for pid in "${HTTP_PID}" "${REALITY_DEST_PID}" "${HTTPS_PID}" "${SHOES_PID}" "${SINGLINK_PID}"; do
      if [[ -n "${pid}" ]] && ! kill -0 "${pid}" 2>/dev/null; then
        e2e_die "${label} process exited before listening on ${port}"
      fi
    done

    now="$(date +%s)"
    if ((now - start >= timeout)); then
      e2e_die "${label} did not listen on port ${port} within ${timeout}s"
    fi
    sleep 0.2
  done
}

wait_for_udp_listen_port() {
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

    for pid in "${HTTP_PID}" "${REALITY_DEST_PID}" "${HTTPS_PID}" "${SHOES_PID}" "${SINGLINK_PID}"; do
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

case_uses_quic_node() {
  [[ "${CASE_CLIENT_TYPE}" == "tuic" || "${CASE_CLIENT_TYPE}" == "hysteria2" ]]
}

case_uses_builtin_ss_obfs_client() {
  [[ "${CASE_NAME}" == "shadowsocks_obfs_http" ]]
}

case_uses_builtin_xhttp_client() {
  [[ ( "${CASE_CLIENT_TYPE}" == "vless" || "${CASE_CLIENT_TYPE}" == "vmess" ) && ( "${CASE_NETWORK}" == "xhttp" || "${CASE_NETWORK}" == "splithttp" || "${CASE_NETWORK}" == "split-http" || "${CASE_NETWORK}" == "split_http" ) ]]
}

resolve_binaries() {
  e2e_section "binaries"
  e2e_require_command docker
  e2e_require_command curl
  e2e_require_command ss
  e2e_require_command python3
  e2e_require_command openssl

  if [[ -z "${SHOES_BIN}" ]]; then
    SHOES_BIN="${ROOT_DIR}/target/debug/shoes"
    if ((SHOES_BIN_EXPLICIT == 0)); then
      e2e_run cargo build --manifest-path "${ROOT_DIR}/Cargo.toml"
    elif [[ ! -x "${SHOES_BIN}" ]]; then
      e2e_die "SHOES_BIN is not executable: ${SHOES_BIN}"
    fi
  fi
  [[ -x "${SHOES_BIN}" ]] || e2e_die "SHOES_BIN is not executable: ${SHOES_BIN}"

  if ((E2E_SS_OBFS_CLIENT_BIN_EXPLICIT == 0)); then
    e2e_run cargo build \
      --manifest-path "${ROOT_DIR}/Cargo.toml" \
      --features e2e-client \
      --bin shoes-ss-obfs-e2e-client
  elif [[ ! -x "${E2E_SS_OBFS_CLIENT_BIN}" ]]; then
    e2e_die "E2E_SS_OBFS_CLIENT_BIN is not executable: ${E2E_SS_OBFS_CLIENT_BIN}"
  fi
  [[ -x "${E2E_SS_OBFS_CLIENT_BIN}" ]] || e2e_die "E2E_SS_OBFS_CLIENT_BIN is not executable: ${E2E_SS_OBFS_CLIENT_BIN}"

  if ((E2E_XHTTP_CLIENT_BIN_EXPLICIT == 0)); then
    e2e_run cargo build \
      --manifest-path "${ROOT_DIR}/Cargo.toml" \
      --features e2e-client \
      --bin shoes-vless-xhttp-e2e-client
  elif [[ ! -x "${E2E_XHTTP_CLIENT_BIN}" ]]; then
    e2e_die "E2E_XHTTP_CLIENT_BIN is not executable: ${E2E_XHTTP_CLIENT_BIN}"
  fi
  [[ -x "${E2E_XHTTP_CLIENT_BIN}" ]] || e2e_die "E2E_XHTTP_CLIENT_BIN is not executable: ${E2E_XHTTP_CLIENT_BIN}"

  if [[ -z "${SINGLINK_BIN}" ]]; then
    e2e_require_dir "${SING_BOX_DIR}" "sing-box checkout"
    e2e_require_command go
    SINGLINK_BIN="${TMP_DIR}/singlink"
    if [[ -n "${SINGLINK_BUILD_TAGS}" ]]; then
      e2e_run go -C "${SING_BOX_DIR}" build -tags "${SINGLINK_BUILD_TAGS}" -o "${SINGLINK_BIN}" ./cmd/singlink
    else
      e2e_run go -C "${SING_BOX_DIR}" build -o "${SINGLINK_BIN}" ./cmd/singlink
    fi
  fi
  [[ -x "${SINGLINK_BIN}" ]] || e2e_die "SINGLINK_BIN is not executable: ${SINGLINK_BIN}"

  e2e_log "SHOES_BIN=${SHOES_BIN}"
  e2e_log "E2E_SS_OBFS_CLIENT_BIN=${E2E_SS_OBFS_CLIENT_BIN}"
  e2e_log "E2E_XHTTP_CLIENT_BIN=${E2E_XHTTP_CLIENT_BIN}"
  e2e_log "SINGLINK_BIN=${SINGLINK_BIN}"
  e2e_log "SINGLINK_BUILD_TAGS=${SINGLINK_BUILD_TAGS:-<none>}"
}

check_environment() {
  e2e_section "environment"
  e2e_require_dir "${V2BOARD_DOCKER_DIR}" "v2board-docker checkout"
  e2e_require_dir "${V2BOARD_DIR}" "v2board checkout"

  docker ps --format '{{.Names}}' | grep -Fxq "${V2BOARD_MYSQL_CONTAINER}" \
    || e2e_die "missing running mysql container: ${V2BOARD_MYSQL_CONTAINER}"
  docker ps --format '{{.Names}}' | grep -Fxq "${V2BOARD_WWW_CONTAINER}" \
    || e2e_die "missing running www container: ${V2BOARD_WWW_CONTAINER}"
  docker ps --format '{{.Names}}' | grep -Fxq "${V2BOARD_REDIS_CONTAINER}" \
    || e2e_die "missing running redis container: ${V2BOARD_REDIS_CONTAINER}"

  e2e_http_probe "${V2BOARD_PANEL_URL}" >/dev/null \
    || e2e_die "panel is not reachable: ${V2BOARD_PANEL_URL}"
}

generate_tls_files() {
  e2e_section "tls fixture"
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -days 1 \
    -nodes \
    -subj "/CN=${CASE_TLS_SERVER_NAME}" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "subjectAltName=DNS:${CASE_TLS_SERVER_NAME}" \
    -keyout "${TMP_DIR}/tls.key" \
    -out "${TMP_DIR}/tls.crt" \
    >/dev/null 2>&1
}

case_config() {
  CASE_NAME="$1"
  CASE_CLIENT_TYPE=""
  CASE_V2_PROTOCOL=""
  CASE_GROUP_ID=""
  CASE_WS_PATH=""
  CASE_CLIENT_WS_PATH=""
  CASE_HTTPUPGRADE_HOST="example.org"
  CASE_HTTPUPGRADE_PATH=""
  CASE_HTTPUPGRADE_HEADER_NAME=""
  CASE_HTTPUPGRADE_HEADER_VALUE=""
  CASE_HTTP_HOST="front.example.org"
  CASE_HTTP_PATH="/v2ray-http"
  CASE_HTTP_METHOD="PUT"
  CASE_XHTTP_HOST="example.org"
  CASE_XHTTP_PATH="/xhttp"
  CASE_XHTTP_MODE="packet-up"
  CASE_XHTTP_SESSION_PLACEMENT="path"
  CASE_XHTTP_SESSION_KEY=""
  CASE_XHTTP_SEQ_PLACEMENT="path"
  CASE_XHTTP_SEQ_KEY=""
  CASE_XHTTP_UPLINK_DATA_PLACEMENT="auto"
  CASE_XHTTP_UPLINK_DATA_KEY=""
  CASE_TCP_HTTP_HEADER=0
  CASE_GRPC_SERVICE_NAME=""
  CASE_GRPC_AUTHORITY=""
  CASE_TLS=0
  CASE_TLS_SERVER_NAME="example.org"
  CASE_FLOW=""
  CASE_REALITY=0
  CASE_VMESS_SECURITY="auto"
  CASE_SS_CIPHER=""
  CASE_SS_CLIENT_PASSWORD=""
  CASE_SS_OBFS=""
  CASE_SS_OBFS_SETTINGS=""
  CASE_SS_OBFS_HOST="example.com"
  CASE_SS_OBFS_PATH="/obfs"
  CASE_ANYTLS_PADDING_SCHEME='["stop=2","0=30-30","1=100-100"]'
  CASE_TUIC_CONGESTION_CONTROL=""
  CASE_TUIC_UDP_RELAY_MODE=""
  CASE_TUIC_ZERO_RTT=0
  CASE_ACCEPT_PROXY_PROTOCOL=0
  CASE_PROXY_PROTOCOL_VERSION=""
  CASE_PROXY_PROTOCOL_BRIDGE_PORT=""
  CASE_PROXY_PROTOCOL_SOURCE_IP=""
  CASE_PROXY_PROTOCOL_SOURCE_PORT=""

  case "${CASE_NAME}" in
    vmess_tcp)
      CASE_NODE_TYPE=vmess
      CASE_NODE_ID=9101
      CASE_USER_ID=19101
      CASE_UUID=11111111-1111-4111-8111-111111111101
      CASE_NODE_PORT=18101
      CASE_PROXY_PORT=18201
      CASE_NETWORK=tcp
      ;;
    vmess_ws)
      CASE_NODE_TYPE=vmess
      CASE_NODE_ID=9102
      CASE_USER_ID=19102
      CASE_UUID=11111111-1111-4111-8111-111111111102
      CASE_NODE_PORT=18102
      CASE_PROXY_PORT=18202
      CASE_NETWORK=ws
      CASE_WS_PATH=/vmess-ws
      ;;
    vmess_ws_path_ed)
      CASE_NODE_TYPE=vmess
      CASE_NODE_ID=9112
      CASE_USER_ID=19112
      CASE_UUID=11111111-1111-4111-8111-111111111112
      CASE_NODE_PORT=18142
      CASE_PROXY_PORT=18242
      CASE_NETWORK=ws
      CASE_WS_PATH="/vmess-ws-ed?ed=4096"
      CASE_CLIENT_WS_PATH=/vmess-ws-ed
      ;;
    vmess_tls)
      CASE_NODE_TYPE=vmess
      CASE_NODE_ID=9103
      CASE_USER_ID=19103
      CASE_UUID=11111111-1111-4111-8111-111111111103
      CASE_NODE_PORT=18103
      CASE_PROXY_PORT=18203
      CASE_NETWORK=tcp
      CASE_TLS=1
      ;;
    vmess_grpc)
      CASE_NODE_TYPE=vmess
      CASE_NODE_ID=9104
      CASE_USER_ID=19104
      CASE_UUID=11111111-1111-4111-8111-111111111104
      CASE_NODE_PORT=18104
      CASE_PROXY_PORT=18204
      CASE_NETWORK=grpc
      CASE_GRPC_SERVICE_NAME=vmess-grpc
      ;;
    vmess_grpc_authority)
      CASE_NODE_TYPE=vmess
      CASE_NODE_ID=9107
      CASE_USER_ID=19107
      CASE_UUID=11111111-1111-4111-8111-111111111107
      CASE_NODE_PORT=18107
      CASE_PROXY_PORT=18207
      CASE_NETWORK=grpc
      CASE_GRPC_SERVICE_NAME=vmess-grpc-authority
      CASE_GRPC_AUTHORITY="${E2E_BIND_HOST}:${CASE_NODE_PORT}"
      ;;
    vmess_httpupgrade)
      CASE_NODE_TYPE=vmess
      CASE_NODE_ID=9105
      CASE_USER_ID=19105
      CASE_UUID=11111111-1111-4111-8111-111111111105
      CASE_NODE_PORT=18105
      CASE_PROXY_PORT=18205
      CASE_NETWORK=httpupgrade
      CASE_HTTPUPGRADE_PATH=/vmess-httpupgrade
      ;;
    vmess_httpupgrade_headers)
      CASE_NODE_TYPE=vmess
      CASE_NODE_ID=9108
      CASE_USER_ID=19108
      CASE_UUID=11111111-1111-4111-8111-111111111108
      CASE_NODE_PORT=18108
      CASE_PROXY_PORT=18208
      CASE_NETWORK=httpupgrade
      CASE_HTTPUPGRADE_PATH=/vmess-httpupgrade-headers
      CASE_HTTPUPGRADE_HEADER_NAME=X-Shoes-E2E
      CASE_HTTPUPGRADE_HEADER_VALUE=matrix
      ;;
    vmess_http)
      CASE_NODE_TYPE=vmess
      CASE_NODE_ID=9109
      CASE_USER_ID=19109
      CASE_UUID=11111111-1111-4111-8111-111111111109
      CASE_NODE_PORT=18109
      CASE_PROXY_PORT=18209
      CASE_NETWORK=http
      CASE_HTTP_PATH=/vmess-http
      ;;
    vmess_http_tls)
      CASE_NODE_TYPE=vmess
      CASE_NODE_ID=9111
      CASE_USER_ID=19111
      CASE_UUID=11111111-1111-4111-8111-111111111111
      CASE_NODE_PORT=18128
      CASE_PROXY_PORT=18228
      CASE_NETWORK=http
      CASE_HTTP_PATH=/vmess-http-tls
      CASE_TLS=1
      ;;
    vmess_xhttp_tls)
      CASE_NODE_TYPE=vmess
      CASE_NODE_ID=9113
      CASE_USER_ID=19113
      CASE_UUID=11111111-1111-4111-8111-111111111113
      CASE_NODE_PORT=18312
      CASE_PROXY_PORT=18412
      CASE_NETWORK=xhttp
      CASE_TLS=1
      CASE_TLS_SERVER_NAME=example.org
      CASE_XHTTP_HOST=example.org
      CASE_XHTTP_PATH=/vmess-xhttp-tls
      CASE_XHTTP_MODE=packet-up
      ;;
    vmess_xhttp_auto_tls)
      CASE_NODE_TYPE=vmess
      CASE_NODE_ID=9501
      CASE_USER_ID=19501
      CASE_UUID=aaaaaaaa-9501-4aaa-8aaa-aaaaaaaa9501
      CASE_NODE_PORT=18501
      CASE_PROXY_PORT=18601
      CASE_NETWORK=xhttp
      CASE_TLS=1
      CASE_TLS_SERVER_NAME=example.org
      CASE_XHTTP_HOST=example.org
      CASE_XHTTP_PATH=/vmess-xhttp-auto
      CASE_XHTTP_MODE=auto
      CASE_XHTTP_SESSION_PLACEMENT=header
      CASE_XHTTP_SESSION_KEY=X-Session
      CASE_XHTTP_SEQ_PLACEMENT=header
      CASE_XHTTP_SEQ_KEY=X-Seq
      CASE_XHTTP_UPLINK_DATA_PLACEMENT=header
      CASE_XHTTP_UPLINK_DATA_KEY=X-Data
      ;;
    vmess_tcp_http_header)
      CASE_NODE_TYPE=vmess
      CASE_NODE_ID=9110
      CASE_USER_ID=19110
      CASE_UUID=11111111-1111-4111-8111-111111111110
      CASE_NODE_PORT=18110
      CASE_PROXY_PORT=18210
      CASE_NETWORK=tcp
      CASE_TCP_HTTP_HEADER=1
      CASE_HTTP_PATH=/vmess-tcp-http-header
      ;;
    vmess_zero_security)
      CASE_NODE_TYPE=vmess
      CASE_NODE_ID=9106
      CASE_USER_ID=19106
      CASE_UUID=11111111-1111-4111-8111-111111111106
      CASE_NODE_PORT=18106
      CASE_PROXY_PORT=18206
      CASE_NETWORK=tcp
      CASE_VMESS_SECURITY=none
      ;;
    vless_tcp)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9201
      CASE_USER_ID=19201
      CASE_UUID=22222222-2222-4222-8222-222222222201
      CASE_NODE_PORT=18111
      CASE_PROXY_PORT=18211
      CASE_NETWORK=tcp
      ;;
    vless_ws)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9202
      CASE_USER_ID=19202
      CASE_UUID=22222222-2222-4222-8222-222222222202
      CASE_NODE_PORT=18112
      CASE_PROXY_PORT=18212
      CASE_NETWORK=ws
      CASE_WS_PATH=/vless-ws
      ;;
    vless_tls)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9203
      CASE_USER_ID=19203
      CASE_UUID=22222222-2222-4222-8222-222222222203
      CASE_NODE_PORT=18113
      CASE_PROXY_PORT=18213
      CASE_NETWORK=tcp
      CASE_TLS=1
      ;;
    vless_grpc)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9204
      CASE_USER_ID=19204
      CASE_UUID=22222222-2222-4222-8222-222222222204
      CASE_NODE_PORT=18114
      CASE_PROXY_PORT=18214
      CASE_NETWORK=grpc
      CASE_GRPC_SERVICE_NAME=vless-grpc
      ;;
    vless_httpupgrade)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9205
      CASE_USER_ID=19205
      CASE_UUID=22222222-2222-4222-8222-222222222205
      CASE_NODE_PORT=18115
      CASE_PROXY_PORT=18215
      CASE_NETWORK=httpupgrade
      CASE_HTTPUPGRADE_PATH=/vless-httpupgrade
      ;;
    vless_http)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9209
      CASE_USER_ID=19209
      CASE_UUID=22222222-2222-4222-8222-222222222209
      CASE_NODE_PORT=18119
      CASE_PROXY_PORT=18219
      CASE_NETWORK=http
      CASE_HTTP_PATH=/vless-http
      ;;
    vless_http_tls)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9210
      CASE_USER_ID=19210
      CASE_UUID=22222222-2222-4222-8222-222222222210
      CASE_NODE_PORT=18120
      CASE_PROXY_PORT=18220
      CASE_NETWORK=http
      CASE_HTTP_PATH=/vless-http-tls
      CASE_TLS=1
      ;;
    vless_xhttp_tls)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9212
      CASE_USER_ID=19212
      CASE_UUID=22222222-2222-4222-8222-222222222212
      CASE_NODE_PORT=18130
      CASE_PROXY_PORT=18230
      CASE_NETWORK=xhttp
      CASE_TLS=1
      CASE_TLS_SERVER_NAME=example.org
      CASE_XHTTP_HOST=example.org
      CASE_XHTTP_PATH=/vless-xhttp
      CASE_XHTTP_MODE=packet-up
      ;;
    vless_xhttp_stream_up_tls)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9502
      CASE_USER_ID=19502
      CASE_UUID=aaaaaaaa-9502-4aaa-8aaa-aaaaaaaa9502
      CASE_NODE_PORT=18502
      CASE_PROXY_PORT=18602
      CASE_NETWORK=xhttp
      CASE_TLS=1
      CASE_TLS_SERVER_NAME=example.org
      CASE_XHTTP_HOST=example.org
      CASE_XHTTP_PATH=/vless-xhttp-stream-up
      CASE_XHTTP_MODE=stream-up
      CASE_XHTTP_SESSION_PLACEMENT=cookie
      CASE_XHTTP_SESSION_KEY=x_session
      CASE_XHTTP_SEQ_PLACEMENT=cookie
      CASE_XHTTP_SEQ_KEY=x_seq
      CASE_XHTTP_UPLINK_DATA_PLACEMENT=body
      ;;
    vless_xhttp_stream_one_tls)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9503
      CASE_USER_ID=19503
      CASE_UUID=aaaaaaaa-9503-4aaa-8aaa-aaaaaaaa9503
      CASE_NODE_PORT=18503
      CASE_PROXY_PORT=18603
      CASE_NETWORK=xhttp
      CASE_TLS=1
      CASE_TLS_SERVER_NAME=example.org
      CASE_XHTTP_HOST=example.org
      CASE_XHTTP_PATH=/vless-xhttp-stream-one
      CASE_XHTTP_MODE=stream-one
      ;;
    vless_splithttp_tls)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9504
      CASE_USER_ID=19504
      CASE_UUID=aaaaaaaa-9504-4aaa-8aaa-aaaaaaaa9504
      CASE_NODE_PORT=18504
      CASE_PROXY_PORT=18604
      CASE_NETWORK=splithttp
      CASE_TLS=1
      CASE_TLS_SERVER_NAME=example.org
      CASE_XHTTP_HOST=example.org
      CASE_XHTTP_PATH=/vless-splithttp
      CASE_XHTTP_MODE=packet-up
      CASE_XHTTP_SESSION_PLACEMENT=query
      CASE_XHTTP_SESSION_KEY=x_session
      CASE_XHTTP_SEQ_PLACEMENT=query
      CASE_XHTTP_SEQ_KEY=x_seq
      CASE_XHTTP_UPLINK_DATA_PLACEMENT=cookie
      CASE_XHTTP_UPLINK_DATA_KEY=x_data
      ;;
    vless_xhttp_reality)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9213
      CASE_USER_ID=19213
      CASE_UUID=22222222-2222-4222-8222-222222222213
      CASE_NODE_PORT=18313
      CASE_PROXY_PORT=18413
      CASE_NETWORK=xhttp
      CASE_TLS=2
      CASE_TLS_SERVER_NAME=localhost
      CASE_XHTTP_HOST=localhost
      CASE_XHTTP_PATH=/vless-xhttp-reality
      CASE_XHTTP_MODE=packet-up
      CASE_REALITY=1
      ;;
    vless_http_reality)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9211
      CASE_USER_ID=19211
      CASE_UUID=22222222-2222-4222-8222-222222222211
      CASE_NODE_PORT=18129
      CASE_PROXY_PORT=18229
      CASE_NETWORK=http
      CASE_HTTP_PATH=/vless-http-reality
      CASE_TLS=2
      CASE_TLS_SERVER_NAME=localhost
      CASE_REALITY=1
      ;;
    vless_vision_tls)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9206
      CASE_USER_ID=19206
      CASE_UUID=22222222-2222-4222-8222-222222222206
      CASE_NODE_PORT=18116
      CASE_PROXY_PORT=18216
      CASE_NETWORK=tcp
      CASE_TLS=1
      CASE_FLOW=xtls-rprx-vision
      ;;
    vless_reality)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9207
      CASE_USER_ID=19207
      CASE_UUID=22222222-2222-4222-8222-222222222207
      CASE_NODE_PORT=18117
      CASE_PROXY_PORT=18217
      CASE_NETWORK=tcp
      CASE_TLS=2
      CASE_TLS_SERVER_NAME=localhost
      CASE_REALITY=1
      ;;
    vless_vision_reality)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9208
      CASE_USER_ID=19208
      CASE_UUID=22222222-2222-4222-8222-222222222208
      CASE_NODE_PORT=18118
      CASE_PROXY_PORT=18218
      CASE_NETWORK=tcp
      CASE_TLS=2
      CASE_TLS_SERVER_NAME=localhost
      CASE_REALITY=1
      CASE_FLOW=xtls-rprx-vision
      ;;
    shadowsocks_aead)
      CASE_NODE_TYPE=shadowsocks
      CASE_NODE_ID=9301
      CASE_USER_ID=19301
      CASE_UUID=33333333-3333-4333-8333-333333333301
      CASE_NODE_PORT=18121
      CASE_PROXY_PORT=18221
      CASE_NETWORK=tcp
      CASE_SS_CIPHER=aes-128-gcm
      ;;
    shadowsocks_aead_aes192)
      CASE_NODE_TYPE=shadowsocks
      CASE_NODE_ID=9304
      CASE_USER_ID=19304
      CASE_UUID=33333333-3333-4333-8333-333333333304
      CASE_NODE_PORT=18124
      CASE_PROXY_PORT=18224
      CASE_NETWORK=tcp
      CASE_SS_CIPHER=aes-192-gcm
      ;;
    shadowsocks_aead_aes256)
      CASE_NODE_TYPE=shadowsocks
      CASE_NODE_ID=9305
      CASE_USER_ID=19305
      CASE_UUID=33333333-3333-4333-8333-333333333305
      CASE_NODE_PORT=18125
      CASE_PROXY_PORT=18225
      CASE_NETWORK=tcp
      CASE_SS_CIPHER=aes-256-gcm
      ;;
    shadowsocks_aead_chacha20)
      CASE_NODE_TYPE=shadowsocks
      CASE_NODE_ID=9306
      CASE_USER_ID=19306
      CASE_UUID=33333333-3333-4333-8333-333333333306
      CASE_NODE_PORT=18126
      CASE_PROXY_PORT=18226
      CASE_NETWORK=tcp
      CASE_SS_CIPHER=chacha20-ietf-poly1305
      ;;
    shadowsocks_obfs_http)
      CASE_NODE_TYPE=shadowsocks
      CASE_NODE_ID=9307
      CASE_USER_ID=19307
      CASE_UUID=33333333-3333-4333-8333-333333333307
      CASE_NODE_PORT=18127
      CASE_PROXY_PORT=18227
      CASE_NETWORK=tcp
      CASE_SS_CIPHER=aes-128-gcm
      CASE_SS_OBFS=http
      CASE_SS_OBFS_SETTINGS='{"host":"example.com","path":"/obfs"}'
      CASE_SS_OBFS_HOST=example.com
      CASE_SS_OBFS_PATH=/obfs
      ;;
    shadowsocks_2022_aes128)
      CASE_NODE_TYPE=shadowsocks
      CASE_NODE_ID=9302
      CASE_USER_ID=19302
      CASE_UUID=33333002-9302-4333-8333-333333333302
      CASE_NODE_PORT=18122
      CASE_PROXY_PORT=18222
      CASE_NETWORK=tcp
      CASE_SS_CIPHER=2022-blake3-aes-128-gcm
      ;;
    shadowsocks_2022_aes256)
      CASE_NODE_TYPE=shadowsocks
      CASE_NODE_ID=9303
      CASE_USER_ID=19303
      CASE_UUID=33333003-9303-4333-8333-333333333303
      CASE_NODE_PORT=18123
      CASE_PROXY_PORT=18223
      CASE_NETWORK=tcp
      CASE_SS_CIPHER=2022-blake3-aes-256-gcm
      ;;
    trojan_tls)
      CASE_NODE_TYPE=trojan
      CASE_NODE_ID=9401
      CASE_USER_ID=19401
      CASE_UUID=44444444-4444-4444-8444-444444444401
      CASE_NODE_PORT=18131
      CASE_PROXY_PORT=18231
      CASE_NETWORK=tcp
      CASE_TLS=1
      ;;
    trojan_ws)
      CASE_NODE_TYPE=trojan
      CASE_NODE_ID=9402
      CASE_USER_ID=19402
      CASE_UUID=44444444-4444-4444-8444-444444444402
      CASE_NODE_PORT=18132
      CASE_PROXY_PORT=18232
      CASE_NETWORK=ws
      CASE_WS_PATH=/trojan-ws
      CASE_TLS=1
      ;;
    trojan_grpc)
      CASE_NODE_TYPE=trojan
      CASE_NODE_ID=9403
      CASE_USER_ID=19403
      CASE_UUID=44444444-4444-4444-8444-444444444403
      CASE_NODE_PORT=18133
      CASE_PROXY_PORT=18233
      CASE_NETWORK=grpc
      CASE_GRPC_SERVICE_NAME=trojan-grpc
      CASE_TLS=1
      ;;
    trojan_httpupgrade)
      CASE_NODE_TYPE=trojan
      CASE_NODE_ID=9404
      CASE_USER_ID=19404
      CASE_UUID=44444444-4444-4444-8444-444444444404
      CASE_NODE_PORT=18134
      CASE_PROXY_PORT=18234
      CASE_NETWORK=httpupgrade
      CASE_HTTPUPGRADE_PATH=/trojan-httpupgrade
      CASE_TLS=1
      ;;
    anytls_tls)
      CASE_NODE_TYPE=anytls
      CASE_NODE_ID=9451
      CASE_USER_ID=19451
      CASE_UUID=55555555-5555-4555-8555-555555555501
      CASE_NODE_PORT=18135
      CASE_PROXY_PORT=18235
      CASE_NETWORK=tcp
      CASE_TLS=1
      ;;
    tuic_tls)
      CASE_NODE_TYPE=tuic
      CASE_NODE_ID=9452
      CASE_USER_ID=19452
      CASE_UUID=55555555-5555-4555-8555-555555555502
      CASE_NODE_PORT=18144
      CASE_PROXY_PORT=18244
      CASE_NETWORK=tcp
      CASE_TLS=1
      CASE_TUIC_CONGESTION_CONTROL=cubic
      CASE_TUIC_UDP_RELAY_MODE=native
      ;;
    tuic_tls_newreno_zero_rtt)
      CASE_NODE_TYPE=tuic
      CASE_NODE_ID=9454
      CASE_USER_ID=19454
      CASE_UUID=55555555-5555-4555-8555-555555555504
      CASE_NODE_PORT=18154
      CASE_PROXY_PORT=18254
      CASE_NETWORK=tcp
      CASE_TLS=1
      CASE_TUIC_CONGESTION_CONTROL=new_reno
      CASE_TUIC_UDP_RELAY_MODE=native
      CASE_TUIC_ZERO_RTT=1
      ;;
    hysteria2_tls)
      CASE_NODE_TYPE=hysteria
      CASE_CLIENT_TYPE=hysteria2
      CASE_NODE_ID=9453
      CASE_USER_ID=19453
      CASE_UUID=55555555-5555-4555-8555-555555555503
      CASE_NODE_PORT=18146
      CASE_PROXY_PORT=18246
      CASE_NETWORK=tcp
      CASE_TLS=1
      ;;
    vless_ws_proxy_protocol_v1)
      CASE_NODE_TYPE=vless
      CASE_NODE_ID=9471
      CASE_USER_ID=19471
      CASE_UUID=77777777-7777-4777-8777-777777777471
      CASE_NODE_PORT=18141
      CASE_PROXY_PORT=18241
      CASE_PROXY_PROTOCOL_BRIDGE_PORT=18341
      CASE_NETWORK=ws
      CASE_WS_PATH=/vless-ws-proxy-protocol-v1
      CASE_ACCEPT_PROXY_PROTOCOL=1
      CASE_PROXY_PROTOCOL_VERSION=1
      CASE_PROXY_PROTOCOL_SOURCE_IP=198.18.0.41
      CASE_PROXY_PROTOCOL_SOURCE_PORT=42441
      ;;
    v2node_anytls_tls_proxy_protocol_v2)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=anytls
      CASE_V2_PROTOCOL=anytls
      CASE_NODE_ID=9472
      CASE_USER_ID=19472
      CASE_UUID=77777777-7777-4777-8777-777777777472
      CASE_NODE_PORT=18142
      CASE_PROXY_PORT=18242
      CASE_PROXY_PROTOCOL_BRIDGE_PORT=18342
      CASE_NETWORK=tcp
      CASE_TLS=1
      CASE_ACCEPT_PROXY_PROTOCOL=1
      CASE_PROXY_PROTOCOL_VERSION=2
      CASE_PROXY_PROTOCOL_SOURCE_IP=198.18.0.42
      CASE_PROXY_PROTOCOL_SOURCE_PORT=42442
      ;;
    v2node_vmess_ws_proxy_protocol_v1)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vmess
      CASE_V2_PROTOCOL=vmess
      CASE_NODE_ID=9473
      CASE_USER_ID=19473
      CASE_UUID=77777777-7777-4777-8777-777777777473
      CASE_NODE_PORT=18143
      CASE_PROXY_PORT=18243
      CASE_PROXY_PROTOCOL_BRIDGE_PORT=18343
      CASE_NETWORK=ws
      CASE_WS_PATH=/v2node-vmess-ws-proxy-protocol-v1
      CASE_ACCEPT_PROXY_PROTOCOL=1
      CASE_PROXY_PROTOCOL_VERSION=1
      CASE_PROXY_PROTOCOL_SOURCE_IP=198.18.0.43
      CASE_PROXY_PROTOCOL_SOURCE_PORT=42443
      ;;
    v2node_vmess_ws)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vmess
      CASE_V2_PROTOCOL=vmess
      CASE_NODE_ID=9462
      CASE_USER_ID=19462
      CASE_UUID=66666666-6666-4666-8666-666666666662
      CASE_NODE_PORT=18137
      CASE_PROXY_PORT=18237
      CASE_NETWORK=ws
      CASE_WS_PATH=/v2node-vmess-ws
      ;;
    v2node_vmess_tcp)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vmess
      CASE_V2_PROTOCOL=vmess
      CASE_NODE_ID=9850
      CASE_USER_ID=19850
      CASE_UUID=99999999-9850-4999-8999-999999999850
      CASE_NODE_PORT=18850
      CASE_PROXY_PORT=18950
      CASE_NETWORK=tcp
      ;;
    v2node_vmess_http)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vmess
      CASE_V2_PROTOCOL=vmess
      CASE_NODE_ID=9851
      CASE_USER_ID=19851
      CASE_UUID=99999999-9851-4999-8999-999999999851
      CASE_NODE_PORT=18851
      CASE_PROXY_PORT=18951
      CASE_NETWORK=http
      CASE_HTTP_PATH=/v2node-vmess-http
      ;;
    v2node_vmess_http_tls)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vmess
      CASE_V2_PROTOCOL=vmess
      CASE_NODE_ID=9481
      CASE_USER_ID=19481
      CASE_UUID=88888888-8888-4888-8888-888888888481
      CASE_NODE_PORT=18381
      CASE_PROXY_PORT=18481
      CASE_NETWORK=http
      CASE_HTTP_PATH=/v2node-vmess-http-tls
      CASE_TLS=1
      ;;
    v2node_vmess_grpc)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vmess
      CASE_V2_PROTOCOL=vmess
      CASE_NODE_ID=9482
      CASE_USER_ID=19482
      CASE_UUID=88888888-8888-4888-8888-888888888482
      CASE_NODE_PORT=18382
      CASE_PROXY_PORT=18482
      CASE_NETWORK=grpc
      CASE_GRPC_SERVICE_NAME=v2node-vmess-grpc
      ;;
    v2node_vmess_httpupgrade)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vmess
      CASE_V2_PROTOCOL=vmess
      CASE_NODE_ID=9483
      CASE_USER_ID=19483
      CASE_UUID=88888888-8888-4888-8888-888888888483
      CASE_NODE_PORT=18383
      CASE_PROXY_PORT=18483
      CASE_NETWORK=httpupgrade
      CASE_HTTPUPGRADE_PATH=/v2node-vmess-httpupgrade
      ;;
    v2node_vmess_xhttp_tls)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vmess
      CASE_V2_PROTOCOL=vmess
      CASE_NODE_ID=9492
      CASE_USER_ID=19492
      CASE_UUID=88888888-8888-4888-8888-888888888492
      CASE_NODE_PORT=18392
      CASE_PROXY_PORT=18492
      CASE_NETWORK=xhttp
      CASE_TLS=1
      CASE_TLS_SERVER_NAME=example.org
      CASE_XHTTP_HOST=example.org
      CASE_XHTTP_PATH=/v2node-vmess-xhttp-tls
      CASE_XHTTP_MODE=packet-up
      ;;
    v2node_vless_ws)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vless
      CASE_V2_PROTOCOL=vless
      CASE_NODE_ID=9484
      CASE_USER_ID=19484
      CASE_UUID=88888888-8888-4888-8888-888888888484
      CASE_NODE_PORT=18384
      CASE_PROXY_PORT=18484
      CASE_NETWORK=ws
      CASE_WS_PATH=/v2node-vless-ws
      ;;
    v2node_vless_tcp)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vless
      CASE_V2_PROTOCOL=vless
      CASE_NODE_ID=9852
      CASE_USER_ID=19852
      CASE_UUID=99999999-9852-4999-8999-999999999852
      CASE_NODE_PORT=18852
      CASE_PROXY_PORT=18952
      CASE_NETWORK=tcp
      ;;
    v2node_vless_tls)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vless
      CASE_V2_PROTOCOL=vless
      CASE_NODE_ID=9853
      CASE_USER_ID=19853
      CASE_UUID=99999999-9853-4999-8999-999999999853
      CASE_NODE_PORT=18853
      CASE_PROXY_PORT=18953
      CASE_NETWORK=tcp
      CASE_TLS=1
      ;;
    v2node_vless_http)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vless
      CASE_V2_PROTOCOL=vless
      CASE_NODE_ID=9854
      CASE_USER_ID=19854
      CASE_UUID=99999999-9854-4999-8999-999999999854
      CASE_NODE_PORT=18854
      CASE_PROXY_PORT=18954
      CASE_NETWORK=http
      CASE_HTTP_PATH=/v2node-vless-http
      ;;
    v2node_vless_http_tls)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vless
      CASE_V2_PROTOCOL=vless
      CASE_NODE_ID=9485
      CASE_USER_ID=19485
      CASE_UUID=88888888-8888-4888-8888-888888888485
      CASE_NODE_PORT=18385
      CASE_PROXY_PORT=18485
      CASE_NETWORK=http
      CASE_HTTP_PATH=/v2node-vless-http-tls
      CASE_TLS=1
      ;;
    v2node_vless_grpc)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vless
      CASE_V2_PROTOCOL=vless
      CASE_NODE_ID=9855
      CASE_USER_ID=19855
      CASE_UUID=99999999-9855-4999-8999-999999999855
      CASE_NODE_PORT=18855
      CASE_PROXY_PORT=18955
      CASE_NETWORK=grpc
      CASE_GRPC_SERVICE_NAME=v2node-vless-grpc
      ;;
    v2node_vless_httpupgrade)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vless
      CASE_V2_PROTOCOL=vless
      CASE_NODE_ID=9856
      CASE_USER_ID=19856
      CASE_UUID=99999999-9856-4999-8999-999999999856
      CASE_NODE_PORT=18856
      CASE_PROXY_PORT=18956
      CASE_NETWORK=httpupgrade
      CASE_HTTPUPGRADE_PATH=/v2node-vless-httpupgrade
      ;;
    v2node_vless_xhttp_tls)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vless
      CASE_V2_PROTOCOL=vless
      CASE_NODE_ID=9486
      CASE_USER_ID=19486
      CASE_UUID=88888888-8888-4888-8888-888888888486
      CASE_NODE_PORT=18386
      CASE_PROXY_PORT=18486
      CASE_NETWORK=xhttp
      CASE_TLS=1
      CASE_TLS_SERVER_NAME=example.org
      CASE_XHTTP_HOST=example.org
      CASE_XHTTP_PATH=/v2node-vless-xhttp-tls
      CASE_XHTTP_MODE=packet-up
      ;;
    v2node_vless_splithttp_tls)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vless
      CASE_V2_PROTOCOL=vless
      CASE_NODE_ID=9511
      CASE_USER_ID=19511
      CASE_UUID=aaaaaaaa-9511-4aaa-8aaa-aaaaaaaa9511
      CASE_NODE_PORT=18511
      CASE_PROXY_PORT=18611
      CASE_NETWORK=splithttp
      CASE_TLS=1
      CASE_TLS_SERVER_NAME=example.org
      CASE_XHTTP_HOST=example.org
      CASE_XHTTP_PATH=/v2node-vless-splithttp
      CASE_XHTTP_MODE=packet-up
      CASE_XHTTP_SESSION_PLACEMENT=query
      CASE_XHTTP_SESSION_KEY=x_session
      CASE_XHTTP_SEQ_PLACEMENT=query
      CASE_XHTTP_SEQ_KEY=x_seq
      CASE_XHTTP_UPLINK_DATA_PLACEMENT=body
      ;;
    v2node_vless_xhttp_reality)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vless
      CASE_V2_PROTOCOL=vless
      CASE_NODE_ID=9487
      CASE_USER_ID=19487
      CASE_UUID=88888888-8888-4888-8888-888888888487
      CASE_NODE_PORT=18387
      CASE_PROXY_PORT=18487
      CASE_NETWORK=xhttp
      CASE_TLS=2
      CASE_TLS_SERVER_NAME=localhost
      CASE_XHTTP_HOST=localhost
      CASE_XHTTP_PATH=/v2node-vless-xhttp-reality
      CASE_XHTTP_MODE=packet-up
      CASE_REALITY=1
      ;;
    v2node_vless_vision_tls)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vless
      CASE_V2_PROTOCOL=vless
      CASE_NODE_ID=9857
      CASE_USER_ID=19857
      CASE_UUID=99999999-9857-4999-8999-999999999857
      CASE_NODE_PORT=18857
      CASE_PROXY_PORT=18957
      CASE_NETWORK=tcp
      CASE_TLS=1
      CASE_FLOW=xtls-rprx-vision
      ;;
    v2node_vless_reality)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=vless
      CASE_V2_PROTOCOL=vless
      CASE_NODE_ID=9463
      CASE_USER_ID=19463
      CASE_UUID=66666666-6666-4666-8666-666666666663
      CASE_NODE_PORT=18138
      CASE_PROXY_PORT=18238
      CASE_NETWORK=tcp
      CASE_TLS=2
      CASE_TLS_SERVER_NAME=localhost
      CASE_REALITY=1
      ;;
    v2node_shadowsocks_aead)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=shadowsocks
      CASE_V2_PROTOCOL=shadowsocks
      CASE_NODE_ID=9491
      CASE_USER_ID=19491
      CASE_UUID=88888888-8888-4888-8888-888888888491
      CASE_NODE_PORT=18391
      CASE_PROXY_PORT=18491
      CASE_NETWORK=tcp
      CASE_SS_CIPHER=aes-128-gcm
      ;;
    v2node_shadowsocks_aead_aes192)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=shadowsocks
      CASE_V2_PROTOCOL=shadowsocks
      CASE_NODE_ID=9858
      CASE_USER_ID=19858
      CASE_UUID=99999999-9858-4999-8999-999999999858
      CASE_NODE_PORT=18858
      CASE_PROXY_PORT=18958
      CASE_NETWORK=tcp
      CASE_SS_CIPHER=aes-192-gcm
      ;;
    v2node_shadowsocks_aead_aes256)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=shadowsocks
      CASE_V2_PROTOCOL=shadowsocks
      CASE_NODE_ID=9859
      CASE_USER_ID=19859
      CASE_UUID=99999999-9859-4999-8999-999999999859
      CASE_NODE_PORT=18859
      CASE_PROXY_PORT=18959
      CASE_NETWORK=tcp
      CASE_SS_CIPHER=aes-256-gcm
      ;;
    v2node_shadowsocks_aead_chacha20)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=shadowsocks
      CASE_V2_PROTOCOL=shadowsocks
      CASE_NODE_ID=9860
      CASE_USER_ID=19860
      CASE_UUID=99999999-9860-4999-8999-999999999860
      CASE_NODE_PORT=18860
      CASE_PROXY_PORT=18960
      CASE_NETWORK=tcp
      CASE_SS_CIPHER=chacha20-ietf-poly1305
      ;;
    v2node_shadowsocks_2022_aes128)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=shadowsocks
      CASE_V2_PROTOCOL=shadowsocks
      CASE_NODE_ID=9464
      CASE_USER_ID=19464
      CASE_UUID=66666666-6666-4666-8666-666666666664
      CASE_NODE_PORT=18139
      CASE_PROXY_PORT=18239
      CASE_NETWORK=tcp
      CASE_SS_CIPHER=2022-blake3-aes-128-gcm
      ;;
    v2node_shadowsocks_2022_aes256)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=shadowsocks
      CASE_V2_PROTOCOL=shadowsocks
      CASE_NODE_ID=9490
      CASE_USER_ID=19490
      CASE_UUID=88888888-8888-4888-8888-888888888490
      CASE_NODE_PORT=18390
      CASE_PROXY_PORT=18490
      CASE_NETWORK=tcp
      CASE_SS_CIPHER=2022-blake3-aes-256-gcm
      ;;
    v2node_trojan_tls)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=trojan
      CASE_V2_PROTOCOL=trojan
      CASE_NODE_ID=9465
      CASE_USER_ID=19465
      CASE_UUID=66666666-6666-4666-8666-666666666665
      CASE_NODE_PORT=18140
      CASE_PROXY_PORT=18240
      CASE_NETWORK=tcp
      CASE_TLS=1
      ;;
    v2node_trojan_ws)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=trojan
      CASE_V2_PROTOCOL=trojan
      CASE_NODE_ID=9488
      CASE_USER_ID=19488
      CASE_UUID=88888888-8888-4888-8888-888888888488
      CASE_NODE_PORT=18388
      CASE_PROXY_PORT=18488
      CASE_NETWORK=ws
      CASE_WS_PATH=/v2node-trojan-ws
      CASE_TLS=1
      ;;
    v2node_trojan_grpc)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=trojan
      CASE_V2_PROTOCOL=trojan
      CASE_NODE_ID=9489
      CASE_USER_ID=19489
      CASE_UUID=88888888-8888-4888-8888-888888888489
      CASE_NODE_PORT=18389
      CASE_PROXY_PORT=18489
      CASE_NETWORK=grpc
      CASE_GRPC_SERVICE_NAME=v2node-trojan-grpc
      CASE_TLS=1
      ;;
    v2node_trojan_httpupgrade)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=trojan
      CASE_V2_PROTOCOL=trojan
      CASE_NODE_ID=9861
      CASE_USER_ID=19861
      CASE_UUID=99999999-9861-4999-8999-999999999861
      CASE_NODE_PORT=18861
      CASE_PROXY_PORT=18961
      CASE_NETWORK=httpupgrade
      CASE_HTTPUPGRADE_PATH=/v2node-trojan-httpupgrade
      CASE_TLS=1
      ;;
    v2node_tuic_tls)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=tuic
      CASE_V2_PROTOCOL=tuic
      CASE_NODE_ID=9466
      CASE_USER_ID=19466
      CASE_UUID=66666666-6666-4666-8666-666666666666
      CASE_NODE_PORT=18145
      CASE_PROXY_PORT=18245
      CASE_NETWORK=tcp
      CASE_TLS=1
      CASE_TUIC_CONGESTION_CONTROL=bbr
      CASE_TUIC_UDP_RELAY_MODE=native
      ;;
    v2node_hysteria2_tls)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=hysteria2
      CASE_V2_PROTOCOL=hysteria2
      CASE_NODE_ID=9467
      CASE_USER_ID=19467
      CASE_UUID=66666666-6666-4666-8666-666666666667
      CASE_NODE_PORT=18147
      CASE_PROXY_PORT=18247
      CASE_NETWORK=tcp
      CASE_TLS=1
      ;;
    v2node_anytls_reality)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=anytls
      CASE_V2_PROTOCOL=anytls
      CASE_NODE_ID=9461
      CASE_USER_ID=19461
      CASE_UUID=55555555-5555-4555-8555-555555555561
      CASE_NODE_PORT=18136
      CASE_PROXY_PORT=18236
      CASE_NETWORK=tcp
      CASE_TLS=2
      CASE_TLS_SERVER_NAME=localhost
      CASE_REALITY=1
      ;;
    v2node_anytls_tls)
      CASE_NODE_TYPE=v2node
      CASE_CLIENT_TYPE=anytls
      CASE_V2_PROTOCOL=anytls
      CASE_NODE_ID=9862
      CASE_USER_ID=19862
      CASE_UUID=99999999-9862-4999-8999-999999999862
      CASE_NODE_PORT=18862
      CASE_PROXY_PORT=18962
      CASE_NETWORK=tcp
      CASE_TLS=1
      ;;
    *)
      e2e_die "unknown matrix case: ${CASE_NAME}"
      ;;
  esac

  CASE_GROUP_ID="${CASE_NODE_ID}"
  if [[ -z "${CASE_CLIENT_TYPE}" ]]; then
    CASE_CLIENT_TYPE="${CASE_NODE_TYPE}"
  fi
  if [[ -z "${CASE_V2_PROTOCOL}" && "${CASE_NODE_TYPE}" == "v2node" ]]; then
    CASE_V2_PROTOCOL="${CASE_CLIENT_TYPE}"
  fi
  if [[ "${CASE_ACCEPT_PROXY_PROTOCOL}" == "1" && -z "${CASE_PROXY_PROTOCOL_BRIDGE_PORT}" ]]; then
    CASE_PROXY_PROTOCOL_BRIDGE_PORT="$((CASE_NODE_PORT + 2000))"
  fi
}

network_settings_json() {
  local settings

  if [[ "${CASE_TCP_HTTP_HEADER}" == "1" ]]; then
    settings="$(printf '{"header":{"type":"http","request":{"method":"%s","path":["%s"],"headers":{"Host":["%s"]}}}}' \
      "${CASE_HTTP_METHOD}" \
      "${CASE_HTTP_PATH}" \
      "${CASE_HTTP_HOST}")"
  else
    case "${CASE_NETWORK}" in
      http)
        settings="$(printf '{"host":["%s"],"path":["%s"],"method":"%s","headers":{"X-Shoes-E2E":["matrix"]}}' \
          "${CASE_HTTP_HOST}" \
          "${CASE_HTTP_PATH}" \
          "${CASE_HTTP_METHOD}")"
        ;;
      ws)
        settings="$(printf '{"path":"%s","headers":{"Host":"example.org"}}' "${CASE_WS_PATH}")"
        ;;
      grpc)
        if [[ -n "${CASE_GRPC_AUTHORITY}" ]]; then
          settings="$(printf '{"serviceName":"%s","authority":"%s"}' "${CASE_GRPC_SERVICE_NAME}" "${CASE_GRPC_AUTHORITY}")"
        else
          settings="$(printf '{"serviceName":"%s"}' "${CASE_GRPC_SERVICE_NAME}")"
        fi
        ;;
      httpupgrade)
        if [[ -n "${CASE_HTTPUPGRADE_HEADER_NAME}" ]]; then
          settings="$(printf '{"path":"%s","host":"%s","headers":{"%s":"%s"}}' \
            "${CASE_HTTPUPGRADE_PATH}" \
            "${CASE_HTTPUPGRADE_HOST}" \
            "${CASE_HTTPUPGRADE_HEADER_NAME}" \
            "${CASE_HTTPUPGRADE_HEADER_VALUE}")"
        else
          settings="$(printf '{"path":"%s","host":"%s"}' "${CASE_HTTPUPGRADE_PATH}" "${CASE_HTTPUPGRADE_HOST}")"
        fi
        ;;
      xhttp | splithttp | split-http | split_http)
        settings="$(
          CASE_XHTTP_PATH="${CASE_XHTTP_PATH}" \
            CASE_XHTTP_HOST="${CASE_XHTTP_HOST}" \
            CASE_XHTTP_MODE="${CASE_XHTTP_MODE}" \
            CASE_XHTTP_SESSION_PLACEMENT="${CASE_XHTTP_SESSION_PLACEMENT}" \
            CASE_XHTTP_SESSION_KEY="${CASE_XHTTP_SESSION_KEY}" \
            CASE_XHTTP_SEQ_PLACEMENT="${CASE_XHTTP_SEQ_PLACEMENT}" \
            CASE_XHTTP_SEQ_KEY="${CASE_XHTTP_SEQ_KEY}" \
            CASE_XHTTP_UPLINK_DATA_PLACEMENT="${CASE_XHTTP_UPLINK_DATA_PLACEMENT}" \
            CASE_XHTTP_UPLINK_DATA_KEY="${CASE_XHTTP_UPLINK_DATA_KEY}" \
            python3 - <<'PY'
import json
import os

settings = {
    "path": os.environ["CASE_XHTTP_PATH"],
    "host": os.environ["CASE_XHTTP_HOST"],
    "mode": os.environ["CASE_XHTTP_MODE"],
    "extra": {
        "scMaxEachPostBytes": {"from": 1048576, "to": 1048576},
        "scMaxBufferedPosts": 64,
        "noGRPCHeader": True,
        "sessionIDPlacement": os.environ["CASE_XHTTP_SESSION_PLACEMENT"],
        "seqPlacement": os.environ["CASE_XHTTP_SEQ_PLACEMENT"],
        "uplinkDataPlacement": os.environ["CASE_XHTTP_UPLINK_DATA_PLACEMENT"],
    },
}
optional_keys = [
    ("CASE_XHTTP_SESSION_KEY", "sessionIDKey"),
    ("CASE_XHTTP_SEQ_KEY", "seqKey"),
    ("CASE_XHTTP_UPLINK_DATA_KEY", "uplinkDataKey"),
]
for env_key, settings_key in optional_keys:
    value = os.environ.get(env_key, "")
    if value:
        settings["extra"][settings_key] = value

print(json.dumps(settings, separators=(",", ":")))
PY
        )"
        ;;
      *)
        settings='{}'
        ;;
    esac
  fi

  SETTINGS_JSON="${settings}" python3 - \
    "${CASE_CLIENT_TYPE}" \
    "${CASE_VMESS_SECURITY}" \
    "${CASE_ACCEPT_PROXY_PROTOCOL}" <<'PY'
import json
import os
import sys

settings = json.loads(os.environ["SETTINGS_JSON"])
client_type = sys.argv[1]
vmess_security = sys.argv[2]
accept_proxy_protocol = sys.argv[3] == "1"
if client_type == "vmess" and vmess_security != "auto":
    settings["security"] = vmess_security
if accept_proxy_protocol:
    settings["acceptProxyProtocol"] = True
print(json.dumps(settings, separators=(",", ":")))
PY
}

tls_settings_json() {
  if [[ "${CASE_REALITY}" == "1" ]]; then
    printf '{"server_name":"%s","dest":"%s:%s","server_port":"%s","private_key":"%s","public_key":"%s","short_id":"%s","fingerprint":"chrome"}' \
      "${CASE_TLS_SERVER_NAME}" \
      "${CASE_TLS_SERVER_NAME}" \
      "${E2E_REALITY_DEST_PORT}" \
      "${E2E_REALITY_DEST_PORT}" \
      "${CASE_REALITY_PRIVATE_KEY}" \
      "${CASE_REALITY_PUBLIC_KEY}" \
      "${CASE_REALITY_SHORT_ID}"
    return
  fi

  if [[ "${CASE_TLS}" == "1" ]]; then
    printf '{"server_name":"%s"}' "${CASE_TLS_SERVER_NAME}"
    return
  fi

  printf '{}'
}

base64_prefix() {
  python3 - "$1" "$2" <<'PY'
import base64
import sys

value = sys.argv[1].encode()
length = int(sys.argv[2])
print(base64.b64encode(value[:length]).decode())
PY
}

ss_2022_server_key() {
  python3 - "$1" "$2" <<'PY'
import base64
import hashlib
import sys

created_at = sys.argv[1]
length = int(sys.argv[2])
digest = hashlib.md5(created_at.encode()).hexdigest()
print(base64.b64encode(digest[:length].encode()).decode())
PY
}

derive_case_client_passwords() {
  local created_at
  local key_len
  local server_key
  local server_table
  local user_key

  if [[ "${CASE_CLIENT_TYPE}" != "shadowsocks" ]]; then
    return
  fi

  CASE_SS_CLIENT_PASSWORD="${CASE_UUID}"
  case "${CASE_SS_CIPHER}" in
    2022-blake3-aes-128-gcm)
      key_len=16
      ;;
    2022-blake3-aes-256-gcm)
      key_len=32
      ;;
    *)
      return
      ;;
  esac

  server_table=v2_server_shadowsocks
  if [[ "${CASE_NODE_TYPE}" == "v2node" ]]; then
    server_table=v2_server_v2node
  fi
  created_at="$(mysql_query "SELECT created_at FROM ${server_table} WHERE id=${CASE_NODE_ID};")"
  [[ -n "${created_at}" ]] || e2e_die "${CASE_NAME}: could not read ${server_table} created_at"
  server_key="$(ss_2022_server_key "${created_at}" "${key_len}")"
  user_key="$(base64_prefix "${CASE_UUID}" "${key_len}")"
  CASE_SS_CLIENT_PASSWORD="${server_key}:${user_key}"
}

seed_user() {
  local now
  local expires_at

  now="$(date +%s)"
  expires_at="$((now + 86400))"

  mysql_exec <<SQL
INSERT INTO v2_user
(id, invite_user_id, telegram_id, email, language, password, password_algo, password_salt, balance, discount, commission_type, commission_rate, commission_balance, t, u, d, transfer_enable, device_limit, banned, is_admin, last_login_at, is_staff, last_login_ip, uuid, group_id, plan_id, speed_limit, auto_renewal, remind_expire, remind_traffic, token, expired_at, remarks, created_at, updated_at)
VALUES
(${CASE_USER_ID}, NULL, NULL, 'shoes-e2e-${CASE_NAME}@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '${CASE_UUID}', ${CASE_GROUP_ID}, NULL, NULL, 0, 1, 1, MD5('shoes-e2e-${CASE_NAME}@example.local'), ${expires_at}, 'shoes ${CASE_NAME} e2e user', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
  group_id=${CASE_GROUP_ID},
  speed_limit=NULL,
  device_limit=NULL,
  expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);

DELETE FROM v2_stat_user WHERE user_id=${CASE_USER_ID};
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${CASE_USER_ID}"
}

seed_group() {
  local now

  now="$(date +%s)"

  mysql_exec <<SQL
INSERT INTO v2_server_group
(id, name, created_at, updated_at)
VALUES
(${CASE_GROUP_ID}, 'shoes-e2e-${CASE_NAME}', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  updated_at=VALUES(updated_at);
SQL
}

seed_node() {
  local now
  local ns
  local ts
  local flow_sql
  local cipher_sql
  local encryption_sql
  local ss_obfs_sql
  local ss_obfs_settings_sql
  local tuic_udp_relay_mode_sql
  local tuic_congestion_control_sql

  now="$(date +%s)"
  ns="$(network_settings_json)"
  ts="$(tls_settings_json)"
  flow_sql=NULL
  if [[ -n "${CASE_FLOW}" ]]; then
    flow_sql="'${CASE_FLOW}'"
  fi
  cipher_sql=NULL
  if [[ -n "${CASE_SS_CIPHER}" ]]; then
    cipher_sql="'${CASE_SS_CIPHER}'"
  elif [[ "${CASE_CLIENT_TYPE}" == "vmess" ]]; then
    cipher_sql="'${CASE_VMESS_SECURITY}'"
  fi
  encryption_sql=NULL
  if [[ "${CASE_CLIENT_TYPE}" == "vless" ]]; then
    encryption_sql="'none'"
  fi
  ss_obfs_sql=NULL
  if [[ -n "${CASE_SS_OBFS}" ]]; then
    ss_obfs_sql="'${CASE_SS_OBFS}'"
  fi
  ss_obfs_settings_sql=NULL
  if [[ -n "${CASE_SS_OBFS_SETTINGS}" ]]; then
    ss_obfs_settings_sql="'${CASE_SS_OBFS_SETTINGS}'"
  fi
  tuic_udp_relay_mode_sql=NULL
  if [[ -n "${CASE_TUIC_UDP_RELAY_MODE}" ]]; then
    tuic_udp_relay_mode_sql="'${CASE_TUIC_UDP_RELAY_MODE}'"
  fi
  tuic_congestion_control_sql=NULL
  if [[ -n "${CASE_TUIC_CONGESTION_CONTROL}" ]]; then
    tuic_congestion_control_sql="'${CASE_TUIC_CONGESTION_CONTROL}'"
  fi

  case "${CASE_NODE_TYPE}" in
    vmess)
      mysql_exec <<SQL
INSERT INTO v2_server_vmess
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tags, rate, network, rules, networkSettings, tlsSettings, ruleSettings, dnsSettings, \`show\`, sort, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, '["${CASE_GROUP_ID}"]', NULL, 'shoes-e2e-${CASE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${CASE_NODE_PORT}', ${CASE_NODE_PORT}, ${CASE_TLS}, NULL, '1', '${CASE_NETWORK}', NULL, '${ns}', '{}', '{}', '{}', 1, ${CASE_NODE_ID}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  tls=VALUES(tls),
  rate=VALUES(rate),
  network=VALUES(network),
  networkSettings=VALUES(networkSettings),
  \`show\`=VALUES(\`show\`),
  sort=VALUES(sort),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='vmess';
SQL
      ;;
    vless)
      mysql_exec <<SQL
	INSERT INTO v2_server_vless
	(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tls_settings, flow, network, network_settings, encryption, encryption_settings, tags, rate, \`show\`, sort, created_at, updated_at)
	VALUES
	(${CASE_NODE_ID}, '["${CASE_GROUP_ID}"]', NULL, 'shoes-e2e-${CASE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', ${CASE_NODE_PORT}, ${CASE_NODE_PORT}, ${CASE_TLS}, '${ts}', ${flow_sql}, '${CASE_NETWORK}', '${ns}', 'none', '{}', NULL, '1', 1, ${CASE_NODE_ID}, ${now}, ${now})
	ON DUPLICATE KEY UPDATE
	  group_id=VALUES(group_id),
	  name=VALUES(name),
	  host=VALUES(host),
	  port=VALUES(port),
	  server_port=VALUES(server_port),
	  tls=VALUES(tls),
	  tls_settings=VALUES(tls_settings),
	  flow=VALUES(flow),
  network=VALUES(network),
  network_settings=VALUES(network_settings),
  encryption=VALUES(encryption),
  \`show\`=VALUES(\`show\`),
  sort=VALUES(sort),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='vless';
SQL
      ;;
    shadowsocks)
      mysql_exec <<SQL
INSERT INTO v2_server_shadowsocks
(id, group_id, route_id, parent_id, tags, name, country_code, city_name, city_id, rate, host, port, server_port, cipher, obfs, obfs_settings, gost_enable, gost_settings, \`show\`, sort, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, '["${CASE_GROUP_ID}"]', NULL, NULL, NULL, 'shoes-e2e-${CASE_NAME}', 'US', 'Local', NULL, '1', '${E2E_BIND_HOST}', '${CASE_NODE_PORT}', ${CASE_NODE_PORT}, '${CASE_SS_CIPHER}', ${ss_obfs_sql}, ${ss_obfs_settings_sql}, 0, NULL, 1, ${CASE_NODE_ID}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  cipher=VALUES(cipher),
  obfs=VALUES(obfs),
  obfs_settings=VALUES(obfs_settings),
  \`show\`=VALUES(\`show\`),
  sort=VALUES(sort),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='shadowsocks';
SQL
      ;;
    trojan)
      mysql_exec <<SQL
INSERT INTO v2_server_trojan
(id, group_id, route_id, parent_id, tags, name, country_code, city_name, city_id, rate, host, port, server_port, network, network_settings, allow_insecure, server_name, \`show\`, sort, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, '["${CASE_GROUP_ID}"]', NULL, NULL, NULL, 'shoes-e2e-${CASE_NAME}', 'US', 'Local', NULL, '1', '${E2E_BIND_HOST}', '${CASE_NODE_PORT}', ${CASE_NODE_PORT}, '${CASE_NETWORK}', '${ns}', 0, '${CASE_TLS_SERVER_NAME}', 1, ${CASE_NODE_ID}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  network=VALUES(network),
  network_settings=VALUES(network_settings),
  server_name=VALUES(server_name),
  \`show\`=VALUES(\`show\`),
  sort=VALUES(sort),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='trojan';
SQL
      ;;
    anytls)
      mysql_exec <<SQL
INSERT INTO v2_server_anytls
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tags, rate, \`show\`, sort, server_name, insecure, padding_scheme, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, '["${CASE_GROUP_ID}"]', NULL, 'shoes-e2e-${CASE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${CASE_NODE_PORT}', ${CASE_NODE_PORT}, NULL, '1', 1, ${CASE_NODE_ID}, '${CASE_TLS_SERVER_NAME}', 0, '${CASE_ANYTLS_PADDING_SCHEME}', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  rate=VALUES(rate),
  server_name=VALUES(server_name),
  insecure=VALUES(insecure),
  padding_scheme=VALUES(padding_scheme),
  \`show\`=VALUES(\`show\`),
  sort=VALUES(sort),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='anytls';
SQL
      ;;
    tuic)
      mysql_exec <<SQL
INSERT INTO v2_server_tuic
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tags, rate, \`show\`, sort, server_name, insecure, disable_sni, udp_relay_mode, zero_rtt_handshake, congestion_control, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, '["${CASE_GROUP_ID}"]', NULL, 'shoes-e2e-${CASE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${CASE_NODE_PORT}', ${CASE_NODE_PORT}, NULL, '1', 1, ${CASE_NODE_ID}, '${CASE_TLS_SERVER_NAME}', 0, 0, ${tuic_udp_relay_mode_sql}, ${CASE_TUIC_ZERO_RTT}, ${tuic_congestion_control_sql}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  rate=VALUES(rate),
  server_name=VALUES(server_name),
  insecure=VALUES(insecure),
  disable_sni=VALUES(disable_sni),
  udp_relay_mode=VALUES(udp_relay_mode),
  zero_rtt_handshake=VALUES(zero_rtt_handshake),
  congestion_control=VALUES(congestion_control),
  \`show\`=VALUES(\`show\`),
  sort=VALUES(sort),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='tuic';
SQL
      ;;
    hysteria)
      mysql_exec <<SQL
INSERT INTO v2_server_hysteria
(id, version, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tags, rate, \`show\`, sort, up_mbps, down_mbps, obfs, obfs_password, server_name, insecure, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, 2, '["${CASE_GROUP_ID}"]', NULL, 'shoes-e2e-${CASE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${CASE_NODE_PORT}', ${CASE_NODE_PORT}, NULL, '1', 1, ${CASE_NODE_ID}, 0, 0, NULL, NULL, '${CASE_TLS_SERVER_NAME}', 0, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  version=VALUES(version),
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  rate=VALUES(rate),
  up_mbps=VALUES(up_mbps),
  down_mbps=VALUES(down_mbps),
  obfs=NULL,
  obfs_password=NULL,
  server_name=VALUES(server_name),
  insecure=VALUES(insecure),
  \`show\`=VALUES(\`show\`),
  sort=VALUES(sort),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='hysteria';
SQL
      ;;
    v2node)
      mysql_exec <<SQL
INSERT INTO v2_server_v2node
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, listen_ip, port, server_port, tags, rate, \`show\`, sort, protocol, tls, tls_settings, flow, network, network_settings, encryption, encryption_settings, disable_sni, udp_relay_mode, zero_rtt_handshake, congestion_control, cipher, up_mbps, down_mbps, obfs, obfs_password, padding_scheme, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, '["${CASE_GROUP_ID}"]', NULL, 'shoes-e2e-${CASE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_BIND_HOST}', '${CASE_NODE_PORT}', ${CASE_NODE_PORT}, NULL, '1', 1, ${CASE_NODE_ID}, '${CASE_V2_PROTOCOL}', ${CASE_TLS}, '${ts}', ${flow_sql}, '${CASE_NETWORK}', '${ns}', ${encryption_sql}, '{}', 0, ${tuic_udp_relay_mode_sql}, ${CASE_TUIC_ZERO_RTT}, ${tuic_congestion_control_sql}, ${cipher_sql}, 0, 0, NULL, NULL, '${CASE_ANYTLS_PADDING_SCHEME}', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  listen_ip=VALUES(listen_ip),
  port=VALUES(port),
  server_port=VALUES(server_port),
  protocol=VALUES(protocol),
  tls=VALUES(tls),
  tls_settings=VALUES(tls_settings),
  flow=VALUES(flow),
  network=VALUES(network),
  network_settings=VALUES(network_settings),
  encryption=VALUES(encryption),
  encryption_settings=VALUES(encryption_settings),
  udp_relay_mode=VALUES(udp_relay_mode),
  zero_rtt_handshake=VALUES(zero_rtt_handshake),
  congestion_control=VALUES(congestion_control),
  cipher=VALUES(cipher),
  padding_scheme=VALUES(padding_scheme),
  \`show\`=VALUES(\`show\`),
  sort=VALUES(sort),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='v2node';
SQL
      ;;
  esac
}

write_shoes_config() {
  cat >"${TMP_DIR}/${CASE_NAME}.shoes.yml" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${SERVER_TOKEN}"
  nodes:
    - tag: "${CASE_NAME}"
      node_id: ${CASE_NODE_ID}
      node_type: "${CASE_NODE_TYPE}"
      listen: "${E2E_BIND_HOST}"
      pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
      push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
runtime:
  data_dir: "${TMP_DIR}/${CASE_NAME}-shoes-data"
  pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
  push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
tls:
  cert_file: "${TMP_DIR}/tls.crt"
  key_file: "${TMP_DIR}/tls.key"
log:
  level: "${E2E_SHOES_LOG_LEVEL}"
YAML
}

write_singlink_config() {
  local outbound_extra=""
  local outbound_server_port="${CASE_NODE_PORT}"
  local client_ws_path="${CASE_CLIENT_WS_PATH:-${CASE_WS_PATH}}"
  local flow=""
  local ss_password=""
  local transport=""
  local tuic_zero_rtt_json=false
  local tls=""

  if [[ "${CASE_ACCEPT_PROXY_PROTOCOL}" == "1" ]]; then
    outbound_server_port="${CASE_PROXY_PROTOCOL_BRIDGE_PORT}"
  fi

  if [[ "${CASE_TCP_HTTP_HEADER}" == "1" ]]; then
    transport=", \"transport\": {\"type\": \"http\", \"host\": [\"${CASE_HTTP_HOST}\"], \"path\": \"${CASE_HTTP_PATH}\", \"method\": \"${CASE_HTTP_METHOD}\"}"
  else
    case "${CASE_NETWORK}" in
      http)
        transport=", \"transport\": {\"type\": \"http\", \"host\": [\"${CASE_HTTP_HOST}\"], \"path\": \"${CASE_HTTP_PATH}\", \"method\": \"${CASE_HTTP_METHOD}\"}"
        ;;
      ws)
        transport=", \"transport\": {\"type\": \"ws\", \"path\": \"${client_ws_path}\", \"headers\": {\"Host\": \"example.org\"}, \"max_early_data\": 2048, \"early_data_header_name\": \"Sec-WebSocket-Protocol\"}"
        ;;
      grpc)
        transport=", \"transport\": {\"type\": \"grpc\", \"service_name\": \"${CASE_GRPC_SERVICE_NAME}\"}"
        ;;
      httpupgrade)
        if [[ -n "${CASE_HTTPUPGRADE_HEADER_NAME}" ]]; then
          transport=", \"transport\": {\"type\": \"httpupgrade\", \"path\": \"${CASE_HTTPUPGRADE_PATH}\", \"host\": \"${CASE_HTTPUPGRADE_HOST}\", \"headers\": {\"${CASE_HTTPUPGRADE_HEADER_NAME}\": \"${CASE_HTTPUPGRADE_HEADER_VALUE}\"}}"
        else
          transport=", \"transport\": {\"type\": \"httpupgrade\", \"path\": \"${CASE_HTTPUPGRADE_PATH}\", \"host\": \"${CASE_HTTPUPGRADE_HOST}\"}"
        fi
        ;;
    esac
  fi
  if [[ "${CASE_REALITY}" == "1" ]]; then
    tls=", \"tls\": {\"enabled\": true, \"server_name\": \"${CASE_TLS_SERVER_NAME}\", \"utls\": {\"enabled\": true, \"fingerprint\": \"chrome\"}, \"reality\": {\"enabled\": true, \"public_key\": \"${CASE_REALITY_PUBLIC_KEY}\", \"short_id\": \"${CASE_REALITY_SHORT_ID}\"}}"
  elif [[ "${CASE_TLS}" == "1" ]]; then
    tls=", \"tls\": {\"enabled\": true, \"server_name\": \"${CASE_TLS_SERVER_NAME}\", \"certificate_path\": \"${TMP_DIR}/tls.crt\"}"
  fi
  if [[ -n "${CASE_FLOW}" ]]; then
    flow=", \"flow\": \"${CASE_FLOW}\""
  fi
  if [[ "${CASE_TUIC_ZERO_RTT}" != "0" ]]; then
    tuic_zero_rtt_json=true
  fi

  case "${CASE_CLIENT_TYPE}" in
    vmess)
      outbound_extra="\"uuid\": \"${CASE_UUID}\", \"security\": \"${CASE_VMESS_SECURITY}\", \"alter_id\": 0, \"network\": \"tcp\"${transport}${tls}"
      ;;
    vless)
      outbound_extra="\"uuid\": \"${CASE_UUID}\", \"network\": \"tcp\"${flow}${transport}${tls}"
      ;;
    shadowsocks)
      ss_password="${CASE_SS_CLIENT_PASSWORD:-${CASE_UUID}}"
      outbound_extra="\"method\": \"${CASE_SS_CIPHER}\", \"password\": \"${ss_password}\", \"network\": \"tcp\""
      ;;
    trojan)
      outbound_extra="\"password\": \"${CASE_UUID}\", \"network\": \"tcp\"${transport}${tls}"
      ;;
    anytls)
      outbound_extra="\"password\": \"${CASE_UUID}\"${tls}"
      ;;
    tuic)
      outbound_extra="\"uuid\": \"${CASE_UUID}\", \"password\": \"${CASE_UUID}\", \"congestion_control\": \"${CASE_TUIC_CONGESTION_CONTROL:-cubic}\", \"udp_relay_mode\": \"${CASE_TUIC_UDP_RELAY_MODE:-native}\", \"zero_rtt_handshake\": ${tuic_zero_rtt_json}, \"network\": \"tcp\", \"tls\": {\"enabled\": true, \"server_name\": \"${CASE_TLS_SERVER_NAME}\", \"certificate_path\": \"${TMP_DIR}/tls.crt\", \"alpn\": [\"h3\"]}"
      ;;
    hysteria2)
      outbound_extra="\"password\": \"${CASE_UUID}\", \"network\": \"tcp\", \"tls\": {\"enabled\": true, \"server_name\": \"${CASE_TLS_SERVER_NAME}\", \"certificate_path\": \"${TMP_DIR}/tls.crt\", \"alpn\": [\"h3\"]}"
      ;;
  esac

  cat >"${TMP_DIR}/${CASE_NAME}.singlink.json" <<JSON
{
  "log": {"level": "info", "timestamp": true},
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "${E2E_BIND_HOST}",
      "listen_port": ${CASE_PROXY_PORT}
    }
  ],
  "outbounds": [
    {
      "type": "${CASE_CLIENT_TYPE}",
      "tag": "proxy-out",
      "server": "${E2E_BIND_HOST}",
      "server_port": ${outbound_server_port},
      ${outbound_extra}
    }
  ],
  "route": {"final": "proxy-out"}
}
JSON
}

start_http_target() {
  e2e_section "start http target"
  e2e_assert_port_free "${E2E_HTTP_PORT}" "http target"
  mkdir -p "${TMP_DIR}/http-root"
  dd if=/dev/zero of="${TMP_DIR}/http-root/payload.bin" bs=1024 count="${E2E_PAYLOAD_KIB}" status=none

  python3 -m http.server "${E2E_HTTP_PORT}" \
    --bind "${E2E_BIND_HOST}" \
    --directory "${TMP_DIR}/http-root" \
    >"${TMP_DIR}/http.log" 2>&1 &
  HTTP_PID=$!
  wait_for_listen_port "${E2E_HTTP_PORT}" "http target" 10
}

start_tls_http_server() {
  local port="$1"
  local label="$2"
  local log_file="$3"
  local pid_var="$4"

  e2e_assert_port_free "${port}" "${label}"

  python3 -u -c '
import http.server
import os
import ssl
import sys

host = sys.argv[1]
port = int(sys.argv[2])
cert = sys.argv[3]
key = sys.argv[4]
root = sys.argv[5]

os.chdir(root)

class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("%s - - [%s] %s" % (self.client_address[0], self.log_date_time_string(), fmt % args), flush=True)

server = http.server.ThreadingHTTPServer((host, port), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
if hasattr(ssl, "TLSVersion"):
    context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(cert, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
' \
    "${E2E_BIND_HOST}" \
    "${port}" \
    "${TMP_DIR}/tls.crt" \
    "${TMP_DIR}/tls.key" \
    "${TMP_DIR}/http-root" \
    >"${log_file}" 2>&1 &
  printf -v "${pid_var}" '%s' "$!"
  wait_for_listen_port "${port}" "${label}" 10
}

ensure_reality_target() {
  if [[ -n "${REALITY_DEST_PID}" ]] && kill -0 "${REALITY_DEST_PID}" 2>/dev/null; then
    return
  fi

  REALITY_DEST_PID=""
  e2e_section "start reality tls1.3 target"
  start_tls_http_server \
    "${E2E_REALITY_DEST_PORT}" \
    "reality tls target" \
    "${TMP_DIR}/reality-target.log" \
    REALITY_DEST_PID
}

ensure_https_target() {
  if [[ -n "${HTTPS_PID}" ]] && kill -0 "${HTTPS_PID}" 2>/dev/null; then
    return
  fi

  HTTPS_PID=""
  e2e_section "start https tls1.3 target"
  start_tls_http_server \
    "${E2E_HTTPS_PORT}" \
    "https target" \
    "${TMP_DIR}/https-target.log" \
    HTTPS_PID
}

case_list_needs_reality_target() {
  local case_name

  for case_name in "$@"; do
    case_name="${case_name//[[:space:]]/}"
    if [[ "${case_name}" == *reality* ]]; then
      return 0
    fi
  done

  return 1
}

case_list_needs_https_target() {
  local case_name

  for case_name in "$@"; do
    case_name="${case_name//[[:space:]]/}"
    if [[ "${case_name}" == *vision* ]]; then
      return 0
    fi
  done

  return 1
}

start_proxy_protocol_bridge() {
  if [[ "${CASE_ACCEPT_PROXY_PROTOCOL}" != "1" ]]; then
    return
  fi

  e2e_assert_port_free "${CASE_PROXY_PROTOCOL_BRIDGE_PORT}" "proxy protocol bridge ${CASE_NAME}"

  python3 -u - \
    "${E2E_BIND_HOST}" \
    "${CASE_PROXY_PROTOCOL_BRIDGE_PORT}" \
    "${E2E_BIND_HOST}" \
    "${CASE_NODE_PORT}" \
    "${CASE_PROXY_PROTOCOL_VERSION}" \
    "${CASE_PROXY_PROTOCOL_SOURCE_IP}" \
    "${CASE_PROXY_PROTOCOL_SOURCE_PORT}" \
    >"${TMP_DIR}/${CASE_NAME}.proxy-protocol-bridge.log" 2>&1 <<'PY' &
import select
import socket
import socketserver
import struct
import sys

listen_host = sys.argv[1]
listen_port = int(sys.argv[2])
target_host = sys.argv[3]
target_port = int(sys.argv[4])
version = sys.argv[5]
source_ip = sys.argv[6]
source_port = int(sys.argv[7])


def proxy_header():
    if version == "1":
        return f"PROXY TCP4 {source_ip} {target_host} {source_port} {target_port}\r\n".encode()
    if version == "2":
        signature = b"\r\n\r\n\0\r\nQUIT\n"
        ver_cmd = 0x21
        fam_proto = 0x11
        payload = (
            socket.inet_aton(source_ip)
            + socket.inet_aton(target_host)
            + struct.pack("!HH", source_port, target_port)
        )
        return signature + bytes([ver_cmd, fam_proto]) + struct.pack("!H", len(payload)) + payload
    raise RuntimeError(f"unsupported PROXY protocol version: {version}")


HEADER = proxy_header()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        upstream = socket.create_connection((target_host, target_port), timeout=5)
        try:
            upstream.sendall(HEADER)
            self.request.setblocking(False)
            upstream.setblocking(False)
            sockets = [self.request, upstream]
            while sockets:
                readable, _, _ = select.select(sockets, [], [], 0.5)
                for sock in readable:
                    data = sock.recv(65536)
                    other = upstream if sock is self.request else self.request
                    if not data:
                        sockets.clear()
                        break
                    other.sendall(data)
        finally:
            upstream.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


with Server((listen_host, listen_port), Handler) as server:
    print(f"proxy protocol bridge listening on {listen_host}:{listen_port}", flush=True)
    server.serve_forever()
PY
  # shellcheck disable=SC2034
  PROXY_PROTOCOL_PID=$!
  wait_for_listen_port "${CASE_PROXY_PROTOCOL_BRIDGE_PORT}" "proxy protocol bridge ${CASE_NAME}" 10
}

start_case_services() {
  if case_uses_quic_node; then
    e2e_assert_udp_port_free "${CASE_NODE_PORT}" "shoes ${CASE_NAME}"
  else
    e2e_assert_port_free "${CASE_NODE_PORT}" "shoes ${CASE_NAME}"
  fi
  if ! case_uses_builtin_ss_obfs_client && ! case_uses_builtin_xhttp_client; then
    e2e_assert_port_free "${CASE_PROXY_PORT}" "singlink ${CASE_NAME}"
  fi
  if [[ "${CASE_ACCEPT_PROXY_PROTOCOL}" == "1" ]]; then
    e2e_assert_port_free "${CASE_PROXY_PROTOCOL_BRIDGE_PORT}" "proxy protocol bridge ${CASE_NAME}"
  fi

  "${SHOES_BIN}" run -c "${TMP_DIR}/${CASE_NAME}.shoes.yml" >"${TMP_DIR}/${CASE_NAME}.shoes.log" 2>&1 &
  SHOES_PID=$!
  if case_uses_quic_node; then
    wait_for_udp_listen_port "${CASE_NODE_PORT}" "shoes ${CASE_NAME}" 15
  else
    wait_for_listen_port "${CASE_NODE_PORT}" "shoes ${CASE_NAME}" 15
  fi

  start_proxy_protocol_bridge

  if ! case_uses_builtin_ss_obfs_client && ! case_uses_builtin_xhttp_client; then
    "${SINGLINK_BIN}" -c "${TMP_DIR}/${CASE_NAME}.singlink.json" check >"${TMP_DIR}/${CASE_NAME}.singlink-check.log" 2>&1
    "${SINGLINK_BIN}" -c "${TMP_DIR}/${CASE_NAME}.singlink.json" run >"${TMP_DIR}/${CASE_NAME}.singlink.log" 2>&1 &
    SINGLINK_PID=$!
    wait_for_listen_port "${CASE_PROXY_PORT}" "singlink ${CASE_NAME}" 15
  fi
}

assert_httpupgrade_rejects_websocket_handshake() {
  if [[ "${CASE_NAME}" != "vmess_httpupgrade_headers" ]]; then
    return
  fi

  e2e_section "httpupgrade rejects websocket handshake"
  python3 - \
    "${E2E_BIND_HOST}" \
    "${CASE_NODE_PORT}" \
    "${CASE_HTTPUPGRADE_PATH}" \
    "${CASE_HTTPUPGRADE_HOST}" \
    "${CASE_HTTPUPGRADE_HEADER_NAME}" \
    "${CASE_HTTPUPGRADE_HEADER_VALUE}" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
path = sys.argv[3]
request_host = sys.argv[4]
header_name = sys.argv[5]
header_value = sys.argv[6]

request = "\r\n".join(
    [
        f"GET {path} HTTP/1.1",
        f"Host: {request_host}",
        "Connection: Upgrade",
        "Upgrade: websocket",
        f"{header_name}: {header_value}",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version: 13",
        "",
        "",
    ]
).encode()

chunks = []
with socket.create_connection((host, port), timeout=5) as sock:
    sock.settimeout(5)
    sock.sendall(request)
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    except (TimeoutError, socket.timeout):
        pass

response = b"".join(chunks)
if b"101 Switching Protocols" in response:
    raise SystemExit(f"unexpected websocket upgrade response: {response!r}")
PY
  e2e_log "${CASE_NAME}: real websocket handshake rejected"
}

run_builtin_ss_obfs_client() {
  local target_url="$1"

  "${E2E_SS_OBFS_CLIENT_BIN}" \
    --proxy-host "${E2E_BIND_HOST}" \
    --proxy-port "${CASE_NODE_PORT}" \
    --method "${CASE_SS_CIPHER}" \
    --password "${CASE_UUID}" \
    --obfs-host "${CASE_SS_OBFS_HOST}" \
    --obfs-path "${CASE_SS_OBFS_PATH}" \
    --url "${target_url}" \
    --output "${TMP_DIR}/${CASE_NAME}.download.bin" \
    --connect-timeout-secs "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time-secs "${E2E_CURL_MAX_TIME_SECS}"
}

run_builtin_xhttp_client() {
  local target_url="$1"
  local client_args=()
  local tls_args=()

  if [[ "${CASE_REALITY}" == "1" ]]; then
    tls_args=(
      --reality-public-key "${CASE_REALITY_PUBLIC_KEY}"
      --reality-short-id "${CASE_REALITY_SHORT_ID}"
    )
  else
    tls_args=(--ca-cert "${TMP_DIR}/tls.crt")
  fi

  if [[ -n "${CASE_XHTTP_SESSION_KEY}" ]]; then
    client_args+=(--xhttp-session-key "${CASE_XHTTP_SESSION_KEY}")
  fi
  if [[ -n "${CASE_XHTTP_SEQ_KEY}" ]]; then
    client_args+=(--xhttp-seq-key "${CASE_XHTTP_SEQ_KEY}")
  fi
  if [[ -n "${CASE_XHTTP_UPLINK_DATA_KEY}" ]]; then
    client_args+=(--xhttp-uplink-data-key "${CASE_XHTTP_UPLINK_DATA_KEY}")
  fi

  "${E2E_XHTTP_CLIENT_BIN}" \
    --proxy-host "${E2E_BIND_HOST}" \
    --proxy-port "${CASE_NODE_PORT}" \
    --server-name "${CASE_TLS_SERVER_NAME}" \
    --protocol "${CASE_CLIENT_TYPE}" \
    --uuid "${CASE_UUID}" \
    --vmess-security "${CASE_VMESS_SECURITY}" \
    --xhttp-host "${CASE_XHTTP_HOST}" \
    --xhttp-path "${CASE_XHTTP_PATH}" \
    --xhttp-mode "${CASE_XHTTP_MODE}" \
    --xhttp-session-placement "${CASE_XHTTP_SESSION_PLACEMENT}" \
    --xhttp-seq-placement "${CASE_XHTTP_SEQ_PLACEMENT}" \
    --xhttp-uplink-data-placement "${CASE_XHTTP_UPLINK_DATA_PLACEMENT}" \
    --url "${target_url}" \
    --output "${TMP_DIR}/${CASE_NAME}.download.bin" \
    --connect-timeout-secs "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time-secs "${E2E_CURL_MAX_TIME_SECS}" \
    "${client_args[@]}" \
    "${tls_args[@]}"
}

stop_case_services() {
  for pid_var in SINGLINK_PID PROXY_PROTOCOL_PID SHOES_PID; do
    local pid="${!pid_var:-}"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
    printf -v "${pid_var}" ''
  done
}

wait_for_traffic() {
  local expected_min="$1"
  local start
  local now
  local stat_user
  local stat_server
  local stat_user_u
  local stat_user_d
  local stat_server_u
  local stat_server_d

  start="$(date +%s)"
  while true; do
    e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"
    stat_user="$(mysql_query "SELECT COALESCE(SUM(u),0), COALESCE(SUM(d),0) FROM v2_stat_user WHERE user_id=${CASE_USER_ID};")"
    stat_server="$(mysql_query "SELECT COALESCE(SUM(u),0), COALESCE(SUM(d),0) FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='${CASE_NODE_TYPE}';")"
    read -r stat_user_u stat_user_d <<<"${stat_user}"
    read -r stat_server_u stat_server_d <<<"${stat_server}"
    if ((stat_user_u > 0 && stat_server_u > 0 && stat_user_d >= expected_min && stat_server_d >= expected_min)); then
      e2e_log "${CASE_NAME}: stats user=${stat_user_u}/${stat_user_d} server=${stat_server_u}/${stat_server_d}"
      return
    fi

    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_die "${CASE_NAME}: traffic stats did not reach expected upload > 0 and download ${expected_min}; user=${stat_user_u}/${stat_user_d} server=${stat_server_u}/${stat_server_d}"
    fi
    sleep 1
  done
}

wait_for_user_counter() {
  local expected_min="$1"
  local start
  local now
  local user_totals
  local user_u
  local user_d

  e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"
  docker exec "${V2BOARD_WWW_CONTAINER}" php artisan traffic:update >/dev/null
  start="$(date +%s)"
  while true; do
    user_totals="$(mysql_query "SELECT u,d FROM v2_user WHERE id=${CASE_USER_ID};")"
    read -r user_u user_d <<<"${user_totals}"
    if ((user_u > 0 && user_d >= expected_min)); then
      e2e_log "${CASE_NAME}: user ${CASE_USER_ID} traffic u=${user_u} d=${user_d}"
      return
    fi

    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_die "${CASE_NAME}: user counter did not reach expected upload > 0 and download ${expected_min}; got ${user_u}/${user_d}"
    fi
    e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"
    docker exec "${V2BOARD_WWW_CONTAINER}" php artisan traffic:update >/dev/null
    sleep 1
  done
}

run_case() {
  local expected_min
  local curl_extra=()
  local target_url

  case_config "$1"
  e2e_section "case ${CASE_NAME}"
  seed_group
  seed_user
  seed_node
  derive_case_client_passwords
  write_shoes_config
  write_singlink_config
  if [[ "${CASE_REALITY}" == "1" ]]; then
    ensure_reality_target
  fi
  if [[ "${CASE_FLOW}" == "xtls-rprx-vision" ]]; then
    ensure_https_target
  fi
  start_case_services
  assert_httpupgrade_rejects_websocket_handshake

  if [[ "${CASE_FLOW}" == "xtls-rprx-vision" ]]; then
    curl_extra=(-k)
    target_url="https://localhost:${E2E_HTTPS_PORT}/payload.bin"
  else
    target_url="http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/payload.bin"
  fi

  if case_uses_builtin_ss_obfs_client; then
    run_builtin_ss_obfs_client "${target_url}"
  elif case_uses_builtin_xhttp_client; then
    run_builtin_xhttp_client "${target_url}"
  else
    curl -fsS \
      --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
      --max-time "${E2E_CURL_MAX_TIME_SECS}" \
      --noproxy '' \
      --proxy "http://${E2E_BIND_HOST}:${CASE_PROXY_PORT}" \
      "${curl_extra[@]}" \
      "${target_url}" \
      -o "${TMP_DIR}/${CASE_NAME}.download.bin"
  fi

  expected_min="$((E2E_PAYLOAD_KIB * 1024))"
  [[ "$(wc -c <"${TMP_DIR}/${CASE_NAME}.download.bin")" -eq "${expected_min}" ]] \
    || e2e_die "${CASE_NAME}: download size mismatch"

  wait_for_traffic "${expected_min}"
  wait_for_user_counter "${expected_min}"
  stop_case_services
}

maybe_cleanup_fixtures() {
  if e2e_env_bool E2E_KEEP_FIXTURES 1; then
    e2e_log "keeping E2E fixtures"
    return
  fi

  e2e_section "cleanup fixtures"
  mysql_exec <<SQL
DELETE su FROM v2_stat_user su JOIN v2_user u ON u.id=su.user_id WHERE u.email LIKE 'shoes-e2e-%@example.local';
DELETE ss FROM v2_stat_server ss JOIN v2_server_vmess n ON ss.server_type='vmess' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-e2e-%';
DELETE ss FROM v2_stat_server ss JOIN v2_server_vless n ON ss.server_type='vless' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-e2e-%';
DELETE ss FROM v2_stat_server ss JOIN v2_server_shadowsocks n ON ss.server_type='shadowsocks' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-e2e-%';
DELETE ss FROM v2_stat_server ss JOIN v2_server_trojan n ON ss.server_type='trojan' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-e2e-%';
DELETE ss FROM v2_stat_server ss JOIN v2_server_anytls n ON ss.server_type='anytls' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-e2e-%';
DELETE ss FROM v2_stat_server ss JOIN v2_server_tuic n ON ss.server_type='tuic' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-e2e-%';
DELETE ss FROM v2_stat_server ss JOIN v2_server_hysteria n ON ss.server_type='hysteria' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-e2e-%';
DELETE ss FROM v2_stat_server ss JOIN v2_server_v2node n ON ss.server_type='v2node' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-e2e-%';
DELETE FROM v2_user WHERE email LIKE 'shoes-e2e-%@example.local';
DELETE FROM v2_server_vmess WHERE name LIKE 'shoes-e2e-%';
DELETE FROM v2_server_vless WHERE name LIKE 'shoes-e2e-%';
DELETE FROM v2_server_shadowsocks WHERE name LIKE 'shoes-e2e-%';
DELETE FROM v2_server_trojan WHERE name LIKE 'shoes-e2e-%';
DELETE FROM v2_server_anytls WHERE name LIKE 'shoes-e2e-%';
DELETE FROM v2_server_tuic WHERE name LIKE 'shoes-e2e-%';
DELETE FROM v2_server_hysteria WHERE name LIKE 'shoes-e2e-%';
DELETE FROM v2_server_v2node WHERE name LIKE 'shoes-e2e-%';
DELETE FROM v2_server_group WHERE name LIKE 'shoes-e2e-%';
SQL

  local user_id
  for user_id in \
    19101 19102 19103 19104 19105 19106 19107 19108 19109 19110 19111 19112 19113 \
    19201 19202 19203 19204 19205 19206 19207 19208 19209 19210 19211 19212 \
    19301 19302 19303 19304 19305 19306 19307 \
    19401 19402 19403 19404 19451 19452 19453 19461 19462 19463 19464 19465 19466 19467 19471 19472 19473 \
    19481 19482 19483 19484 19485 19486 19487 19488 19489 19490 19491 19492 \
    19501 19502 19503 19504 19511 \
    19850 19851 19852 19853 19854 19855 19856 19857 19858 19859 19860 19861 19862; do
    e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${user_id}"
  done
}

main() {
  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-matrix-e2e.XXXXXX)"

  check_environment
  resolve_binaries
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"
  generate_tls_files
  start_http_target

  IFS=',' read -r -a cases <<<"${E2E_MATRIX_CASES}"
  if case_list_needs_reality_target "${cases[@]}"; then
    ensure_reality_target
  fi
  if case_list_needs_https_target "${cases[@]}"; then
    ensure_https_target
  fi
  for case_name in "${cases[@]}"; do
    case_name="${case_name//[[:space:]]/}"
    [[ -n "${case_name}" ]] || continue
    run_case "${case_name}"
  done

  maybe_cleanup_fixtures
  e2e_section "done"
}

main "$@"
