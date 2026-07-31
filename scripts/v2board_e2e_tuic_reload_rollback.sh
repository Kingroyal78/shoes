#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/scripts"

# shellcheck source=scripts/v2board_e2e_common.sh
source "${SCRIPT_DIR}/v2board_e2e_common.sh"

trap e2e_on_error ERR

V2BOARD_DIR="${V2BOARD_DIR:-${ROOT_DIR}/../v2board}"
V2BOARD_PANEL_URL="${V2BOARD_PANEL_URL:-http://127.0.0.1}"
V2BOARD_MYSQL_CONTAINER="${V2BOARD_MYSQL_CONTAINER:-v2board-docker-mysql-1}"
V2BOARD_WWW_CONTAINER="${V2BOARD_WWW_CONTAINER:-v2board-docker-www-1}"
V2BOARD_REDIS_CONTAINER="${V2BOARD_REDIS_CONTAINER:-v2board-docker-redis-1}"
V2BOARD_MYSQL_USER="${V2BOARD_MYSQL_USER:-root}"
V2BOARD_MYSQL_PASSWORD="${V2BOARD_MYSQL_PASSWORD:-v2boardisbest}"
V2BOARD_MYSQL_DATABASE="${V2BOARD_MYSQL_DATABASE:-v2board}"

SING_BOX_DIR="${SING_BOX_DIR:-${ROOT_DIR}/../sing-box}"
SINGLINK_BIN="${SINGLINK_BIN:-}"
SINGLINK_BUILD_TAGS="${SINGLINK_BUILD_TAGS:-with_quic}"
SHOES_BIN="${SHOES_BIN:-}"

E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18095}"
E2E_NODE_PORT="${E2E_NODE_PORT:-18149}"
E2E_BAD_NODE_PORT="${E2E_BAD_NODE_PORT:-18150}"
E2E_PROXY_PORT="${E2E_PROXY_PORT:-18250}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-2}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-5}"
E2E_WAIT_TIMEOUT_SECS="${E2E_WAIT_TIMEOUT_SECS:-45}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_CURL_CONNECT_TIMEOUT_SECS="${E2E_CURL_CONNECT_TIMEOUT_SECS:-5}"
E2E_CURL_MAX_TIME_SECS="${E2E_CURL_MAX_TIME_SECS:-15}"
E2E_TLS_SERVER_NAME="${E2E_TLS_SERVER_NAME:-example.org}"

NODE_ID=9554
GROUP_ID=9554
USER_ID=19554
USER_UUID=55555555-5555-4555-8555-555555555554

TMP_DIR=""
HTTP_PID=""
SHOES_PID=""
SINGLINK_PID=""
BLOCKER_PID=""
SERVER_TOKEN=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_tuic_reload_rollback.sh

Runs a real V2Board TUIC reload rollback E2E check:
  - starts a V2Board V1 TUIC node over QUIC/TLS.
  - proves the old UDP listener proxies traffic.
  - updates the panel node to a UDP port occupied by another process.
  - verifies shoes logs rollback and a fresh client still reaches the old listener.
EOF
}

cleanup() {
  local status=$?
  set +e
  stop_services
  if [[ "${status}" -ne 0 ]] && ! e2e_env_bool E2E_KEEP_FIXTURES 1; then
    cleanup_fixtures || true
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

ensure_running() {
  local label="$1"
  local port="$2"

  for pid in "${HTTP_PID}" "${SHOES_PID}" "${SINGLINK_PID}" "${BLOCKER_PID}"; do
    if [[ -n "${pid}" ]] && ! kill -0 "${pid}" 2>/dev/null; then
      e2e_die "${label} process exited before listening on ${port}"
    fi
  done
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
    ensure_running "${label}" "${port}"
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
    ensure_running "${label}" "UDP ${port}"
    now="$(date +%s)"
    if ((now - start >= timeout)); then
      e2e_die "${label} did not listen on UDP port ${port} within ${timeout}s"
    fi
    sleep 0.2
  done
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
    e2e_run cargo build --manifest-path "${ROOT_DIR}/Cargo.toml"
  fi
  [[ -x "${SHOES_BIN}" ]] || e2e_die "SHOES_BIN is not executable: ${SHOES_BIN}"

  if [[ -z "${SINGLINK_BIN}" ]]; then
    e2e_require_dir "${SING_BOX_DIR}" "sing-box checkout"
    e2e_require_command go
    SINGLINK_BIN="${TMP_DIR}/singlink"
    e2e_run go -C "${SING_BOX_DIR}" build -tags "${SINGLINK_BUILD_TAGS}" -o "${SINGLINK_BIN}" ./cmd/singlink
  fi
  [[ -x "${SINGLINK_BIN}" ]] || e2e_die "SINGLINK_BIN is not executable: ${SINGLINK_BIN}"
}

check_environment() {
  e2e_section "environment"
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
    -subj "/CN=${E2E_TLS_SERVER_NAME}" \
    -addext "subjectAltName=DNS:${E2E_TLS_SERVER_NAME}" \
    -keyout "${TMP_DIR}/tls.key" \
    -out "${TMP_DIR}/tls.crt" \
    >/dev/null 2>&1
}

start_http_target() {
  e2e_section "start tuic reload http target"
  e2e_assert_port_free "${E2E_HTTP_PORT}" "tuic reload http target"
  mkdir -p "${TMP_DIR}/http-root"
  dd if=/dev/zero of="${TMP_DIR}/http-root/payload.bin" bs=1024 count=16 status=none
  python3 -m http.server "${E2E_HTTP_PORT}" \
    --bind "${E2E_BIND_HOST}" \
    --directory "${TMP_DIR}/http-root" \
    >"${TMP_DIR}/http.log" 2>&1 &
  HTTP_PID=$!
  wait_for_listen_port "${E2E_HTTP_PORT}" "tuic reload http target" 10
}

seed_fixture() {
  local now
  local expires_at

  now="$(date +%s)"
  expires_at="$((now + 86400))"

  mysql_exec <<SQL
INSERT INTO v2_server_group
(id, name, created_at, updated_at)
VALUES
(${GROUP_ID}, 'shoes-tuic-reload', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  updated_at=VALUES(updated_at);

INSERT INTO v2_server_tuic
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tags, rate, \`show\`, sort, server_name, insecure, disable_sni, udp_relay_mode, zero_rtt_handshake, congestion_control, created_at, updated_at)
VALUES
(${NODE_ID}, '["${GROUP_ID}"]', NULL, 'shoes-tuic-reload', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_NODE_PORT}', ${E2E_NODE_PORT}, NULL, '1', 1, ${NODE_ID}, '${E2E_TLS_SERVER_NAME}', 0, 0, 'native', 0, 'cubic', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  server_name=VALUES(server_name),
  udp_relay_mode=VALUES(udp_relay_mode),
  zero_rtt_handshake=VALUES(zero_rtt_handshake),
  congestion_control=VALUES(congestion_control),
  \`show\`=VALUES(\`show\`),
  updated_at=VALUES(updated_at);

INSERT INTO v2_user
(id, invite_user_id, telegram_id, email, language, password, password_algo, password_salt, balance, discount, commission_type, commission_rate, commission_balance, t, u, d, transfer_enable, device_limit, banned, is_admin, last_login_at, is_staff, last_login_ip, uuid, group_id, plan_id, speed_limit, auto_renewal, remind_expire, remind_traffic, token, expired_at, remarks, created_at, updated_at)
VALUES
(${USER_ID}, NULL, NULL, 'shoes-tuic-reload@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '${USER_UUID}', ${GROUP_ID}, NULL, NULL, 0, 1, 1, MD5('shoes-tuic-reload@example.local'), ${expires_at}, 'shoes tuic reload rollback e2e', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
  group_id=${GROUP_ID},
  speed_limit=NULL,
  device_limit=NULL,
  expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);

DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='tuic';
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
}

write_configs() {
  cat >"${TMP_DIR}/tuic-reload.shoes.yml" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${SERVER_TOKEN}"
  nodes:
    - tag: "tuic_reload_rollback"
      node_id: ${NODE_ID}
      node_type: "tuic"
      listen: "${E2E_BIND_HOST}"
      pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
      push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
runtime:
  data_dir: "${TMP_DIR}/tuic-reload-data"
  pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
  push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
tls:
  cert_file: "${TMP_DIR}/tls.crt"
  key_file: "${TMP_DIR}/tls.key"
log:
  level: "debug"
YAML

  cat >"${TMP_DIR}/tuic-reload.singlink.json" <<JSON
{
  "log": {"level": "info", "timestamp": true},
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "${E2E_BIND_HOST}",
      "listen_port": ${E2E_PROXY_PORT}
    }
  ],
  "outbounds": [
    {
      "type": "tuic",
      "tag": "tuic-out",
      "server": "${E2E_BIND_HOST}",
      "server_port": ${E2E_NODE_PORT},
      "uuid": "${USER_UUID}",
      "password": "${USER_UUID}",
      "congestion_control": "cubic",
      "udp_relay_mode": "native",
      "zero_rtt_handshake": false,
      "network": "tcp",
      "tls": {
        "enabled": true,
        "server_name": "${E2E_TLS_SERVER_NAME}",
        "certificate_path": "${TMP_DIR}/tls.crt",
        "alpn": ["h3"]
      }
    }
  ],
  "route": {"final": "tuic-out"}
}
JSON
}

start_shoes() {
  e2e_assert_udp_port_free "${E2E_NODE_PORT}" "tuic reload shoes"
  "${SHOES_BIN}" sync-once -c "${TMP_DIR}/tuic-reload.shoes.yml" >"${TMP_DIR}/tuic-reload.sync.log" 2>&1
  "${SHOES_BIN}" run -c "${TMP_DIR}/tuic-reload.shoes.yml" >"${TMP_DIR}/tuic-reload.shoes.log" 2>&1 &
  SHOES_PID=$!
  wait_for_udp_listen_port "${E2E_NODE_PORT}" "tuic reload shoes" 15
}

start_singlink() {
  "${SINGLINK_BIN}" -c "${TMP_DIR}/tuic-reload.singlink.json" check \
    >"${TMP_DIR}/tuic-reload.singlink-check.log" 2>&1
  e2e_assert_port_free "${E2E_PROXY_PORT}" "tuic reload singlink"
  "${SINGLINK_BIN}" -c "${TMP_DIR}/tuic-reload.singlink.json" run \
    >"${TMP_DIR}/tuic-reload.singlink.log" 2>&1 &
  SINGLINK_PID=$!
  wait_for_listen_port "${E2E_PROXY_PORT}" "tuic reload singlink" 15
}

stop_singlink() {
  if [[ -n "${SINGLINK_PID}" ]] && kill -0 "${SINGLINK_PID}" 2>/dev/null; then
    kill "${SINGLINK_PID}" 2>/dev/null || true
    wait "${SINGLINK_PID}" 2>/dev/null || true
  fi
  SINGLINK_PID=""
}

start_udp_port_blocker() {
  e2e_assert_udp_port_free "${E2E_BAD_NODE_PORT}" "tuic reload bad port"
  cat >"${TMP_DIR}/udp_port_blocker.py" <<'PY'
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((host, port))
while True:
    time.sleep(3600)
PY
  python3 "${TMP_DIR}/udp_port_blocker.py" "${E2E_BIND_HOST}" "${E2E_BAD_NODE_PORT}" >"${TMP_DIR}/udp_port_blocker.log" 2>&1 &
  BLOCKER_PID=$!
  wait_for_udp_listen_port "${E2E_BAD_NODE_PORT}" "tuic reload bad port blocker" 10
}

update_node_to_blocked_port() {
  local now

  now="$(date +%s)"
  mysql_exec <<SQL
UPDATE v2_server_tuic
SET port='${E2E_BAD_NODE_PORT}',
    server_port=${E2E_BAD_NODE_PORT},
    updated_at=${now}
WHERE id=${NODE_ID};
SQL
}

curl_through_proxy() {
  local label="$1"
  local output="${TMP_DIR}/${label}.bin"

  curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${E2E_PROXY_PORT}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/payload.bin" \
    -o "${output}"

  [[ "$(wc -c <"${output}")" -eq 16384 ]] || e2e_die "${label}: download size mismatch"
  e2e_log "${label}: TUIC connection accepted"
}

wait_for_rollback_log() {
  local start
  local now

  start="$(date +%s)"
  while true; do
    if grep -q "restored previous V2Board node" "${TMP_DIR}/tuic-reload.shoes.log"; then
      e2e_log "tuic reload rollback log observed"
      return
    fi
    if [[ -n "${SHOES_PID}" ]] && ! kill -0 "${SHOES_PID}" 2>/dev/null; then
      e2e_die "shoes exited while waiting for TUIC rollback"
    fi
    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_die "TUIC reload rollback log was not observed"
    fi
    sleep 1
  done
}

stop_services() {
  stop_singlink
  for pid_var in SHOES_PID BLOCKER_PID HTTP_PID; do
    local pid="${!pid_var:-}"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
    printf -v "${pid_var}" ''
  done
}

cleanup_fixtures() {
  if e2e_env_bool E2E_KEEP_FIXTURES 1; then
    e2e_log "keeping TUIC reload E2E fixtures"
    return
  fi

  mysql_exec <<SQL
DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='tuic';
DELETE FROM v2_user WHERE email='shoes-tuic-reload@example.local';
DELETE FROM v2_server_tuic WHERE name='shoes-tuic-reload';
DELETE FROM v2_server_group WHERE name='shoes-tuic-reload';
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
}

main() {
  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-tuic-reload-e2e.XXXXXX)"

  check_environment
  resolve_binaries
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"
  generate_tls_files
  start_http_target
  seed_fixture
  write_configs
  start_shoes
  start_singlink
  curl_through_proxy "before-reload"
  start_udp_port_blocker
  update_node_to_blocked_port
  wait_for_rollback_log
  wait_for_udp_listen_port "${E2E_NODE_PORT}" "tuic reload restored shoes" 10
  stop_singlink
  start_singlink
  curl_through_proxy "after-rollback"
  cleanup_fixtures
  e2e_section "done"
}

main "$@"
