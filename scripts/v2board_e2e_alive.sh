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
SHOES_BIN="${SHOES_BIN:-}"

E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18095}"
E2E_NODE_PORT="${E2E_NODE_PORT:-18161}"
E2E_PROXY_PORT="${E2E_PROXY_PORT:-18261}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-2}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-2}"
E2E_WAIT_TIMEOUT_SECS="${E2E_WAIT_TIMEOUT_SECS:-45}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_CURL_CONNECT_TIMEOUT_SECS="${E2E_CURL_CONNECT_TIMEOUT_SECS:-3}"

NODE_ID=9701
USER_ID=19701
USER_UUID=77777777-7777-4777-8777-777777777701

TMP_DIR=""
HTTP_PID=""
SHOES_PID=""
SINGLINK_PID=""
SLOW_CURL_PID=""
SERVER_TOKEN=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_alive.sh

Runs a real V2Board alive E2E check:
  - starts a long-lived VMess/TCP user connection
  - waits for shoes to push /alive
  - verifies Laravel Cache ALIVE_IP_USER_<uid>
  - verifies /alivelist returns the same online count
EOF
}

cleanup() {
  local status=$?
  set +e
  if [[ -n "${SLOW_CURL_PID}" ]] && kill -0 "${SLOW_CURL_PID}" 2>/dev/null; then
    kill "${SLOW_CURL_PID}" 2>/dev/null || true
    wait "${SLOW_CURL_PID}" 2>/dev/null || true
  fi
  stop_services
  if [[ -n "${HTTP_PID}" ]] && kill -0 "${HTTP_PID}" 2>/dev/null; then
    kill "${HTTP_PID}" 2>/dev/null || true
    wait "${HTTP_PID}" 2>/dev/null || true
  fi

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
    for pid in "${HTTP_PID}" "${SHOES_PID}" "${SINGLINK_PID}"; do
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

resolve_binaries() {
  e2e_section "binaries"
  e2e_require_command docker
  e2e_require_command curl
  e2e_require_command ss
  e2e_require_command python3

  if [[ -z "${SHOES_BIN}" ]]; then
    SHOES_BIN="${ROOT_DIR}/target/debug/shoes"
    e2e_run cargo build --manifest-path "${ROOT_DIR}/Cargo.toml"
  fi
  [[ -x "${SHOES_BIN}" ]] || e2e_die "SHOES_BIN is not executable: ${SHOES_BIN}"

  if [[ -z "${SINGLINK_BIN}" ]]; then
    e2e_require_dir "${SING_BOX_DIR}" "sing-box checkout"
    e2e_require_command go
    SINGLINK_BIN="${TMP_DIR}/singlink"
    e2e_run go -C "${SING_BOX_DIR}" build -o "${SINGLINK_BIN}" ./cmd/singlink
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

cache_forget() {
  local key="$1"

  docker exec "${V2BOARD_WWW_CONTAINER}" \
    php artisan tinker --execute="Cache::forget('${key}');" >/dev/null
}

cache_json() {
  local key="$1"

  docker exec "${V2BOARD_WWW_CONTAINER}" \
    php artisan tinker --execute="echo json_encode(Cache::get('${key}'));" 2>/dev/null
}

start_http_target() {
  e2e_section "start slow http target"
  e2e_assert_port_free "${E2E_HTTP_PORT}" "alive http target"
  cat >"${TMP_DIR}/alive_http.py" <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys
import time

SIZE = 8 * 1024 * 1024
CHUNK = 16 * 1024

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(SIZE))
        self.end_headers()
        sent = 0
        while sent < SIZE:
            n = min(CHUNK, SIZE - sent)
            self.wfile.write(b"\0" * n)
            self.wfile.flush()
            sent += n
            time.sleep(0.05)

ThreadingHTTPServer((sys.argv[1], int(sys.argv[2])), Handler).serve_forever()
PY
  python3 "${TMP_DIR}/alive_http.py" "${E2E_BIND_HOST}" "${E2E_HTTP_PORT}" >"${TMP_DIR}/http.log" 2>&1 &
  HTTP_PID=$!
  wait_for_listen_port "${E2E_HTTP_PORT}" "alive http target" 10
}

seed_fixture() {
  local now
  local expires_at

  now="$(date +%s)"
  expires_at="$((now + 86400))"

  mysql_exec <<SQL
INSERT INTO v2_server_vmess
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tags, rate, network, rules, networkSettings, tlsSettings, ruleSettings, dnsSettings, \`show\`, sort, created_at, updated_at)
VALUES
(${NODE_ID}, '["1"]', NULL, 'shoes-alive-user', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_NODE_PORT}', ${E2E_NODE_PORT}, 0, NULL, '1', 'tcp', NULL, '{}', '{}', '{}', '{}', 1, ${NODE_ID}, ${now}, ${now})
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
  updated_at=VALUES(updated_at);

INSERT INTO v2_user
(id, invite_user_id, telegram_id, email, language, password, password_algo, password_salt, balance, discount, commission_type, commission_rate, commission_balance, t, u, d, transfer_enable, device_limit, banned, is_admin, last_login_at, is_staff, last_login_ip, uuid, group_id, plan_id, speed_limit, auto_renewal, remind_expire, remind_traffic, token, expired_at, remarks, created_at, updated_at)
VALUES
(${USER_ID}, NULL, NULL, 'shoes-alive-user@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, 2, 0, 0, NULL, 0, NULL, '${USER_UUID}', 1, NULL, NULL, 0, 1, 1, MD5('shoes-alive-user@example.local'), ${expires_at}, 'shoes alive user e2e', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
  group_id=1,
  speed_limit=NULL,
  device_limit=2,
  expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
  cache_forget "ALIVE_IP_USER_${USER_ID}"
  cache_forget "ALIVE_LIST"
}

write_configs() {
  cat >"${TMP_DIR}/alive.shoes.yml" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${SERVER_TOKEN}"
  nodes:
    - tag: "alive_user"
      node_id: ${NODE_ID}
      node_type: "vmess"
      listen: "${E2E_BIND_HOST}"
      pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
      push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
runtime:
  data_dir: "${TMP_DIR}/alive-shoes-data"
  pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
  push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
  device_online_min_traffic: 0
log:
  level: "debug"
YAML

  cat >"${TMP_DIR}/alive.singlink.json" <<JSON
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
      "type": "vmess",
      "tag": "vmess-out",
      "server": "${E2E_BIND_HOST}",
      "server_port": ${E2E_NODE_PORT},
      "uuid": "${USER_UUID}",
      "security": "auto",
      "alter_id": 0,
      "network": "tcp"
    }
  ],
  "route": {"final": "vmess-out"}
}
JSON
}

start_services() {
  "${SHOES_BIN}" sync-once -c "${TMP_DIR}/alive.shoes.yml" >"${TMP_DIR}/alive.sync.log" 2>&1
  e2e_assert_port_free "${E2E_NODE_PORT}" "alive shoes"
  "${SHOES_BIN}" run -c "${TMP_DIR}/alive.shoes.yml" >"${TMP_DIR}/alive.shoes.log" 2>&1 &
  SHOES_PID=$!
  wait_for_listen_port "${E2E_NODE_PORT}" "alive shoes" 15

  "${SINGLINK_BIN}" -c "${TMP_DIR}/alive.singlink.json" check >"${TMP_DIR}/alive.singlink-check.log" 2>&1
  e2e_assert_port_free "${E2E_PROXY_PORT}" "alive singlink"
  "${SINGLINK_BIN}" -c "${TMP_DIR}/alive.singlink.json" run >"${TMP_DIR}/alive.singlink.log" 2>&1 &
  SINGLINK_PID=$!
  wait_for_listen_port "${E2E_PROXY_PORT}" "alive singlink" 15
}

stop_services() {
  for pid_var in SINGLINK_PID SHOES_PID; do
    local pid="${!pid_var:-}"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
    printf -v "${pid_var}" ''
  done
}

start_slow_connection() {
  curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${E2E_PROXY_PORT}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/slow.bin" \
    -o "${TMP_DIR}/slow.bin" \
    >"${TMP_DIR}/slow.curl.out" 2>"${TMP_DIR}/slow.curl.err" &
  SLOW_CURL_PID=$!
  sleep 1
  kill -0 "${SLOW_CURL_PID}" 2>/dev/null || e2e_die "slow alive connection exited too early"
}

assert_alive_cache_json() {
  local json="$1"

  ALIVE_JSON="${json}" python3 - "${USER_ID}" "${NODE_ID}" <<'PY'
import json
import os
import sys

uid = sys.argv[1]
node_id = sys.argv[2]
data = json.loads(os.environ["ALIVE_JSON"])
if not isinstance(data, dict):
    raise SystemExit(f"alive cache is not an object: {data!r}")
node_key = f"vmess{node_id}"
node = data.get(node_key)
if not isinstance(node, dict):
    raise SystemExit(f"missing node key {node_key}: {data!r}")
ips = node.get("aliveips")
if not isinstance(ips, list) or f"127.0.0.1_{node_id}" not in ips:
    raise SystemExit(f"missing loopback alive ip for user {uid}: {data!r}")
if int(data.get("alive_ip", 0)) != 1:
    raise SystemExit(f"expected alive_ip=1 for user {uid}: {data!r}")
PY
}

assert_alivelist_json() {
  local json="$1"

  ALIVE_LIST_JSON="${json}" python3 - "${USER_ID}" <<'PY'
import json
import os
import sys

uid = sys.argv[1]
data = json.loads(os.environ["ALIVE_LIST_JSON"])
alive = data.get("alive")
if not isinstance(alive, dict):
    raise SystemExit(f"alivelist payload missing alive object: {data!r}")
if int(alive.get(uid, 0)) != 1:
    raise SystemExit(f"expected alivelist alive[{uid}]=1: {data!r}")
PY
}

wait_for_alive_cache() {
  local start
  local now
  local json

  start="$(date +%s)"
  while true; do
    json="$(cache_json "ALIVE_IP_USER_${USER_ID}")"
    if assert_alive_cache_json "${json}" 2>"${TMP_DIR}/alive-cache.assert.log"; then
      e2e_log "alive cache: ${json}"
      return
    fi
    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_die "alive cache did not contain expected user/node data; last=${json}; assert=$(cat "${TMP_DIR}/alive-cache.assert.log")"
    fi
    sleep 1
  done
}

verify_alivelist() {
  local url
  local json

  cache_forget "ALIVE_LIST"
  url="${V2BOARD_PANEL_URL}/api/v1/server/UniProxy/alivelist?token=${SERVER_TOKEN}&node_type=vmess&node_id=${NODE_ID}"
  json="$(curl -fsS --max-time 5 "${url}")"
  assert_alivelist_json "${json}"
  e2e_log "alivelist: ${json}"
}

cleanup_fixtures() {
  if e2e_env_bool E2E_KEEP_FIXTURES 1; then
    e2e_log "keeping alive E2E fixtures"
    return
  fi

  mysql_exec <<SQL
DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
DELETE FROM v2_user WHERE email='shoes-alive-user@example.local';
DELETE FROM v2_server_vmess WHERE name='shoes-alive-user';
SQL
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
  cache_forget "ALIVE_IP_USER_${USER_ID}"
  cache_forget "ALIVE_LIST"
}

main() {
  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-alive-e2e.XXXXXX)"

  check_environment
  resolve_binaries
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"
  start_http_target
  seed_fixture
  write_configs
  start_services
  start_slow_connection
  wait_for_alive_cache
  verify_alivelist
  cleanup_fixtures
  e2e_section "done"
}

main "$@"
