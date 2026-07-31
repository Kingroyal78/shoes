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
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18099}"
E2E_NODE_A_PORT="${E2E_NODE_A_PORT:-18162}"
E2E_NODE_B_PORT="${E2E_NODE_B_PORT:-18163}"
E2E_PROXY_A_PORT="${E2E_PROXY_A_PORT:-18262}"
E2E_PROXY_B_PORT="${E2E_PROXY_B_PORT:-18263}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-2}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-2}"
E2E_WAIT_TIMEOUT_SECS="${E2E_WAIT_TIMEOUT_SECS:-45}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_CURL_CONNECT_TIMEOUT_SECS="${E2E_CURL_CONNECT_TIMEOUT_SECS:-3}"
E2E_CURL_MAX_TIME_SECS="${E2E_CURL_MAX_TIME_SECS:-60}"

GROUP_ID=9702
NODE_A_ID=9702
NODE_B_ID=9703
USER_ID=19702
USER_UUID=77777777-7777-4777-8777-777777777702

TMP_DIR=""
HTTP_PID=""
SHOES_PID=""
SINGLINK_PIDS=()
SLOW_CURL_PIDS=()
SERVER_TOKEN=""
V2BOARD_CONFIG_BACKUP=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_device_limit_mode.sh

Runs a real V2Board cross-node device_limit_mode E2E check:
  - starts two VMess nodes for the same device-limited user
  - keeps one connection alive through each node from the same source IP
  - verifies V2Board ALIVE_IP_USER_<uid> and /alivelist with mode 0 and mode 1

The script temporarily sets config/v2board.php device_limit_mode and restores
the original file on exit.
EOF
}

cleanup() {
  local status=$?
  set +e
  stop_slow_connections
  stop_services
  if [[ -n "${HTTP_PID}" ]] && kill -0 "${HTTP_PID}" 2>/dev/null; then
    kill "${HTTP_PID}" 2>/dev/null || true
    wait "${HTTP_PID}" 2>/dev/null || true
  fi
  restore_v2board_config

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
  local pid

  start="$(date +%s)"
  while true; do
    if ss -ltn | awk '{print $4}' | grep -Eq "(^|:)${port}$"; then
      return
    fi
    if [[ -n "${HTTP_PID}" ]] && ! kill -0 "${HTTP_PID}" 2>/dev/null; then
      e2e_die "${label} process exited before listening on ${port}"
    fi
    if [[ -n "${SHOES_PID}" ]] && ! kill -0 "${SHOES_PID}" 2>/dev/null; then
      e2e_die "${label} process exited before listening on ${port}"
    fi
    for pid in "${SINGLINK_PIDS[@]:-}"; do
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

clear_laravel_config() {
  docker exec "${V2BOARD_WWW_CONTAINER}" php artisan config:clear >/dev/null
}

read_device_limit_mode() {
  docker exec "${V2BOARD_WWW_CONTAINER}" \
    php artisan tinker --execute='echo config("v2board.device_limit_mode", "missing");' 2>/dev/null \
    | tr -d '[:space:]'
}

backup_v2board_config() {
  local config_path="${V2BOARD_DIR}/config/v2board.php"

  e2e_require_file "${config_path}" "V2Board config"
  V2BOARD_CONFIG_BACKUP="${TMP_DIR}/v2board.php.backup"
  cp "${config_path}" "${V2BOARD_CONFIG_BACKUP}"
}

restore_v2board_config() {
  local config_path="${V2BOARD_DIR}/config/v2board.php"

  if [[ -n "${V2BOARD_CONFIG_BACKUP}" && -f "${V2BOARD_CONFIG_BACKUP}" ]]; then
    cp "${V2BOARD_CONFIG_BACKUP}" "${config_path}" || true
    clear_laravel_config || true
    V2BOARD_CONFIG_BACKUP=""
  fi
}

set_device_limit_mode() {
  local mode="$1"
  local actual

  docker exec -i -e SHOES_E2E_DEVICE_LIMIT_MODE="${mode}" "${V2BOARD_WWW_CONTAINER}" php <<'PHP'
<?php
$path = '/www/config/v2board.php';
$mode = (int) getenv('SHOES_E2E_DEVICE_LIMIT_MODE');
$contents = file_get_contents($path);
if ($contents === false) {
    fwrite(STDERR, "failed to read $path\n");
    exit(1);
}
$entry = "  'device_limit_mode' => {$mode},";
if (preg_match("/\\n\\s*'device_limit_mode'\\s*=>\\s*[^,\\n]+,?/", $contents)) {
    $contents = preg_replace("/\\n\\s*'device_limit_mode'\\s*=>\\s*[^,\\n]+,?/", "\n" . $entry, $contents, 1);
} else {
    $contents = preg_replace("/\\n\\)\\s*;\\s*$/", "\n" . $entry . "\n) ;\n", $contents, 1, $count);
    if ($count !== 1) {
        fwrite(STDERR, "failed to insert device_limit_mode into $path\n");
        exit(1);
    }
}
if (file_put_contents($path, $contents) === false) {
    fwrite(STDERR, "failed to write $path\n");
    exit(1);
}
PHP
  clear_laravel_config
  actual="$(read_device_limit_mode)"
  [[ "${actual}" == "${mode}" ]] \
    || e2e_die "V2Board device_limit_mode expected ${mode}, got ${actual}"
}

start_http_target() {
  e2e_section "start device-limit-mode http target"
  e2e_assert_port_free "${E2E_HTTP_PORT}" "device-limit-mode http target"
  cat >"${TMP_DIR}/device_limit_mode_http.py" <<'PY'
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
  python3 "${TMP_DIR}/device_limit_mode_http.py" "${E2E_BIND_HOST}" "${E2E_HTTP_PORT}" >"${TMP_DIR}/http.log" 2>&1 &
  HTTP_PID=$!
  wait_for_listen_port "${E2E_HTTP_PORT}" "device-limit-mode http target" 10
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
(${GROUP_ID}, 'shoes-device-limit-mode', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  updated_at=VALUES(updated_at);

INSERT INTO v2_server_vmess
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tags, rate, network, rules, networkSettings, tlsSettings, ruleSettings, dnsSettings, \`show\`, sort, created_at, updated_at)
VALUES
(${NODE_A_ID}, '["${GROUP_ID}"]', NULL, 'shoes-device-limit-mode-a', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_NODE_A_PORT}', ${E2E_NODE_A_PORT}, 0, NULL, '1', 'tcp', NULL, '{}', '{}', '{}', '{}', 1, ${NODE_A_ID}, ${now}, ${now}),
(${NODE_B_ID}, '["${GROUP_ID}"]', NULL, 'shoes-device-limit-mode-b', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_NODE_B_PORT}', ${E2E_NODE_B_PORT}, 0, NULL, '1', 'tcp', NULL, '{}', '{}', '{}', '{}', 1, ${NODE_B_ID}, ${now}, ${now})
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
(${USER_ID}, NULL, NULL, 'shoes-device-limit-mode@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, 10, 0, 0, NULL, 0, NULL, '${USER_UUID}', ${GROUP_ID}, NULL, NULL, 0, 1, 1, MD5('shoes-device-limit-mode@example.local'), ${expires_at}, 'shoes device limit mode e2e', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
  group_id=${GROUP_ID},
  speed_limit=NULL,
  device_limit=10,
  expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);

DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id IN (${NODE_A_ID}, ${NODE_B_ID}) AND server_type='vmess';
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
  clear_alive_cache
}

clear_alive_cache() {
  cache_forget "ALIVE_IP_USER_${USER_ID}"
  cache_forget "ALIVE_LIST"
}

write_configs() {
  cat >"${TMP_DIR}/device_limit_mode.shoes.yml" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${SERVER_TOKEN}"
  nodes:
    - tag: "device_limit_mode_a"
      node_id: ${NODE_A_ID}
      node_type: "vmess"
      listen: "${E2E_BIND_HOST}"
      pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
      push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
    - tag: "device_limit_mode_b"
      node_id: ${NODE_B_ID}
      node_type: "vmess"
      listen: "${E2E_BIND_HOST}"
      pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
      push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
runtime:
  data_dir: "${TMP_DIR}/device-limit-mode-shoes-data"
  pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
  push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
  node_report_min_traffic: 0
  device_online_min_traffic: 0
log:
  level: "debug"
YAML

  write_singlink_config "a" "${E2E_NODE_A_PORT}" "${E2E_PROXY_A_PORT}"
  write_singlink_config "b" "${E2E_NODE_B_PORT}" "${E2E_PROXY_B_PORT}"
}

write_singlink_config() {
  local suffix="$1"
  local node_port="$2"
  local proxy_port="$3"

  cat >"${TMP_DIR}/device_limit_mode_${suffix}.singlink.json" <<JSON
{
  "log": {"level": "info", "timestamp": true},
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "${E2E_BIND_HOST}",
      "listen_port": ${proxy_port}
    }
  ],
  "outbounds": [
    {
      "type": "vmess",
      "tag": "vmess-out",
      "server": "${E2E_BIND_HOST}",
      "server_port": ${node_port},
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
  "${SHOES_BIN}" sync-once -c "${TMP_DIR}/device_limit_mode.shoes.yml" >"${TMP_DIR}/device_limit_mode.sync.log" 2>&1
  e2e_assert_port_free "${E2E_NODE_A_PORT}" "device-limit-mode shoes node a"
  e2e_assert_port_free "${E2E_NODE_B_PORT}" "device-limit-mode shoes node b"
  "${SHOES_BIN}" run -c "${TMP_DIR}/device_limit_mode.shoes.yml" >"${TMP_DIR}/device_limit_mode.shoes.log" 2>&1 &
  SHOES_PID=$!
  wait_for_listen_port "${E2E_NODE_A_PORT}" "device-limit-mode shoes node a" 15
  wait_for_listen_port "${E2E_NODE_B_PORT}" "device-limit-mode shoes node b" 15

  start_singlink "a" "${E2E_PROXY_A_PORT}"
  start_singlink "b" "${E2E_PROXY_B_PORT}"
}

start_singlink() {
  local suffix="$1"
  local proxy_port="$2"

  "${SINGLINK_BIN}" -c "${TMP_DIR}/device_limit_mode_${suffix}.singlink.json" check \
    >"${TMP_DIR}/device_limit_mode_${suffix}.singlink-check.log" 2>&1
  e2e_assert_port_free "${proxy_port}" "device-limit-mode singlink ${suffix}"
  "${SINGLINK_BIN}" -c "${TMP_DIR}/device_limit_mode_${suffix}.singlink.json" run \
    >"${TMP_DIR}/device_limit_mode_${suffix}.singlink.log" 2>&1 &
  SINGLINK_PIDS+=("$!")
  wait_for_listen_port "${proxy_port}" "device-limit-mode singlink ${suffix}" 15
}

stop_slow_connections() {
  local pid

  for pid in "${SLOW_CURL_PIDS[@]:-}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  SLOW_CURL_PIDS=()
}

stop_services() {
  local pid

  stop_slow_connections
  for pid in "${SINGLINK_PIDS[@]:-}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  SINGLINK_PIDS=()
  if [[ -n "${SHOES_PID}" ]] && kill -0 "${SHOES_PID}" 2>/dev/null; then
    kill "${SHOES_PID}" 2>/dev/null || true
    wait "${SHOES_PID}" 2>/dev/null || true
  fi
  SHOES_PID=""
}

start_slow_connection() {
  local suffix="$1"
  local proxy_port="$2"
  local output="${TMP_DIR}/device_limit_mode_${suffix}.bin"
  local pid

  curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${proxy_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/slow.bin" \
    -o "${output}" \
    >"${TMP_DIR}/device_limit_mode_${suffix}.curl.out" \
    2>"${TMP_DIR}/device_limit_mode_${suffix}.curl.err" &
  pid=$!
  SLOW_CURL_PIDS+=("${pid}")
  sleep 0.5
  kill -0 "${pid}" 2>/dev/null || e2e_die "slow connection ${suffix} exited too early"
}

assert_alive_cache_json() {
  local json="$1"
  local expected_count="$2"

  ALIVE_JSON="${json}" python3 - "${USER_ID}" "${NODE_A_ID}" "${NODE_B_ID}" "${expected_count}" <<'PY'
import json
import os
import sys

uid = sys.argv[1]
node_a = sys.argv[2]
node_b = sys.argv[3]
expected = int(sys.argv[4])
data = json.loads(os.environ["ALIVE_JSON"])
if not isinstance(data, dict):
    raise SystemExit(f"alive cache is not an object: {data!r}")
for node_id in (node_a, node_b):
    node_key = f"vmess{node_id}"
    node = data.get(node_key)
    if not isinstance(node, dict):
        raise SystemExit(f"missing node key {node_key}: {data!r}")
    ips = node.get("aliveips")
    expected_ip = f"127.0.0.1_{node_id}"
    if not isinstance(ips, list) or expected_ip not in ips:
        raise SystemExit(f"missing {expected_ip} for user {uid}: {data!r}")
if int(data.get("alive_ip", -1)) != expected:
    raise SystemExit(f"expected alive_ip={expected} for user {uid}: {data!r}")
PY
}

assert_alivelist_json() {
  local json="$1"
  local expected_count="$2"

  ALIVE_LIST_JSON="${json}" python3 - "${USER_ID}" "${expected_count}" <<'PY'
import json
import os
import sys

uid = sys.argv[1]
expected = int(sys.argv[2])
data = json.loads(os.environ["ALIVE_LIST_JSON"])
alive = data.get("alive")
if not isinstance(alive, dict):
    raise SystemExit(f"alivelist payload missing alive object: {data!r}")
if int(alive.get(uid, -1)) != expected:
    raise SystemExit(f"expected alivelist alive[{uid}]={expected}: {data!r}")
PY
}

wait_for_alive_cache() {
  local expected_count="$1"
  local mode="$2"
  local start
  local now
  local json

  start="$(date +%s)"
  while true; do
    json="$(cache_json "ALIVE_IP_USER_${USER_ID}")"
    if assert_alive_cache_json "${json}" "${expected_count}" 2>"${TMP_DIR}/device_limit_mode_${mode}.assert.log"; then
      e2e_log "device_limit_mode=${mode} alive cache: ${json}"
      return
    fi
    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_die "device_limit_mode=${mode} alive cache did not reach expected count ${expected_count}; last=${json}; assert=$(cat "${TMP_DIR}/device_limit_mode_${mode}.assert.log")"
    fi
    sleep 1
  done
}

verify_alivelist() {
  local expected_count="$1"
  local mode="$2"
  local url
  local json

  cache_forget "ALIVE_LIST"
  url="${V2BOARD_PANEL_URL}/api/v1/server/UniProxy/alivelist?token=${SERVER_TOKEN}&node_type=vmess&node_id=${NODE_A_ID}"
  json="$(curl -fsS --max-time 5 "${url}")"
  assert_alivelist_json "${json}" "${expected_count}"
  e2e_log "device_limit_mode=${mode} alivelist: ${json}"
}

run_mode_case() {
  local mode="$1"
  local expected_count="$2"

  e2e_section "device_limit_mode=${mode}"
  set_device_limit_mode "${mode}"
  clear_alive_cache
  start_services
  start_slow_connection "a" "${E2E_PROXY_A_PORT}"
  start_slow_connection "b" "${E2E_PROXY_B_PORT}"
  wait_for_alive_cache "${expected_count}" "${mode}"
  verify_alivelist "${expected_count}" "${mode}"
  stop_services
  clear_alive_cache
}

cleanup_fixtures() {
  if e2e_env_bool E2E_KEEP_FIXTURES 1; then
    e2e_log "keeping device-limit-mode E2E fixtures"
    return
  fi

  e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"

  mysql_exec <<SQL
DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id IN (${NODE_A_ID}, ${NODE_B_ID}) AND server_type='vmess';
DELETE FROM v2_user WHERE email='shoes-device-limit-mode@example.local';
DELETE FROM v2_server_vmess WHERE name IN ('shoes-device-limit-mode-a', 'shoes-device-limit-mode-b');
DELETE FROM v2_server_group WHERE name='shoes-device-limit-mode';
SQL
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
  clear_alive_cache
}

main() {
  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-device-limit-mode-e2e.XXXXXX)"

  check_environment
  resolve_binaries
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"
  backup_v2board_config
  start_http_target
  seed_fixture
  write_configs
  run_mode_case 0 2
  run_mode_case 1 1
  cleanup_fixtures
  e2e_section "done"
}

main "$@"
