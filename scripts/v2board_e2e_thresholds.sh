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
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18106}"
E2E_NODE_PORT="${E2E_NODE_PORT:-18196}"
E2E_PROXY_PORT="${E2E_PROXY_PORT:-18296}"
E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB:-128}"
E2E_SLOW_PAYLOAD_KIB="${E2E_SLOW_PAYLOAD_KIB:-8192}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-2}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-2}"
E2E_WAIT_TIMEOUT_SECS="${E2E_WAIT_TIMEOUT_SECS:-45}"
E2E_NO_REPORT_WAIT_SECS="${E2E_NO_REPORT_WAIT_SECS:-7}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_CURL_CONNECT_TIMEOUT_SECS="${E2E_CURL_CONNECT_TIMEOUT_SECS:-3}"
E2E_CURL_MAX_TIME_SECS="${E2E_CURL_MAX_TIME_SECS:-45}"

GROUP_ID=9911
NODE_ID=9911
USER_ID=19911
USER_UUID=99999999-9999-4999-8999-999999999911

NODE_REPORT_HIGH_THRESHOLD_BYTES=$((1024 * 1024))
ALIVE_HIGH_THRESHOLD_BYTES=$((100 * 1024 * 1024))
ALIVE_PASS_THRESHOLD_BYTES=$((64 * 1024))

TMP_DIR=""
HTTP_PID=""
SHOES_PID=""
SINGLINK_PID=""
SLOW_CURL_PID=""
SERVER_TOKEN=""
V2BOARD_CONFIG_BACKUP=""
SHOES_DATA_DIR=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_thresholds.sh

Runs real V2Board threshold E2E checks:
  - node_report_min_traffic suppresses sub-threshold traffic pushes
  - suppressed traffic is persisted and flushed after the threshold is lowered
  - device_online_min_traffic suppresses low-traffic alive pushes
  - nonzero reachable device_online_min_traffic eventually reports alive IPs

The script temporarily edits config/v2board.php and restores the original file
on exit.
EOF
}

cleanup() {
  local status=$?
  set +e
  stop_slow_connection
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

clear_laravel_config() {
  docker exec "${V2BOARD_WWW_CONTAINER}" php artisan config:clear >/dev/null
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

read_v2board_config_int() {
  local key="$1"

  docker exec "${V2BOARD_WWW_CONTAINER}" \
    php artisan tinker --execute="echo config('v2board.${key}', 'missing');" 2>/dev/null \
    | tr -d '[:space:]'
}

set_v2board_thresholds() {
  local node_report_min="$1"
  local device_online_min="$2"
  local actual_node_report_min
  local actual_device_online_min

  docker exec -i \
    -e SHOES_E2E_NODE_REPORT_MIN_TRAFFIC="${node_report_min}" \
    -e SHOES_E2E_DEVICE_ONLINE_MIN_TRAFFIC="${device_online_min}" \
    "${V2BOARD_WWW_CONTAINER}" \
    php <<'PHP'
<?php
$path = '/www/config/v2board.php';
$updates = [
    'server_node_report_min_traffic' => (int)getenv('SHOES_E2E_NODE_REPORT_MIN_TRAFFIC'),
    'server_device_online_min_traffic' => (int)getenv('SHOES_E2E_DEVICE_ONLINE_MIN_TRAFFIC'),
];
$contents = file_get_contents($path);
if ($contents === false) {
    fwrite(STDERR, "failed to read $path\n");
    exit(1);
}
foreach ($updates as $key => $value) {
    $entry = "  '{$key}' => {$value},";
    $pattern = "/\n\s*'" . preg_quote($key, '/') . "'\s*=>\s*[^,\n]+,?/";
    $contents = preg_replace($pattern, "\n" . $entry, $contents, 1, $count);
    if ($count !== 1) {
        $contents = preg_replace("/\n\)\s*;\s*$/", "\n" . $entry . "\n) ;\n", $contents, 1, $inserted);
        if ($inserted !== 1) {
            fwrite(STDERR, "failed to insert {$key} into $path\n");
            exit(1);
        }
    }
}
if (file_put_contents($path, $contents) === false) {
    fwrite(STDERR, "failed to write $path\n");
    exit(1);
}
PHP
  clear_laravel_config
  actual_node_report_min="$(read_v2board_config_int server_node_report_min_traffic)"
  actual_device_online_min="$(read_v2board_config_int server_device_online_min_traffic)"
  [[ "${actual_node_report_min}" == "${node_report_min}" ]] \
    || e2e_die "V2Board server_node_report_min_traffic expected ${node_report_min}, got ${actual_node_report_min}"
  [[ "${actual_device_online_min}" == "${device_online_min}" ]] \
    || e2e_die "V2Board server_device_online_min_traffic expected ${device_online_min}, got ${actual_device_online_min}"
  wait_for_uniproxy_thresholds "${node_report_min}" "${device_online_min}"
}

wait_for_uniproxy_thresholds() {
  local expected_node_report_min="$1"
  local expected_device_online_min="$2"
  local start
  local now
  local body

  start="$(date +%s)"
  while true; do
    body="$(curl -fsS \
      --max-time 5 \
      "${V2BOARD_PANEL_URL%/}/api/v1/server/UniProxy/config?token=${SERVER_TOKEN}&node_id=${NODE_ID}&node_type=vmess")"
    if BODY="${body}" python3 - "${expected_node_report_min}" "${expected_device_online_min}" <<'PY'
import json
import os
import sys

expected_node_report_min = int(sys.argv[1])
expected_device_online_min = int(sys.argv[2])
data = json.loads(os.environ["BODY"])
base = data.get("base_config") or {}
if base.get("node_report_min_traffic") != expected_node_report_min:
    raise SystemExit(1)
if base.get("device_online_min_traffic") != expected_device_online_min:
    raise SystemExit(1)
PY
    then
      e2e_log "UniProxy thresholds node_report_min=${expected_node_report_min} device_online_min=${expected_device_online_min}"
      return
    fi
    now="$(date +%s)"
    if ((now - start >= 15)); then
      e2e_die "UniProxy thresholds did not become node_report_min=${expected_node_report_min} device_online_min=${expected_device_online_min}; last=${body}"
    fi
    sleep 1
  done
}

clear_status_cache() {
  for suffix in LAST_CHECK_AT LAST_PUSH_AT ONLINE_USER; do
    cache_forget "SERVER_VMESS_${suffix}_${NODE_ID}"
  done
  cache_forget "ALIVE_IP_USER_${USER_ID}"
  cache_forget "ALIVE_LIST"
}

reset_accounting_rows() {
  mysql_exec <<SQL
UPDATE v2_user SET u=0, d=0, t=0 WHERE id=${USER_ID};
DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
SQL
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
}

reset_runtime_state() {
  stop_slow_connection
  stop_services
  rm -rf "${SHOES_DATA_DIR}"
  reset_accounting_rows
  clear_status_cache
}

start_http_target() {
  e2e_section "start thresholds http target"
  e2e_assert_port_free "${E2E_HTTP_PORT}" "thresholds http target"
  cat >"${TMP_DIR}/thresholds_http.py" <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys
import time

FAST_SIZE = int(sys.argv[3]) * 1024
SLOW_SIZE = int(sys.argv[4]) * 1024
CHUNK = 16 * 1024

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        if self.path == "/payload.bin":
            size = FAST_SIZE
            delay = 0
        else:
            size = SLOW_SIZE
            delay = 0.05
        self.send_response(200)
        self.send_header("Content-Length", str(size))
        self.end_headers()
        sent = 0
        while sent < size:
            n = min(CHUNK, size - sent)
            self.wfile.write(b"\0" * n)
            self.wfile.flush()
            sent += n
            if delay:
                time.sleep(delay)

ThreadingHTTPServer((sys.argv[1], int(sys.argv[2])), Handler).serve_forever()
PY
  python3 "${TMP_DIR}/thresholds_http.py" \
    "${E2E_BIND_HOST}" \
    "${E2E_HTTP_PORT}" \
    "${E2E_PAYLOAD_KIB}" \
    "${E2E_SLOW_PAYLOAD_KIB}" \
    >"${TMP_DIR}/http.log" 2>&1 &
  HTTP_PID=$!
  wait_for_listen_port "${E2E_HTTP_PORT}" "thresholds http target" 10
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
(${GROUP_ID}, 'shoes-thresholds', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  updated_at=VALUES(updated_at);

INSERT INTO v2_server_vmess
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tags, rate, network, rules, networkSettings, tlsSettings, ruleSettings, dnsSettings, \`show\`, sort, created_at, updated_at)
VALUES
(${NODE_ID}, '["${GROUP_ID}"]', NULL, 'shoes-thresholds', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_NODE_PORT}', ${E2E_NODE_PORT}, 0, NULL, '1', 'tcp', NULL, '{}', '{}', '{}', '{}', 1, ${NODE_ID}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  parent_id=VALUES(parent_id),
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
(${USER_ID}, NULL, NULL, 'shoes-thresholds@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, 2, 0, 0, NULL, 0, NULL, '${USER_UUID}', ${GROUP_ID}, NULL, NULL, 0, 1, 1, MD5('shoes-thresholds@example.local'), ${expires_at}, 'shoes thresholds e2e', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
  group_id=${GROUP_ID},
  speed_limit=NULL,
  device_limit=2,
  expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);
SQL

  reset_accounting_rows
  clear_status_cache
}

write_configs() {
  SHOES_DATA_DIR="${TMP_DIR}/thresholds-shoes-data"
  cat >"${TMP_DIR}/thresholds.shoes.yml" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${SERVER_TOKEN}"
  nodes:
    - tag: "thresholds"
      node_id: ${NODE_ID}
      node_type: "vmess"
      listen: "${E2E_BIND_HOST}"
      pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
      push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
runtime:
  data_dir: "${SHOES_DATA_DIR}"
  pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
  push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
  node_report_min_traffic: 0
  device_online_min_traffic: 0
log:
  level: "debug"
YAML

  cat >"${TMP_DIR}/thresholds.singlink.json" <<JSON
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
  "${SHOES_BIN}" sync-once -c "${TMP_DIR}/thresholds.shoes.yml" >"${TMP_DIR}/thresholds.sync.log" 2>&1
  e2e_assert_port_free "${E2E_NODE_PORT}" "thresholds shoes"
  "${SHOES_BIN}" run -c "${TMP_DIR}/thresholds.shoes.yml" >"${TMP_DIR}/thresholds.shoes.log" 2>&1 &
  SHOES_PID=$!
  wait_for_listen_port "${E2E_NODE_PORT}" "thresholds shoes" 15

  "${SINGLINK_BIN}" -c "${TMP_DIR}/thresholds.singlink.json" check >"${TMP_DIR}/thresholds.singlink-check.log" 2>&1
  e2e_assert_port_free "${E2E_PROXY_PORT}" "thresholds singlink"
  "${SINGLINK_BIN}" -c "${TMP_DIR}/thresholds.singlink.json" run >"${TMP_DIR}/thresholds.singlink.log" 2>&1 &
  SINGLINK_PID=$!
  wait_for_listen_port "${E2E_PROXY_PORT}" "thresholds singlink" 15
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

run_proxy_download() {
  local expected_size

  e2e_section "proxy traffic"
  curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${E2E_PROXY_PORT}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/payload.bin" \
    -o "${TMP_DIR}/download.bin"

  expected_size="$((E2E_PAYLOAD_KIB * 1024))"
  [[ "$(wc -c <"${TMP_DIR}/download.bin")" -eq "${expected_size}" ]] \
    || e2e_die "download size mismatch"
}

start_slow_connection() {
  curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${E2E_PROXY_PORT}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/slow.bin" \
    -o "${TMP_DIR}/slow.bin" \
    >"${TMP_DIR}/slow.curl.out" 2>"${TMP_DIR}/slow.curl.err" &
  SLOW_CURL_PID=$!
  sleep 1
  kill -0 "${SLOW_CURL_PID}" 2>/dev/null || e2e_die "slow threshold connection exited too early"
}

stop_slow_connection() {
  if [[ -n "${SLOW_CURL_PID}" ]] && kill -0 "${SLOW_CURL_PID}" 2>/dev/null; then
    kill "${SLOW_CURL_PID}" 2>/dev/null || true
    wait "${SLOW_CURL_PID}" 2>/dev/null || true
  fi
  SLOW_CURL_PID=""
}

assert_no_accounting_now() {
  local label="$1"
  local row_count
  local user_row
  local user_u
  local user_d

  e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"
  docker exec "${V2BOARD_WWW_CONTAINER}" php artisan traffic:update >/dev/null
  row_count="$(mysql_query "SELECT (SELECT COUNT(*) FROM v2_stat_user WHERE user_id=${USER_ID}) + (SELECT COUNT(*) FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess');")"
  user_row="$(mysql_query "SELECT u, d FROM v2_user WHERE id=${USER_ID};")"
  read -r user_u user_d <<<"${user_row}"
  ((row_count == 0)) || e2e_die "${label}: expected no stat rows, got ${row_count}"
  ((user_u == 0 && user_d == 0)) || e2e_die "${label}: expected user traffic 0/0, got ${user_u}/${user_d}"
}

wait_for_no_accounting() {
  local label="$1"
  local start
  local now

  start="$(date +%s)"
  while true; do
    assert_no_accounting_now "${label}"
    now="$(date +%s)"
    if ((now - start >= E2E_NO_REPORT_WAIT_SECS)); then
      e2e_log "${label}: no accounting rows after ${E2E_NO_REPORT_WAIT_SECS}s"
      return
    fi
    sleep 1
  done
}

wait_for_accounting_rows() {
  local expected_payload="$1"
  local label="$2"
  local start
  local now
  local row
  local user_u
  local user_d
  local stat_user_u
  local stat_user_d
  local stat_server_u
  local stat_server_d

  start="$(date +%s)"
  while true; do
    e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"
    docker exec "${V2BOARD_WWW_CONTAINER}" php artisan traffic:update >/dev/null
    row="$(mysql_query "SELECT u.u, u.d, su.u, su.d, ss.u, ss.d FROM v2_user u JOIN v2_stat_user su ON su.user_id=u.id JOIN v2_stat_server ss ON ss.server_id=${NODE_ID} AND ss.server_type='vmess' WHERE u.id=${USER_ID} ORDER BY su.id DESC LIMIT 1;")"
    if [[ -n "${row}" ]]; then
      read -r user_u user_d stat_user_u stat_user_d stat_server_u stat_server_d <<<"${row}"
      if ((stat_user_d >= expected_payload && stat_server_d >= expected_payload && user_d >= expected_payload)); then
        e2e_log "${label}: user=${user_u}/${user_d} stat_user=${stat_user_u}/${stat_user_d} stat_server=${stat_server_u}/${stat_server_d}"
        return
      fi
    fi

    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_die "${label}: accounting did not reach expected payload ${expected_payload}; last=${row:-<empty>}"
    fi
    sleep 1
  done
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
expected_ip = f"127.0.0.1_{node_id}"
if not isinstance(ips, list) or expected_ip not in ips:
    raise SystemExit(f"missing {expected_ip} for user {uid}: {data!r}")
if int(data.get("alive_ip", 0)) != 1:
    raise SystemExit(f"expected alive_ip=1 for user {uid}: {data!r}")
PY
}

wait_for_no_alive_cache() {
  local label="$1"
  local start
  local now
  local json

  start="$(date +%s)"
  while true; do
    json="$(cache_json "ALIVE_IP_USER_${USER_ID}")"
    [[ "${json}" == "null" ]] || e2e_die "${label}: expected no alive cache, got ${json}"
    now="$(date +%s)"
    if ((now - start >= E2E_NO_REPORT_WAIT_SECS)); then
      e2e_log "${label}: no alive cache after ${E2E_NO_REPORT_WAIT_SECS}s"
      return
    fi
    sleep 1
  done
}

wait_for_alive_cache() {
  local label="$1"
  local start
  local now
  local json

  start="$(date +%s)"
  while true; do
    json="$(cache_json "ALIVE_IP_USER_${USER_ID}")"
    if assert_alive_cache_json "${json}" 2>"${TMP_DIR}/thresholds_alive.assert.log"; then
      e2e_log "${label}: alive cache ${json}"
      return
    fi
    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_die "${label}: alive cache did not match; last=${json}; assert=$(cat "${TMP_DIR}/thresholds_alive.assert.log")"
    fi
    sleep 1
  done
}

run_node_report_threshold_case() {
  e2e_section "node_report_min_traffic high threshold"
  reset_runtime_state
  set_v2board_thresholds "${NODE_REPORT_HIGH_THRESHOLD_BYTES}" 0
  start_services
  run_proxy_download
  wait_for_no_accounting "node_report_min_traffic=${NODE_REPORT_HIGH_THRESHOLD_BYTES}"
  stop_services
  assert_no_accounting_now "node_report_min_traffic=${NODE_REPORT_HIGH_THRESHOLD_BYTES} final push"

  e2e_section "node_report_min_traffic flush pending"
  set_v2board_thresholds 0 0
  start_services
  wait_for_accounting_rows "$((E2E_PAYLOAD_KIB * 1024))" "node_report_min_traffic=0 pending flush"
  stop_services
}

run_alive_threshold_case() {
  e2e_section "device_online_min_traffic high threshold"
  reset_runtime_state
  set_v2board_thresholds 0 "${ALIVE_HIGH_THRESHOLD_BYTES}"
  start_services
  start_slow_connection
  wait_for_no_alive_cache "device_online_min_traffic=${ALIVE_HIGH_THRESHOLD_BYTES}"
  stop_slow_connection
  stop_services

  e2e_section "device_online_min_traffic nonzero threshold"
  reset_runtime_state
  set_v2board_thresholds 0 "${ALIVE_PASS_THRESHOLD_BYTES}"
  start_services
  start_slow_connection
  wait_for_alive_cache "device_online_min_traffic=${ALIVE_PASS_THRESHOLD_BYTES}"
  stop_slow_connection
  stop_services
}

cleanup_fixtures() {
  if e2e_env_bool E2E_KEEP_FIXTURES 1; then
    e2e_log "keeping thresholds E2E fixtures"
    return
  fi

  e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
  mysql_exec <<SQL
DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
DELETE FROM v2_user WHERE email='shoes-thresholds@example.local';
DELETE FROM v2_server_vmess WHERE name='shoes-thresholds';
DELETE FROM v2_server_group WHERE name='shoes-thresholds';
SQL

  e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
  mysql_exec <<SQL
DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
SQL
  clear_status_cache
}

main() {
  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-thresholds-e2e.XXXXXX)"

  check_environment
  resolve_binaries
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"
  backup_v2board_config
  write_configs
  start_http_target
  seed_fixture
  run_node_report_threshold_case
  run_alive_threshold_case
  cleanup_fixtures
  e2e_section "done"
}

main "$@"
