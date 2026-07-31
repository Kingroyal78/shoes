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
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18112}"
E2E_NODE_PORT="${E2E_NODE_PORT:-18197}"
E2E_PROXY_PORT="${E2E_PROXY_PORT:-18297}"
E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB:-128}"
E2E_INITIAL_PULL_INTERVAL="${E2E_INITIAL_PULL_INTERVAL:-2}"
E2E_INITIAL_PUSH_INTERVAL="${E2E_INITIAL_PUSH_INTERVAL:-30}"
E2E_UPDATED_PULL_INTERVAL="${E2E_UPDATED_PULL_INTERVAL:-4}"
E2E_UPDATED_PUSH_INTERVAL="${E2E_UPDATED_PUSH_INTERVAL:-2}"
E2E_NO_REPORT_WAIT_SECS="${E2E_NO_REPORT_WAIT_SECS:-8}"
E2E_WAIT_TIMEOUT_SECS="${E2E_WAIT_TIMEOUT_SECS:-45}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_CURL_CONNECT_TIMEOUT_SECS="${E2E_CURL_CONNECT_TIMEOUT_SECS:-3}"
E2E_CURL_MAX_TIME_SECS="${E2E_CURL_MAX_TIME_SECS:-20}"

GROUP_ID=9912
NODE_ID=9912
USER_ID=19912
USER_UUID=99999999-9999-4999-8999-999999999912

TMP_DIR=""
HTTP_PID=""
SHOES_PID=""
SINGLINK_PID=""
SERVER_TOKEN=""
V2BOARD_CONFIG_BACKUP=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_base_config_hot_update.sh

Runs a real V2Board base_config hot-update E2E check:
  - shoes starts with panel pull_interval=2 and push_interval=30
  - traffic remains pending while push_interval is high
  - panel changes to pull_interval=4 and push_interval=2 without restarting shoes
  - the same shoes process syncs the new base_config, logs interval changes, and flushes traffic
EOF
}

cleanup() {
  local status=$?
  set +e
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

set_v2board_base_config() {
  local pull_interval="$1"
  local push_interval="$2"
  local actual_pull
  local actual_push

  docker exec -i \
    -e SHOES_E2E_PULL_INTERVAL="${pull_interval}" \
    -e SHOES_E2E_PUSH_INTERVAL="${push_interval}" \
    "${V2BOARD_WWW_CONTAINER}" \
    php <<'PHP'
<?php
$path = '/www/config/v2board.php';
$updates = [
    'server_pull_interval' => (int)getenv('SHOES_E2E_PULL_INTERVAL'),
    'server_push_interval' => (int)getenv('SHOES_E2E_PUSH_INTERVAL'),
    'server_node_report_min_traffic' => 0,
    'server_device_online_min_traffic' => 0,
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
  actual_pull="$(read_v2board_config_int server_pull_interval)"
  actual_push="$(read_v2board_config_int server_push_interval)"
  [[ "${actual_pull}" == "${pull_interval}" ]] \
    || e2e_die "V2Board server_pull_interval expected ${pull_interval}, got ${actual_pull}"
  [[ "${actual_push}" == "${push_interval}" ]] \
    || e2e_die "V2Board server_push_interval expected ${push_interval}, got ${actual_push}"
  wait_for_uniproxy_base_config "${pull_interval}" "${push_interval}"
}

wait_for_uniproxy_base_config() {
  local expected_pull="$1"
  local expected_push="$2"
  local start
  local now
  local body

  start="$(date +%s)"
  while true; do
    body="$(curl -fsS \
      --max-time 5 \
      "${V2BOARD_PANEL_URL%/}/api/v1/server/UniProxy/config?token=${SERVER_TOKEN}&node_id=${NODE_ID}&node_type=vmess")"
    if BODY="${body}" python3 - "${expected_pull}" "${expected_push}" <<'PY'
import json
import os
import sys

expected_pull = int(sys.argv[1])
expected_push = int(sys.argv[2])
data = json.loads(os.environ["BODY"])
base = data.get("base_config") or {}
if base.get("pull_interval") != expected_pull:
    raise SystemExit(1)
if base.get("push_interval") != expected_push:
    raise SystemExit(1)
PY
    then
      e2e_log "UniProxy base_config pull=${expected_pull} push=${expected_push}"
      return
    fi
    now="$(date +%s)"
    if ((now - start >= 15)); then
      e2e_die "UniProxy base_config did not become pull=${expected_pull} push=${expected_push}; last=${body}"
    fi
    sleep 1
  done
}

reset_accounting_rows() {
  mysql_exec <<SQL
UPDATE v2_user SET u=0, d=0, t=0 WHERE id=${USER_ID};
DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
SQL
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
}

start_http_target() {
  e2e_section "start base_config http target"
  e2e_assert_port_free "${E2E_HTTP_PORT}" "base_config http target"
  mkdir -p "${TMP_DIR}/http-root"
  dd if=/dev/zero of="${TMP_DIR}/http-root/payload.bin" bs=1024 count="${E2E_PAYLOAD_KIB}" status=none

  python3 -m http.server "${E2E_HTTP_PORT}" \
    --bind "${E2E_BIND_HOST}" \
    --directory "${TMP_DIR}/http-root" \
    >"${TMP_DIR}/http.log" 2>&1 &
  HTTP_PID=$!
  wait_for_listen_port "${E2E_HTTP_PORT}" "base_config http target" 10
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
(${GROUP_ID}, 'shoes-base-config-hot-update', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  updated_at=VALUES(updated_at);

INSERT INTO v2_server_vmess
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tags, rate, network, rules, networkSettings, tlsSettings, ruleSettings, dnsSettings, \`show\`, sort, created_at, updated_at)
VALUES
(${NODE_ID}, '["${GROUP_ID}"]', NULL, 'shoes-base-config-hot-update', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_NODE_PORT}', ${E2E_NODE_PORT}, 0, NULL, '1', 'tcp', NULL, '{}', '{}', '{}', '{}', 1, ${NODE_ID}, ${now}, ${now})
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
(${USER_ID}, NULL, NULL, 'shoes-base-config-hot-update@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '${USER_UUID}', ${GROUP_ID}, NULL, NULL, 0, 1, 1, MD5('shoes-base-config-hot-update@example.local'), ${expires_at}, 'shoes base_config hot update e2e', ${now}, ${now})
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
SQL

  reset_accounting_rows
}

write_configs() {
  cat >"${TMP_DIR}/base-config.shoes.yml" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${SERVER_TOKEN}"
  nodes:
    - tag: "base_config_hot_update"
      node_id: ${NODE_ID}
      node_type: "vmess"
      listen: "${E2E_BIND_HOST}"
runtime:
  data_dir: "${TMP_DIR}/base-config-shoes-data"
  pull_interval_secs: 60
  push_interval_secs: 60
  node_report_min_traffic: 0
  device_online_min_traffic: 0
log:
  level: "debug"
YAML

  cat >"${TMP_DIR}/base-config.singlink.json" <<JSON
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
  "${SHOES_BIN}" sync-once -c "${TMP_DIR}/base-config.shoes.yml" >"${TMP_DIR}/base-config.sync.log" 2>&1
  e2e_assert_port_free "${E2E_NODE_PORT}" "base_config shoes"
  "${SHOES_BIN}" run -c "${TMP_DIR}/base-config.shoes.yml" >"${TMP_DIR}/base-config.shoes.log" 2>&1 &
  SHOES_PID=$!
  wait_for_listen_port "${E2E_NODE_PORT}" "base_config shoes" 15

  "${SINGLINK_BIN}" -c "${TMP_DIR}/base-config.singlink.json" check >"${TMP_DIR}/base-config.singlink-check.log" 2>&1
  e2e_assert_port_free "${E2E_PROXY_PORT}" "base_config singlink"
  "${SINGLINK_BIN}" -c "${TMP_DIR}/base-config.singlink.json" run >"${TMP_DIR}/base-config.singlink.log" 2>&1 &
  SINGLINK_PID=$!
  wait_for_listen_port "${E2E_PROXY_PORT}" "base_config singlink" 15
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
  local start
  local now

  start="$(date +%s)"
  while true; do
    assert_no_accounting_now "base_config push_interval=${E2E_INITIAL_PUSH_INTERVAL}"
    now="$(date +%s)"
    if ((now - start >= E2E_NO_REPORT_WAIT_SECS)); then
      e2e_log "no accounting rows after ${E2E_NO_REPORT_WAIT_SECS}s with push_interval=${E2E_INITIAL_PUSH_INTERVAL}"
      return
    fi
    sleep 1
  done
}

wait_for_accounting_rows() {
  local expected_payload="$1"
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
        e2e_log "base_config hot update flushed traffic: user=${user_u}/${user_d} stat_user=${stat_user_u}/${stat_user_d} stat_server=${stat_server_u}/${stat_server_d}"
        return
      fi
    fi

    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_die "accounting did not reach expected payload ${expected_payload}; last=${row:-<empty>}"
    fi
    sleep 1
  done
}

wait_for_log_line() {
  local pattern="$1"
  local label="$2"
  local start
  local now

  start="$(date +%s)"
  while true; do
    if grep -Fq "${pattern}" "${TMP_DIR}/base-config.shoes.log"; then
      e2e_log "${label}: ${pattern}"
      return
    fi
    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_die "${label}: log did not contain ${pattern}"
    fi
    sleep 1
  done
}

run_hot_update_case() {
  e2e_section "initial slow push interval"
  set_v2board_base_config "${E2E_INITIAL_PULL_INTERVAL}" "${E2E_INITIAL_PUSH_INTERVAL}"
  start_services
  run_proxy_download
  wait_for_no_accounting

  e2e_section "update base_config without shoes restart"
  set_v2board_base_config "${E2E_UPDATED_PULL_INTERVAL}" "${E2E_UPDATED_PUSH_INTERVAL}"
  wait_for_log_line \
    "node \`base_config_hot_update\` pull interval changed from ${E2E_INITIAL_PULL_INTERVAL}s to ${E2E_UPDATED_PULL_INTERVAL}s" \
    "pull interval hot update"
  wait_for_log_line \
    "node \`base_config_hot_update\` push interval changed from ${E2E_INITIAL_PUSH_INTERVAL}s to ${E2E_UPDATED_PUSH_INTERVAL}s" \
    "push interval hot update"
  wait_for_accounting_rows "$((E2E_PAYLOAD_KIB * 1024))"
}

cleanup_fixtures() {
  if e2e_env_bool E2E_KEEP_FIXTURES 1; then
    e2e_log "keeping base_config hot update E2E fixtures"
    return
  fi

  mysql_exec <<SQL
DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
DELETE FROM v2_user WHERE email='shoes-base-config-hot-update@example.local';
DELETE FROM v2_server_vmess WHERE name='shoes-base-config-hot-update';
DELETE FROM v2_server_group WHERE name='shoes-base-config-hot-update';
SQL
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
}

main() {
  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-base-config-e2e.XXXXXX)"

  check_environment
  resolve_binaries
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"
  backup_v2board_config
  write_configs
  start_http_target
  seed_fixture
  run_hot_update_case
  stop_services
  cleanup_fixtures
  e2e_section "done"
}

main "$@"
