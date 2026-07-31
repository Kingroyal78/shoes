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
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18114}"
E2E_NODE_PORT="${E2E_NODE_PORT:-18199}"
E2E_PROXY_PORT="${E2E_PROXY_PORT:-18299}"
E2E_TRIGGER_PAYLOAD_KIB="${E2E_TRIGGER_PAYLOAD_KIB:-12288}"
E2E_LIMIT_PAYLOAD_KIB="${E2E_LIMIT_PAYLOAD_KIB:-2048}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-2}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-2}"
E2E_WAIT_TIMEOUT_SECS="${E2E_WAIT_TIMEOUT_SECS:-75}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_CURL_CONNECT_TIMEOUT_SECS="${E2E_CURL_CONNECT_TIMEOUT_SECS:-3}"
E2E_CURL_MAX_TIME_SECS="${E2E_CURL_MAX_TIME_SECS:-90}"
E2E_V2BOARD_CONFIG_RELOAD_DELAY_SECS="${E2E_V2BOARD_CONFIG_RELOAD_DELAY_SECS:-3}"

GROUP_ID=9915
NODE_ID=9915
USER_ID=19915
USER_UUID=99999999-9999-4999-8999-999999999915
USER_DYNAMIC_SPEED=1
DYNAMIC_WINDOW_MINUTES=60
DYNAMIC_THRESHOLD_GB=0.01

TMP_DIR=""
HTTP_PID=""
SHOES_PID=""
SINGLINK_PID=""
SERVER_TOKEN=""
V2BOARD_CONFIG_BACKUP=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_dynamic_speed_trigger.sh

Runs a production-path V2Board dynamic speed E2E check:
  - global dynamic speed is enabled in config/v2board.php
  - shoes reports real proxy traffic to /UniProxy/push
  - V2Board queue + traffic:update records the dynamic traffic bucket
  - /UniProxy/user returns the lower effective speed_limit
  - the same shoes process hot-syncs that user change and throttles a new connection

The script temporarily edits config/v2board.php and restores the original file
on exit.
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

now_ms() {
  python3 -c 'import time; print(int(time.monotonic() * 1000))'
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

api_url() {
  printf '%s/api/v1/server/UniProxy/user?token=%s&node_type=vmess&node_id=%s' \
    "${V2BOARD_PANEL_URL}" \
    "${SERVER_TOKEN}" \
    "${NODE_ID}"
}

clear_laravel_config() {
  docker exec "${V2BOARD_WWW_CONTAINER}" php artisan config:clear >/dev/null
  sleep "${E2E_V2BOARD_CONFIG_RELOAD_DELAY_SECS}"
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

read_dynamic_speed_config() {
  docker exec "${V2BOARD_WWW_CONTAINER}" \
    php artisan tinker --execute='echo json_encode((new \App\Services\DynamicSpeedLimitService())->getConfig());' \
    2>/dev/null
}

set_global_dynamic_speed_config() {
  local actual

  e2e_section "enable global dynamic speed"
  backup_v2board_config
  docker exec \
    -e SHOES_E2E_DYNAMIC_WINDOW="${DYNAMIC_WINDOW_MINUTES}" \
    -e SHOES_E2E_DYNAMIC_THRESHOLD="${DYNAMIC_THRESHOLD_GB}" \
    -e SHOES_E2E_DYNAMIC_SPEED="${USER_DYNAMIC_SPEED}" \
    "${V2BOARD_WWW_CONTAINER}" \
    php artisan tinker --execute='(new \App\Services\DynamicSpeedLimitService())->saveConfig(["enable" => 1, "window_minutes" => (int)getenv("SHOES_E2E_DYNAMIC_WINDOW"), "threshold_gb" => (float)getenv("SHOES_E2E_DYNAMIC_THRESHOLD"), "speed_mbps" => (int)getenv("SHOES_E2E_DYNAMIC_SPEED"), "tiers" => [["window_minutes" => (int)getenv("SHOES_E2E_DYNAMIC_WINDOW"), "threshold_gb" => (float)getenv("SHOES_E2E_DYNAMIC_THRESHOLD"), "speed_mbps" => (int)getenv("SHOES_E2E_DYNAMIC_SPEED")]]]);' \
    >/dev/null
  clear_laravel_config
  actual="$(read_dynamic_speed_config)"
  DYNAMIC_CONFIG_JSON="${actual}" python3 - "${USER_DYNAMIC_SPEED}" "${DYNAMIC_THRESHOLD_GB}" <<'PY'
import json
import os
import sys

expected_speed = int(sys.argv[1])
expected_threshold = float(sys.argv[2])
data = json.loads(os.environ["DYNAMIC_CONFIG_JSON"])
if int(data.get("enable", 0)) != 1:
    raise SystemExit(f"dynamic speed config not enabled: {data!r}")
tiers = data.get("tiers") or []
if not tiers:
    raise SystemExit(f"dynamic speed tiers missing: {data!r}")
tier = tiers[0]
if int(tier.get("speed_mbps", -1)) != expected_speed:
    raise SystemExit(f"expected tier speed {expected_speed}, got {tier!r}")
if abs(float(tier.get("threshold_gb", -1)) - expected_threshold) > 0.000001:
    raise SystemExit(f"expected tier threshold {expected_threshold}, got {tier!r}")
PY
  e2e_log "global dynamic speed threshold=${DYNAMIC_THRESHOLD_GB}GB speed=${USER_DYNAMIC_SPEED}Mbps"
}

clear_dynamic_speed_state() {
  local key_prefix

  for key_prefix in "" "v2board_database_"; do
    docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli HDEL "${key_prefix}dynamic_speed_limit:limited_users" "${USER_ID}" >/dev/null
    docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli ZREM "${key_prefix}dynamic_speed_limit:traffic_users_v2" "${USER_ID}" >/dev/null
    docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli SREM "${key_prefix}dynamic_speed_limit:traffic_users" "${USER_ID}" >/dev/null
    docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli DEL \
      "${key_prefix}dynamic_speed_limit:user:${USER_ID}" \
      "${key_prefix}dynamic_speed_limit:traffic:${USER_ID}" \
      >/dev/null
  done
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
(${GROUP_ID}, 'shoes-dynamic-speed-trigger', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  updated_at=VALUES(updated_at);

INSERT INTO v2_server_vmess
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tags, rate, network, rules, networkSettings, tlsSettings, ruleSettings, dnsSettings, \`show\`, sort, created_at, updated_at)
VALUES
(${NODE_ID}, '["${GROUP_ID}"]', NULL, 'shoes-dynamic-speed-trigger', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_NODE_PORT}', ${E2E_NODE_PORT}, 0, NULL, '1', 'tcp', NULL, '{}', '{}', '{}', '{}', 1, ${NODE_ID}, ${now}, ${now})
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
(${USER_ID}, NULL, NULL, 'shoes-dynamic-speed-trigger@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '${USER_UUID}', ${GROUP_ID}, NULL, NULL, 0, 1, 1, MD5('shoes-dynamic-speed-trigger@example.local'), ${expires_at}, 'shoes dynamic speed trigger e2e', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
  group_id=${GROUP_ID},
  plan_id=NULL,
  speed_limit=NULL,
  device_limit=NULL,
  expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);

DELETE FROM v2_dynamic_speed_limit_user_rule WHERE user_id=${USER_ID};
DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
  clear_dynamic_speed_state
}

assert_uniproxy_speed() {
  local expected="$1"
  local label="$2"

  curl -fsS --max-time 5 "$(api_url)" -o "${TMP_DIR}/user-${label}.json"
  python3 - "${TMP_DIR}/user-${label}.json" "${USER_ID}" "${expected}" <<'PY'
import json
import sys

path = sys.argv[1]
uid = int(sys.argv[2])
expected = sys.argv[3]
with open(path, "rb") as fh:
    data = json.load(fh)
users = data.get("users")
if not isinstance(users, list):
    raise SystemExit(f"users missing: {data!r}")
matches = [user for user in users if int(user.get("id", -1)) == uid]
if len(matches) != 1:
    raise SystemExit(f"expected one user {uid}, got {users!r}")
speed = matches[0].get("speed_limit")
if expected == "null":
    if speed is not None:
        raise SystemExit(f"expected no effective speed_limit, got {speed!r}")
else:
    if int(speed) != int(expected):
        raise SystemExit(f"expected effective speed_limit={expected}, got {speed!r}")
PY
}

write_configs() {
  cat >"${TMP_DIR}/dynamic_speed_trigger.shoes.yml" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${SERVER_TOKEN}"
  nodes:
    - tag: "dynamic_speed_trigger"
      node_id: ${NODE_ID}
      node_type: "vmess"
      listen: "${E2E_BIND_HOST}"
      pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
      push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
runtime:
  data_dir: "${TMP_DIR}/dynamic-speed-trigger-shoes-data"
  pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
  push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
  node_report_min_traffic: 0
  device_online_min_traffic: 0
log:
  level: "debug"
YAML

  cat >"${TMP_DIR}/dynamic_speed_trigger.singlink.json" <<JSON
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

start_http_target() {
  e2e_section "start dynamic-speed-trigger http target"
  e2e_assert_port_free "${E2E_HTTP_PORT}" "dynamic-speed-trigger http target"
  mkdir -p "${TMP_DIR}/http-root"
  dd if=/dev/zero of="${TMP_DIR}/http-root/trigger.bin" bs=1024 count="${E2E_TRIGGER_PAYLOAD_KIB}" status=none
  dd if=/dev/zero of="${TMP_DIR}/http-root/limited.bin" bs=1024 count="${E2E_LIMIT_PAYLOAD_KIB}" status=none
  python3 -m http.server "${E2E_HTTP_PORT}" \
    --bind "${E2E_BIND_HOST}" \
    --directory "${TMP_DIR}/http-root" \
    >"${TMP_DIR}/http.log" 2>&1 &
  HTTP_PID=$!
  wait_for_listen_port "${E2E_HTTP_PORT}" "dynamic-speed-trigger http target" 10
}

start_services() {
  "${SHOES_BIN}" sync-once -c "${TMP_DIR}/dynamic_speed_trigger.shoes.yml" >"${TMP_DIR}/dynamic_speed_trigger.sync.log" 2>&1
  e2e_assert_port_free "${E2E_NODE_PORT}" "dynamic-speed-trigger shoes"
  "${SHOES_BIN}" run -c "${TMP_DIR}/dynamic_speed_trigger.shoes.yml" >"${TMP_DIR}/dynamic_speed_trigger.shoes.log" 2>&1 &
  SHOES_PID=$!
  wait_for_listen_port "${E2E_NODE_PORT}" "dynamic-speed-trigger shoes" 15

  "${SINGLINK_BIN}" -c "${TMP_DIR}/dynamic_speed_trigger.singlink.json" check >"${TMP_DIR}/dynamic_speed_trigger.singlink-check.log" 2>&1
  e2e_assert_port_free "${E2E_PROXY_PORT}" "dynamic-speed-trigger singlink"
  "${SINGLINK_BIN}" -c "${TMP_DIR}/dynamic_speed_trigger.singlink.json" run >"${TMP_DIR}/dynamic_speed_trigger.singlink.log" 2>&1 &
  SINGLINK_PID=$!
  wait_for_listen_port "${E2E_PROXY_PORT}" "dynamic-speed-trigger singlink" 15
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

download_via_proxy() {
  local path="$1"
  local output="$2"

  curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${E2E_PROXY_PORT}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/${path}" \
    -o "${output}"
}

generate_trigger_traffic() {
  local expected_size

  e2e_section "generate threshold traffic"
  expected_size="$((E2E_TRIGGER_PAYLOAD_KIB * 1024))"
  download_via_proxy "trigger.bin" "${TMP_DIR}/trigger.bin"
  [[ "$(wc -c <"${TMP_DIR}/trigger.bin")" -eq "${expected_size}" ]] \
    || e2e_die "dynamic trigger download size mismatch"
  e2e_log "downloaded ${expected_size} bytes to exceed ${DYNAMIC_THRESHOLD_GB}GB dynamic threshold"
}

wait_for_dynamic_limit() {
  local start
  local now

  e2e_section "wait for traffic:update dynamic limit"
  start="$(date +%s)"
  while true; do
    e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"
    docker exec "${V2BOARD_WWW_CONTAINER}" php artisan traffic:update >/dev/null
    if assert_uniproxy_speed "${USER_DYNAMIC_SPEED}" "limited" 2>"${TMP_DIR}/speed-check.err"; then
      e2e_log "V2Board returned dynamic effective speed_limit=${USER_DYNAMIC_SPEED}"
      return
    fi

    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_warn "last speed check error: $(cat "${TMP_DIR}/speed-check.err")"
      e2e_die "dynamic speed limit did not trigger within ${E2E_WAIT_TIMEOUT_SECS}s"
    fi
    sleep 1
  done
}

wait_for_shoes_user_sync() {
  local wait_secs

  e2e_section "wait for shoes hot sync"
  wait_secs="$((E2E_PULL_INTERVAL_SECS * 3))"
  if ((wait_secs < 5)); then
    wait_secs=5
  fi
  sleep "${wait_secs}"
}

assert_dynamic_speed_enforced() {
  local expected_size
  local start
  local end
  local elapsed_ms

  e2e_section "dynamic speed enforcement after hot sync"
  expected_size="$((E2E_LIMIT_PAYLOAD_KIB * 1024))"
  start="$(now_ms)"
  download_via_proxy "limited.bin" "${TMP_DIR}/limited.bin"
  end="$(now_ms)"
  elapsed_ms="$((end - start))"

  [[ "$(wc -c <"${TMP_DIR}/limited.bin")" -eq "${expected_size}" ]] \
    || e2e_die "dynamic limited download size mismatch"
  ((elapsed_ms >= 10000)) \
    || e2e_die "dynamic traffic-triggered limit did not throttle enough: elapsed ${elapsed_ms}ms, expected >= 10000ms"
  e2e_log "dynamic traffic-triggered limit elapsed=${elapsed_ms}ms"
}

cleanup_fixtures() {
  if e2e_env_bool E2E_KEEP_FIXTURES 1; then
    e2e_log "keeping dynamic-speed-trigger E2E fixtures"
    return
  fi

  mysql_exec <<SQL
DELETE FROM v2_dynamic_speed_limit_user_rule WHERE user_id=${USER_ID};
DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
DELETE FROM v2_user WHERE email='shoes-dynamic-speed-trigger@example.local';
DELETE FROM v2_server_vmess WHERE name='shoes-dynamic-speed-trigger';
DELETE FROM v2_server_group WHERE name='shoes-dynamic-speed-trigger';
SQL
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
  clear_dynamic_speed_state
}

main() {
  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-dynamic-speed-trigger-e2e.XXXXXX)"

  check_environment
  resolve_binaries
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"
  set_global_dynamic_speed_config
  seed_fixture
  assert_uniproxy_speed "null" "initial"
  write_configs
  start_http_target
  start_services
  generate_trigger_traffic
  wait_for_dynamic_limit
  wait_for_shoes_user_sync
  assert_dynamic_speed_enforced
  cleanup_fixtures
  e2e_section "done"
}

main "$@"
