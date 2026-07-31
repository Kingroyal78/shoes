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
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18115}"
E2E_NODE_PORT="${E2E_NODE_PORT:-18198}"
E2E_PROXY_PORT="${E2E_PROXY_PORT:-18298}"
E2E_LIMIT_PAYLOAD_KIB="${E2E_LIMIT_PAYLOAD_KIB:-1024}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_CURL_CONNECT_TIMEOUT_SECS="${E2E_CURL_CONNECT_TIMEOUT_SECS:-3}"
E2E_CURL_MAX_TIME_SECS="${E2E_CURL_MAX_TIME_SECS:-60}"
E2E_V2BOARD_CONFIG_RELOAD_DELAY_SECS="${E2E_V2BOARD_CONFIG_RELOAD_DELAY_SECS:-3}"

GROUP_ID=9916
NODE_ID=9916
PLAN_ID=9916
GLOBAL_USER_ID=19916
PLAN_USER_ID=19917
WHITELIST_USER_ID=19918
DIRECT_USER_ID=19919
GLOBAL_USER_UUID=99999999-9999-4999-8999-999999999916
PLAN_USER_UUID=99999999-9999-4999-8999-999999999917
WHITELIST_USER_UUID=99999999-9999-4999-8999-999999999918
DIRECT_USER_UUID=99999999-9999-4999-8999-999999999919
DYNAMIC_WINDOW_MINUTES=60
DYNAMIC_THRESHOLD_GB=0.01
GLOBAL_DYNAMIC_SPEED=4
PLAN_DYNAMIC_SPEED=1
DIRECT_DYNAMIC_SPEED=2
ORIGINAL_SPEED=20
DYNAMIC_TRAFFIC_BYTES=$((12 * 1024 * 1024))

TMP_DIR=""
HTTP_PID=""
SHOES_PID=""
SINGLINK_PID=""
SERVER_TOKEN=""
V2BOARD_CONFIG_BACKUP=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_dynamic_speed_rules.sh

Runs a production-oriented V2Board dynamic speed rule priority check:
  - global dynamic rule limits inherited users
  - enabled plan rule overrides the global dynamic rule
  - user whitelist bypasses dynamic speed limits
  - user direct_limit overrides inherited dynamic rules
  - shoes consumes the plan-rule effective speed_limit and enforces it

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
    -e SHOES_E2E_DYNAMIC_SPEED="${GLOBAL_DYNAMIC_SPEED}" \
    "${V2BOARD_WWW_CONTAINER}" \
    php artisan tinker --execute='(new \App\Services\DynamicSpeedLimitService())->saveConfig(["enable" => 1, "window_minutes" => (int)getenv("SHOES_E2E_DYNAMIC_WINDOW"), "threshold_gb" => (float)getenv("SHOES_E2E_DYNAMIC_THRESHOLD"), "speed_mbps" => (int)getenv("SHOES_E2E_DYNAMIC_SPEED"), "tiers" => [["window_minutes" => (int)getenv("SHOES_E2E_DYNAMIC_WINDOW"), "threshold_gb" => (float)getenv("SHOES_E2E_DYNAMIC_THRESHOLD"), "speed_mbps" => (int)getenv("SHOES_E2E_DYNAMIC_SPEED")]]]);' \
    >/dev/null
  clear_laravel_config
  actual="$(read_dynamic_speed_config)"
  printf '%s\n' "${actual}" >"${TMP_DIR}/dynamic-speed-config.json"
  DYNAMIC_CONFIG_JSON="${actual}" python3 - "${GLOBAL_DYNAMIC_SPEED}" "${DYNAMIC_THRESHOLD_GB}" <<'PY'
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
    raise SystemExit(f"expected global speed {expected_speed}, got {tier!r}")
if abs(float(tier.get("threshold_gb", -1)) - expected_threshold) > 0.000001:
    raise SystemExit(f"expected global threshold {expected_threshold}, got {tier!r}")
PY
  e2e_log "global dynamic speed threshold=${DYNAMIC_THRESHOLD_GB}GB speed=${GLOBAL_DYNAMIC_SPEED}Mbps"
}

clear_dynamic_speed_state() {
  local key_prefix
  local user_id

  for user_id in "${GLOBAL_USER_ID}" "${PLAN_USER_ID}" "${WHITELIST_USER_ID}" "${DIRECT_USER_ID}"; do
    for key_prefix in "" "v2board_database_"; do
      docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli HDEL "${key_prefix}dynamic_speed_limit:limited_users" "${user_id}" >/dev/null
      docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli ZREM "${key_prefix}dynamic_speed_limit:traffic_users_v2" "${user_id}" >/dev/null
      docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli SREM "${key_prefix}dynamic_speed_limit:traffic_users" "${user_id}" >/dev/null
      docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli DEL \
        "${key_prefix}dynamic_speed_limit:user:${user_id}" \
        "${key_prefix}dynamic_speed_limit:traffic:${user_id}" \
        >/dev/null
    done
    e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${user_id}"
  done
}

seed_fixture() {
  local now
  local expires_at
  local tiers_json

  now="$(date +%s)"
  expires_at="$((now + 86400))"
  tiers_json='[{"window_minutes":60,"threshold_gb":0.01,"speed_mbps":1}]'

  mysql_exec <<SQL
INSERT INTO v2_server_group
(id, name, created_at, updated_at)
VALUES
(${GROUP_ID}, 'shoes-dynamic-speed-rules', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  updated_at=VALUES(updated_at);

INSERT INTO v2_plan
(id, group_id, transfer_enable, device_limit, name, speed_limit, \`show\`, sort, renew, content, month_price, quarter_price, half_year_price, year_price, two_year_price, three_year_price, onetime_price, reset_price, reset_traffic_method, capacity_limit, created_at, updated_at)
VALUES
(${PLAN_ID}, ${GROUP_ID}, 1073741824, NULL, 'shoes-dynamic-speed-rules-plan', NULL, 1, ${PLAN_ID}, 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  transfer_enable=VALUES(transfer_enable),
  name=VALUES(name),
  speed_limit=NULL,
  updated_at=VALUES(updated_at);

INSERT INTO v2_dynamic_speed_limit_plan_rule
(plan_id, enable, window_minutes, threshold_gb, speed_mbps, tiers, created_at, updated_at)
VALUES
(${PLAN_ID}, 1, ${DYNAMIC_WINDOW_MINUTES}, ${DYNAMIC_THRESHOLD_GB}, ${PLAN_DYNAMIC_SPEED}, '${tiers_json}', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  enable=VALUES(enable),
  window_minutes=VALUES(window_minutes),
  threshold_gb=VALUES(threshold_gb),
  speed_mbps=VALUES(speed_mbps),
  tiers=VALUES(tiers),
  updated_at=VALUES(updated_at);

INSERT INTO v2_server_vmess
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tags, rate, network, rules, networkSettings, tlsSettings, ruleSettings, dnsSettings, \`show\`, sort, created_at, updated_at)
VALUES
(${NODE_ID}, '["${GROUP_ID}"]', NULL, 'shoes-dynamic-speed-rules', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_NODE_PORT}', ${E2E_NODE_PORT}, 0, NULL, '1', 'tcp', NULL, '{}', '{}', '{}', '{}', 1, ${NODE_ID}, ${now}, ${now})
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
(${GLOBAL_USER_ID}, NULL, NULL, 'shoes-dynamic-speed-global@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '${GLOBAL_USER_UUID}', ${GROUP_ID}, NULL, NULL, 0, 1, 1, MD5('shoes-dynamic-speed-global@example.local'), ${expires_at}, 'shoes dynamic speed global e2e', ${now}, ${now}),
(${PLAN_USER_ID}, NULL, NULL, 'shoes-dynamic-speed-plan@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '${PLAN_USER_UUID}', ${GROUP_ID}, ${PLAN_ID}, NULL, 0, 1, 1, MD5('shoes-dynamic-speed-plan@example.local'), ${expires_at}, 'shoes dynamic speed plan e2e', ${now}, ${now}),
(${WHITELIST_USER_ID}, NULL, NULL, 'shoes-dynamic-speed-whitelist@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '${WHITELIST_USER_UUID}', ${GROUP_ID}, NULL, ${ORIGINAL_SPEED}, 0, 1, 1, MD5('shoes-dynamic-speed-whitelist@example.local'), ${expires_at}, 'shoes dynamic speed whitelist e2e', ${now}, ${now}),
(${DIRECT_USER_ID}, NULL, NULL, 'shoes-dynamic-speed-direct@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '${DIRECT_USER_UUID}', ${GROUP_ID}, ${PLAN_ID}, ${ORIGINAL_SPEED}, 0, 1, 1, MD5('shoes-dynamic-speed-direct@example.local'), ${expires_at}, 'shoes dynamic speed direct e2e', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
  group_id=${GROUP_ID},
  plan_id=VALUES(plan_id),
  speed_limit=VALUES(speed_limit),
  device_limit=NULL,
  expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);

INSERT INTO v2_dynamic_speed_limit_user_rule
(user_id, mode, speed_mbps, remark, created_at, updated_at)
VALUES
(${WHITELIST_USER_ID}, 'whitelist', NULL, 'shoes dynamic speed whitelist e2e', ${now}, ${now}),
(${DIRECT_USER_ID}, 'direct_limit', ${DIRECT_DYNAMIC_SPEED}, 'shoes dynamic speed direct e2e', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  mode=VALUES(mode),
  speed_mbps=VALUES(speed_mbps),
  remark=VALUES(remark),
  updated_at=VALUES(updated_at);

DELETE FROM v2_stat_user WHERE user_id IN (${GLOBAL_USER_ID}, ${PLAN_USER_ID}, ${WHITELIST_USER_ID}, ${DIRECT_USER_ID});
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
SQL

  clear_dynamic_speed_state
}

record_dynamic_traffic() {
  e2e_section "record dynamic speed traffic buckets"
  docker exec -i \
    -e SHOES_E2E_DYNAMIC_USER_IDS="${GLOBAL_USER_ID},${PLAN_USER_ID},${WHITELIST_USER_ID},${DIRECT_USER_ID}" \
    -e SHOES_E2E_DYNAMIC_TRAFFIC_BYTES="${DYNAMIC_TRAFFIC_BYTES}" \
    "${V2BOARD_WWW_CONTAINER}" \
    php <<'PHP'
<?php
require '/www/vendor/autoload.php';
$app = require '/www/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

$ids = array_values(array_filter(array_map('intval', explode(',', (string)getenv('SHOES_E2E_DYNAMIC_USER_IDS')))));
$bytes = (int)getenv('SHOES_E2E_DYNAMIC_TRAFFIC_BYTES');
if (!$ids || $bytes <= 0) {
    fwrite(STDERR, "invalid dynamic traffic inputs\n");
    exit(1);
}

$service = new \App\Services\DynamicSpeedLimitService();
$users = \App\Models\User::whereIn('id', $ids)->get(['id', 'speed_limit', 'plan_id']);
foreach ($users as $user) {
    $service->recordTraffic($user, $bytes, time());
}
PHP
}

assert_dynamic_limited_users_written() {
  local global_payload
  local plan_payload

  global_payload="$(docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli HGET v2board_database_dynamic_speed_limit:limited_users "${GLOBAL_USER_ID}")"
  plan_payload="$(docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli HGET v2board_database_dynamic_speed_limit:limited_users "${PLAN_USER_ID}")"
  if [[ -z "${global_payload}" ]]; then
    global_payload="$(docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli HGET dynamic_speed_limit:limited_users "${GLOBAL_USER_ID}")"
  fi
  if [[ -z "${plan_payload}" ]]; then
    plan_payload="$(docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli HGET dynamic_speed_limit:limited_users "${PLAN_USER_ID}")"
  fi
  [[ -n "${global_payload}" ]] || e2e_die "global dynamic user was not written to dynamic_speed_limit:limited_users"
  [[ -n "${plan_payload}" ]] || e2e_die "plan dynamic user was not written to dynamic_speed_limit:limited_users"
}

assert_uniproxy_speeds() {
  e2e_section "assert UniProxy effective dynamic speeds"
  curl -fsS --max-time 5 "$(api_url)" -o "${TMP_DIR}/users.json"
  python3 - "${TMP_DIR}/users.json" \
    "${GLOBAL_USER_ID}:${GLOBAL_DYNAMIC_SPEED}" \
    "${PLAN_USER_ID}:${PLAN_DYNAMIC_SPEED}" \
    "${WHITELIST_USER_ID}:${ORIGINAL_SPEED}" \
    "${DIRECT_USER_ID}:${DIRECT_DYNAMIC_SPEED}" <<'PY'
import json
import sys

path = sys.argv[1]
expected = {}
for item in sys.argv[2:]:
    uid, speed = item.split(":", 1)
    expected[int(uid)] = int(speed)
with open(path, "rb") as fh:
    data = json.load(fh)
users = data.get("users")
if not isinstance(users, list):
    raise SystemExit(f"users missing: {data!r}")
by_id = {int(user.get("id", -1)): user for user in users}
for uid, speed in expected.items():
    user = by_id.get(uid)
    if user is None:
        raise SystemExit(f"missing user {uid}: {users!r}")
    actual = user.get("speed_limit")
    if actual is None or int(actual) != speed:
        raise SystemExit(f"user {uid} expected speed_limit={speed}, got {actual!r}; payload={user!r}")
PY
  e2e_log "effective speeds: global=${GLOBAL_DYNAMIC_SPEED}, plan=${PLAN_DYNAMIC_SPEED}, whitelist=${ORIGINAL_SPEED}, direct=${DIRECT_DYNAMIC_SPEED}"
}

write_configs() {
  cat >"${TMP_DIR}/dynamic_speed_rules.shoes.yml" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${SERVER_TOKEN}"
  nodes:
    - tag: "dynamic_speed_rules"
      node_id: ${NODE_ID}
      node_type: "vmess"
      listen: "${E2E_BIND_HOST}"
      pull_interval_secs: 2
      push_interval_secs: 2
runtime:
  data_dir: "${TMP_DIR}/dynamic-speed-rules-shoes-data"
  pull_interval_secs: 2
  push_interval_secs: 2
  node_report_min_traffic: 0
  device_online_min_traffic: 0
log:
  level: "debug"
YAML

  cat >"${TMP_DIR}/dynamic_speed_rules.singlink.json" <<JSON
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
      "uuid": "${PLAN_USER_UUID}",
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
  e2e_section "start dynamic-speed-rules http target"
  e2e_assert_port_free "${E2E_HTTP_PORT}" "dynamic-speed-rules http target"
  mkdir -p "${TMP_DIR}/http-root"
  dd if=/dev/zero of="${TMP_DIR}/http-root/limited.bin" bs=1024 count="${E2E_LIMIT_PAYLOAD_KIB}" status=none
  python3 -m http.server "${E2E_HTTP_PORT}" \
    --bind "${E2E_BIND_HOST}" \
    --directory "${TMP_DIR}/http-root" \
    >"${TMP_DIR}/http.log" 2>&1 &
  HTTP_PID=$!
  wait_for_listen_port "${E2E_HTTP_PORT}" "dynamic-speed-rules http target" 10
}

start_services() {
  "${SHOES_BIN}" sync-once -c "${TMP_DIR}/dynamic_speed_rules.shoes.yml" >"${TMP_DIR}/dynamic_speed_rules.sync.log" 2>&1
  e2e_assert_port_free "${E2E_NODE_PORT}" "dynamic-speed-rules shoes"
  "${SHOES_BIN}" run -c "${TMP_DIR}/dynamic_speed_rules.shoes.yml" >"${TMP_DIR}/dynamic_speed_rules.shoes.log" 2>&1 &
  SHOES_PID=$!
  wait_for_listen_port "${E2E_NODE_PORT}" "dynamic-speed-rules shoes" 15

  "${SINGLINK_BIN}" -c "${TMP_DIR}/dynamic_speed_rules.singlink.json" check >"${TMP_DIR}/dynamic_speed_rules.singlink-check.log" 2>&1
  e2e_assert_port_free "${E2E_PROXY_PORT}" "dynamic-speed-rules singlink"
  "${SINGLINK_BIN}" -c "${TMP_DIR}/dynamic_speed_rules.singlink.json" run >"${TMP_DIR}/dynamic_speed_rules.singlink.log" 2>&1 &
  SINGLINK_PID=$!
  wait_for_listen_port "${E2E_PROXY_PORT}" "dynamic-speed-rules singlink" 15
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

assert_plan_speed_enforced() {
  local expected_size
  local start
  local end
  local elapsed_ms

  e2e_section "plan rule speed enforcement"
  expected_size="$((E2E_LIMIT_PAYLOAD_KIB * 1024))"
  start="$(now_ms)"
  curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${E2E_PROXY_PORT}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/limited.bin" \
    -o "${TMP_DIR}/limited.bin"
  end="$(now_ms)"
  elapsed_ms="$((end - start))"

  [[ "$(wc -c <"${TMP_DIR}/limited.bin")" -eq "${expected_size}" ]] \
    || e2e_die "dynamic plan-rule download size mismatch"
  ((elapsed_ms >= 5000)) \
    || e2e_die "dynamic plan-rule speed did not throttle enough: elapsed ${elapsed_ms}ms, expected >= 5000ms"
  e2e_log "dynamic plan-rule limit elapsed=${elapsed_ms}ms"
}

cleanup_fixtures() {
  if e2e_env_bool E2E_KEEP_FIXTURES 1; then
    e2e_log "keeping dynamic-speed-rules E2E fixtures"
    return
  fi

  mysql_exec <<SQL
DELETE FROM v2_dynamic_speed_limit_user_rule WHERE user_id IN (${GLOBAL_USER_ID}, ${PLAN_USER_ID}, ${WHITELIST_USER_ID}, ${DIRECT_USER_ID});
DELETE FROM v2_dynamic_speed_limit_plan_rule WHERE plan_id=${PLAN_ID};
DELETE FROM v2_stat_user WHERE user_id IN (${GLOBAL_USER_ID}, ${PLAN_USER_ID}, ${WHITELIST_USER_ID}, ${DIRECT_USER_ID});
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
DELETE FROM v2_user WHERE email IN ('shoes-dynamic-speed-global@example.local', 'shoes-dynamic-speed-plan@example.local', 'shoes-dynamic-speed-whitelist@example.local', 'shoes-dynamic-speed-direct@example.local');
DELETE FROM v2_plan WHERE name='shoes-dynamic-speed-rules-plan';
DELETE FROM v2_server_vmess WHERE name='shoes-dynamic-speed-rules';
DELETE FROM v2_server_group WHERE name='shoes-dynamic-speed-rules';
SQL
  clear_dynamic_speed_state
}

main() {
  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-dynamic-speed-rules-e2e.XXXXXX)"

  check_environment
  resolve_binaries
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"
  set_global_dynamic_speed_config
  seed_fixture
  record_dynamic_traffic
  assert_dynamic_limited_users_written
  assert_uniproxy_speeds
  write_configs
  start_http_target
  start_services
  assert_plan_speed_enforced
  cleanup_fixtures
  e2e_section "done"
}

main "$@"
