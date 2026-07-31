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
V2BOARD_MYSQL_USER="${V2BOARD_MYSQL_USER:-root}"
V2BOARD_MYSQL_PASSWORD="${V2BOARD_MYSQL_PASSWORD:-v2boardisbest}"
V2BOARD_MYSQL_DATABASE="${V2BOARD_MYSQL_DATABASE:-v2board}"
V2BOARD_REDIS_CONTAINER="${V2BOARD_REDIS_CONTAINER:-v2board-docker-redis-1}"

SING_BOX_DIR="${SING_BOX_DIR:-${ROOT_DIR}/../sing-box}"
SINGLINK_BIN="${SINGLINK_BIN:-}"
SHOES_BIN="${SHOES_BIN:-}"

E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18104}"
E2E_NODE_PORT="${E2E_NODE_PORT:-18193}"
E2E_PROXY_PORT="${E2E_PROXY_PORT:-18293}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-2}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-2}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_CURL_CONNECT_TIMEOUT_SECS="${E2E_CURL_CONNECT_TIMEOUT_SECS:-3}"
E2E_CURL_MAX_TIME_SECS="${E2E_CURL_MAX_TIME_SECS:-60}"

GROUP_ID=9908
NODE_ID=9908
USER_ID=19908
USER_UUID=99999999-9999-4999-8999-999999999908
USER_ORIGINAL_SPEED=20
USER_DYNAMIC_SPEED=1

TMP_DIR=""
HTTP_PID=""
SHOES_PID=""
SINGLINK_PID=""
SERVER_TOKEN=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_dynamic_speed.sh

Runs a real V2Board dynamic speed E2E check:
  - user table speed_limit is high
  - v2_dynamic_speed_limit_user_rule direct_limit lowers effective speed_limit
  - /UniProxy/user returns the effective limit
  - shoes enforces the effective limit during proxy traffic
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

seed_fixture() {
  local now
  local expires_at

  now="$(date +%s)"
  expires_at="$((now + 86400))"

  mysql_exec <<SQL
INSERT INTO v2_server_group
(id, name, created_at, updated_at)
VALUES
(${GROUP_ID}, 'shoes-dynamic-speed', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  updated_at=VALUES(updated_at);

INSERT INTO v2_server_vmess
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tags, rate, network, rules, networkSettings, tlsSettings, ruleSettings, dnsSettings, \`show\`, sort, created_at, updated_at)
VALUES
(${NODE_ID}, '["${GROUP_ID}"]', NULL, 'shoes-dynamic-speed', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_NODE_PORT}', ${E2E_NODE_PORT}, 0, NULL, '1', 'tcp', NULL, '{}', '{}', '{}', '{}', 1, ${NODE_ID}, ${now}, ${now})
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
(${USER_ID}, NULL, NULL, 'shoes-dynamic-speed@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '${USER_UUID}', ${GROUP_ID}, NULL, ${USER_ORIGINAL_SPEED}, 0, 1, 1, MD5('shoes-dynamic-speed@example.local'), ${expires_at}, 'shoes dynamic speed e2e', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
  group_id=${GROUP_ID},
  speed_limit=${USER_ORIGINAL_SPEED},
  device_limit=NULL,
  expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);

INSERT INTO v2_dynamic_speed_limit_user_rule
(user_id, mode, speed_mbps, remark, created_at, updated_at)
VALUES
(${USER_ID}, 'direct_limit', ${USER_DYNAMIC_SPEED}, 'shoes dynamic speed e2e', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  mode=VALUES(mode),
  speed_mbps=VALUES(speed_mbps),
  remark=VALUES(remark),
  updated_at=VALUES(updated_at);

DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
}

assert_uniproxy_effective_speed() {
  e2e_section "UniProxy effective speed"
  curl -fsS --max-time 5 "$(api_url)" -o "${TMP_DIR}/user.json"
  python3 - "${TMP_DIR}/user.json" "${USER_ID}" "${USER_DYNAMIC_SPEED}" "${USER_ORIGINAL_SPEED}" <<'PY'
import json
import sys

path = sys.argv[1]
uid = int(sys.argv[2])
expected = int(sys.argv[3])
original = int(sys.argv[4])
with open(path, "rb") as fh:
    data = json.load(fh)
users = data.get("users")
if not isinstance(users, list):
    raise SystemExit(f"users missing: {data!r}")
matches = [user for user in users if int(user.get("id", -1)) == uid]
if len(matches) != 1:
    raise SystemExit(f"expected one user {uid}, got {users!r}")
speed = int(matches[0].get("speed_limit", -1))
if speed != expected:
    raise SystemExit(f"expected effective speed_limit={expected}, got {speed}; original was {original}")
PY
  e2e_log "V2Board returned effective speed_limit=${USER_DYNAMIC_SPEED} from original ${USER_ORIGINAL_SPEED}"
}

write_configs() {
  cat >"${TMP_DIR}/dynamic_speed.shoes.yml" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${SERVER_TOKEN}"
  nodes:
    - tag: "dynamic_speed"
      node_id: ${NODE_ID}
      node_type: "vmess"
      listen: "${E2E_BIND_HOST}"
      pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
      push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
runtime:
  data_dir: "${TMP_DIR}/dynamic-speed-shoes-data"
  pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
  push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
  node_report_min_traffic: 0
log:
  level: "debug"
YAML

  cat >"${TMP_DIR}/dynamic_speed.singlink.json" <<JSON
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
  e2e_section "start dynamic-speed http target"
  e2e_assert_port_free "${E2E_HTTP_PORT}" "dynamic-speed http target"
  mkdir -p "${TMP_DIR}/http-root"
  dd if=/dev/zero of="${TMP_DIR}/http-root/fast.bin" bs=1024 count=1024 status=none
  python3 -m http.server "${E2E_HTTP_PORT}" \
    --bind "${E2E_BIND_HOST}" \
    --directory "${TMP_DIR}/http-root" \
    >"${TMP_DIR}/http.log" 2>&1 &
  HTTP_PID=$!
  wait_for_listen_port "${E2E_HTTP_PORT}" "dynamic-speed http target" 10
}

start_services() {
  "${SHOES_BIN}" sync-once -c "${TMP_DIR}/dynamic_speed.shoes.yml" >"${TMP_DIR}/dynamic_speed.sync.log" 2>&1
  e2e_assert_port_free "${E2E_NODE_PORT}" "dynamic-speed shoes"
  "${SHOES_BIN}" run -c "${TMP_DIR}/dynamic_speed.shoes.yml" >"${TMP_DIR}/dynamic_speed.shoes.log" 2>&1 &
  SHOES_PID=$!
  wait_for_listen_port "${E2E_NODE_PORT}" "dynamic-speed shoes" 15

  "${SINGLINK_BIN}" -c "${TMP_DIR}/dynamic_speed.singlink.json" check >"${TMP_DIR}/dynamic_speed.singlink-check.log" 2>&1
  e2e_assert_port_free "${E2E_PROXY_PORT}" "dynamic-speed singlink"
  "${SINGLINK_BIN}" -c "${TMP_DIR}/dynamic_speed.singlink.json" run >"${TMP_DIR}/dynamic_speed.singlink.log" 2>&1 &
  SINGLINK_PID=$!
  wait_for_listen_port "${E2E_PROXY_PORT}" "dynamic-speed singlink" 15
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

assert_dynamic_speed_limit() {
  local start
  local end
  local elapsed_ms

  e2e_section "effective speed enforcement"
  start="$(now_ms)"
  curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${E2E_PROXY_PORT}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    -o "${TMP_DIR}/fast.bin"
  end="$(now_ms)"
  elapsed_ms="$((end - start))"

  [[ "$(wc -c <"${TMP_DIR}/fast.bin")" -eq 1048576 ]] \
    || e2e_die "dynamic speed download size mismatch"
  ((elapsed_ms >= 5000)) \
    || e2e_die "dynamic direct_limit did not throttle enough: elapsed ${elapsed_ms}ms, expected >= 5000ms"
  e2e_log "dynamic direct_limit elapsed=${elapsed_ms}ms"
}

cleanup_fixtures() {
  if e2e_env_bool E2E_KEEP_FIXTURES 1; then
    e2e_log "keeping dynamic-speed E2E fixtures"
    return
  fi

  mysql_exec <<SQL
DELETE FROM v2_dynamic_speed_limit_user_rule WHERE user_id=${USER_ID};
DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
DELETE FROM v2_user WHERE email='shoes-dynamic-speed@example.local';
DELETE FROM v2_server_vmess WHERE name='shoes-dynamic-speed';
DELETE FROM v2_server_group WHERE name='shoes-dynamic-speed';
SQL
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
}

main() {
  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-dynamic-speed-e2e.XXXXXX)"

  check_environment
  resolve_binaries
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"
  seed_fixture
  assert_uniproxy_effective_speed
  write_configs
  start_http_target
  start_services
  assert_dynamic_speed_limit
  cleanup_fixtures
  e2e_section "done"
}

main "$@"
