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
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18103}"
E2E_NODE_PORT="${E2E_NODE_PORT:-18192}"
E2E_PROXY_PORT="${E2E_PROXY_PORT:-18292}"
E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB:-128}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-2}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-2}"
E2E_WAIT_TIMEOUT_SECS="${E2E_WAIT_TIMEOUT_SECS:-45}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_CURL_CONNECT_TIMEOUT_SECS="${E2E_CURL_CONNECT_TIMEOUT_SECS:-3}"
E2E_CURL_MAX_TIME_SECS="${E2E_CURL_MAX_TIME_SECS:-45}"

GROUP_ID=9907
NODE_ID=9907
USER_ID=19907
USER_UUID=99999999-9999-4999-8999-999999999907
NODE_RATE=2

TMP_DIR=""
HTTP_PID=""
SHOES_PID=""
SINGLINK_PID=""
SERVER_TOKEN=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_traffic_accounting.sh

Runs a real V2Board traffic accounting E2E check:
  - node rate is 2
  - v2_stat_user/v2_stat_server keep raw bytes
  - v2_user counters receive raw bytes multiplied by node rate
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

seed_fixture() {
  local now
  local expires_at

  now="$(date +%s)"
  expires_at="$((now + 86400))"

  mysql_exec <<SQL
INSERT INTO v2_server_group
(id, name, created_at, updated_at)
VALUES
(${GROUP_ID}, 'shoes-accounting-user', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  updated_at=VALUES(updated_at);

INSERT INTO v2_server_vmess
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tags, rate, network, rules, networkSettings, tlsSettings, ruleSettings, dnsSettings, \`show\`, sort, created_at, updated_at)
VALUES
(${NODE_ID}, '["${GROUP_ID}"]', NULL, 'shoes-accounting-user', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_NODE_PORT}', ${E2E_NODE_PORT}, 0, NULL, '${NODE_RATE}', 'tcp', NULL, '{}', '{}', '{}', '{}', 1, ${NODE_ID}, ${now}, ${now})
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
(${USER_ID}, NULL, NULL, 'shoes-accounting-user@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '${USER_UUID}', ${GROUP_ID}, NULL, NULL, 0, 1, 1, MD5('shoes-accounting-user@example.local'), ${expires_at}, 'shoes accounting e2e', ${now}, ${now})
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
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
}

write_configs() {
  cat >"${TMP_DIR}/accounting.shoes.yml" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${SERVER_TOKEN}"
  nodes:
    - tag: "accounting_user"
      node_id: ${NODE_ID}
      node_type: "vmess"
      listen: "${E2E_BIND_HOST}"
      pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
      push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
runtime:
  data_dir: "${TMP_DIR}/accounting-shoes-data"
  pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
  push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
  node_report_min_traffic: 0
  device_online_min_traffic: 0
log:
  level: "info"
YAML

  cat >"${TMP_DIR}/accounting.singlink.json" <<JSON
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
  e2e_section "start accounting http target"
  e2e_assert_port_free "${E2E_HTTP_PORT}" "accounting http target"
  mkdir -p "${TMP_DIR}/http-root"
  dd if=/dev/zero of="${TMP_DIR}/http-root/payload.bin" bs=1024 count="${E2E_PAYLOAD_KIB}" status=none
  python3 -m http.server "${E2E_HTTP_PORT}" \
    --bind "${E2E_BIND_HOST}" \
    --directory "${TMP_DIR}/http-root" \
    >"${TMP_DIR}/http.log" 2>&1 &
  HTTP_PID=$!
  wait_for_listen_port "${E2E_HTTP_PORT}" "accounting http target" 10
}

start_services() {
  "${SHOES_BIN}" sync-once -c "${TMP_DIR}/accounting.shoes.yml" >"${TMP_DIR}/accounting.sync.log" 2>&1
  e2e_assert_port_free "${E2E_NODE_PORT}" "accounting shoes"
  "${SHOES_BIN}" run -c "${TMP_DIR}/accounting.shoes.yml" >"${TMP_DIR}/accounting.shoes.log" 2>&1 &
  SHOES_PID=$!
  wait_for_listen_port "${E2E_NODE_PORT}" "accounting shoes" 15

  "${SINGLINK_BIN}" -c "${TMP_DIR}/accounting.singlink.json" check >"${TMP_DIR}/accounting.singlink-check.log" 2>&1
  e2e_assert_port_free "${E2E_PROXY_PORT}" "accounting singlink"
  "${SINGLINK_BIN}" -c "${TMP_DIR}/accounting.singlink.json" run >"${TMP_DIR}/accounting.singlink.log" 2>&1 &
  SINGLINK_PID=$!
  wait_for_listen_port "${E2E_PROXY_PORT}" "accounting singlink" 15
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

assert_accounting_rows() {
  local expected_payload="$1"
  local start
  local now
  local row
  local user_u
  local user_d
  local stat_user_rate
  local stat_user_u
  local stat_user_d
  local stat_server_u
  local stat_server_d
  local expected_user_d

  start="$(date +%s)"
  while true; do
    e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"
    docker exec "${V2BOARD_WWW_CONTAINER}" php artisan traffic:update >/dev/null
    row="$(mysql_query "SELECT u.d, su.server_rate, su.u, su.d, ss.u, ss.d, u.u FROM v2_user u JOIN v2_stat_user su ON su.user_id=u.id JOIN v2_stat_server ss ON ss.server_id=${NODE_ID} AND ss.server_type='vmess' WHERE u.id=${USER_ID} AND su.server_rate=${NODE_RATE} ORDER BY su.id DESC LIMIT 1;")"
    if [[ -n "${row}" ]]; then
      read -r user_d stat_user_rate stat_user_u stat_user_d stat_server_u stat_server_d user_u <<<"${row}"
      expected_user_d="$((stat_user_d * NODE_RATE))"
      if ((stat_user_d >= expected_payload && stat_server_d >= expected_payload && user_d >= expected_user_d)); then
        [[ "${stat_user_rate}" == "2.00" || "${stat_user_rate}" == "2" ]] \
          || e2e_die "unexpected stat_user server_rate=${stat_user_rate}"
        ((stat_server_d == stat_user_d)) \
          || e2e_die "stat_server.d=${stat_server_d} differs from stat_user.d=${stat_user_d}"
        ((user_d == expected_user_d)) \
          || e2e_die "user.d=${user_d} did not equal stat_user.d*${NODE_RATE}=${expected_user_d}"
        e2e_log "accounting user=${user_u}/${user_d} stat_user(rate=${stat_user_rate})=${stat_user_u}/${stat_user_d} stat_server=${stat_server_u}/${stat_server_d}"
        return
      fi
    fi

    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_die "traffic accounting did not reach expected payload ${expected_payload}; last=${row:-<empty>}"
    fi
    sleep 1
  done
}

cleanup_fixtures() {
  if e2e_env_bool E2E_KEEP_FIXTURES 1; then
    e2e_log "keeping traffic-accounting E2E fixtures"
    return
  fi

  mysql_exec <<SQL
DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
DELETE FROM v2_user WHERE email='shoes-accounting-user@example.local';
DELETE FROM v2_server_vmess WHERE name='shoes-accounting-user';
DELETE FROM v2_server_group WHERE name='shoes-accounting-user';
SQL
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
}

main() {
  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-accounting-e2e.XXXXXX)"

  check_environment
  resolve_binaries
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"
  seed_fixture
  write_configs
  start_http_target
  start_services
  run_proxy_download
  stop_services
  assert_accounting_rows "$((E2E_PAYLOAD_KIB * 1024))"
  cleanup_fixtures
  e2e_section "done"
}

main "$@"
