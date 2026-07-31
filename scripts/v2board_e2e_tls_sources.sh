#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/scripts"

# shellcheck source=scripts/v2board_e2e_common.sh
# shellcheck disable=SC1091
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
SINGLINK_BUILD_TAGS="${SINGLINK_BUILD_TAGS:-with_utls}"
SHOES_BIN="${SHOES_BIN:-}"

E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18092}"
E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB:-128}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-5}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-5}"
E2E_WAIT_TIMEOUT_SECS="${E2E_WAIT_TIMEOUT_SECS:-45}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_TLS_SOURCE_CASES="${E2E_TLS_SOURCE_CASES:-panel_tls_settings_files,node_tls_override,v2node_panel_tls_settings_files,v2node_node_tls_override}"
E2E_CURL_CONNECT_TIMEOUT_SECS="${E2E_CURL_CONNECT_TIMEOUT_SECS:-5}"
E2E_CURL_MAX_TIME_SECS="${E2E_CURL_MAX_TIME_SECS:-45}"

TMP_DIR=""
HTTP_PID=""
SHOES_PID=""
SINGLINK_PID=""
SERVER_TOKEN=""

CASE_NAME=""
CASE_NODE_ID=""
CASE_USER_ID=""
CASE_GROUP_ID=""
CASE_UUID=""
CASE_NODE_PORT=""
CASE_PROXY_PORT=""
CASE_PANEL_CERT=""
CASE_NODE_TLS=""
CASE_NODE_TYPE="vless"
CASE_SERVER_TYPE="vless"
CASE_TLS_SERVER_NAME="example.org"

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_tls_sources.sh

Runs local production-oriented V2Board VLESS/TLS E2E checks for TLS
certificate sources:
  panel_tls_settings_files  Panel vless tls_settings has cert_file/key_file.
  node_tls_override         Panel has no cert files; local nodes[].tls is used.
  v2node_panel_tls_settings_files
                             V2Node vless tls_settings has cert_file/key_file.
  v2node_node_tls_override   V2Node has no cert files; local nodes[].tls is used.

Environment:
  E2E_TLS_SOURCE_CASES       Comma-separated case list. Default: both cases.
  V2BOARD_SERVER_TOKEN       Override server token. Defaults to parsing ../v2board/config/v2board.php.
  SHOES_BIN                  Optional prebuilt shoes binary.
  SINGLINK_BIN               Optional prebuilt singlink/sing-box binary.
  SINGLINK_BUILD_TAGS        Tags used when building singlink. Default: with_utls.
  E2E_HTTP_PORT              Local HTTP payload target. Default: 18092.
  E2E_KEEP_FIXTURES          Keep seeded V2Board fixtures. Default: 1.
  E2E_WAIT_TIMEOUT_SECS      Wait time for traffic rows/user counters. Default: 45.
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
    if [[ -n "${SINGLINK_BUILD_TAGS}" ]]; then
      e2e_run go -C "${SING_BOX_DIR}" build -tags "${SINGLINK_BUILD_TAGS}" -o "${SINGLINK_BIN}" ./cmd/singlink
    else
      e2e_run go -C "${SING_BOX_DIR}" build -o "${SINGLINK_BIN}" ./cmd/singlink
    fi
  fi
  [[ -x "${SINGLINK_BIN}" ]] || e2e_die "SINGLINK_BIN is not executable: ${SINGLINK_BIN}"

  e2e_log "SHOES_BIN=${SHOES_BIN}"
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
    -addext "subjectAltName=DNS:${CASE_TLS_SERVER_NAME}" \
    -keyout "${TMP_DIR}/tls.key" \
    -out "${TMP_DIR}/tls.crt" \
    >/dev/null 2>&1
}

case_config() {
  CASE_NAME="$1"
  CASE_GROUP_ID=""
  CASE_PANEL_CERT=0
  CASE_NODE_TLS=0
  CASE_NODE_TYPE="vless"
  CASE_SERVER_TYPE="vless"
  CASE_TLS_SERVER_NAME="example.org"

  case "${CASE_NAME}" in
    panel_tls_settings_files)
      CASE_NODE_ID=9902
      CASE_USER_ID=19902
      CASE_GROUP_ID=9902
      CASE_UUID=99999002-9902-4999-8999-999999999902
      CASE_NODE_PORT=18182
      CASE_PROXY_PORT=18282
      CASE_PANEL_CERT=1
      ;;
    node_tls_override)
      CASE_NODE_ID=9903
      CASE_USER_ID=19903
      CASE_GROUP_ID=9903
      CASE_UUID=99999003-9903-4999-8999-999999999903
      CASE_NODE_PORT=18183
      CASE_PROXY_PORT=18283
      CASE_NODE_TLS=1
      ;;
    v2node_panel_tls_settings_files)
      CASE_NODE_ID=9904
      CASE_USER_ID=19904
      CASE_GROUP_ID=9904
      CASE_UUID=99999004-9904-4999-8999-999999999904
      CASE_NODE_PORT=18184
      CASE_PROXY_PORT=18284
      CASE_PANEL_CERT=1
      CASE_NODE_TYPE="v2node"
      CASE_SERVER_TYPE="v2node"
      ;;
    v2node_node_tls_override)
      CASE_NODE_ID=9905
      CASE_USER_ID=19905
      CASE_GROUP_ID=9905
      CASE_UUID=99999005-9905-4999-8999-999999999905
      CASE_NODE_PORT=18185
      CASE_PROXY_PORT=18285
      CASE_NODE_TLS=1
      CASE_NODE_TYPE="v2node"
      CASE_SERVER_TYPE="v2node"
      ;;
    *)
      e2e_die "unknown TLS source case: ${CASE_NAME}"
      ;;
  esac
}

tls_settings_json() {
  if [[ "${CASE_PANEL_CERT}" == "1" ]]; then
    printf '{"server_name":"%s","cert_file":"%s","key_file":"%s","cert_mode":"file"}' \
      "${CASE_TLS_SERVER_NAME}" \
      "${TMP_DIR}/tls.crt" \
      "${TMP_DIR}/tls.key"
    return
  fi

  printf '{"server_name":"%s"}' "${CASE_TLS_SERVER_NAME}"
}

seed_group() {
  local now

  now="$(date +%s)"

  mysql_exec <<SQL
INSERT INTO v2_server_group
(id, name, created_at, updated_at)
VALUES
(${CASE_GROUP_ID}, 'shoes-e2e-tls-src-${CASE_NAME}', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  updated_at=VALUES(updated_at);
SQL
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
(${CASE_USER_ID}, NULL, NULL, 'shoes-e2e-tls-src-${CASE_NAME}@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '${CASE_UUID}', ${CASE_GROUP_ID}, NULL, NULL, 0, 1, 1, MD5('shoes-e2e-tls-src-${CASE_NAME}@example.local'), ${expires_at}, 'shoes tls source e2e user', ${now}, ${now})
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

seed_node() {
  local now
  local ts

  now="$(date +%s)"
  ts="$(tls_settings_json)"

  if [[ "${CASE_NODE_TYPE}" == "v2node" ]]; then
    mysql_exec <<SQL
INSERT INTO v2_server_v2node
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, listen_ip, port, server_port, tags, rate, \`show\`, sort, protocol, tls, tls_settings, flow, network, network_settings, encryption, encryption_settings, disable_sni, udp_relay_mode, zero_rtt_handshake, congestion_control, cipher, up_mbps, down_mbps, obfs, obfs_password, padding_scheme, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, '["${CASE_GROUP_ID}"]', NULL, 'shoes-e2e-tls-src-${CASE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_BIND_HOST}', '${CASE_NODE_PORT}', ${CASE_NODE_PORT}, NULL, '1', 1, ${CASE_NODE_ID}, 'vless', 1, '${ts}', NULL, 'tcp', '{}', 'none', '{}', 0, NULL, 0, NULL, NULL, 0, 0, NULL, NULL, NULL, ${now}, ${now})
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
  flow=NULL,
  network=VALUES(network),
  network_settings=VALUES(network_settings),
  encryption=VALUES(encryption),
  encryption_settings=VALUES(encryption_settings),
  \`show\`=VALUES(\`show\`),
  sort=VALUES(sort),
  updated_at=VALUES(updated_at);

DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='v2node';
SQL
    return
  fi

  mysql_exec <<SQL
INSERT INTO v2_server_vless
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tls_settings, flow, network, network_settings, encryption, encryption_settings, tags, rate, \`show\`, sort, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, '["${CASE_GROUP_ID}"]', NULL, 'shoes-e2e-tls-src-${CASE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', ${CASE_NODE_PORT}, ${CASE_NODE_PORT}, 1, '${ts}', NULL, 'tcp', '{}', 'none', '{}', NULL, '1', 1, ${CASE_NODE_ID}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  tls=VALUES(tls),
  tls_settings=VALUES(tls_settings),
  flow=NULL,
  network=VALUES(network),
  network_settings=VALUES(network_settings),
  encryption=VALUES(encryption),
  encryption_settings=VALUES(encryption_settings),
  \`show\`=VALUES(\`show\`),
  sort=VALUES(sort),
  updated_at=VALUES(updated_at);

DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='vless';
SQL
}

write_shoes_config() {
  e2e_section "write shoes config ${CASE_NAME}"
  {
    cat <<YAML
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
YAML

    if [[ "${CASE_NODE_TLS}" == "1" ]]; then
      cat <<YAML
      tls:
        cert_file: "${TMP_DIR}/tls.crt"
        key_file: "${TMP_DIR}/tls.key"
YAML
    fi

    cat <<YAML
runtime:
  data_dir: "${TMP_DIR}/${CASE_NAME}-shoes-data"
  pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
  push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
  node_report_min_traffic: 0
log:
  level: "info"
YAML
  } >"${TMP_DIR}/${CASE_NAME}.shoes.yml"
}

write_singlink_config() {
  e2e_section "write singlink config ${CASE_NAME}"
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
      "type": "vless",
      "tag": "vless-out",
      "server": "${E2E_BIND_HOST}",
      "server_port": ${CASE_NODE_PORT},
      "uuid": "${CASE_UUID}",
      "network": "tcp",
      "tls": {
        "enabled": true,
        "server_name": "${CASE_TLS_SERVER_NAME}",
        "certificate_path": "${TMP_DIR}/tls.crt"
      }
    }
  ],
  "route": {"final": "vless-out"}
}
JSON
}

start_http_target() {
  e2e_section "start http target"
  e2e_assert_port_free "${E2E_HTTP_PORT}" "tls-source http target"
  mkdir -p "${TMP_DIR}/http-root"
  dd if=/dev/zero of="${TMP_DIR}/http-root/payload.bin" bs=1024 count="${E2E_PAYLOAD_KIB}" status=none

  python3 -m http.server "${E2E_HTTP_PORT}" \
    --bind "${E2E_BIND_HOST}" \
    --directory "${TMP_DIR}/http-root" \
    >"${TMP_DIR}/http.log" 2>&1 &
  HTTP_PID=$!
  wait_for_listen_port "${E2E_HTTP_PORT}" "tls-source http target" 10
}

start_case_services() {
  e2e_section "start services ${CASE_NAME}"
  e2e_assert_port_free "${CASE_NODE_PORT}" "shoes ${CASE_NAME}"
  e2e_assert_port_free "${CASE_PROXY_PORT}" "singlink ${CASE_NAME}"

  "${SHOES_BIN}" sync-once -c "${TMP_DIR}/${CASE_NAME}.shoes.yml" >"${TMP_DIR}/${CASE_NAME}.sync.log" 2>&1
  "${SHOES_BIN}" run -c "${TMP_DIR}/${CASE_NAME}.shoes.yml" >"${TMP_DIR}/${CASE_NAME}.shoes.log" 2>&1 &
  SHOES_PID=$!
  wait_for_listen_port "${CASE_NODE_PORT}" "shoes ${CASE_NAME}" 15

  "${SINGLINK_BIN}" -c "${TMP_DIR}/${CASE_NAME}.singlink.json" check >"${TMP_DIR}/${CASE_NAME}.singlink-check.log" 2>&1
  "${SINGLINK_BIN}" -c "${TMP_DIR}/${CASE_NAME}.singlink.json" run >"${TMP_DIR}/${CASE_NAME}.singlink.log" 2>&1 &
  SINGLINK_PID=$!
  wait_for_listen_port "${CASE_PROXY_PORT}" "singlink ${CASE_NAME}" 15
}

stop_case_services() {
  for pid_var in SINGLINK_PID SHOES_PID; do
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
    stat_server="$(mysql_query "SELECT COALESCE(SUM(u),0), COALESCE(SUM(d),0) FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='${CASE_SERVER_TYPE}';")"
    read -r stat_user_u stat_user_d <<<"${stat_user}"
    read -r stat_server_u stat_server_d <<<"${stat_server}"
    if ((stat_user_d >= expected_min && stat_server_d >= expected_min)); then
      e2e_log "${CASE_NAME}: stats user=${stat_user_u}/${stat_user_d} server=${stat_server_u}/${stat_server_d}"
      return
    fi

    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_die "${CASE_NAME}: traffic stats did not reach expected download ${expected_min}; user=${stat_user_u}/${stat_user_d} server=${stat_server_u}/${stat_server_d}"
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
    if ((user_d >= expected_min)); then
      e2e_log "${CASE_NAME}: user ${CASE_USER_ID} traffic u=${user_u} d=${user_d}"
      return
    fi

    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_die "${CASE_NAME}: user counter did not reach expected download ${expected_min}; got ${user_u}/${user_d}"
    fi
    e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"
    docker exec "${V2BOARD_WWW_CONTAINER}" php artisan traffic:update >/dev/null
    sleep 1
  done
}

run_case() {
  local expected_min
  local case_name="$1"

  case_config "${case_name}"
  e2e_section "case ${CASE_NAME}"
  seed_group
  seed_user
  seed_node
  write_shoes_config
  write_singlink_config
  start_case_services

  curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${CASE_PROXY_PORT}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/payload.bin" \
    -o "${TMP_DIR}/${CASE_NAME}.download.bin"

  expected_min="$((E2E_PAYLOAD_KIB * 1024))"
  [[ "$(wc -c <"${TMP_DIR}/${CASE_NAME}.download.bin")" -eq "${expected_min}" ]] \
    || e2e_die "${CASE_NAME}: download size mismatch"

  wait_for_traffic "${expected_min}"
  wait_for_user_counter "${expected_min}"
  stop_case_services
}

maybe_cleanup_fixtures() {
  if e2e_env_bool E2E_KEEP_FIXTURES 1; then
  e2e_log "keeping TLS source E2E fixtures: nodes=9902,9903,9904,9905 users=19902,19903,19904,19905"
    return
  fi

  e2e_section "cleanup fixtures"
  mysql_exec <<SQL
DELETE FROM v2_stat_user WHERE user_id IN (19902, 19903, 19904, 19905);
DELETE FROM v2_stat_server WHERE server_id IN (9902, 9903) AND server_type='vless';
DELETE FROM v2_stat_server WHERE server_id IN (9904, 9905) AND server_type='v2node';
DELETE FROM v2_user WHERE id IN (19902, 19903, 19904, 19905);
DELETE FROM v2_server_vless WHERE id IN (9902, 9903);
DELETE FROM v2_server_v2node WHERE id IN (9904, 9905);
DELETE FROM v2_server_group WHERE id IN (9902, 9903, 9904, 9905);
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19902
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19903
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19904
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19905
}

main() {
  local case_name
  local cases

  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-tls-sources-e2e.XXXXXX)"

  check_environment
  resolve_binaries
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"
  generate_tls_files
  start_http_target

  IFS=',' read -r -a cases <<<"${E2E_TLS_SOURCE_CASES}"
  for case_name in "${cases[@]}"; do
    case_name="${case_name//[[:space:]]/}"
    [[ -n "${case_name}" ]] || continue
    run_case "${case_name}"
  done

  maybe_cleanup_fixtures
  e2e_section "done"
}

main "$@"
