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
V2BOARD_REDIS_CONTAINER="${V2BOARD_REDIS_CONTAINER:-v2board-docker-redis-1}"
V2BOARD_MYSQL_USER="${V2BOARD_MYSQL_USER:-root}"
V2BOARD_MYSQL_PASSWORD="${V2BOARD_MYSQL_PASSWORD:-v2boardisbest}"
V2BOARD_MYSQL_DATABASE="${V2BOARD_MYSQL_DATABASE:-v2board}"

SHOES_BIN="${SHOES_BIN:-}"
E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_NODE_PORT="${E2E_NODE_PORT:-18440}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-2}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-2}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"

NODE_ID=9940
GROUP_ID=9940
USER_ID=19940
USER_UUID=99999999-9999-4999-8999-000000009940

TMP_DIR=""
SHOES_PID=""
SERVER_TOKEN=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_xhttp_cors.sh

Runs a real V2Board VLESS/XHTTP HTTP/1 CORS preflight check:
  - seeds a VLESS xhttp node with cookie placement settings
  - starts shoes from the V2Board UniProxy config
  - sends OPTIONS directly to the XHTTP listener
  - verifies Origin echo, requested method/header reflection, and credentials
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
    if [[ -n "${SHOES_PID}" ]] && ! kill -0 "${SHOES_PID}" 2>/dev/null; then
      e2e_die "${label} process exited before listening on ${port}"
    fi
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
  e2e_require_command grep
  e2e_require_command ss

  if [[ -z "${SHOES_BIN}" ]]; then
    SHOES_BIN="${ROOT_DIR}/target/debug/shoes"
    e2e_run cargo build --manifest-path "${ROOT_DIR}/Cargo.toml"
  fi
  [[ -x "${SHOES_BIN}" ]] || e2e_die "SHOES_BIN is not executable: ${SHOES_BIN}"
}

check_environment() {
  e2e_section "environment"
  docker ps --format '{{.Names}}' | grep -Fxq "${V2BOARD_MYSQL_CONTAINER}" \
    || e2e_die "missing running mysql container: ${V2BOARD_MYSQL_CONTAINER}"
  docker ps --format '{{.Names}}' | grep -Fxq "${V2BOARD_REDIS_CONTAINER}" \
    || e2e_die "missing running redis container: ${V2BOARD_REDIS_CONTAINER}"
  e2e_http_probe "${V2BOARD_PANEL_URL}" >/dev/null \
    || e2e_die "panel is not reachable: ${V2BOARD_PANEL_URL}"
}

seed_fixtures() {
  local now
  local expires_at

  e2e_section "seed v2board fixtures"
  now="$(date +%s)"
  expires_at="$((now + 86400))"

  mysql_exec <<SQL
INSERT INTO v2_server_group
(id, name, created_at, updated_at)
VALUES
(${GROUP_ID}, 'shoes-xhttp-cors', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  updated_at=VALUES(updated_at);

INSERT INTO v2_user
(id, invite_user_id, telegram_id, email, language, password, password_algo, password_salt, balance, discount, commission_type, commission_rate, commission_balance, t, u, d, transfer_enable, device_limit, banned, is_admin, last_login_at, is_staff, last_login_ip, uuid, group_id, plan_id, speed_limit, auto_renewal, remind_expire, remind_traffic, token, expired_at, remarks, created_at, updated_at)
VALUES
(${USER_ID}, NULL, NULL, 'shoes-xhttp-cors@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '${USER_UUID}', ${GROUP_ID}, NULL, NULL, 0, 1, 1, MD5('shoes-xhttp-cors@example.local'), ${expires_at}, 'shoes xhttp cors e2e', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
  group_id=${GROUP_ID},
  expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);

INSERT INTO v2_server_vless
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tls_settings, flow, network, network_settings, encryption, encryption_settings, tags, rate, \`show\`, sort, created_at, updated_at)
VALUES
(${NODE_ID}, '["${GROUP_ID}"]', NULL, 'shoes-xhttp-cors', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', ${E2E_NODE_PORT}, ${E2E_NODE_PORT}, 0, '{}', NULL, 'xhttp', '{"path":"/cors","mode":"auto","extra":{"sessionIDPlacement":"cookie","seqPlacement":"cookie","uplinkDataPlacement":"cookie"}}', 'none', '{}', NULL, '1', 1, ${NODE_ID}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  tls=VALUES(tls),
  network=VALUES(network),
  network_settings=VALUES(network_settings),
  encryption=VALUES(encryption),
  encryption_settings=VALUES(encryption_settings),
  \`show\`=VALUES(\`show\`),
  updated_at=VALUES(updated_at);

DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vless';
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
}

write_shoes_config() {
  cat >"${TMP_DIR}/xhttp-cors.shoes.yml" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${SERVER_TOKEN}"
  nodes:
    - tag: "xhttp_cors"
      node_id: ${NODE_ID}
      node_type: "vless"
      listen: "${E2E_BIND_HOST}"
      pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
      push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
runtime:
  data_dir: "${TMP_DIR}/shoes-data"
  pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
  push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
log:
  level: "debug"
YAML
}

start_services() {
  e2e_section "start shoes"
  e2e_assert_port_free "${E2E_NODE_PORT}" "xhttp cors shoes"
  "${SHOES_BIN}" run -c "${TMP_DIR}/xhttp-cors.shoes.yml" >"${TMP_DIR}/shoes.log" 2>&1 &
  SHOES_PID=$!
  wait_for_listen_port "${E2E_NODE_PORT}" "shoes xhttp cors" 15
}

stop_services() {
  if [[ -n "${SHOES_PID}" ]] && kill -0 "${SHOES_PID}" 2>/dev/null; then
    kill "${SHOES_PID}" 2>/dev/null || true
    wait "${SHOES_PID}" 2>/dev/null || true
  fi
  SHOES_PID=""
}

assert_header() {
  local headers_file="$1"
  local expected="$2"

  grep -Fqi "${expected}" "${headers_file}" \
    || e2e_die "missing expected response header: ${expected}"
}

assert_xhttp_options_cors() {
  local headers_file="${TMP_DIR}/options.headers"
  local body_file="${TMP_DIR}/options.body"
  local status

  e2e_section "xhttp options cors"
  status="$(
    curl -sS \
      --http1.1 \
      --connect-timeout 3 \
      --max-time 10 \
      -X OPTIONS \
      -H 'Origin: https://client.example' \
      -H 'Access-Control-Request-Method: POST' \
      -H 'Access-Control-Request-Headers: X-Session, X-Data-0' \
      -D "${headers_file}" \
      -o "${body_file}" \
      -w '%{http_code}' \
      "http://${E2E_BIND_HOST}:${E2E_NODE_PORT}/cors"
  )"

  [[ "${status}" == "200" ]] || e2e_die "unexpected OPTIONS status: ${status}"
  assert_header "${headers_file}" "Access-Control-Allow-Origin: https://client.example"
  assert_header "${headers_file}" "Access-Control-Allow-Credentials: true"
  assert_header "${headers_file}" "Access-Control-Allow-Methods: POST"
  assert_header "${headers_file}" "Access-Control-Allow-Headers: X-Session, X-Data-0"
  assert_header "${headers_file}" "Content-Length: 0"
  [[ "$(wc -c <"${body_file}")" -eq 0 ]] || e2e_die "OPTIONS response body is not empty"
  e2e_log "xhttp OPTIONS CORS response matched Xray-compatible headers"
}

cleanup_fixtures() {
  mysql_exec <<SQL
DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vless';
DELETE FROM v2_user WHERE id=${USER_ID};
DELETE FROM v2_server_vless WHERE id=${NODE_ID};
DELETE FROM v2_server_group WHERE id=${GROUP_ID};
SQL
}

main() {
  parse_args "$@"
  check_environment
  TMP_DIR="$(mktemp -d)"
  resolve_binaries
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server_token"
  seed_fixtures
  write_shoes_config
  start_services
  assert_xhttp_options_cors

  if ! e2e_env_bool E2E_KEEP_FIXTURES 1; then
    cleanup_fixtures
  fi

  e2e_section "done"
}

main "$@"
