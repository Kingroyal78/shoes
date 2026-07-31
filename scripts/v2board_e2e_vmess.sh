#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/scripts"

# shellcheck source=scripts/v2board_e2e_common.sh
source "${SCRIPT_DIR}/v2board_e2e_common.sh"

trap e2e_on_error ERR

V2BOARD_DOCKER_DIR="${V2BOARD_DOCKER_DIR:-${ROOT_DIR}/../v2board-docker}"
V2BOARD_DIR="${V2BOARD_DIR:-${ROOT_DIR}/../v2board}"
V2BOARD_PANEL_URL="${V2BOARD_PANEL_URL:-http://127.0.0.1}"
V2BOARD_MYSQL_CONTAINER="${V2BOARD_MYSQL_CONTAINER:-v2board-docker-mysql-1}"
V2BOARD_WWW_CONTAINER="${V2BOARD_WWW_CONTAINER:-v2board-docker-www-1}"
V2BOARD_MYSQL_USER="${V2BOARD_MYSQL_USER:-root}"
V2BOARD_MYSQL_PASSWORD="${V2BOARD_MYSQL_PASSWORD:-v2boardisbest}"
V2BOARD_MYSQL_DATABASE="${V2BOARD_MYSQL_DATABASE:-v2board}"

SING_BOX_DIR="${SING_BOX_DIR:-${ROOT_DIR}/../sing-box}"
SINGLINK_BIN="${SINGLINK_BIN:-}"
SHOES_BIN="${SHOES_BIN:-}"

E2E_NODE_ID="${E2E_NODE_ID:-9001}"
E2E_NODE_TAG="${E2E_NODE_TAG:-vmess-e2e}"
E2E_USER_ID="${E2E_USER_ID:-19001}"
E2E_USER_EMAIL="${E2E_USER_EMAIL:-shoes-e2e-vmess@example.local}"
E2E_USER_UUID="${E2E_USER_UUID:-8b4c1a62-d3c1-4a3f-9f99-bcb9f8e6f001}"
E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_NODE_PORT="${E2E_NODE_PORT:-18081}"
E2E_PROXY_PORT="${E2E_PROXY_PORT:-18082}"
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18083}"
E2E_PAYLOAD_KIB="${E2E_PAYLOAD_KIB:-128}"
E2E_PUSH_WAIT_SECS="${E2E_PUSH_WAIT_SECS:-12}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-5}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-5}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"

TMP_DIR=""
HTTP_PID=""
SHOES_PID=""
SINGLINK_PID=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_vmess.sh

Runs a real local VMess/TCP E2E against sibling v2board-docker:
  curl -> singlink mixed inbound -> shoes VMess backend -> local HTTP target

Important environment:
  V2BOARD_SERVER_TOKEN      Override server token. Defaults to parsing ../v2board/config/v2board.php.
  SHOES_BIN                 Optional prebuilt shoes binary. Defaults to target/debug/shoes, building it when missing.
  SINGLINK_BIN              Optional prebuilt singlink/sing-box binary. Defaults to building ../sing-box/cmd/singlink.
  E2E_NODE_ID               VMess node id to upsert. Default: 9001.
  E2E_USER_ID               Dedicated user id to upsert/reset. Default: 19001.
  E2E_NODE_PORT             shoes VMess listen port. Default: 18081.
  E2E_PROXY_PORT            singlink mixed inbound port. Default: 18082.
  E2E_HTTP_PORT             local HTTP target port. Default: 18083.
  E2E_KEEP_FIXTURES         Keep DB node/user fixtures after success. Default: 1.
EOF
}

cleanup() {
  local status=$?
  set +e

  for pid in "${SINGLINK_PID}" "${SHOES_PID}" "${HTTP_PID}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
    fi
  done

  for pid in "${SINGLINK_PID}" "${SHOES_PID}" "${HTTP_PID}"; do
    if [[ -n "${pid}" ]]; then
      wait "${pid}" 2>/dev/null || true
    fi
  done

  if [[ "${status}" -ne 0 && -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    e2e_warn "temporary logs kept for failure analysis: ${TMP_DIR}"
    e2e_warn "shoes log: ${TMP_DIR}/shoes.log"
    e2e_warn "singlink log: ${TMP_DIR}/singlink.log"
    e2e_warn "http log: ${TMP_DIR}/http.log"
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
  local timeout="${3:-10}"
  local start
  local now

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
    if [[ -n "${SINGLINK_PID}" ]] && ! kill -0 "${SINGLINK_PID}" 2>/dev/null; then
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

  e2e_log "SHOES_BIN=${SHOES_BIN}"
  e2e_log "SINGLINK_BIN=${SINGLINK_BIN}"
}

check_environment() {
  e2e_section "environment"
  e2e_require_dir "${V2BOARD_DOCKER_DIR}" "v2board-docker checkout"
  e2e_require_dir "${V2BOARD_DIR}" "v2board checkout"

  docker ps --format '{{.Names}}' | grep -Fxq "${V2BOARD_MYSQL_CONTAINER}" \
    || e2e_die "missing running mysql container: ${V2BOARD_MYSQL_CONTAINER}"
  docker ps --format '{{.Names}}' | grep -Fxq "${V2BOARD_WWW_CONTAINER}" \
    || e2e_die "missing running www container: ${V2BOARD_WWW_CONTAINER}"

  e2e_http_probe "${V2BOARD_PANEL_URL}" >/dev/null \
    || e2e_die "panel is not reachable: ${V2BOARD_PANEL_URL}"
}

seed_fixtures() {
  local now
  local expires_at

  now="$(date +%s)"
  expires_at="$((now + 86400))"

  e2e_section "seed v2board fixtures"
  mysql_exec <<SQL
INSERT INTO v2_server_vmess
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tags, rate, network, rules, networkSettings, tlsSettings, ruleSettings, dnsSettings, \`show\`, sort, created_at, updated_at)
VALUES
(${E2E_NODE_ID}, '["1"]', NULL, 'shoes-e2e-vmess', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_NODE_PORT}', ${E2E_NODE_PORT}, 0, NULL, '1', 'tcp', NULL, '{}', '{}', '{}', '{}', 1, ${E2E_NODE_ID}, ${now}, ${now})
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
  sort=VALUES(sort),
  updated_at=VALUES(updated_at);

INSERT INTO v2_user
(id, invite_user_id, telegram_id, email, language, password, password_algo, password_salt, balance, discount, commission_type, commission_rate, commission_balance, t, u, d, transfer_enable, device_limit, banned, is_admin, last_login_at, is_staff, last_login_ip, uuid, group_id, plan_id, speed_limit, auto_renewal, remind_expire, remind_traffic, token, expired_at, remarks, created_at, updated_at)
VALUES
(${E2E_USER_ID}, NULL, NULL, '${E2E_USER_EMAIL}', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '${E2E_USER_UUID}', 1, NULL, NULL, 0, 1, 1, MD5('${E2E_USER_EMAIL}'), ${expires_at}, 'shoes vmess e2e user', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
  group_id=1,
  speed_limit=NULL,
  device_limit=NULL,
  expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);

DELETE FROM v2_stat_user WHERE user_id=${E2E_USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${E2E_NODE_ID} AND server_type='vmess';
SQL
}

write_configs() {
  local token="$1"

  e2e_section "write runtime configs"
  cat >"${TMP_DIR}/shoes.yml" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${token}"
  nodes:
    - tag: "${E2E_NODE_TAG}"
      node_id: ${E2E_NODE_ID}
      node_type: "vmess"
      listen: "${E2E_BIND_HOST}"
      pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
      push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
runtime:
  data_dir: "${TMP_DIR}/shoes-data"
  pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
  push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
log:
  level: "info"
YAML

  cat >"${TMP_DIR}/singlink.json" <<JSON
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
      "uuid": "${E2E_USER_UUID}",
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
  e2e_section "start local services"
  mkdir -p "${TMP_DIR}/http-root"
  dd if=/dev/zero of="${TMP_DIR}/http-root/payload.bin" bs=1024 count="${E2E_PAYLOAD_KIB}" status=none

  python3 -m http.server "${E2E_HTTP_PORT}" \
    --bind "${E2E_BIND_HOST}" \
    --directory "${TMP_DIR}/http-root" \
    >"${TMP_DIR}/http.log" 2>&1 &
  HTTP_PID=$!
  wait_for_listen_port "${E2E_HTTP_PORT}" "http target" 10

  "${SHOES_BIN}" run -c "${TMP_DIR}/shoes.yml" >"${TMP_DIR}/shoes.log" 2>&1 &
  SHOES_PID=$!
  wait_for_listen_port "${E2E_NODE_PORT}" "shoes" 15

  "${SINGLINK_BIN}" -c "${TMP_DIR}/singlink.json" check >"${TMP_DIR}/singlink-check.log" 2>&1
  "${SINGLINK_BIN}" -c "${TMP_DIR}/singlink.json" run >"${TMP_DIR}/singlink.log" 2>&1 &
  SINGLINK_PID=$!
  wait_for_listen_port "${E2E_PROXY_PORT}" "singlink" 15
}

run_traffic_check() {
  local expected_min
  local stat_user
  local stat_server
  local user_totals
  local user_u
  local user_d
  local stat_user_u
  local stat_user_d
  local stat_server_u
  local stat_server_d

  e2e_section "proxy traffic"
  curl -fsS \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${E2E_PROXY_PORT}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/payload.bin" \
    -o "${TMP_DIR}/download.bin"

  expected_min="$((E2E_PAYLOAD_KIB * 1024))"
  [[ "$(wc -c <"${TMP_DIR}/download.bin")" -eq "${expected_min}" ]] \
    || e2e_die "download size mismatch"

  e2e_log "waiting ${E2E_PUSH_WAIT_SECS}s for shoes push"
  sleep "${E2E_PUSH_WAIT_SECS}"

  stat_user="$(mysql_query "SELECT COALESCE(SUM(u),0), COALESCE(SUM(d),0) FROM v2_stat_user WHERE user_id=${E2E_USER_ID};")"
  stat_server="$(mysql_query "SELECT COALESCE(SUM(u),0), COALESCE(SUM(d),0) FROM v2_stat_server WHERE server_id=${E2E_NODE_ID} AND server_type='vmess';")"
  read -r stat_user_u stat_user_d <<<"${stat_user}"
  read -r stat_server_u stat_server_d <<<"${stat_server}"

  ((stat_user_d >= expected_min)) \
    || e2e_die "v2_stat_user download too small: got ${stat_user_d}, expected at least ${expected_min}"
  ((stat_server_d >= expected_min)) \
    || e2e_die "v2_stat_server download too small: got ${stat_server_d}, expected at least ${expected_min}"

  docker exec "${V2BOARD_WWW_CONTAINER}" php artisan traffic:update >/dev/null
  user_totals="$(mysql_query "SELECT u,d FROM v2_user WHERE id=${E2E_USER_ID};")"
  read -r user_u user_d <<<"${user_totals}"
  ((user_d >= expected_min)) \
    || e2e_die "v2_user download too small after traffic:update: got ${user_d}, expected at least ${expected_min}"

  e2e_log "v2_user ${E2E_USER_ID}: u=${user_u} d=${user_d}"
  e2e_log "v2_stat_user ${E2E_USER_ID}: u=${stat_user_u} d=${stat_user_d}"
  e2e_log "v2_stat_server ${E2E_NODE_ID}/vmess: u=${stat_server_u} d=${stat_server_d}"
}

maybe_cleanup_fixtures() {
  if e2e_env_bool E2E_KEEP_FIXTURES 1; then
    e2e_log "keeping E2E fixtures: node=${E2E_NODE_ID}, user=${E2E_USER_ID}"
    return
  fi

  e2e_section "cleanup fixtures"
  mysql_exec <<SQL
DELETE FROM v2_stat_user WHERE user_id=${E2E_USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${E2E_NODE_ID} AND server_type='vmess';
DELETE FROM v2_user WHERE id=${E2E_USER_ID};
DELETE FROM v2_server_vmess WHERE id=${E2E_NODE_ID};
SQL
}

main() {
  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1

  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-vmess-e2e.XXXXXX)"

  check_environment
  resolve_binaries

  local token
  token="$(discover_server_token)"
  [[ -n "${token}" ]] || e2e_die "could not discover V2Board server token"

  seed_fixtures
  write_configs "${token}"
  start_services
  run_traffic_check
  maybe_cleanup_fixtures

  e2e_section "done"
}

main "$@"
