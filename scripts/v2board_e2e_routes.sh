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
E2E_HTTP_ALLOWED_PORT="${E2E_HTTP_ALLOWED_PORT:-18101}"
E2E_HTTP_BLOCKED_PORT="${E2E_HTTP_BLOCKED_PORT:-18102}"
E2E_HTTP_COLON_RANGE_PORT="${E2E_HTTP_COLON_RANGE_PORT:-18103}"
E2E_NODE_PORT="${E2E_NODE_PORT:-18191}"
E2E_PROXY_PORT="${E2E_PROXY_PORT:-18291}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-2}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-2}"
E2E_WAIT_TIMEOUT_SECS="${E2E_WAIT_TIMEOUT_SECS:-45}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_CURL_CONNECT_TIMEOUT_SECS="${E2E_CURL_CONNECT_TIMEOUT_SECS:-3}"
E2E_CURL_MAX_TIME_SECS="${E2E_CURL_MAX_TIME_SECS:-15}"

GROUP_ID=9904
NODE_ID=9904
USER_ID=19904
USER_UUID=99999999-9999-4999-8999-999999999904
ROUTE_DOMAIN_ID=9904
ROUTE_PORT_ID=9905
ROUTE_UNSUPPORTED_ID=9906
ROUTE_REGEX_ID=9907
ROUTE_GEOSITE_ID=9908
ROUTE_GEOIP_ID=9909
ROUTE_PROTOCOL_ID=9910
ROUTE_BLOCK_PROTOCOL_ID=9911
ROUTE_PORT_COLON_ID=9912
ROUTE_UNSUPPORTED_DNS_ID=9913
ROUTE_UNSUPPORTED_ROUTE_IP_ID=9914
ROUTE_UNSUPPORTED_DEFAULT_OUT_ID=9915

TMP_DIR=""
HTTP_PIDS=()
SHOES_PID=""
SINGLINK_PID=""
SERVER_TOKEN=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_routes.sh

Runs real V2Board route_id E2E checks:
  - domain block routes reject matching hostname targets
  - regexp domain block routes reject matching hostname targets
  - geosite/geoip rule-set routes load local operator-managed files
  - protocol block routes sniff HTTP payloads and reject matching traffic
  - block routes with protocol: matchers sniff and reject matching traffic
  - port block routes reject matching destination ports
  - unsupported Xray outbound routes fail sync-once instead of silently allowing
EOF
}

cleanup() {
  local status=$?
  set +e
  stop_services
  stop_http_targets

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
    if [[ -n "${SHOES_PID}" ]] && ! kill -0 "${SHOES_PID}" 2>/dev/null; then
      e2e_die "${label} process exited before listening on ${port}"
    fi
    if [[ -n "${SINGLINK_PID}" ]] && ! kill -0 "${SINGLINK_PID}" 2>/dev/null; then
      e2e_die "${label} process exited before listening on ${port}"
    fi
    for pid in "${HTTP_PIDS[@]:-}"; do
      if [[ -n "${pid}" ]] && ! kill -0 "${pid}" 2>/dev/null; then
        e2e_die "${label} http target exited before listening on ${port}"
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
  docker ps --format '{{.Names}}' | grep -Fxq "${V2BOARD_REDIS_CONTAINER}" \
    || e2e_die "missing running redis container: ${V2BOARD_REDIS_CONTAINER}"
  e2e_http_probe "${V2BOARD_PANEL_URL}" >/dev/null \
    || e2e_die "panel is not reachable: ${V2BOARD_PANEL_URL}"
}

start_http_target() {
  local port="$1"
  local label="$2"

  e2e_assert_port_free "${port}" "${label}"
  python3 - "${E2E_BIND_HOST}" "${port}" >"${TMP_DIR}/${label}.http.log" 2>&1 <<'PY' &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys

PAYLOAD = b"route-ok\n" * 4096

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

ThreadingHTTPServer((sys.argv[1], int(sys.argv[2])), Handler).serve_forever()
PY
  HTTP_PIDS+=("$!")
  wait_for_listen_port "${port}" "${label}" 10
}

start_http_targets() {
  e2e_section "start route http targets"
  start_http_target "${E2E_HTTP_ALLOWED_PORT}" "route-allowed"
  start_http_target "${E2E_HTTP_BLOCKED_PORT}" "route-blocked"
  start_http_target "${E2E_HTTP_COLON_RANGE_PORT}" "route-colon-range"
}

stop_http_targets() {
  local pid

  for pid in "${HTTP_PIDS[@]:-}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  HTTP_PIDS=()
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
(${GROUP_ID}, 'shoes-route-user', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  updated_at=VALUES(updated_at);

INSERT INTO v2_server_route
(id, remarks, \`match\`, action, action_value, created_at, updated_at)
VALUES
(${ROUTE_DOMAIN_ID}, 'shoes route domain block', '["blocked-route.example"]', 'block', NULL, ${now}, ${now}),
(${ROUTE_PORT_ID}, 'shoes route port block', '["${E2E_HTTP_BLOCKED_PORT}"]', 'block_port', NULL, ${now}, ${now}),
(${ROUTE_PORT_COLON_ID}, 'shoes route port colon range block', '["${E2E_HTTP_BLOCKED_PORT}:${E2E_HTTP_COLON_RANGE_PORT}"]', 'block_port', NULL, ${now}, ${now}),
(${ROUTE_UNSUPPORTED_ID}, 'shoes route unsupported outbound', '["example.com"]', 'route', '{"protocol":"freedom"}', ${now}, ${now}),
(${ROUTE_UNSUPPORTED_DNS_ID}, 'shoes route unsupported dns', '["example.com"]', 'dns', '{"server":"8.8.8.8"}', ${now}, ${now}),
(${ROUTE_UNSUPPORTED_ROUTE_IP_ID}, 'shoes route unsupported route ip', '["203.0.113.0/24"]', 'route_ip', '{"protocol":"freedom"}', ${now}, ${now}),
(${ROUTE_UNSUPPORTED_DEFAULT_OUT_ID}, 'shoes route unsupported default out', '["all"]', 'default_out', '{"protocol":"freedom"}', ${now}, ${now}),
(${ROUTE_REGEX_ID}, 'shoes route regex block', '["regexp:^cdn-[0-9]+\\\\.regex-route\\\\.example$"]', 'block', NULL, ${now}, ${now}),
(${ROUTE_GEOSITE_ID}, 'shoes route geosite block', '["geosite:local"]', 'block', NULL, ${now}, ${now}),
(${ROUTE_GEOIP_ID}, 'shoes route geoip block', '["geoip:local"]', 'block_ip', NULL, ${now}, ${now}),
(${ROUTE_PROTOCOL_ID}, 'shoes route protocol http block', '["http"]', 'protocol', NULL, ${now}, ${now}),
(${ROUTE_BLOCK_PROTOCOL_ID}, 'shoes route block protocol http', '["protocol:http"]', 'block', NULL, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  remarks=VALUES(remarks),
  \`match\`=VALUES(\`match\`),
  action=VALUES(action),
  action_value=VALUES(action_value),
  updated_at=VALUES(updated_at);

INSERT INTO v2_server_vmess
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tags, rate, network, rules, networkSettings, tlsSettings, ruleSettings, dnsSettings, \`show\`, sort, created_at, updated_at)
VALUES
(${NODE_ID}, '["${GROUP_ID}"]', '["${ROUTE_DOMAIN_ID}"]', 'shoes-route-user', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_NODE_PORT}', ${E2E_NODE_PORT}, 0, NULL, '1', 'tcp', NULL, '{}', '{}', '{}', '{}', 1, ${NODE_ID}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  route_id=VALUES(route_id),
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
(${USER_ID}, NULL, NULL, 'shoes-route-user@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '${USER_UUID}', ${GROUP_ID}, NULL, NULL, 0, 1, 1, MD5('shoes-route-user@example.local'), ${expires_at}, 'shoes route e2e', ${now}, ${now})
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

write_route_rule_sets() {
  cat >"${TMP_DIR}/geosite-local.txt" <<'EOF'
# Local V2Board route rule-set fixture.
domain:geosite-route.example
full:api.geosite-route.local
regexp:^cdn-[0-9]+\.geosite-route\.example$
EOF

  cat >"${TMP_DIR}/geoip-local.txt" <<'EOF'
# Local V2Board route rule-set fixture.
127.0.0.1/32
2001:db8::/32
EOF
}

set_node_route() {
  local route_id="$1"

  mysql_exec <<SQL
UPDATE v2_server_vmess
SET route_id='["${route_id}"]', updated_at=$(date +%s)
WHERE id=${NODE_ID};
SQL
}

write_configs() {
  cat >"${TMP_DIR}/routes.shoes.yml" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${SERVER_TOKEN}"
  route_rule_sets:
    geosite:
      local: "${TMP_DIR}/geosite-local.txt"
    geoip:
      local: "${TMP_DIR}/geoip-local.txt"
  nodes:
    - tag: "route_user"
      node_id: ${NODE_ID}
      node_type: "vmess"
      listen: "${E2E_BIND_HOST}"
      pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
      push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
runtime:
  data_dir: "${TMP_DIR}/routes-shoes-data"
  pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
  push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
  node_report_min_traffic: 0
  device_online_min_traffic: 0
log:
  level: "debug"
YAML

  cat >"${TMP_DIR}/routes.singlink.json" <<JSON
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
  "${SHOES_BIN}" sync-once -c "${TMP_DIR}/routes.shoes.yml" >"${TMP_DIR}/routes.sync.log" 2>&1
  e2e_assert_port_free "${E2E_NODE_PORT}" "route shoes"
  "${SHOES_BIN}" run -c "${TMP_DIR}/routes.shoes.yml" >"${TMP_DIR}/routes.shoes.log" 2>&1 &
  SHOES_PID=$!
  wait_for_listen_port "${E2E_NODE_PORT}" "route shoes" 15

  "${SINGLINK_BIN}" -c "${TMP_DIR}/routes.singlink.json" check >"${TMP_DIR}/routes.singlink-check.log" 2>&1
  e2e_assert_port_free "${E2E_PROXY_PORT}" "route singlink"
  "${SINGLINK_BIN}" -c "${TMP_DIR}/routes.singlink.json" run >"${TMP_DIR}/routes.singlink.log" 2>&1 &
  SINGLINK_PID=$!
  wait_for_listen_port "${E2E_PROXY_PORT}" "route singlink" 15
}

stop_services() {
  if [[ -n "${SINGLINK_PID}" ]] && kill -0 "${SINGLINK_PID}" 2>/dev/null; then
    kill "${SINGLINK_PID}" 2>/dev/null || true
    wait "${SINGLINK_PID}" 2>/dev/null || true
  fi
  SINGLINK_PID=""
  if [[ -n "${SHOES_PID}" ]] && kill -0 "${SHOES_PID}" 2>/dev/null; then
    kill "${SHOES_PID}" 2>/dev/null || true
    wait "${SHOES_PID}" 2>/dev/null || true
  fi
  SHOES_PID=""
}

curl_expect_success() {
  local url="$1"
  local output="$2"

  curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${E2E_PROXY_PORT}" \
    "${url}" \
    -o "${output}"
  [[ "$(wc -c <"${output}")" -gt 1024 ]] || e2e_die "route allowed download too small for ${url}"
}

curl_expect_blocked() {
  local url="$1"
  local output="$2"

  if curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${E2E_PROXY_PORT}" \
    "${url}" \
    -o "${output}" \
    >"${output}.curl.out" 2>"${output}.curl.err"; then
    e2e_die "route did not block ${url}"
  fi
}

run_domain_block_case() {
  e2e_section "route domain block"
  set_node_route "${ROUTE_DOMAIN_ID}"
  start_services
  curl_expect_blocked \
    "http://blocked-route.example:${E2E_HTTP_ALLOWED_PORT}/payload.bin" \
    "${TMP_DIR}/domain-blocked.bin"
  curl_expect_success \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_ALLOWED_PORT}/payload.bin" \
    "${TMP_DIR}/domain-allowed.bin"
  e2e_log "domain route blocked matching hostname and allowed non-matching target"
  stop_services
}

run_regex_block_case() {
  e2e_section "route regexp block"
  set_node_route "${ROUTE_REGEX_ID}"
  start_services
  curl_expect_blocked \
    "http://cdn-42.regex-route.example:${E2E_HTTP_ALLOWED_PORT}/payload.bin" \
    "${TMP_DIR}/regex-blocked.bin"
  curl_expect_success \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_ALLOWED_PORT}/payload.bin" \
    "${TMP_DIR}/regex-allowed.bin"
  e2e_log "regexp route blocked matching hostname and allowed non-matching target"
  stop_services
}

run_geosite_block_case() {
  e2e_section "route geosite block"
  set_node_route "${ROUTE_GEOSITE_ID}"
  start_services
  curl_expect_blocked \
    "http://cdn-42.geosite-route.example:${E2E_HTTP_ALLOWED_PORT}/payload.bin" \
    "${TMP_DIR}/geosite-blocked.bin"
  curl_expect_success \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_ALLOWED_PORT}/payload.bin" \
    "${TMP_DIR}/geosite-allowed.bin"
  e2e_log "geosite route loaded local rule-set and blocked matching hostname"
  stop_services
}

run_geoip_block_case() {
  e2e_section "route geoip block"
  set_node_route "${ROUTE_GEOIP_ID}"
  start_services
  curl_expect_blocked \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_ALLOWED_PORT}/payload.bin" \
    "${TMP_DIR}/geoip-blocked.bin"
  e2e_log "geoip route loaded local rule-set and blocked matching IP"
  stop_services
}

run_protocol_block_case() {
  e2e_section "route protocol block"
  set_node_route "${ROUTE_PROTOCOL_ID}"
  start_services
  curl_expect_blocked \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_ALLOWED_PORT}/payload.bin" \
    "${TMP_DIR}/protocol-http-blocked.bin"
  e2e_log "protocol route sniffed and blocked HTTP payload"
  stop_services
}

run_block_protocol_prefix_case() {
  e2e_section "route block protocol prefix"
  set_node_route "${ROUTE_BLOCK_PROTOCOL_ID}"
  start_services
  curl_expect_blocked \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_ALLOWED_PORT}/payload.bin" \
    "${TMP_DIR}/block-protocol-http-blocked.bin"
  e2e_log "block route protocol: matcher sniffed and blocked HTTP payload"
  stop_services
}

run_port_block_case() {
  e2e_section "route port block"
  set_node_route "${ROUTE_PORT_ID}"
  start_services
  curl_expect_blocked \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_BLOCKED_PORT}/payload.bin" \
    "${TMP_DIR}/port-blocked.bin"
  curl_expect_success \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_ALLOWED_PORT}/payload.bin" \
    "${TMP_DIR}/port-allowed.bin"
  e2e_log "port route blocked matching destination port and allowed another port"
  stop_services
}

run_port_colon_range_block_case() {
  e2e_section "route port colon range block"
  set_node_route "${ROUTE_PORT_COLON_ID}"
  start_services
  curl_expect_blocked \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_COLON_RANGE_PORT}/payload.bin" \
    "${TMP_DIR}/port-colon-range-blocked.bin"
  curl_expect_success \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_ALLOWED_PORT}/payload.bin" \
    "${TMP_DIR}/port-colon-range-allowed.bin"
  e2e_log "port route blocked colon range destination port and allowed outside range"
  stop_services
}

run_unsupported_route_action_case() {
  local route_id="$1"
  local action="$2"
  local log_file="${TMP_DIR}/routes.unsupported-${action}.sync.log"

  e2e_section "route unsupported action ${action}"
  set_node_route "${route_id}"
  if "${SHOES_BIN}" sync-once -c "${TMP_DIR}/routes.shoes.yml" >"${log_file}" 2>&1; then
    e2e_die "unsupported V2Board route action ${action} unexpectedly passed sync-once"
  fi
  grep -q "route action .*${action}.* is not supported" "${log_file}" \
    || e2e_die "unsupported route sync error for ${action} did not mention unsupported action"
  e2e_log "unsupported route action ${action} failed sync-once as expected"
}

run_unsupported_route_cases() {
  run_unsupported_route_action_case "${ROUTE_UNSUPPORTED_ID}" "route"
  run_unsupported_route_action_case "${ROUTE_UNSUPPORTED_DNS_ID}" "dns"
  run_unsupported_route_action_case "${ROUTE_UNSUPPORTED_ROUTE_IP_ID}" "route_ip"
  run_unsupported_route_action_case "${ROUTE_UNSUPPORTED_DEFAULT_OUT_ID}" "default_out"
}

cleanup_fixtures() {
  if e2e_env_bool E2E_KEEP_FIXTURES 1; then
    e2e_log "keeping route E2E fixtures"
    return
  fi

  e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"

  mysql_exec <<SQL
DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
DELETE FROM v2_user WHERE email='shoes-route-user@example.local';
DELETE FROM v2_server_vmess WHERE name='shoes-route-user';
DELETE FROM v2_server_route WHERE remarks IN ('shoes route domain block', 'shoes route port block', 'shoes route port colon range block', 'shoes route unsupported outbound', 'shoes route unsupported dns', 'shoes route unsupported route ip', 'shoes route unsupported default out', 'shoes route regex block', 'shoes route geosite block', 'shoes route geoip block', 'shoes route protocol http block', 'shoes route block protocol http');
DELETE FROM v2_server_group WHERE name='shoes-route-user';
SQL
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
}

main() {
  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-routes-e2e.XXXXXX)"

  check_environment
  resolve_binaries
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"
  start_http_targets
  seed_fixture
  write_route_rule_sets
  write_configs
  run_domain_block_case
  run_regex_block_case
  run_geosite_block_case
  run_geoip_block_case
  run_protocol_block_case
  run_block_protocol_prefix_case
  run_port_block_case
  run_port_colon_range_block_case
  run_unsupported_route_cases
  cleanup_fixtures
  e2e_section "done"
}

main "$@"
