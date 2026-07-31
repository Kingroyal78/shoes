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
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18093}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-5}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-5}"
E2E_WAIT_TIMEOUT_SECS="${E2E_WAIT_TIMEOUT_SECS:-45}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_SHOES_LOG_LEVEL="${E2E_SHOES_LOG_LEVEL:-debug}"
E2E_SINGLINK_LOG_LEVEL="${E2E_SINGLINK_LOG_LEVEL:-debug}"
E2E_CURL_CONNECT_TIMEOUT_SECS="${E2E_CURL_CONNECT_TIMEOUT_SECS:-5}"
E2E_CURL_MAX_TIME_SECS="${E2E_CURL_MAX_TIME_SECS:-60}"

TMP_DIR=""
HTTP_PID=""
SHOES_PID=""
SINGLINK_PIDS=()
SERVER_TOKEN=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_policy.sh

Runs real V2Board policy E2E checks:
  - speed_limit: VMess user capped at 1 Mbps must throttle a 1 MiB transfer.
  - device_limit: VMess user capped at 1 distinct source IP rejects a second
    concurrent connection from another loopback source address.
  - V2Node VMess repeats speed/device checks through /api/v2/server/config and
    verifies server_type=v2node reporting.
EOF
}

cleanup() {
  local status=$?
  set +e
  stop_singlink
  stop_shoes
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
    if [[ -n "${HTTP_PID}" ]] && ! kill -0 "${HTTP_PID}" 2>/dev/null; then
      e2e_die "${label} process exited before listening on ${port}"
    fi
    if [[ -n "${SHOES_PID}" ]] && ! kill -0 "${SHOES_PID}" 2>/dev/null; then
      e2e_die "${label} process exited before listening on ${port}"
    fi
    for pid in "${SINGLINK_PIDS[@]:-}"; do
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

start_policy_http() {
  e2e_section "start policy http target"
  e2e_assert_port_free "${E2E_HTTP_PORT}" "policy http target"
  cat >"${TMP_DIR}/policy_http.py" <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys
import time

FAST_SIZE = 1024 * 1024
SLOW_SIZE = 8 * 1024 * 1024
CHUNK = 16 * 1024

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        print(f"{self.client_address[0]}:{self.client_address[1]} {self.path}", file=sys.stderr, flush=True)
        if self.path == "/slow.bin":
            self.send_response(200)
            self.send_header("Content-Length", str(SLOW_SIZE))
            self.end_headers()
            sent = 0
            while sent < SLOW_SIZE:
                n = min(CHUNK, SLOW_SIZE - sent)
                self.wfile.write(b"\0" * n)
                self.wfile.flush()
                sent += n
                time.sleep(0.05)
            return

        self.send_response(200)
        self.send_header("Content-Length", str(FAST_SIZE))
        self.end_headers()
        remaining = FAST_SIZE
        while remaining:
            n = min(CHUNK, remaining)
            self.wfile.write(b"\0" * n)
            remaining -= n

ThreadingHTTPServer((sys.argv[1], int(sys.argv[2])), Handler).serve_forever()
PY
  python3 "${TMP_DIR}/policy_http.py" "${E2E_BIND_HOST}" "${E2E_HTTP_PORT}" >"${TMP_DIR}/http.log" 2>&1 &
  HTTP_PID=$!
  wait_for_listen_port "${E2E_HTTP_PORT}" "policy http target" 10
}

seed_vmess_fixture() {
  local case_name="$1"
  local node_id="$2"
  local user_id="$3"
  local uuid="$4"
  local port="$5"
  local speed_limit="${6:-NULL}"
  local device_limit="${7:-NULL}"
  local now
  local expires_at

  now="$(date +%s)"
  expires_at="$((now + 86400))"

  mysql_exec <<SQL
INSERT INTO v2_server_vmess
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tags, rate, network, rules, networkSettings, tlsSettings, ruleSettings, dnsSettings, \`show\`, sort, created_at, updated_at)
VALUES
(${node_id}, '["1"]', NULL, 'shoes-policy-${case_name}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${port}', ${port}, 0, NULL, '1', 'tcp', NULL, '{}', '{}', '{}', '{}', 1, ${node_id}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  tls=VALUES(tls),
  network=VALUES(network),
  \`show\`=VALUES(\`show\`),
  updated_at=VALUES(updated_at);

INSERT INTO v2_user
(id, invite_user_id, telegram_id, email, language, password, password_algo, password_salt, balance, discount, commission_type, commission_rate, commission_balance, t, u, d, transfer_enable, device_limit, banned, is_admin, last_login_at, is_staff, last_login_ip, uuid, group_id, plan_id, speed_limit, auto_renewal, remind_expire, remind_traffic, token, expired_at, remarks, created_at, updated_at)
VALUES
(${user_id}, NULL, NULL, 'shoes-policy-${case_name}@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, ${device_limit}, 0, 0, NULL, 0, NULL, '${uuid}', 1, NULL, ${speed_limit}, 0, 1, 1, MD5('shoes-policy-${case_name}@example.local'), ${expires_at}, 'shoes policy ${case_name} e2e user', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
  group_id=1,
  speed_limit=VALUES(speed_limit),
  device_limit=VALUES(device_limit),
  expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);

DELETE FROM v2_stat_user WHERE user_id=${user_id};
DELETE FROM v2_stat_server WHERE server_id=${node_id} AND server_type='vmess';
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${user_id}"
}

seed_v2node_vmess_fixture() {
  local case_name="$1"
  local node_id="$2"
  local user_id="$3"
  local uuid="$4"
  local port="$5"
  local speed_limit="${6:-NULL}"
  local device_limit="${7:-NULL}"
  local now
  local expires_at

  now="$(date +%s)"
  expires_at="$((now + 86400))"

  mysql_exec <<SQL
INSERT INTO v2_server_v2node
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, listen_ip, port, server_port, tags, rate, \`show\`, sort, protocol, tls, tls_settings, flow, network, network_settings, encryption, encryption_settings, disable_sni, udp_relay_mode, zero_rtt_handshake, congestion_control, cipher, up_mbps, down_mbps, obfs, obfs_password, padding_scheme, created_at, updated_at)
VALUES
(${node_id}, '["1"]', NULL, 'shoes-policy-${case_name}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_BIND_HOST}', '${port}', ${port}, NULL, '1', 1, ${node_id}, 'vmess', 0, '{}', NULL, 'tcp', '{}', NULL, '{}', 0, NULL, 0, NULL, 'auto', 0, 0, NULL, NULL, NULL, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  listen_ip=VALUES(listen_ip),
  port=VALUES(port),
  server_port=VALUES(server_port),
  protocol=VALUES(protocol),
  tls=VALUES(tls),
  network=VALUES(network),
  network_settings=VALUES(network_settings),
  cipher=VALUES(cipher),
  \`show\`=VALUES(\`show\`),
  updated_at=VALUES(updated_at);

INSERT INTO v2_user
(id, invite_user_id, telegram_id, email, language, password, password_algo, password_salt, balance, discount, commission_type, commission_rate, commission_balance, t, u, d, transfer_enable, device_limit, banned, is_admin, last_login_at, is_staff, last_login_ip, uuid, group_id, plan_id, speed_limit, auto_renewal, remind_expire, remind_traffic, token, expired_at, remarks, created_at, updated_at)
VALUES
(${user_id}, NULL, NULL, 'shoes-policy-${case_name}@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, ${device_limit}, 0, 0, NULL, 0, NULL, '${uuid}', 1, NULL, ${speed_limit}, 0, 1, 1, MD5('shoes-policy-${case_name}@example.local'), ${expires_at}, 'shoes policy ${case_name} e2e user', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
  group_id=1,
  speed_limit=VALUES(speed_limit),
  device_limit=VALUES(device_limit),
  expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);

DELETE FROM v2_stat_user WHERE user_id=${user_id};
DELETE FROM v2_stat_server WHERE server_id=${node_id} AND server_type='v2node';
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${user_id}"
}

write_shoes_config() {
  local case_name="$1"
  local node_id="$2"
  local port="$3"
  local node_type="${4:-vmess}"

  cat >"${TMP_DIR}/${case_name}.shoes.yml" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${SERVER_TOKEN}"
  nodes:
    - tag: "${case_name}"
      node_id: ${node_id}
      node_type: "${node_type}"
      listen: "${E2E_BIND_HOST}"
      pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
      push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
runtime:
  data_dir: "${TMP_DIR}/${case_name}-shoes-data"
  pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
  push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
log:
  level: "${E2E_SHOES_LOG_LEVEL}"
YAML

  "${SHOES_BIN}" sync-once -c "${TMP_DIR}/${case_name}.shoes.yml" >"${TMP_DIR}/${case_name}.sync.log" 2>&1
  e2e_assert_port_free "${port}" "shoes ${case_name}"
  "${SHOES_BIN}" run -c "${TMP_DIR}/${case_name}.shoes.yml" >"${TMP_DIR}/${case_name}.shoes.log" 2>&1 &
  SHOES_PID=$!
  wait_for_listen_port "${port}" "shoes ${case_name}" 15
}

write_singlink_config() {
  local case_name="$1"
  local uuid="$2"
  local node_port="$3"
  local proxy_port="$4"
  local bind_addr="${5:-}"
  local bind_json=""

  if [[ -n "${bind_addr}" ]]; then
    bind_json=", \"inet4_bind_address\": \"${bind_addr}\""
  fi

  cat >"${TMP_DIR}/${case_name}-${proxy_port}.singlink.json" <<JSON
{
  "log": {"level": "${E2E_SINGLINK_LOG_LEVEL}", "timestamp": true},
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "${E2E_BIND_HOST}",
      "listen_port": ${proxy_port}
    }
  ],
  "outbounds": [
    {
      "type": "vmess",
      "tag": "vmess-out",
      "server": "${E2E_BIND_HOST}",
      "server_port": ${node_port},
      "uuid": "${uuid}",
      "security": "auto",
      "alter_id": 0,
      "network": "tcp"${bind_json}
    }
  ],
  "route": {"final": "vmess-out"}
}
JSON
}

start_singlink() {
  local case_name="$1"
  local proxy_port="$2"

  "${SINGLINK_BIN}" -c "${TMP_DIR}/${case_name}-${proxy_port}.singlink.json" check \
    >"${TMP_DIR}/${case_name}-${proxy_port}.singlink-check.log" 2>&1
  e2e_assert_port_free "${proxy_port}" "singlink ${case_name}/${proxy_port}"
  "${SINGLINK_BIN}" -c "${TMP_DIR}/${case_name}-${proxy_port}.singlink.json" run \
    >"${TMP_DIR}/${case_name}-${proxy_port}.singlink.log" 2>&1 &
  SINGLINK_PIDS+=("$!")
  wait_for_listen_port "${proxy_port}" "singlink ${case_name}/${proxy_port}" 15
}

stop_singlink() {
  local pid
  for pid in "${SINGLINK_PIDS[@]:-}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  SINGLINK_PIDS=()
}

stop_shoes() {
  if [[ -n "${SHOES_PID}" ]] && kill -0 "${SHOES_PID}" 2>/dev/null; then
    kill "${SHOES_PID}" 2>/dev/null || true
    wait "${SHOES_PID}" 2>/dev/null || true
  fi
  SHOES_PID=""
}

wait_for_policy_download() {
  local user_id="$1"
  local node_id="$2"
  local expected_min="$3"
  local server_type="${4:-vmess}"
  local start
  local now
  local user_totals
  local stat_user
  local stat_server
  local user_u
  local user_d
  local stat_user_u
  local stat_user_d
  local stat_server_u
  local stat_server_d

  e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"
  docker exec "${V2BOARD_WWW_CONTAINER}" php artisan traffic:update >/dev/null
  start="$(date +%s)"
  while true; do
    e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"
    docker exec "${V2BOARD_WWW_CONTAINER}" php artisan traffic:update >/dev/null
    user_totals="$(mysql_query "SELECT u,d FROM v2_user WHERE id=${user_id};")"
    stat_user="$(mysql_query "SELECT COALESCE(SUM(u),0), COALESCE(SUM(d),0) FROM v2_stat_user WHERE user_id=${user_id};")"
    stat_server="$(mysql_query "SELECT COALESCE(SUM(u),0), COALESCE(SUM(d),0) FROM v2_stat_server WHERE server_id=${node_id} AND server_type='${server_type}';")"
    read -r user_u user_d <<<"${user_totals}"
    read -r stat_user_u stat_user_d <<<"${stat_user}"
    read -r stat_server_u stat_server_d <<<"${stat_server}"
    if ((user_d >= expected_min && stat_user_d >= expected_min && stat_server_d >= expected_min)); then
      e2e_log "policy server_type=${server_type} user=${user_u}/${user_d} stat_user=${stat_user_u}/${stat_user_d} stat_server=${stat_server_u}/${stat_server_d}"
      return
    fi
    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_die "user ${user_id} download did not reach ${expected_min}; user=${user_u}/${user_d} stat_user=${stat_user_u}/${stat_user_d} stat_server=${stat_server_u}/${stat_server_d}"
    fi
    sleep 1
  done
}

run_speed_limit_case() {
  local case_name=speed_limit
  local node_id=9501
  local user_id=19501
  local uuid=55555555-5555-4555-8555-555555555501
  local node_port=18141
  local proxy_port=18241
  local start
  local end
  local elapsed_ms

  e2e_section "policy speed_limit"
  seed_vmess_fixture "${case_name}" "${node_id}" "${user_id}" "${uuid}" "${node_port}" 1 NULL
  write_shoes_config "${case_name}" "${node_id}" "${node_port}"
  write_singlink_config "${case_name}" "${uuid}" "${node_port}" "${proxy_port}"
  start_singlink "${case_name}" "${proxy_port}"

  start="$(now_ms)"
  curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${proxy_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    -o "${TMP_DIR}/${case_name}.bin"
  end="$(now_ms)"
  elapsed_ms="$((end - start))"

  [[ "$(wc -c <"${TMP_DIR}/${case_name}.bin")" -eq 1048576 ]] \
    || e2e_die "speed_limit download size mismatch"
  ((elapsed_ms >= 5000)) \
    || e2e_die "speed_limit did not throttle enough: elapsed ${elapsed_ms}ms, expected >= 5000ms"
  wait_for_policy_download "${user_id}" "${node_id}" 1048576
  e2e_log "speed_limit elapsed=${elapsed_ms}ms"

  stop_singlink
  stop_shoes
}

run_v2node_speed_limit_case() {
  local case_name=v2node_speed_limit
  local node_id=9503
  local user_id=19503
  local uuid=55555555-5555-4555-8555-555555555503
  local node_port=18501
  local proxy_port=18601
  local start
  local end
  local elapsed_ms

  e2e_section "policy v2node_speed_limit"
  seed_v2node_vmess_fixture "${case_name}" "${node_id}" "${user_id}" "${uuid}" "${node_port}" 1 NULL
  write_shoes_config "${case_name}" "${node_id}" "${node_port}" v2node
  write_singlink_config "${case_name}" "${uuid}" "${node_port}" "${proxy_port}"
  start_singlink "${case_name}" "${proxy_port}"

  start="$(now_ms)"
  curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${proxy_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    -o "${TMP_DIR}/${case_name}.bin"
  end="$(now_ms)"
  elapsed_ms="$((end - start))"

  [[ "$(wc -c <"${TMP_DIR}/${case_name}.bin")" -eq 1048576 ]] \
    || e2e_die "v2node_speed_limit download size mismatch"
  ((elapsed_ms >= 5000)) \
    || e2e_die "v2node_speed_limit did not throttle enough: elapsed ${elapsed_ms}ms, expected >= 5000ms"
  wait_for_policy_download "${user_id}" "${node_id}" 1048576 v2node
  e2e_log "v2node_speed_limit elapsed=${elapsed_ms}ms"

  stop_singlink
  stop_shoes
}

run_device_limit_case() {
  local case_name=device_limit
  local node_id=9502
  local user_id=19502
  local uuid=55555555-5555-4555-8555-555555555502
  local node_port=18142
  local proxy_a=18242
  local proxy_b=18243
  local slow_pid

  e2e_section "policy device_limit"
  seed_vmess_fixture "${case_name}" "${node_id}" "${user_id}" "${uuid}" "${node_port}" NULL 1
  write_shoes_config "${case_name}" "${node_id}" "${node_port}"
  write_singlink_config "${case_name}" "${uuid}" "${node_port}" "${proxy_a}" "127.0.0.1"
  write_singlink_config "${case_name}" "${uuid}" "${node_port}" "${proxy_b}" "127.0.0.2"
  start_singlink "${case_name}" "${proxy_a}"
  start_singlink "${case_name}" "${proxy_b}"

  curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${proxy_a}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/slow.bin" \
    -o "${TMP_DIR}/${case_name}-slow.bin" &
  slow_pid=$!

  sleep 1
  kill -0 "${slow_pid}" 2>/dev/null || e2e_die "first slow device-limit connection exited too early"

  if curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time 8 \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${proxy_b}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    -o "${TMP_DIR}/${case_name}-second.bin"; then
    kill "${slow_pid}" 2>/dev/null || true
    wait "${slow_pid}" 2>/dev/null || true
    e2e_die "device_limit allowed a second concurrent source IP"
  fi

  kill "${slow_pid}" 2>/dev/null || true
  wait "${slow_pid}" 2>/dev/null || true

  grep -q "device limit exceeded for user ${user_id}" "${TMP_DIR}/${case_name}.shoes.log" \
    || e2e_die "device_limit rejection was not observed in shoes log"
  e2e_log "device_limit rejected second source IP as expected"

  stop_singlink
  stop_shoes
}

run_v2node_device_limit_case() {
  local case_name=v2node_device_limit
  local node_id=9504
  local user_id=19504
  local uuid=55555555-5555-4555-8555-555555555504
  local node_port=18502
  local proxy_a=18602
  local proxy_b=18603
  local slow_pid

  e2e_section "policy v2node_device_limit"
  seed_v2node_vmess_fixture "${case_name}" "${node_id}" "${user_id}" "${uuid}" "${node_port}" NULL 1
  write_shoes_config "${case_name}" "${node_id}" "${node_port}" v2node
  write_singlink_config "${case_name}" "${uuid}" "${node_port}" "${proxy_a}" "127.0.0.1"
  write_singlink_config "${case_name}" "${uuid}" "${node_port}" "${proxy_b}" "127.0.0.2"
  start_singlink "${case_name}" "${proxy_a}"
  start_singlink "${case_name}" "${proxy_b}"

  curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${proxy_a}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/slow.bin" \
    -o "${TMP_DIR}/${case_name}-slow.bin" &
  slow_pid=$!

  sleep 1
  kill -0 "${slow_pid}" 2>/dev/null || e2e_die "first v2node device-limit connection exited too early"

  if curl -fsS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time 8 \
    --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${proxy_b}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    -o "${TMP_DIR}/${case_name}-second.bin"; then
    kill "${slow_pid}" 2>/dev/null || true
    wait "${slow_pid}" 2>/dev/null || true
    e2e_die "v2node_device_limit allowed a second concurrent source IP"
  fi

  kill "${slow_pid}" 2>/dev/null || true
  wait "${slow_pid}" 2>/dev/null || true

  grep -q "device limit exceeded for user ${user_id}" "${TMP_DIR}/${case_name}.shoes.log" \
    || e2e_die "v2node_device_limit rejection was not observed in shoes log"
  e2e_log "v2node_device_limit rejected second source IP as expected"

  stop_singlink
  stop_shoes
}

maybe_cleanup_fixtures() {
  if e2e_env_bool E2E_KEEP_FIXTURES 1; then
    e2e_log "keeping policy E2E fixtures"
    return
  fi

  mysql_exec <<SQL
DELETE su FROM v2_stat_user su JOIN v2_user u ON u.id=su.user_id WHERE u.email LIKE 'shoes-policy-%@example.local';
DELETE ss FROM v2_stat_server ss JOIN v2_server_vmess n ON ss.server_type='vmess' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-policy-%';
DELETE ss FROM v2_stat_server ss JOIN v2_server_v2node n ON ss.server_type='v2node' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-policy-%';
DELETE FROM v2_user WHERE email LIKE 'shoes-policy-%@example.local';
DELETE FROM v2_server_vmess WHERE name LIKE 'shoes-policy-%';
DELETE FROM v2_server_v2node WHERE name LIKE 'shoes-policy-%';
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19501
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19502
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19503
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19504
}

main() {
  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-policy-e2e.XXXXXX)"

  check_environment
  resolve_binaries
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"
  start_policy_http
  run_speed_limit_case
  run_device_limit_case
  run_v2node_speed_limit_case
  run_v2node_device_limit_case
  maybe_cleanup_fixtures
  e2e_section "done"
}

main "$@"
