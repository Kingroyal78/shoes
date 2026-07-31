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

SHOES_BIN="${SHOES_BIN:-}"
E2E_NAIVE_CLIENT_BIN="${E2E_NAIVE_CLIENT_BIN:-${ROOT_DIR}/target/debug/shoes-naiveproxy-e2e-client}"

E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_HTTP_PORT="${E2E_HTTP_PORT:-18095}"
E2E_UDP_ECHO_PORT="${E2E_UDP_ECHO_PORT:-18096}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-5}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-5}"
E2E_WAIT_TIMEOUT_SECS="${E2E_WAIT_TIMEOUT_SECS:-45}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_SHOES_LOG_LEVEL="${E2E_SHOES_LOG_LEVEL:-debug}"
E2E_CLIENT_CONNECT_TIMEOUT_SECS="${E2E_CLIENT_CONNECT_TIMEOUT_SECS:-5}"
E2E_CLIENT_MAX_TIME_SECS="${E2E_CLIENT_MAX_TIME_SECS:-60}"
E2E_TLS_SERVER_NAME="${E2E_TLS_SERVER_NAME:-example.org}"

TMP_DIR=""
HTTP_PID=""
UDP_ECHO_PID=""
SHOES_PID=""
SERVER_TOKEN=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_naiveproxy_policy.sh

Runs real V2Board NaiveProxy policy E2E checks:
  - wrong Basic Auth password fails and records no traffic.
  - speed_limit=1 Mbps throttles a 1 MiB transfer.
  - device_limit=1 rejects a second concurrent source IP.
  - enable_quic=1 starts the V2Board NaiveProxy TCP+H3 dual-stack listener.
  - V2Node protocol=naive pulls config through /api/v2/server/config and
    reports traffic with server_type=v2node for both TCP/H2 and UDP/H3.
  - V2Node NaiveProxy H3 speed_limit and device_limit enforce user policy.

The test client is a feature-gated shoes NaiveProxy E2E binary. It uses real
TLS, HTTP/2 or HTTP/3 CONNECT, and NaiveProxy padding.
EOF
}

cleanup() {
  local status=$?
  set +e
  stop_shoes
  if [[ -n "${HTTP_PID}" ]] && kill -0 "${HTTP_PID}" 2>/dev/null; then
    kill "${HTTP_PID}" 2>/dev/null || true
    wait "${HTTP_PID}" 2>/dev/null || true
  fi
  if [[ -n "${UDP_ECHO_PID}" ]] && kill -0 "${UDP_ECHO_PID}" 2>/dev/null; then
    kill "${UDP_ECHO_PID}" 2>/dev/null || true
    wait "${UDP_ECHO_PID}" 2>/dev/null || true
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
  local proto="${4:-tcp}"
  local start
  local now

  start="$(date +%s)"
  while true; do
    if [[ "${proto}" == "udp" ]]; then
      if ss -lun | awk '{print $4; print $5}' | grep -Eq "(^|:)${port}$"; then
        return
      fi
    elif ss -ltn | awk '{print $4}' | grep -Eq "(^|:)${port}$"; then
      return
    fi
    ensure_running "${label}" "${port}"
    now="$(date +%s)"
    if ((now - start >= timeout)); then
      e2e_die "${label} did not listen on port ${port} within ${timeout}s"
    fi
    sleep 0.2
  done
}

ensure_running() {
  local label="$1"
  local port="$2"

  if [[ -n "${HTTP_PID}" ]] && ! kill -0 "${HTTP_PID}" 2>/dev/null; then
    e2e_die "${label} process exited before listening on ${port}"
  fi
  if [[ -n "${UDP_ECHO_PID}" ]] && ! kill -0 "${UDP_ECHO_PID}" 2>/dev/null; then
    e2e_die "${label} UDP echo process exited before listening on ${port}"
  fi
  if [[ -n "${SHOES_PID}" ]] && ! kill -0 "${SHOES_PID}" 2>/dev/null; then
    e2e_die "${label} process exited before listening on ${port}"
  fi
}

now_ms() {
  python3 -c 'import time; print(int(time.monotonic() * 1000))'
}

resolve_binaries() {
  e2e_section "binaries"
  e2e_require_command cargo
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

  e2e_run cargo build \
    --manifest-path "${ROOT_DIR}/Cargo.toml" \
    --features e2e-client \
    --bin shoes-naiveproxy-e2e-client
  [[ -x "${E2E_NAIVE_CLIENT_BIN}" ]] \
    || e2e_die "E2E_NAIVE_CLIENT_BIN is not executable: ${E2E_NAIVE_CLIENT_BIN}"
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

generate_tls_files() {
  e2e_section "tls fixture"
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -days 1 \
    -nodes \
    -subj "/CN=shoes-naiveproxy-e2e-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "${TMP_DIR}/ca.key" \
    -out "${TMP_DIR}/ca.crt" \
    >/dev/null 2>&1

  openssl req \
    -newkey rsa:2048 \
    -nodes \
    -subj "/CN=${E2E_TLS_SERVER_NAME}" \
    -keyout "${TMP_DIR}/tls.key" \
    -out "${TMP_DIR}/tls.csr" \
    >/dev/null 2>&1

  cat >"${TMP_DIR}/tls.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${E2E_TLS_SERVER_NAME}
EOF

  openssl x509 \
    -req \
    -in "${TMP_DIR}/tls.csr" \
    -CA "${TMP_DIR}/ca.crt" \
    -CAkey "${TMP_DIR}/ca.key" \
    -CAcreateserial \
    -days 1 \
    -sha256 \
    -extfile "${TMP_DIR}/tls.ext" \
    -out "${TMP_DIR}/tls.crt" \
    >/dev/null 2>&1
}

start_policy_http() {
  e2e_section "start naiveproxy policy http target"
  e2e_assert_port_free "${E2E_HTTP_PORT}" "naiveproxy policy http target"
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
  wait_for_listen_port "${E2E_HTTP_PORT}" "naiveproxy policy http target" 10
}

start_policy_udp_echo() {
  e2e_section "start naiveproxy policy udp echo target"
  e2e_assert_udp_port_free "${E2E_UDP_ECHO_PORT}" "naiveproxy policy udp echo target"
  cat >"${TMP_DIR}/policy_udp_echo.py" <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((sys.argv[1], int(sys.argv[2])))
while True:
    data, addr = sock.recvfrom(65535)
    sock.sendto(data, addr)
PY
  python3 "${TMP_DIR}/policy_udp_echo.py" "${E2E_BIND_HOST}" "${E2E_UDP_ECHO_PORT}" >"${TMP_DIR}/udp-echo.log" 2>&1 &
  UDP_ECHO_PID=$!
  wait_for_listen_port "${E2E_UDP_ECHO_PORT}" "naiveproxy policy udp echo target" 10 udp
}

seed_naiveproxy_fixture() {
  local case_name="$1"
  local node_id="$2"
  local user_id="$3"
  local uuid="$4"
  local port="$5"
  local speed_limit="${6:-NULL}"
  local device_limit="${7:-NULL}"
  local enable_quic="${8:-0}"
  local quic_congestion_control="${9:-NULL}"
  local now
  local expires_at

  now="$(date +%s)"
  expires_at="$((now + 86400))"

  mysql_exec <<SQL
INSERT INTO v2_server_naiveproxy
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tags, rate, \`show\`, sort, listen_ip, tls, server_name, enable_quic, quic_congestion_control, created_at, updated_at)
VALUES
(${node_id}, '["1"]', NULL, 'shoes-naiveproxy-policy-${case_name}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${port}', ${port}, NULL, '1', 1, ${node_id}, '${E2E_BIND_HOST}', 1, '${E2E_TLS_SERVER_NAME}', ${enable_quic}, ${quic_congestion_control}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  listen_ip=VALUES(listen_ip),
  tls=VALUES(tls),
  server_name=VALUES(server_name),
  enable_quic=VALUES(enable_quic),
  quic_congestion_control=VALUES(quic_congestion_control),
  \`show\`=VALUES(\`show\`),
  updated_at=VALUES(updated_at);

INSERT INTO v2_user
(id, invite_user_id, telegram_id, email, language, password, password_algo, password_salt, balance, discount, commission_type, commission_rate, commission_balance, t, u, d, transfer_enable, device_limit, banned, is_admin, last_login_at, is_staff, last_login_ip, uuid, group_id, plan_id, speed_limit, auto_renewal, remind_expire, remind_traffic, token, expired_at, remarks, created_at, updated_at)
VALUES
(${user_id}, NULL, NULL, 'shoes-naiveproxy-policy-${case_name}@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, ${device_limit}, 0, 0, NULL, 0, NULL, '${uuid}', 1, NULL, ${speed_limit}, 0, 1, 1, MD5('shoes-naiveproxy-policy-${case_name}@example.local'), ${expires_at}, 'shoes naiveproxy policy ${case_name} e2e user', ${now}, ${now})
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
DELETE FROM v2_stat_server WHERE server_id=${node_id} AND server_type='naiveproxy';
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${user_id}"
}

seed_v2node_naiveproxy_fixture() {
  local case_name="$1"
  local node_id="$2"
  local user_id="$3"
  local uuid="$4"
  local port="$5"
  local network="${6:-tcp}"
  local alpn_json="${7:-[\"h2\",\"http/1.1\"]}"
  local speed_limit="${8:-NULL}"
  local device_limit="${9:-NULL}"
  local now
  local expires_at

  now="$(date +%s)"
  expires_at="$((now + 86400))"

  mysql_exec <<SQL
INSERT INTO v2_server_v2node
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, listen_ip, port, server_port, tags, rate, \`show\`, sort, protocol, tls, tls_settings, flow, network, network_settings, encryption, encryption_settings, disable_sni, udp_relay_mode, zero_rtt_handshake, congestion_control, cipher, up_mbps, down_mbps, obfs, obfs_password, padding_scheme, created_at, updated_at)
VALUES
(${node_id}, '["1"]', NULL, 'shoes-naiveproxy-policy-${case_name}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_BIND_HOST}', '${port}', ${port}, NULL, '1', 1, ${node_id}, 'naive', 1, '{"serverName":"${E2E_TLS_SERVER_NAME}","alpn":${alpn_json}}', NULL, '${network}', '{}', 'none', '{}', 0, NULL, 0, NULL, NULL, 0, 0, NULL, NULL, NULL, ${now}, ${now})
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
  network=VALUES(network),
  network_settings=VALUES(network_settings),
  encryption=VALUES(encryption),
  \`show\`=VALUES(\`show\`),
  updated_at=VALUES(updated_at);

INSERT INTO v2_user
(id, invite_user_id, telegram_id, email, language, password, password_algo, password_salt, balance, discount, commission_type, commission_rate, commission_balance, t, u, d, transfer_enable, device_limit, banned, is_admin, last_login_at, is_staff, last_login_ip, uuid, group_id, plan_id, speed_limit, auto_renewal, remind_expire, remind_traffic, token, expired_at, remarks, created_at, updated_at)
VALUES
(${user_id}, NULL, NULL, 'shoes-naiveproxy-policy-${case_name}@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, ${device_limit}, 0, 0, NULL, 0, NULL, '${uuid}', 1, NULL, ${speed_limit}, 0, 1, 1, MD5('shoes-naiveproxy-policy-${case_name}@example.local'), ${expires_at}, 'shoes v2node naiveproxy policy ${case_name} e2e user', ${now}, ${now})
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
  local node_type="${4:-naiveproxy}"
  local listen_proto="${5:-tcp}"

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
tls:
  cert_file: "${TMP_DIR}/tls.crt"
  key_file: "${TMP_DIR}/tls.key"
log:
  level: "${E2E_SHOES_LOG_LEVEL}"
YAML

  "${SHOES_BIN}" sync-once -c "${TMP_DIR}/${case_name}.shoes.yml" >"${TMP_DIR}/${case_name}.sync.log" 2>&1
  e2e_assert_port_free "${port}" "shoes ${case_name}"
  "${SHOES_BIN}" run -c "${TMP_DIR}/${case_name}.shoes.yml" >"${TMP_DIR}/${case_name}.shoes.log" 2>&1 &
  SHOES_PID=$!
  wait_for_listen_port "${port}" "shoes ${case_name}" 15 "${listen_proto}"
}

stop_shoes() {
  if [[ -n "${SHOES_PID}" ]] && kill -0 "${SHOES_PID}" 2>/dev/null; then
    kill "${SHOES_PID}" 2>/dev/null || true
    wait "${SHOES_PID}" 2>/dev/null || true
  fi
  SHOES_PID=""
}

run_naiveproxy_client() {
  local user_id="$1"
  local password="$2"
  local node_port="$3"
  local url="$4"
  local output="$5"
  local max_time="$6"
  local bind_addr="${7:-}"
  local transport="${8:-h2}"
  local padding="${9:-padded}"
  local bind_args=()
  local transport_args=()
  local padding_args=()

  if [[ -n "${bind_addr}" ]]; then
    bind_args=(--bind "${bind_addr}")
  fi
  if [[ "${transport}" == "h3" ]]; then
    transport_args=(--http3)
  elif [[ "${transport}" != "h2" ]]; then
    e2e_die "unknown naiveproxy client transport: ${transport}"
  fi
  if [[ "${padding}" == "unpadded" ]]; then
    padding_args=(--no-padding)
  elif [[ "${padding}" != "padded" ]]; then
    e2e_die "unknown naiveproxy padding mode: ${padding}"
  fi

  "${E2E_NAIVE_CLIENT_BIN}" \
    --proxy-host "${E2E_BIND_HOST}" \
    --proxy-port "${node_port}" \
    --server-name "${E2E_TLS_SERVER_NAME}" \
    --ca-cert "${TMP_DIR}/ca.crt" \
    --username "user-${user_id}" \
    --password "${password}" \
    --url "${url}" \
    --output "${output}" \
    --connect-timeout-secs "${E2E_CLIENT_CONNECT_TIMEOUT_SECS}" \
    --max-time-secs "${max_time}" \
    "${transport_args[@]}" \
    "${padding_args[@]}" \
    "${bind_args[@]}"
}

run_naiveproxy_udp_client() {
  local user_id="$1"
  local password="$2"
  local node_port="$3"
  local max_time="$4"
  local transport="${5:-h2}"
  local transport_args=()

  if [[ "${transport}" == "h3" ]]; then
    transport_args=(--http3)
  elif [[ "${transport}" != "h2" ]]; then
    e2e_die "unknown naiveproxy client transport: ${transport}"
  fi

  "${E2E_NAIVE_CLIENT_BIN}" \
    --proxy-host "${E2E_BIND_HOST}" \
    --proxy-port "${node_port}" \
    --server-name "${E2E_TLS_SERVER_NAME}" \
    --ca-cert "${TMP_DIR}/ca.crt" \
    --username "user-${user_id}" \
    --password "${password}" \
    --udp-echo "${E2E_BIND_HOST}:${E2E_UDP_ECHO_PORT}" \
    --udp-payload-size 4096 \
    --connect-timeout-secs "${E2E_CLIENT_CONNECT_TIMEOUT_SECS}" \
    --max-time-secs "${max_time}" \
    "${transport_args[@]}"
}

wait_for_policy_download() {
  local user_id="$1"
  local node_id="$2"
  local expected_min="$3"
  local server_type="${4:-naiveproxy}"
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
      e2e_log "naiveproxy policy server_type=${server_type} user=${user_u}/${user_d} stat_user=${stat_user_u}/${stat_user_d} stat_server=${stat_server_u}/${stat_server_d}"
      return
    fi
    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_die "NaiveProxy user ${user_id} download did not reach ${expected_min}; server_type=${server_type} user=${user_u}/${user_d} stat_user=${stat_user_u}/${stat_user_d} stat_server=${stat_server_u}/${stat_server_d}"
    fi
    sleep 1
  done
}

assert_no_traffic() {
  local user_id="$1"
  local node_id="$2"
  local stat_user
  local stat_server
  local stat_user_total
  local stat_server_total

  e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"
  docker exec "${V2BOARD_WWW_CONTAINER}" php artisan traffic:update >/dev/null
  stat_user="$(mysql_query "SELECT COALESCE(SUM(u+d),0) FROM v2_stat_user WHERE user_id=${user_id};")"
  stat_server="$(mysql_query "SELECT COALESCE(SUM(u+d),0) FROM v2_stat_server WHERE server_id=${node_id} AND server_type='naiveproxy';")"
  read -r stat_user_total <<<"${stat_user}"
  read -r stat_server_total <<<"${stat_server}"
  ((stat_user_total == 0 && stat_server_total == 0)) \
    || e2e_die "NaiveProxy auth failure recorded traffic: user=${stat_user_total} server=${stat_server_total}"
}

run_auth_failure_case() {
  local case_name=auth_failure
  local node_id=9571
  local user_id=19571
  local uuid=55555555-5555-4555-8555-555555555571
  local node_port=18171

  e2e_section "naiveproxy policy auth_failure"
  seed_naiveproxy_fixture "${case_name}" "${node_id}" "${user_id}" "${uuid}" "${node_port}" NULL NULL
  write_shoes_config "${case_name}" "${node_id}" "${node_port}"

  if run_naiveproxy_client \
    "${user_id}" \
    "wrong-${uuid}" \
    "${node_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    "${TMP_DIR}/${case_name}.bin" \
    8 \
    >"${TMP_DIR}/${case_name}.client.log" 2>&1; then
    e2e_die "NaiveProxy auth_failure unexpectedly downloaded payload"
  fi
  assert_no_traffic "${user_id}" "${node_id}"
  e2e_log "naiveproxy auth_failure rejected wrong password as expected"

  stop_shoes
}

run_speed_limit_case() {
  local case_name=speed_limit
  local node_id=9572
  local user_id=19572
  local uuid=55555555-5555-4555-8555-555555555572
  local node_port=18172
  local start
  local end
  local elapsed_ms

  e2e_section "naiveproxy policy speed_limit"
  seed_naiveproxy_fixture "${case_name}" "${node_id}" "${user_id}" "${uuid}" "${node_port}" 1 NULL
  write_shoes_config "${case_name}" "${node_id}" "${node_port}"

  start="$(now_ms)"
  run_naiveproxy_client \
    "${user_id}" \
    "${uuid}" \
    "${node_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    "${TMP_DIR}/${case_name}.bin" \
    "${E2E_CLIENT_MAX_TIME_SECS}"
  end="$(now_ms)"
  elapsed_ms="$((end - start))"

  [[ "$(wc -c <"${TMP_DIR}/${case_name}.bin")" -eq 1048576 ]] \
    || e2e_die "naiveproxy speed_limit download size mismatch"
  ((elapsed_ms >= 5000)) \
    || e2e_die "naiveproxy speed_limit did not throttle enough: elapsed ${elapsed_ms}ms, expected >= 5000ms"
  wait_for_policy_download "${user_id}" "${node_id}" 1048576
  e2e_log "naiveproxy speed_limit elapsed=${elapsed_ms}ms"

  stop_shoes
}

run_device_limit_case() {
  local case_name=device_limit
  local node_id=9573
  local user_id=19573
  local uuid=55555555-5555-4555-8555-555555555573
  local node_port=18173
  local slow_pid

  e2e_section "naiveproxy policy device_limit"
  seed_naiveproxy_fixture "${case_name}" "${node_id}" "${user_id}" "${uuid}" "${node_port}" NULL 1
  write_shoes_config "${case_name}" "${node_id}" "${node_port}"

  run_naiveproxy_client \
    "${user_id}" \
    "${uuid}" \
    "${node_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/slow.bin" \
    "${TMP_DIR}/${case_name}-slow.bin" \
    "${E2E_CLIENT_MAX_TIME_SECS}" \
    "127.0.0.1" \
    >"${TMP_DIR}/${case_name}-slow.client.log" 2>&1 &
  slow_pid=$!

  sleep 1
  kill -0 "${slow_pid}" 2>/dev/null || e2e_die "first slow device-limit connection exited too early"

  if run_naiveproxy_client \
    "${user_id}" \
    "${uuid}" \
    "${node_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    "${TMP_DIR}/${case_name}-second.bin" \
    8 \
    "127.0.0.2" \
    >"${TMP_DIR}/${case_name}-second.client.log" 2>&1; then
    kill "${slow_pid}" 2>/dev/null || true
    wait "${slow_pid}" 2>/dev/null || true
    e2e_die "naiveproxy device_limit allowed a second concurrent source IP"
  fi

  kill "${slow_pid}" 2>/dev/null || true
  wait "${slow_pid}" 2>/dev/null || true

  grep -q "device limit exceeded for user ${user_id}" "${TMP_DIR}/${case_name}.shoes.log" \
    || e2e_die "naiveproxy device_limit rejection was not observed in shoes log"
  e2e_log "naiveproxy device_limit rejected second source IP as expected"

  stop_shoes
}

run_v2node_success_case() {
  local case_name=v2node_success
  local node_id=9574
  local user_id=19574
  local uuid=55555555-5555-4555-8555-555555555574
  local node_port=18174

  e2e_section "naiveproxy policy v2node_success"
  seed_v2node_naiveproxy_fixture "${case_name}" "${node_id}" "${user_id}" "${uuid}" "${node_port}"
  write_shoes_config "${case_name}" "${node_id}" "${node_port}" v2node

  run_naiveproxy_client \
    "${user_id}" \
    "${uuid}" \
    "${node_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    "${TMP_DIR}/${case_name}.bin" \
    "${E2E_CLIENT_MAX_TIME_SECS}"

  [[ "$(wc -c <"${TMP_DIR}/${case_name}.bin")" -eq 1048576 ]] \
    || e2e_die "naiveproxy v2node_success download size mismatch"
  wait_for_policy_download "${user_id}" "${node_id}" 1048576 v2node
  e2e_log "naiveproxy v2node_success downloaded payload and reported v2node traffic"

  stop_shoes
}

run_udp_uot_h2_success_case() {
  local case_name=udp_uot_h2_success
  local node_id=9578
  local user_id=19578
  local uuid=55555555-5555-4555-8555-555555555578
  local node_port=18178

  e2e_section "naiveproxy policy udp_uot_h2_success"
  seed_naiveproxy_fixture "${case_name}" "${node_id}" "${user_id}" "${uuid}" "${node_port}" NULL NULL
  write_shoes_config "${case_name}" "${node_id}" "${node_port}"

  run_naiveproxy_udp_client \
    "${user_id}" \
    "${uuid}" \
    "${node_port}" \
    "${E2E_CLIENT_MAX_TIME_SECS}" \
    h2 \
    >"${TMP_DIR}/${case_name}.client.log" 2>&1

  wait_for_policy_download "${user_id}" "${node_id}" 4096
  e2e_log "naiveproxy udp_uot_h2_success echoed UDP payload and reported traffic"

  stop_shoes
}

run_quic_dual_stack_success_case() {
  local case_name=quic_dual_stack_success
  local node_id=9575
  local user_id=19575
  local uuid=55555555-5555-4555-8555-555555555575
  local node_port=18175

  e2e_section "naiveproxy policy quic_dual_stack_success"
  seed_naiveproxy_fixture "${case_name}" "${node_id}" "${user_id}" "${uuid}" "${node_port}" NULL NULL 1 "'bbr2_variant'"
  write_shoes_config "${case_name}" "${node_id}" "${node_port}"
  wait_for_listen_port "${node_port}" "shoes ${case_name} h3" 15 udp

  run_naiveproxy_client \
    "${user_id}" \
    "${uuid}" \
    "${node_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    "${TMP_DIR}/${case_name}-h3.bin" \
    "${E2E_CLIENT_MAX_TIME_SECS}" \
    "" \
    h3
  run_naiveproxy_client \
    "${user_id}" \
    "${uuid}" \
    "${node_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    "${TMP_DIR}/${case_name}-h2.bin" \
    "${E2E_CLIENT_MAX_TIME_SECS}"
  run_naiveproxy_client \
    "${user_id}" \
    "${uuid}" \
    "${node_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    "${TMP_DIR}/${case_name}-h3-unpadded.bin" \
    "${E2E_CLIENT_MAX_TIME_SECS}" \
    "" \
    h3 \
    unpadded
  run_naiveproxy_client \
    "${user_id}" \
    "${uuid}" \
    "${node_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    "${TMP_DIR}/${case_name}-h2-unpadded.bin" \
    "${E2E_CLIENT_MAX_TIME_SECS}" \
    "" \
    h2 \
    unpadded

  [[ "$(wc -c <"${TMP_DIR}/${case_name}-h3.bin")" -eq 1048576 ]] \
    || e2e_die "naiveproxy quic_dual_stack_success H3 download size mismatch"
  [[ "$(wc -c <"${TMP_DIR}/${case_name}-h2.bin")" -eq 1048576 ]] \
    || e2e_die "naiveproxy quic_dual_stack_success H2 download size mismatch"
  [[ "$(wc -c <"${TMP_DIR}/${case_name}-h3-unpadded.bin")" -eq 1048576 ]] \
    || e2e_die "naiveproxy quic_dual_stack_success unpadded H3 download size mismatch"
  [[ "$(wc -c <"${TMP_DIR}/${case_name}-h2-unpadded.bin")" -eq 1048576 ]] \
    || e2e_die "naiveproxy quic_dual_stack_success unpadded H2 download size mismatch"
  wait_for_policy_download "${user_id}" "${node_id}" 4194304
  e2e_log "naiveproxy quic_dual_stack_success downloaded padded and unpadded via both H3 and H2"

  stop_shoes
}

run_quic_h3_auth_failure_case() {
  local case_name=quic_h3_auth_failure
  local node_id=9576
  local user_id=19576
  local uuid=55555555-5555-4555-8555-555555555576
  local node_port=18176

  e2e_section "naiveproxy policy quic_h3_auth_failure"
  seed_naiveproxy_fixture "${case_name}" "${node_id}" "${user_id}" "${uuid}" "${node_port}" NULL NULL 1 "'bbr'"
  write_shoes_config "${case_name}" "${node_id}" "${node_port}"
  wait_for_listen_port "${node_port}" "shoes ${case_name} h3" 15 udp

  if run_naiveproxy_client \
    "${user_id}" \
    "wrong-${uuid}" \
    "${node_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    "${TMP_DIR}/${case_name}.bin" \
    8 \
    "" \
    h3 \
    >"${TMP_DIR}/${case_name}.client.log" 2>&1; then
    e2e_die "NaiveProxy quic_h3_auth_failure unexpectedly downloaded payload"
  fi
  assert_no_traffic "${user_id}" "${node_id}"
  e2e_log "naiveproxy quic_h3_auth_failure rejected wrong password as expected"

  stop_shoes
}

run_v2node_h3_success_case() {
  local case_name=v2node_h3_success
  local node_id=9577
  local user_id=19577
  local uuid=55555555-5555-4555-8555-555555555577
  local node_port=18177

  e2e_section "naiveproxy policy v2node_h3_success"
  seed_v2node_naiveproxy_fixture "${case_name}" "${node_id}" "${user_id}" "${uuid}" "${node_port}" udp '["h3"]'
  write_shoes_config "${case_name}" "${node_id}" "${node_port}" v2node udp

  run_naiveproxy_client \
    "${user_id}" \
    "${uuid}" \
    "${node_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    "${TMP_DIR}/${case_name}.bin" \
    "${E2E_CLIENT_MAX_TIME_SECS}" \
    "" \
    h3

  [[ "$(wc -c <"${TMP_DIR}/${case_name}.bin")" -eq 1048576 ]] \
    || e2e_die "naiveproxy v2node_h3_success download size mismatch"
  wait_for_policy_download "${user_id}" "${node_id}" 1048576 v2node
  e2e_log "naiveproxy v2node_h3_success downloaded payload and reported v2node traffic"

  stop_shoes
}

run_v2node_h3_speed_limit_case() {
  local case_name=v2node_h3_speed_limit
  local node_id=9671
  local user_id=19671
  local uuid=66666666-6666-4666-8666-666666666671
  local node_port=18571
  local start
  local end
  local elapsed_ms

  e2e_section "naiveproxy policy v2node_h3_speed_limit"
  seed_v2node_naiveproxy_fixture "${case_name}" "${node_id}" "${user_id}" "${uuid}" "${node_port}" udp '["h3"]' 1 NULL
  write_shoes_config "${case_name}" "${node_id}" "${node_port}" v2node udp

  start="$(now_ms)"
  run_naiveproxy_client \
    "${user_id}" \
    "${uuid}" \
    "${node_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    "${TMP_DIR}/${case_name}.bin" \
    "${E2E_CLIENT_MAX_TIME_SECS}" \
    "" \
    h3
  end="$(now_ms)"
  elapsed_ms="$((end - start))"

  [[ "$(wc -c <"${TMP_DIR}/${case_name}.bin")" -eq 1048576 ]] \
    || e2e_die "naiveproxy v2node_h3_speed_limit download size mismatch"
  ((elapsed_ms >= 5000)) \
    || e2e_die "naiveproxy v2node_h3_speed_limit did not throttle enough: elapsed ${elapsed_ms}ms, expected >= 5000ms"
  wait_for_policy_download "${user_id}" "${node_id}" 1048576 v2node
  e2e_log "naiveproxy v2node_h3_speed_limit elapsed=${elapsed_ms}ms"

  stop_shoes
}

run_v2node_h3_device_limit_case() {
  local case_name=v2node_h3_device_limit
  local node_id=9672
  local user_id=19672
  local uuid=66666666-6666-4666-8666-666666666672
  local node_port=18572
  local slow_pid

  e2e_section "naiveproxy policy v2node_h3_device_limit"
  seed_v2node_naiveproxy_fixture "${case_name}" "${node_id}" "${user_id}" "${uuid}" "${node_port}" udp '["h3"]' NULL 1
  write_shoes_config "${case_name}" "${node_id}" "${node_port}" v2node udp

  run_naiveproxy_client \
    "${user_id}" \
    "${uuid}" \
    "${node_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/slow.bin" \
    "${TMP_DIR}/${case_name}-slow.bin" \
    "${E2E_CLIENT_MAX_TIME_SECS}" \
    "127.0.0.1" \
    h3 \
    >"${TMP_DIR}/${case_name}-slow.client.log" 2>&1 &
  slow_pid=$!

  sleep 1
  kill -0 "${slow_pid}" 2>/dev/null || e2e_die "first V2Node NaiveProxy H3 slow device-limit connection exited too early"

  if run_naiveproxy_client \
    "${user_id}" \
    "${uuid}" \
    "${node_port}" \
    "http://${E2E_BIND_HOST}:${E2E_HTTP_PORT}/fast.bin" \
    "${TMP_DIR}/${case_name}-second.bin" \
    8 \
    "127.0.0.2" \
    h3 \
    >"${TMP_DIR}/${case_name}-second.client.log" 2>&1; then
    kill "${slow_pid}" 2>/dev/null || true
    wait "${slow_pid}" 2>/dev/null || true
    e2e_die "naiveproxy v2node_h3_device_limit allowed a second concurrent source IP"
  fi

  kill "${slow_pid}" 2>/dev/null || true
  wait "${slow_pid}" 2>/dev/null || true

  grep -q "device limit exceeded for user ${user_id}" "${TMP_DIR}/${case_name}.shoes.log" \
    || e2e_die "naiveproxy v2node_h3_device_limit rejection was not observed in shoes log"
  e2e_log "naiveproxy v2node_h3_device_limit rejected second source IP as expected"

  stop_shoes
}

maybe_cleanup_fixtures() {
  if e2e_env_bool E2E_KEEP_FIXTURES 1; then
    e2e_log "keeping naiveproxy policy E2E fixtures"
    return
  fi

mysql_exec <<SQL
DELETE su FROM v2_stat_user su JOIN v2_user u ON u.id=su.user_id WHERE u.email LIKE 'shoes-naiveproxy-policy-%@example.local';
DELETE ss FROM v2_stat_server ss JOIN v2_server_naiveproxy n ON ss.server_type='naiveproxy' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-naiveproxy-policy-%';
DELETE ss FROM v2_stat_server ss JOIN v2_server_v2node n ON ss.server_type='v2node' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-naiveproxy-policy-%';
DELETE FROM v2_user WHERE email LIKE 'shoes-naiveproxy-policy-%@example.local';
DELETE FROM v2_server_naiveproxy WHERE name LIKE 'shoes-naiveproxy-policy-%';
DELETE FROM v2_server_v2node WHERE name LIKE 'shoes-naiveproxy-policy-%';
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19571
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19572
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19573
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19574
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19575
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19576
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19577
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19578
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19671
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" 19672
}

main() {
  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-naiveproxy-policy-e2e.XXXXXX)"

  check_environment
  resolve_binaries
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"
  generate_tls_files
  start_policy_http
  start_policy_udp_echo
  run_auth_failure_case
  run_speed_limit_case
  run_device_limit_case
  run_v2node_success_case
  run_udp_uot_h2_success_case
  run_quic_dual_stack_success_case
  run_quic_h3_auth_failure_case
  run_v2node_h3_success_case
  run_v2node_h3_speed_limit_case
  run_v2node_h3_device_limit_case
  maybe_cleanup_fixtures
  e2e_section "done"
}

main "$@"
