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

SHOES_BIN_EXPLICIT=0
if [[ -n "${SHOES_BIN:-}" ]]; then
  SHOES_BIN_EXPLICIT=1
fi
SHOES_BIN="${SHOES_BIN:-${ROOT_DIR}/target/debug/shoes}"

E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_NODE_PORT="${E2E_NODE_PORT:-18731}"
E2E_FALLBACK_PORT="${E2E_FALLBACK_PORT:-18732}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-2}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-2}"
E2E_NO_REPORT_WAIT_SECS="${E2E_NO_REPORT_WAIT_SECS:-6}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_SHOES_LOG_LEVEL="${E2E_SHOES_LOG_LEVEL:-debug}"

NODE_ID="${E2E_NODE_ID:-9971}"
USER_ID="${E2E_USER_ID:-19971}"
GROUP_ID="${E2E_GROUP_ID:-29971}"
USER_UUID="${E2E_USER_UUID:-99999999-9971-4999-8999-999999999971}"
TLS_SERVER_NAME="${E2E_TLS_SERVER_NAME:-example.org}"

TMP_DIR=""
DECOY_PID=""
SHOES_PID=""
SERVER_TOKEN=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_trojan_fallback.sh

Runs a real V2Board-backed Trojan/TLS fallback check:
  - verifies an ordinary TLS-decoded HTTP probe is replayed byte-for-byte to a
    node-local TCP fallback and echoed without loss, duplication, or reordering;
  - verifies that fallback traffic creates no authenticated V2Board traffic or
    alive record;
  - restarts the same node without trojan_fallback and verifies fail-closed
    behavior without any connection reaching the decoy.

Environment:
  SHOES_BIN                    Optional prebuilt shoes binary.
  E2E_NODE_PORT                Trojan TLS listener. Default: 18731.
  E2E_FALLBACK_PORT            Plain TCP echo/recording decoy. Default: 18732.
  E2E_NO_REPORT_WAIT_SECS      Observation window for absent reports. Default: 6.
  E2E_KEEP_FIXTURES            Keep seeded V2Board rows. Default: 1.
EOF
}

cleanup() {
  local status=$?
  set +e

  stop_shoes
  if [[ -n "${DECOY_PID}" ]] && kill -0 "${DECOY_PID}" 2>/dev/null; then
    kill "${DECOY_PID}" 2>/dev/null || true
    wait "${DECOY_PID}" 2>/dev/null || true
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

cache_forget() {
  local key="$1"

  docker exec "${V2BOARD_WWW_CONTAINER}" \
    php artisan tinker --execute="Cache::forget('${key}');" >/dev/null
}

cache_json() {
  local key="$1"

  docker exec "${V2BOARD_WWW_CONTAINER}" \
    php artisan tinker --execute="echo json_encode(Cache::get('${key}'));" 2>/dev/null
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
    for pid in "${DECOY_PID}" "${SHOES_PID}"; do
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
  e2e_require_command cargo
  e2e_require_command docker
  e2e_require_command openssl
  e2e_require_command python3
  e2e_require_command ss

  if ((SHOES_BIN_EXPLICIT == 0)); then
    e2e_run cargo build --manifest-path "${ROOT_DIR}/Cargo.toml" --bin shoes
  fi
  [[ -x "${SHOES_BIN}" ]] || e2e_die "SHOES_BIN is not executable: ${SHOES_BIN}"
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

generate_tls_fixture() {
  e2e_section "tls fixture"
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -days 1 \
    -nodes \
    -subj "/CN=${TLS_SERVER_NAME}" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "subjectAltName=DNS:${TLS_SERVER_NAME}" \
    -keyout "${TMP_DIR}/tls.key" \
    -out "${TMP_DIR}/tls.crt" \
    >/dev/null 2>&1
}

seed_fixture() {
  local now
  local expires_at

  e2e_section "seed V2Board Trojan fixture"
  now="$(date +%s)"
  expires_at="$((now + 86400))"

  mysql_exec <<SQL
INSERT INTO v2_server_group
(id, name, created_at, updated_at)
VALUES
(${GROUP_ID}, 'shoes-trojan-fallback', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  updated_at=VALUES(updated_at);

INSERT INTO v2_server_trojan
(id, group_id, route_id, parent_id, tags, name, country_code, city_name, city_id, rate, host, port, server_port, network, network_settings, allow_insecure, server_name, \`show\`, sort, created_at, updated_at)
VALUES
(${NODE_ID}, '["${GROUP_ID}"]', NULL, NULL, NULL, 'shoes-trojan-fallback', 'US', 'Local', NULL, '1', '${E2E_BIND_HOST}', '${E2E_NODE_PORT}', ${E2E_NODE_PORT}, 'tcp', '{}', 0, '${TLS_SERVER_NAME}', 1, ${NODE_ID}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  network=VALUES(network),
  network_settings=VALUES(network_settings),
  server_name=VALUES(server_name),
  \`show\`=VALUES(\`show\`),
  sort=VALUES(sort),
  updated_at=VALUES(updated_at);

INSERT INTO v2_user
(id, invite_user_id, telegram_id, email, language, password, password_algo, password_salt, balance, discount, commission_type, commission_rate, commission_balance, t, u, d, transfer_enable, device_limit, banned, is_admin, last_login_at, is_staff, last_login_ip, uuid, group_id, plan_id, speed_limit, auto_renewal, remind_expire, remind_traffic, token, expired_at, remarks, created_at, updated_at)
VALUES
(${USER_ID}, NULL, NULL, 'shoes-trojan-fallback@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, 2, 0, 0, NULL, 0, NULL, '${USER_UUID}', ${GROUP_ID}, NULL, NULL, 0, 1, 1, MD5('shoes-trojan-fallback@example.local'), ${expires_at}, 'shoes Trojan fallback E2E user', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
  group_id=VALUES(group_id),
  speed_limit=NULL,
  device_limit=2,
  expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);

DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='trojan';
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
  cache_forget "ALIVE_IP_USER_${USER_ID}"
}

write_shoes_config() {
  local output_path="$1"
  local fallback_line="$2"

  cat >"${output_path}" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${SERVER_TOKEN}"
  nodes:
    - tag: "trojan_fallback"
      node_id: ${NODE_ID}
      node_type: "trojan"
      listen: "${E2E_BIND_HOST}"
      pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
      push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
${fallback_line}
runtime:
  data_dir: "${TMP_DIR}/shoes-data"
  pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
  push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
  node_report_min_traffic: 0
  device_online_min_traffic: 0
tls:
  cert_file: "${TMP_DIR}/tls.crt"
  key_file: "${TMP_DIR}/tls.key"
log:
  level: "${E2E_SHOES_LOG_LEVEL}"
YAML
}

start_decoy() {
  e2e_section "start recording echo decoy"
  e2e_assert_port_free "${E2E_FALLBACK_PORT}" "Trojan fallback decoy"
  mkdir -p "${TMP_DIR}/decoy"
  printf '0\n' >"${TMP_DIR}/decoy/count"

  python3 -u - \
    "${E2E_BIND_HOST}" \
    "${E2E_FALLBACK_PORT}" \
    "${TMP_DIR}/decoy" \
    >"${TMP_DIR}/decoy.log" 2>&1 <<'PY' &
import socketserver
import sys
import threading
from pathlib import Path

host = sys.argv[1]
port = int(sys.argv[2])
state_dir = Path(sys.argv[3])
lock = threading.Lock()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        with lock:
            count_path = state_dir / "count"
            connection_id = int(count_path.read_text()) + 1
            count_path.write_text(f"{connection_id}\n")

        output_path = state_dir / f"connection-{connection_id}.bin"
        with output_path.open("wb") as output:
            while True:
                data = self.request.recv(65536)
                if not data:
                    return
                output.write(data)
                output.flush()
                self.request.sendall(data)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


with Server((host, port), Handler) as server:
    print(f"decoy listening on {host}:{port}", flush=True)
    server.serve_forever()
PY
  DECOY_PID=$!
  wait_for_listen_port "${E2E_FALLBACK_PORT}" "Trojan fallback decoy" 10
}

start_shoes() {
  local config_path="$1"
  local label="$2"

  e2e_assert_port_free "${E2E_NODE_PORT}" "${label}"
  "${SHOES_BIN}" run -c "${config_path}" >"${TMP_DIR}/${label}.shoes.log" 2>&1 &
  SHOES_PID=$!
  wait_for_listen_port "${E2E_NODE_PORT}" "${label}" 15
}

stop_shoes() {
  if [[ -n "${SHOES_PID}" ]] && kill -0 "${SHOES_PID}" 2>/dev/null; then
    kill "${SHOES_PID}" 2>/dev/null || true
    wait "${SHOES_PID}" 2>/dev/null || true
  fi
  SHOES_PID=""
}

write_probe_payload() {
  python3 - "${TMP_DIR}/probe.bin" <<'PY'
import sys
from pathlib import Path

prefix = (
    b"GET /ordinary-browser-probe HTTP/1.1\r\n"
    b"Host: example.org\r\n"
    b"User-Agent: shoes-trojan-fallback-e2e/1\r\n"
    b"X-Not-Trojan: true\r\n"
    b"\r\n"
)
tail = bytes(((index * 73 + 19) % 256 for index in range(16 * 1024 + 37)))
Path(sys.argv[1]).write_bytes(prefix + tail)
PY
}

run_tls_probe() {
  local mode="$1"

  python3 - \
    "${E2E_BIND_HOST}" \
    "${E2E_NODE_PORT}" \
    "${TLS_SERVER_NAME}" \
    "${TMP_DIR}/tls.crt" \
    "${TMP_DIR}/probe.bin" \
    "${mode}" <<'PY'
import socket
import ssl
import sys
from pathlib import Path

host = sys.argv[1]
port = int(sys.argv[2])
server_name = sys.argv[3]
certificate = sys.argv[4]
payload = Path(sys.argv[5]).read_bytes()
mode = sys.argv[6]

context = ssl.create_default_context(cafile=certificate)
application_data = bytearray()
closed_or_reset = False

with socket.create_connection((host, port), timeout=5) as tcp:
    tcp.settimeout(5)
    with context.wrap_socket(tcp, server_hostname=server_name) as tls:
        tls.settimeout(5)
        try:
            offsets = [0, 17, 113, 4099, len(payload)]
            for start, end in zip(offsets, offsets[1:]):
                tls.sendall(payload[start:end])
            while len(application_data) < len(payload):
                chunk = tls.recv(len(payload) - len(application_data))
                if not chunk:
                    closed_or_reset = True
                    break
                application_data.extend(chunk)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            closed_or_reset = True

if mode == "echo":
    if bytes(application_data) != payload:
        raise SystemExit(
            f"fallback echo mismatch: got {len(application_data)} bytes, want {len(payload)}"
        )
    print(f"TLS-decoded fallback echo ok bytes={len(payload)}")
elif mode == "closed":
    if application_data:
        raise SystemExit(f"fail-closed probe unexpectedly received {len(application_data)} bytes")
    if not closed_or_reset:
        raise SystemExit("fail-closed probe was not closed or reset")
    print("probe closed without application response")
else:
    raise SystemExit(f"unknown probe mode: {mode}")
PY
}

wait_for_decoy_recording() {
  local expected_size
  local start
  local now
  local actual_size=0

  expected_size="$(wc -c <"${TMP_DIR}/probe.bin")"
  start="$(date +%s)"
  while true; do
    if [[ -f "${TMP_DIR}/decoy/connection-1.bin" ]]; then
      actual_size="$(wc -c <"${TMP_DIR}/decoy/connection-1.bin")"
      if ((actual_size == expected_size)); then
        cmp "${TMP_DIR}/probe.bin" "${TMP_DIR}/decoy/connection-1.bin" \
          || e2e_die "decoy recording differs from TLS-decoded probe"
        e2e_log "decoy recorded exact probe bytes=${actual_size}"
        return
      fi
    fi
    now="$(date +%s)"
    if ((now - start >= 5)); then
      e2e_die "decoy recording size mismatch: got ${actual_size}, want ${expected_size}"
    fi
    sleep 0.1
  done
}

assert_decoy_connection_count() {
  local expected="$1"
  local actual

  actual="$(tr -d '[:space:]' <"${TMP_DIR}/decoy/count")"
  [[ "${actual}" == "${expected}" ]] \
    || e2e_die "decoy connection count mismatch: got ${actual}, want ${expected}"
}

assert_no_authenticated_reports() {
  local stat_rows
  local user_totals
  local redis_value
  local key_prefix
  local alive_json

  e2e_section "assert no authenticated traffic or alive report"
  sleep "${E2E_NO_REPORT_WAIT_SECS}"
  e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"
  docker exec "${V2BOARD_WWW_CONTAINER}" php artisan traffic:update >/dev/null

  stat_rows="$(mysql_query "SELECT (SELECT COUNT(*) FROM v2_stat_user WHERE user_id=${USER_ID}) + (SELECT COUNT(*) FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='trojan');")"
  [[ "${stat_rows}" == "0" ]] \
    || e2e_die "unauthenticated fallback created ${stat_rows} V2Board stat rows"

  user_totals="$(mysql_query "SELECT u,d FROM v2_user WHERE id=${USER_ID};")"
  [[ "${user_totals}" == $'0\t0' ]] \
    || e2e_die "unauthenticated fallback changed user counters: ${user_totals}"

  for key_prefix in "" "v2board_database_"; do
    redis_value="$(docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli --raw HGET "${key_prefix}v2board_upload_traffic" "${USER_ID}")"
    [[ -z "${redis_value}" ]] \
      || e2e_die "unexpected Redis upload counter ${key_prefix}=${redis_value}"
    redis_value="$(docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli --raw HGET "${key_prefix}v2board_download_traffic" "${USER_ID}")"
    [[ -z "${redis_value}" ]] \
      || e2e_die "unexpected Redis download counter ${key_prefix}=${redis_value}"
  done

  alive_json="$(cache_json "ALIVE_IP_USER_${USER_ID}")"
  [[ "${alive_json}" == "null" ]] \
    || e2e_die "unauthenticated fallback created alive cache: ${alive_json}"

  e2e_log "no user traffic rows/counters and no alive cache for user ${USER_ID}"
}

cleanup_fixtures() {
  e2e_section "cleanup fixtures"
  mysql_exec <<SQL
DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='trojan';
DELETE FROM v2_user WHERE id=${USER_ID} AND email='shoes-trojan-fallback@example.local';
DELETE FROM v2_server_trojan WHERE id=${NODE_ID} AND name='shoes-trojan-fallback';
DELETE FROM v2_server_group WHERE id=${GROUP_ID} AND name='shoes-trojan-fallback';
SQL
  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
  cache_forget "ALIVE_IP_USER_${USER_ID}"
}

main() {
  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-trojan-fallback-e2e.XXXXXX)"

  check_environment
  resolve_binaries
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"

  e2e_assert_port_free "${E2E_NODE_PORT}" "Trojan listener"
  generate_tls_fixture
  seed_fixture
  write_probe_payload
  write_shoes_config "${TMP_DIR}/without-fallback.shoes.yml" ""
  write_shoes_config \
    "${TMP_DIR}/with-fallback.shoes.yml" \
    "      trojan_fallback: \"${E2E_BIND_HOST}:${E2E_FALLBACK_PORT}\""
  start_decoy

  e2e_section "without fallback: fail closed"
  start_shoes "${TMP_DIR}/without-fallback.shoes.yml" "without-fallback"
  run_tls_probe closed
  assert_decoy_connection_count 0
  stop_shoes

  e2e_section "with fallback: exact TLS-decoded replay"
  start_shoes "${TMP_DIR}/with-fallback.shoes.yml" "with-fallback"
  run_tls_probe echo
  wait_for_decoy_recording
  assert_decoy_connection_count 1
  assert_no_authenticated_reports
  stop_shoes

  if ! e2e_env_bool E2E_KEEP_FIXTURES 1; then
    cleanup_fixtures
  else
    e2e_log "keeping E2E fixtures node=${NODE_ID} user=${USER_ID}"
  fi
  e2e_section "done"
}

main "$@"
