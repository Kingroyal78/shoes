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
V2BOARD_REDIS_CONTAINER="${V2BOARD_REDIS_CONTAINER:-v2board-docker-redis-1}"
V2BOARD_MYSQL_USER="${V2BOARD_MYSQL_USER:-root}"
V2BOARD_MYSQL_PASSWORD="${V2BOARD_MYSQL_PASSWORD:-v2boardisbest}"
V2BOARD_MYSQL_DATABASE="${V2BOARD_MYSQL_DATABASE:-v2board}"

E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_NODE_PORT="${E2E_NODE_PORT:-18901}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_CURL_CONNECT_TIMEOUT_SECS="${E2E_CURL_CONNECT_TIMEOUT_SECS:-5}"
E2E_CURL_MAX_TIME_SECS="${E2E_CURL_MAX_TIME_SECS:-15}"

GROUP_ID=9901
GROUP_NAME="shoes-api-compat"
NODE_ID=9901
NODE_NAME="shoes-api-compat-vmess"
V2NODE_ID=9902
V2NODE_NAME="shoes-api-compat-v2node"
V2NODE_PORT=18902
USER_ID=19901
USER_EMAIL="shoes-api-compat-user@example.local"
USER_UUID="99999999-9999-4999-8999-999999999901"
USER_SPEED_LIMIT=7
USER_DEVICE_LIMIT=3
NETWORK_SETTINGS='{"header":{"type":"none"}}'

TMP_DIR=""
SERVER_TOKEN=""
FIXTURES_TOUCHED=0

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_api_compat.sh

Runs a production-oriented Docker E2E check for V2Board UniProxy API
compatibility only:
  - seeds an isolated VMess node/group/user in sibling v2board-docker MySQL
  - verifies /api/v1/server/UniProxy/config JSON fields and ETag 304
  - verifies /api/v2/server/config JSON fields and raw ETag 304 for V2Node
  - verifies /api/v1/server/UniProxy/user JSON fields and ETag 304
  - verifies /api/v1/server/UniProxy/user msgpack response with Python msgpack

Environment:
  V2BOARD_SERVER_TOKEN            Override server token. Defaults to parsing ../v2board/config/v2board.php.
  V2BOARD_PANEL_URL               Panel URL. Default: http://127.0.0.1.
  E2E_NODE_PORT                   Seeded VMess server_port. Default: 18901.
  E2E_KEEP_FIXTURES               Keep DB/cache fixtures after run. Default: 1.
  E2E_CURL_CONNECT_TIMEOUT_SECS   curl connect timeout. Default: 5.
  E2E_CURL_MAX_TIME_SECS          curl max time. Default: 15.
EOF
}

cleanup() {
  local status=$?
  set +e

  if [[ "${FIXTURES_TOUCHED}" == "1" ]]; then
    if e2e_env_bool E2E_KEEP_FIXTURES 1; then
      if [[ "${status}" -eq 0 ]]; then
        e2e_log "keeping API compat E2E fixtures: group=${GROUP_ID}, node=${NODE_ID}, user=${USER_ID}"
      fi
    else
      cleanup_fixtures || true
    fi
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

self_shellcheck() {
  e2e_section "shellcheck"
  e2e_require_command shellcheck
  e2e_run shellcheck -x "${BASH_SOURCE[0]}"
}

resolve_dependencies() {
  e2e_section "dependencies"
  e2e_require_command docker
  e2e_require_command curl
  e2e_require_command python3
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

cache_forget() {
  local key="$1"

  docker exec "${V2BOARD_WWW_CONTAINER}" \
    php artisan tinker --execute="Cache::forget('${key}');" >/dev/null
}

require_python_msgpack() {
  python3 - <<'PY' || e2e_die "missing Python module 'msgpack'; install it for the active python3 before running the msgpack API compatibility check"
try:
    import msgpack  # noqa: F401
except ModuleNotFoundError:
    raise SystemExit(1)
PY
}

assert_no_foreign_fixture_conflicts() {
  local group_conflicts
  local node_conflicts
  local v2node_conflicts
  local user_conflicts
  local group_user_conflicts

  group_conflicts="$(mysql_query "SELECT COUNT(*) FROM v2_server_group WHERE id=${GROUP_ID} AND name <> '${GROUP_NAME}';")"
  node_conflicts="$(mysql_query "SELECT COUNT(*) FROM v2_server_vmess WHERE id=${NODE_ID} AND name <> '${NODE_NAME}';")"
  v2node_conflicts="$(mysql_query "SELECT COUNT(*) FROM v2_server_v2node WHERE id=${V2NODE_ID} AND name <> '${V2NODE_NAME}';")"
  user_conflicts="$(mysql_query "SELECT COUNT(*) FROM v2_user WHERE (id=${USER_ID} AND email <> '${USER_EMAIL}') OR (email='${USER_EMAIL}' AND id <> ${USER_ID});")"
  group_user_conflicts="$(mysql_query "SELECT COUNT(*) FROM v2_user WHERE group_id=${GROUP_ID} AND id <> ${USER_ID};")"

  [[ "${group_conflicts}" == "0" ]] \
    || e2e_die "fixture group id ${GROUP_ID} is already used by a non-E2E row"
  [[ "${node_conflicts}" == "0" ]] \
    || e2e_die "fixture node id ${NODE_ID} is already used by a non-E2E row"
  [[ "${v2node_conflicts}" == "0" ]] \
    || e2e_die "fixture v2node id ${V2NODE_ID} is already used by a non-E2E row"
  [[ "${user_conflicts}" == "0" ]] \
    || e2e_die "fixture user id/email is already used by a non-E2E row"
  [[ "${group_user_conflicts}" == "0" ]] \
    || e2e_die "fixture group id ${GROUP_ID} already has non-E2E users"
}

seed_fixtures() {
  local now
  local expires_at

  e2e_section "seed v2board fixtures"
  assert_no_foreign_fixture_conflicts
  FIXTURES_TOUCHED=1
  now="$(date +%s)"
  expires_at="$((now + 86400))"

  mysql_exec <<SQL
INSERT INTO v2_server_group
(id, name, created_at, updated_at)
VALUES
(${GROUP_ID}, '${GROUP_NAME}', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  updated_at=VALUES(updated_at);

INSERT INTO v2_server_vmess
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tags, rate, network, rules, networkSettings, tlsSettings, ruleSettings, dnsSettings, \`show\`, sort, created_at, updated_at)
VALUES
(${NODE_ID}, '["${GROUP_ID}"]', NULL, '${NODE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_NODE_PORT}', ${E2E_NODE_PORT}, 0, NULL, '1', 'tcp', NULL, '${NETWORK_SETTINGS}', '{}', '{}', '{}', 1, ${NODE_ID}, ${now}, ${now})
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

INSERT INTO v2_server_v2node
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, listen_ip, port, server_port, tags, rate, \`show\`, sort, protocol, tls, tls_settings, flow, network, network_settings, encryption, encryption_settings, disable_sni, udp_relay_mode, zero_rtt_handshake, congestion_control, cipher, up_mbps, down_mbps, obfs, obfs_password, padding_scheme, created_at, updated_at)
VALUES
(${V2NODE_ID}, '["${GROUP_ID}"]', NULL, '${V2NODE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_BIND_HOST}', '${V2NODE_PORT}', ${V2NODE_PORT}, NULL, '1', 1, ${V2NODE_ID}, 'vmess', 0, '{}', NULL, 'tcp', '${NETWORK_SETTINGS}', NULL, '{}', 0, NULL, 0, NULL, NULL, 0, 0, NULL, NULL, NULL, ${now}, ${now})
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
  \`show\`=VALUES(\`show\`),
  sort=VALUES(sort),
  updated_at=VALUES(updated_at);

INSERT INTO v2_user
(id, invite_user_id, telegram_id, email, language, password, password_algo, password_salt, balance, discount, commission_type, commission_rate, commission_balance, t, u, d, transfer_enable, device_limit, banned, is_admin, last_login_at, is_staff, last_login_ip, uuid, group_id, plan_id, speed_limit, auto_renewal, remind_expire, remind_traffic, token, expired_at, remarks, created_at, updated_at)
VALUES
(${USER_ID}, NULL, NULL, '${USER_EMAIL}', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, ${USER_DEVICE_LIMIT}, 0, 0, NULL, 0, NULL, '${USER_UUID}', ${GROUP_ID}, NULL, ${USER_SPEED_LIMIT}, 0, 1, 1, MD5('${USER_EMAIL}'), ${expires_at}, 'shoes API compat e2e user', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
  group_id=${GROUP_ID},
  speed_limit=VALUES(speed_limit),
  device_limit=VALUES(device_limit),
  expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);

DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
DELETE FROM v2_stat_server WHERE server_id=${V2NODE_ID} AND server_type='v2node';
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
  cache_forget "SERVER_VMESS_LAST_CHECK_AT_${NODE_ID}"
  cache_forget "SERVER_VMESS_LAST_PUSH_AT_${NODE_ID}"
  cache_forget "SERVER_VMESS_ONLINE_USER_${NODE_ID}"
}

cleanup_fixtures() {
  e2e_section "cleanup fixtures"
  mysql_exec <<SQL
DELETE FROM v2_stat_user WHERE user_id=${USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${NODE_ID} AND server_type='vmess';
DELETE FROM v2_stat_server WHERE server_id=${V2NODE_ID} AND server_type='v2node';
DELETE FROM v2_user WHERE id=${USER_ID} AND email='${USER_EMAIL}';
DELETE FROM v2_server_vmess WHERE id=${NODE_ID} AND name='${NODE_NAME}';
DELETE FROM v2_server_v2node WHERE id=${V2NODE_ID} AND name='${V2NODE_NAME}';
DELETE FROM v2_server_group WHERE id=${GROUP_ID} AND name='${GROUP_NAME}';
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${USER_ID}"
  cache_forget "SERVER_VMESS_LAST_CHECK_AT_${NODE_ID}"
  cache_forget "SERVER_VMESS_LAST_PUSH_AT_${NODE_ID}"
  cache_forget "SERVER_VMESS_ONLINE_USER_${NODE_ID}"
}

api_url() {
  local action="$1"

  printf '%s/api/v1/server/UniProxy/%s?token=%s&node_type=vmess&node_id=%s' \
    "${V2BOARD_PANEL_URL}" \
    "${action}" \
    "${SERVER_TOKEN}" \
    "${NODE_ID}"
}

v2_config_api_url() {
  printf '%s/api/v2/server/config?token=%s&node_id=%s' \
    "${V2BOARD_PANEL_URL}" \
    "${SERVER_TOKEN}" \
    "${V2NODE_ID}"
}

header_value() {
  local headers_file="$1"
  local header_name="$2"

  tr -d '\r' <"${headers_file}" \
    | sed -n "s/^${header_name}:[[:space:]]*//Ip" \
    | head -n 1
}

etag_unquoted() {
  local etag="$1"

  etag="${etag#\"}"
  etag="${etag%\"}"
  printf '%s\n' "${etag}"
}

body_preview() {
  local body_file="$1"

  head -c 500 "${body_file}" | tr '\n' ' '
}

curl_capture() {
  local url="$1"
  local headers_file="$2"
  local body_file="$3"
  shift 3

  curl -sS \
    --connect-timeout "${E2E_CURL_CONNECT_TIMEOUT_SECS}" \
    --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    -D "${headers_file}" \
    -o "${body_file}" \
    -w '%{http_code}' \
    "$@" \
    "${url}"
}

assert_http_code() {
  local actual="$1"
  local expected="$2"
  local label="$3"
  local body_file="$4"

  if [[ "${actual}" != "${expected}" ]]; then
    e2e_die "${label}: expected HTTP ${expected}, got ${actual}; body=$(body_preview "${body_file}")"
  fi
}

assert_etag_present() {
  local etag="$1"
  local label="$2"

  [[ -n "${etag}" ]] || e2e_die "${label}: missing ETag response header"
}

assert_config_json() {
  local body_file="$1"

  python3 - "${body_file}" "${E2E_NODE_PORT}" <<'PY'
import json
import sys

path = sys.argv[1]
expected_port = int(sys.argv[2])

with open(path, "rb") as fh:
    data = json.load(fh)

required = ["server_port", "network", "networkSettings", "tls", "base_config"]
missing = [key for key in required if key not in data]
if missing:
    raise SystemExit(f"config JSON missing keys: {missing}")

if int(data["server_port"]) != expected_port:
    raise SystemExit(f"config server_port mismatch: {data['server_port']} != {expected_port}")
if data["network"] != "tcp":
    raise SystemExit(f"config network mismatch: {data['network']!r}")
if data["tls"] not in (0, False):
    raise SystemExit(f"config tls mismatch: {data['tls']!r}")
if not isinstance(data["networkSettings"], dict):
    raise SystemExit(f"config networkSettings must be an object, got {type(data['networkSettings']).__name__}")
if data["networkSettings"].get("header", {}).get("type") != "none":
    raise SystemExit(f"config networkSettings header.type mismatch: {data['networkSettings']!r}")

base_config = data["base_config"]
if not isinstance(base_config, dict):
    raise SystemExit("config base_config must be an object")
for key in ["push_interval", "pull_interval", "node_report_min_traffic", "device_online_min_traffic"]:
    if key not in base_config:
        raise SystemExit(f"config base_config missing key: {key}")
    if not isinstance(base_config[key], int):
        raise SystemExit(f"config base_config {key} must be int, got {type(base_config[key]).__name__}")
PY
}

assert_v2node_config_json() {
  local body_file="$1"

  python3 - "${body_file}" "${V2NODE_PORT}" <<'PY'
import json
import sys

path = sys.argv[1]
expected_port = int(sys.argv[2])

with open(path, "rb") as fh:
    data = json.load(fh)

required = [
    "listen_ip",
    "server_port",
    "network",
    "network_settings",
    "protocol",
    "tls",
    "tls_settings",
    "base_config",
]
missing = [key for key in required if key not in data]
if missing:
    raise SystemExit(f"v2 config JSON missing keys: {missing}")

if int(data["server_port"]) != expected_port:
    raise SystemExit(f"v2 config server_port mismatch: {data['server_port']} != {expected_port}")
if data["protocol"] != "vmess":
    raise SystemExit(f"v2 config protocol mismatch: {data['protocol']!r}")
if data["network"] != "tcp":
    raise SystemExit(f"v2 config network mismatch: {data['network']!r}")
if data["tls"] not in (0, False):
    raise SystemExit(f"v2 config tls mismatch: {data['tls']!r}")
if not isinstance(data["network_settings"], dict):
    raise SystemExit(f"v2 config network_settings must be an object, got {type(data['network_settings']).__name__}")
if data["network_settings"].get("header", {}).get("type") != "none":
    raise SystemExit(f"v2 config network_settings header.type mismatch: {data['network_settings']!r}")

base_config = data["base_config"]
if not isinstance(base_config, dict):
    raise SystemExit("v2 config base_config must be an object")
for key in ["push_interval", "pull_interval", "node_report_min_traffic", "device_online_min_traffic"]:
    if key not in base_config:
        raise SystemExit(f"v2 config base_config missing key: {key}")
    if not isinstance(base_config[key], int):
        raise SystemExit(f"v2 config base_config {key} must be int, got {type(base_config[key]).__name__}")
PY
}

assert_user_payload_python() {
  local format="$1"
  local body_file="$2"

  python3 - "${format}" "${body_file}" "${USER_ID}" "${USER_UUID}" "${USER_SPEED_LIMIT}" "${USER_DEVICE_LIMIT}" <<'PY'
import json
import sys

fmt = sys.argv[1]
path = sys.argv[2]
expected_id = int(sys.argv[3])
expected_uuid = sys.argv[4]
expected_speed_limit = int(sys.argv[5])
expected_device_limit = int(sys.argv[6])

with open(path, "rb") as fh:
    raw = fh.read()

if fmt == "json":
    data = json.loads(raw.decode())
elif fmt == "msgpack":
    try:
        import msgpack
    except ModuleNotFoundError:
        raise SystemExit("missing Python module 'msgpack'; install it for the active python3 before running this check")
    data = msgpack.unpackb(raw, raw=False)
else:
    raise SystemExit(f"unsupported format: {fmt}")

users = data.get("users")
if not isinstance(users, list):
    raise SystemExit(f"{fmt} users must be a list")
if len(users) != 1:
    raise SystemExit(f"{fmt} expected exactly one isolated fixture user, got {len(users)}")

user = users[0]
if int(user.get("id", -1)) != expected_id:
    raise SystemExit(f"{fmt} user id mismatch: {user.get('id')!r} != {expected_id}")
if user.get("uuid") != expected_uuid:
    raise SystemExit(f"{fmt} user uuid mismatch: {user.get('uuid')!r}")
if int(user.get("speed_limit", -1)) != expected_speed_limit:
    raise SystemExit(f"{fmt} user speed_limit mismatch: {user.get('speed_limit')!r}")
if int(user.get("device_limit", -1)) != expected_device_limit:
    raise SystemExit(f"{fmt} user device_limit mismatch: {user.get('device_limit')!r}")

for forbidden in ["email", "group_id", "token", "transfer_enable", "plan_id"]:
    if forbidden in user:
        raise SystemExit(f"{fmt} user payload leaked forbidden field: {forbidden}")
PY
}

verify_config_api() {
  local url
  local code
  local etag

  e2e_section "UniProxy config JSON"
  url="$(api_url config)"
  code="$(curl_capture "${url}" "${TMP_DIR}/config.headers" "${TMP_DIR}/config.json")"
  assert_http_code "${code}" "200" "config JSON" "${TMP_DIR}/config.json"
  assert_config_json "${TMP_DIR}/config.json"
  etag="$(header_value "${TMP_DIR}/config.headers" "ETag")"
  assert_etag_present "${etag}" "config JSON"
  e2e_log "config ETag=${etag}"

  code="$(curl_capture "${url}" "${TMP_DIR}/config-304.headers" "${TMP_DIR}/config-304.body" -H "If-None-Match: ${etag}")"
  assert_http_code "${code}" "304" "config ETag revalidation" "${TMP_DIR}/config-304.body"
}

verify_v2node_config_api() {
  local url
  local code
  local etag
  local raw_etag

  e2e_section "V2Node config JSON"
  url="$(v2_config_api_url)"
  code="$(curl_capture "${url}" "${TMP_DIR}/v2-config.headers" "${TMP_DIR}/v2-config.json")"
  assert_http_code "${code}" "200" "v2 config JSON" "${TMP_DIR}/v2-config.json"
  assert_v2node_config_json "${TMP_DIR}/v2-config.json"
  etag="$(header_value "${TMP_DIR}/v2-config.headers" "ETag")"
  assert_etag_present "${etag}" "v2 config JSON"
  raw_etag="$(etag_unquoted "${etag}")"
  e2e_log "v2 config ETag=${etag}"

  code="$(curl_capture "${url}" "${TMP_DIR}/v2-config-304.headers" "${TMP_DIR}/v2-config-304.body" -H "If-None-Match: ${raw_etag}")"
  assert_http_code "${code}" "304" "v2 config ETag revalidation" "${TMP_DIR}/v2-config-304.body"
}

verify_user_json_api() {
  local url
  local code
  local etag

  e2e_section "UniProxy user JSON"
  url="$(api_url user)"
  code="$(curl_capture "${url}" "${TMP_DIR}/user.headers" "${TMP_DIR}/user.json")"
  assert_http_code "${code}" "200" "user JSON" "${TMP_DIR}/user.json"
  assert_user_payload_python json "${TMP_DIR}/user.json"
  etag="$(header_value "${TMP_DIR}/user.headers" "ETag")"
  assert_etag_present "${etag}" "user JSON"
  e2e_log "user ETag=${etag}"

  code="$(curl_capture "${url}" "${TMP_DIR}/user-304.headers" "${TMP_DIR}/user-304.body" -H "If-None-Match: ${etag}")"
  assert_http_code "${code}" "304" "user ETag revalidation" "${TMP_DIR}/user-304.body"
}

verify_user_msgpack_api() {
  local url
  local code
  local content_type

  e2e_section "UniProxy user msgpack"
  require_python_msgpack
  url="$(api_url user)"
  code="$(curl_capture "${url}" "${TMP_DIR}/user-msgpack.headers" "${TMP_DIR}/user.msgpack" -H "X-Response-Format: msgpack")"
  assert_http_code "${code}" "200" "user msgpack" "${TMP_DIR}/user.msgpack"
  content_type="$(header_value "${TMP_DIR}/user-msgpack.headers" "Content-Type")"
  if ! grep -Fqi "application/x-msgpack" <<<"${content_type}"; then
    e2e_die "user msgpack: expected Content-Type application/x-msgpack, got ${content_type:-<missing>}"
  fi
  assert_user_payload_python msgpack "${TMP_DIR}/user.msgpack"
}

main() {
  parse_args "$@"
  e2e_validate_bool_env E2E_KEEP_FIXTURES 1
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-api-compat-e2e.XXXXXX)"

  self_shellcheck
  resolve_dependencies
  check_environment
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"

  seed_fixtures
  verify_config_api
  verify_v2node_config_api
  verify_user_json_api
  verify_user_msgpack_api

  e2e_section "done"
}

main "$@"
