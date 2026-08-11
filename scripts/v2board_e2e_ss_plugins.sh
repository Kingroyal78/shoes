#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Real V2Board panel E2E for the Shadowsocks plugin contract.
#
# shellcheck source=scripts/v2board_e2e_common.sh
# Seeds v2_server_shadowsocks fixtures (with encrypted ss_client_settings
# profiles produced by the panel's own ShadowsocksClientProfileService), runs
# shoes against the real local panel, and verifies every plugin type with an
# external Mihomo client:
#   - plugin-config manifest / ETag 304
#   - ready ACK with matching applied_revision + adapter feature (Redis
#     capability status written by the panel)
#   - 512KiB payload digest through the plugin edge
#   - panel traffic accounting (v2_stat_user / v2_stat_server) on the plugin
#     node after the transfer
#
# Usage:
#   SHOES_BIN=/path/to/shoes scripts/v2board_e2e_ss_plugins.sh
#   E2E_SS_PLUGIN_CASES=obfs-http,restls scripts/v2board_e2e_ss_plugins.sh
#
# Fixtures use reserved ranges: nodes 9601-9618, users 19601-19618, raw ports
# 18601-18618, plugin ports 18701-18718, target/mixed ports 18650-18687.

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

SHOES_BIN="${SHOES_BIN:-${ROOT_DIR}/target/debug/shoes}"
MIHOMO_BIN="${E2E_MIHOMO_BIN:-/tmp/mihomo-interop}"

# The case matrix is declarative and shared by the profile and the Mihomo
# config, so an option combination is described exactly once.
MATRIX_BIN="${SCRIPT_DIR}/e2e_ss_plugin_matrix.py"
E2E_SS_PLUGIN_GROUPS="${E2E_SS_PLUGIN_GROUPS:-base}"

# matrix: drive Mihomo with the case definition (runtime interop only).
# subscription: drive it with the panel's own client payload, so the panel
# description, the client parser and the backend are checked as one chain.
# The dialect the panel emits depends on the client version it sees, so the
# user agent and the Mihomo binary must be moved together.
E2E_SS_PLUGIN_CLIENT="${E2E_SS_PLUGIN_CLIENT:-matrix}"
E2E_MIHOMO_UA="${E2E_MIHOMO_UA:-mihomo/v1.19.29}"
# Empty by default: a real client sends no `flag`, and the panel only sees a
# client's version through the User-Agent when the parameter is absent.
E2E_SUBSCRIBE_FLAG="${E2E_SUBSCRIBE_FLAG:-}"

matrix_cases() {
  local -a group_args=()
  local group
  for group in ${E2E_SS_PLUGIN_GROUPS//,/ }; do
    group_args+=(--group "${group}")
  done
  python3 "${MATRIX_BIN}" list "${group_args[@]}" --joined
}

CASES="${E2E_SS_PLUGIN_CASES:-$(matrix_cases)}"
PAYLOAD_SIZE="${E2E_PAYLOAD_SIZE:-524288}"
E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
CAMOUFLAGE_HOST="${E2E_CAMOUFLAGE_HOST:-127.0.0.1}"
RESTLS_SCRIPT="${E2E_RESTLS_SCRIPT:-}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-2}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-2}"
E2E_WAIT_TIMEOUT_SECS="${E2E_WAIT_TIMEOUT_SECS:-60}"
E2E_CURL_MAX_TIME_SECS="${E2E_CURL_MAX_TIME_SECS:-45}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_SHOES_LOG_LEVEL="${E2E_SHOES_LOG_LEVEL:-info}"
E2E_MIHOMO_LOG_LEVEL="${E2E_MIHOMO_LOG_LEVEL:-info}"

# Fixture identity and ports are index-derived, so a larger matrix needs a
# wider window than the reserved base-group ranges. Override these when running
# a group that does not fit between the neighbouring scripts' reservations.
CASE_NODE_BASE="${E2E_CASE_NODE_BASE:-9601}"
CASE_USER_BASE="${E2E_CASE_USER_BASE:-19601}"
CASE_RAW_PORT_BASE="${E2E_CASE_RAW_PORT_BASE:-18601}"
CASE_PLUGIN_PORT_BASE="${E2E_CASE_PLUGIN_PORT_BASE:-18701}"
CASE_TARGET_PORT_BASE="${E2E_CASE_TARGET_PORT_BASE:-18650}"

TMP_DIR=""
PIDS=()

case_index() {
  local name="$1"
  local index=0
  IFS=',' read -r -a all <<<"${CASES}"
  for entry in "${all[@]}"; do
    if [[ "${entry}" == "${name}" ]]; then
      printf '%d\n' "${index}"
      return
    fi
    index=$((index + 1))
  done
  e2e_die "internal case index lookup failed for ${name}"
}

case_kind() {
  python3 "${MATRIX_BIN}" kind "$1" || e2e_die "unknown case $1"
}

plugin_feature() {
  python3 "${MATRIX_BIN}" feature "$1" || e2e_die "unknown case $1"
}

# CASE_KIND / CASE_FEATURE / CASE_NEEDS_* for one case, as shell assignments.
# Which fixtures a case needs is derived from its definition rather than from
# the shape of its name, so a new case name cannot silently skip a fixture.
# The fixture user's UUID doubles as its Shadowsocks credential, so it is
# derived from the user id and stays unique across fixture ID windows.
case_uuid() {
  printf '00000000-0000-4000-8000-%012d\n' "$1"
}

case_flags() {
  python3 "${MATRIX_BIN}" flags "$1" || e2e_die "unknown case $1"
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

profile_for_case() {
  local case_name="$1"
  local plugin_port="$3"
  python3 "${MATRIX_BIN}" profile "${case_name}" \
    --plugin-port "${plugin_port}" \
    --camouflage-host "${CAMOUFLAGE_HOST}" \
    --restls-script "${RESTLS_SCRIPT}"
}

encode_profile_blob() {
  local profile_json="$1"
  local b64
  b64="$(printf '%s' "${profile_json}" | base64 -w0)"
  docker exec -i \
    -e E2E_PROFILE_B64="${b64}" \
    "${V2BOARD_WWW_CONTAINER}" \
    php artisan tinker --execute='
$service = new \App\Services\ShadowsocksClientProfileService();
$profile = json_decode(base64_decode(getenv("E2E_PROFILE_B64")), true);
if (!is_array($profile)) { throw new RuntimeException("invalid profile input"); }
echo $service->prepareForSave([], $profile);
' 2>/dev/null
}

# The user's subscription token is char(32) in the panel schema, so it is
# derived from the numeric user id rather than the case name.
seed_fixture() {
  local case_name="$1"
  local node_id="$2"
  local user_id="$3"
  local group_id="$4"
  local raw_port="$5"
  local plugin_port="$6"
  local now
  local profile_json
  local blob

  now="$(date +%s)"
  profile_json="$(profile_for_case "${case_name}" "${raw_port}" "${plugin_port}")"
  blob="$(encode_profile_blob "${profile_json}")"
  [[ "${blob}" == sscp:v1:* ]] || e2e_die "${case_name}: panel refused the seeded profile"

  mysql_exec <<SQL
INSERT INTO v2_server_group
(id, name, created_at, updated_at)
VALUES
(${group_id}, 'shoes-e2e-ss-plugin-${case_name}', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  updated_at=VALUES(updated_at);
SQL

  mysql_exec <<SQL
INSERT INTO v2_server_shadowsocks
(id, group_id, route_id, parent_id, tags, name, country_code, city_name, city_id, rate, host, port, server_port, cipher, obfs, obfs_settings, gost_enable, gost_settings, ss_client_settings, \`show\`, sort, created_at, updated_at)
VALUES
(${node_id}, '["${group_id}"]', NULL, NULL, NULL, 'shoes-e2e-${case_name}', 'US', 'Local', NULL, '1', '${E2E_BIND_HOST}', '${plugin_port}', ${raw_port}, 'aes-128-gcm', NULL, NULL, 0, NULL, '${blob}', 1, ${node_id}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  cipher=VALUES(cipher),
  ss_client_settings=VALUES(ss_client_settings),
  \`show\`=VALUES(\`show\`),
  sort=VALUES(sort),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_server WHERE server_id=${node_id} AND server_type='shadowsocks';
SQL

  mysql_exec <<SQL
INSERT INTO v2_user
(id, invite_user_id, telegram_id, email, language, password, password_algo, password_salt, balance, discount, commission_type, commission_rate, commission_balance, t, u, d, transfer_enable, device_limit, banned, is_admin, last_login_at, is_staff, last_login_ip, uuid, group_id, plan_id, speed_limit, auto_renewal, remind_expire, remind_traffic, token, expired_at, remarks, created_at, updated_at)
VALUES
(${user_id}, NULL, NULL, 'shoes-e2e-u${user_id}-${case_name}@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '$(case_uuid "${user_id}")', ${group_id}, NULL, NULL, 0, 1, 1, 'shoes-e2e-u${user_id}', $((now + 86400)), 'shoes ss plugin e2e user', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
  token=VALUES(token),
  email=VALUES(email),
  group_id=VALUES(group_id),
  speed_limit=NULL,
  device_limit=NULL,
  expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_user WHERE user_id=${user_id};
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${user_id}"
  docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli -n 1 DEL \
    "v2board_database_v2board_cache:SERVER_SHADOWSOCKS_CAPABILITY_STATUS_${node_id}" >/dev/null 2>&1 || true
}

free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_http() {
  local url="$1"
  for _ in $(seq 1 100); do
    if curl --silent --show-error --fail --max-time 1 "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

wait_tcp() {
  local port="$1"
  for _ in $(seq 1 100); do
    if python3 - "${port}" <<'PY'
import socket
import sys
try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2):
        pass
except OSError:
    raise SystemExit(1)
PY
    then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

plugin_config_revision() {
  local node_id="$1"
  curl --silent --show-error --fail --max-time 5 \
    "${V2BOARD_PANEL_URL}/api/v1/server/UniProxy/plugin-config?token=${SERVER_TOKEN}&node_type=shadowsocks&node_id=${node_id}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("config_revision", ""))'
}

wait_capability_ready() {
  local node_id="$1"
  local expected_revision="$2"
  local expected_feature="$3"
  local start
  local now
  local raw_status

  start="$(date +%s)"
  while true; do
    raw_status="$(docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli -n 1 GET \
      "v2board_database_v2board_cache:SERVER_SHADOWSOCKS_CAPABILITY_STATUS_${node_id}" 2>/dev/null || true)"
    if printf '%s' "${raw_status}" \
      | python3 "${TMP_DIR}/capability_check.py" "${expected_revision}" "${expected_feature}"; then
      return 0
    fi

    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_die "node ${node_id}: shoes never ACKed a ready plugin generation (revision ${expected_revision})"
    fi
    sleep 0.5
  done
}

# Bounded, non-fatal counterpart of wait_capability_ready, for the cases where
# a ready ACK is the failure: the panel stores the profile and serves the
# manifest, and the backend has to refuse it rather than apply it.
capability_ready_within() {
  local node_id="$1"
  local expected_revision="$2"
  local expected_feature="$3"
  local budget="$4"
  local start
  local now
  local raw_status

  start="$(date +%s)"
  while true; do
    raw_status="$(docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli -n 1 GET \
      "v2board_database_v2board_cache:SERVER_SHADOWSOCKS_CAPABILITY_STATUS_${node_id}" 2>/dev/null || true)"
    if printf '%s' "${raw_status}" \
      | python3 "${TMP_DIR}/capability_check.py" "${expected_revision}" "${expected_feature}"; then
      return 0
    fi
    now="$(date +%s)"
    if ((now - start >= budget)); then
      return 1
    fi
    sleep 0.5
  done
}

assert_plugin_config_etag() {
  local node_id="$1"
  local headers
  local etag
  local code

  headers="$(mktemp)"
  curl --silent --show-error --fail --max-time 5 \
    -D "${headers}" -o /dev/null \
    "${V2BOARD_PANEL_URL}/api/v1/server/UniProxy/plugin-config?token=${SERVER_TOKEN}&node_type=shadowsocks&node_id=${node_id}"
  etag="$(awk 'tolower($1)=="etag:" {print $2}' "${headers}" | tr -d '\r')"
  rm -f "${headers}"
  [[ -n "${etag}" ]] || e2e_die "node ${node_id}: plugin-config response is missing ETag"
  code="$(curl --silent --show-error --max-time 5 \
    -o /dev/null -w '%{http_code}' \
    -H "If-None-Match: ${etag}" \
    "${V2BOARD_PANEL_URL}/api/v1/server/UniProxy/plugin-config?token=${SERVER_TOKEN}&node_type=shadowsocks&node_id=${node_id}")"
  [[ "${code}" == "304" ]] \
    || e2e_die "node ${node_id}: plugin-config did not answer 304 for its own ETag (got ${code})"
}

write_shoes_config() {
  local output="$1"
  local data_dir="$2"
  local node_id="$3"
  local tag="$4"
  local tls_cert="${5:-}"
  local tls_key="${6:-}"
  local tls=""
  if [[ -n "${tls_cert}" ]]; then
    tls="
tls:
  cert_file: \"${tls_cert}\"
  key_file: \"${tls_key}\"
"
  fi
  cat >"${output}" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${SERVER_TOKEN}"
  api_timeout_secs: 3
  nodes:
    - tag: "${tag}"
      node_id: ${node_id}
      node_type: "shadowsocks"
      listen: "${E2E_BIND_HOST}"
      pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
      push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
runtime:
  data_dir: "${data_dir}"
  pull_interval_secs: ${E2E_PULL_INTERVAL_SECS}
  push_interval_secs: ${E2E_PUSH_INTERVAL_SECS}
  max_legacy_shadowsocks_users: 16${tls}
log:
  level: "${E2E_SHOES_LOG_LEVEL}"
YAML
}

write_mihomo_config() {
  local output="$1"
  local case_name="$2"
  local plugin_port="$3"
  local mixed_port="$4"
  local password="$5"
  python3 "${MATRIX_BIN}" mihomo "${case_name}" \
    --plugin-port "${plugin_port}" \
    --mixed-port "${mixed_port}" \
    --password "${password}" \
    --camouflage-host "${CAMOUFLAGE_HOST}" \
    --restls-script "${RESTLS_SCRIPT}" \
    --log-level "${E2E_MIHOMO_LOG_LEVEL}" >"${output}"
}

write_mihomo_config_from_subscription() {
  local output="$1"
  local case_name="$2"
  local user_id="$3"
  local plugin_port="$4"
  local mixed_port="$5"
  local raw="$6"

  curl --silent --show-error --fail --max-time 20 \
    --noproxy "" \
    -H "User-Agent: ${E2E_MIHOMO_UA}" \
    "${V2BOARD_PANEL_URL}/api/v1/client/subscribe?token=shoes-e2e-u${user_id}${E2E_SUBSCRIBE_FLAG:+&flag=${E2E_SUBSCRIBE_FLAG}}" \
    >"${raw}" \
    || e2e_die "${case_name}: subscription fetch failed"

  python3 "${MATRIX_BIN}" from-subscription "${case_name}" \
    --subscription "${raw}" \
    --plugin-port "${plugin_port}" \
    --mixed-port "${mixed_port}" \
    >"${output}" \
    || e2e_die "${case_name}: panel subscription did not describe the node"
}

# A datagram that comes back unchanged is the only proof that the UDP path
# works; the payload download says nothing about it.
assert_udp_round_trip() {
  local case_name="$1"
  local mixed_port="$2"
  local udp_port="$3"
  local case_dir="$4"

  python3 - "${udp_port}" >"${case_dir}/udp-echo.log" 2>&1 <<'ECHO_SERVER' &
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    payload, peer = sock.recvfrom(65535)
    sock.sendto(payload, peer)
ECHO_SERVER
  PIDS+=("$!")
  sleep 0.5

  python3 "${SCRIPT_DIR}/e2e_socks5_udp_probe.py" \
    --proxy-port "${mixed_port}" \
    --target-port "${udp_port}" \
    >"${case_dir}/udp-probe.log" 2>&1 \
    || e2e_die "${case_name}: UDP round trip failed ($(tail -n 1 "${case_dir}/udp-probe.log"))"
  e2e_log "PASS ${case_name}: $(tail -n 1 "${case_dir}/udp-probe.log")"
}

# Withdrawing a plugin is a runtime transition: the backend has to tear the
# plugin graph down, acknowledge the `plugin: null` revision, and leave the
# bare Shadowsocks endpoint serving. A client pointed at the raw port proves
# the last part; the panel keeps the node hidden from real clients until the
# acknowledgement, which is what makes the order matter.
assert_plugin_withdrawal() {
  local case_name="$1"
  local node_id="$2"
  local raw_port="$3"
  local plugin_port="$4"
  local target_port="$5"
  local mixed_port="$6"
  local password="$7"
  local case_dir="$8"
  local profile_json
  local blob
  local revision
  local now

  profile_json="$(python3 "${MATRIX_BIN}" profile "${case_name}" \
    --plugin-port "${plugin_port}" \
    --camouflage-host "${CAMOUFLAGE_HOST}" \
    --restls-script "${RESTLS_SCRIPT}" \
    --without-plugin)"
  blob="$(encode_profile_blob "${profile_json}")"
  [[ "${blob}" == sscp:v1:* ]] \
    || e2e_die "${case_name}: panel refused the profile with its plugin withdrawn"

  now="$(date +%s)"
  mysql_exec <<SQL
UPDATE v2_server_shadowsocks
SET ss_client_settings='${blob}', updated_at=${now}
WHERE id=${node_id};
SQL

  revision="$(plugin_config_revision "${node_id}")"
  [[ "${revision}" == sha256:* ]] \
    || e2e_die "${case_name}: panel served no revision after the plugin was withdrawn"
  wait_capability_ready "${node_id}" "${revision}" "shadowsocks-plugin-runtime-v1"
  e2e_log "${case_name}: shoes ACKed the plugin-less generation"

  python3 "${MATRIX_BIN}" mihomo "${case_name}" \
    --plugin-port "${raw_port}" \
    --mixed-port "${mixed_port}" \
    --password "${password}" \
    --without-plugin >"${case_dir}/mihomo-raw.yml"
  mkdir -p "${case_dir}/mihomo-raw"
  "${MIHOMO_BIN}" -d "${case_dir}/mihomo-raw" -f "${case_dir}/mihomo-raw.yml" \
    >"${case_dir}/mihomo-raw.log" 2>&1 &
  PIDS+=("$!")
  wait_tcp "${mixed_port}" || e2e_die "${case_name}: Mihomo did not start for the raw endpoint"

  curl --silent --show-error --fail --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    --noproxy "" \
    --proxy "socks5h://127.0.0.1:${mixed_port}" \
    --output "${case_dir}/raw-payload.bin" \
    "http://127.0.0.1:${target_port}/payload.bin" \
    || e2e_die "${case_name}: raw Shadowsocks download failed after the plugin was withdrawn"

  if ! printf '%s  %s\n' "$(cat "${case_dir}/expected.sha256")" "${case_dir}/raw-payload.bin" \
    | sha256sum --check --status; then
    e2e_die "${case_name}: raw Shadowsocks payload digest mismatch"
  fi
  e2e_log "PASS ${case_name}: bare Shadowsocks runtime took over"
}

wait_traffic_accounted() {
  local node_id="$1"
  local user_id="$2"
  local expected_payload="$3"
  local start
  local now
  local row

  start="$(date +%s)"
  while true; do
    e2e_drain_v2board_queues "${V2BOARD_WWW_CONTAINER}"
    docker exec "${V2BOARD_WWW_CONTAINER}" php artisan traffic:update >/dev/null 2>&1 || true
    row="$(mysql_query "SELECT su.d, ss.d FROM v2_stat_user su JOIN v2_stat_server ss ON ss.server_id=${node_id} AND ss.server_type='shadowsocks' WHERE su.user_id=${user_id} ORDER BY su.id DESC LIMIT 1;")"
    if [[ -n "${row}" ]]; then
      read -r stat_user_d stat_server_d <<<"${row}"
      if ((stat_user_d >= expected_payload && stat_server_d >= expected_payload)); then
        e2e_log "accounted stat_user.d=${stat_user_d} stat_server.d=${stat_server_d}"
        return
      fi
    fi

    now="$(date +%s)"
    if ((now - start >= E2E_WAIT_TIMEOUT_SECS)); then
      e2e_die "node ${node_id}: panel traffic accounting did not reach ${expected_payload}; last=${row:-<empty>}"
    fi
    sleep 1
  done
}

cleanup_case() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
  done
  for pid in "${PIDS[@]:-}"; do
    wait "${pid}" 2>/dev/null || true
  done
  PIDS=()
}

run_case() {
  local case_name="$1"
  local index
  local node_id
  local user_id
  local group_id
  local raw_port
  local plugin_port
  local target_port
  local mixed_port
  local case_dir
  local expected_revision
  local expected_feature
  local CASE_KIND CASE_FEATURE CASE_GROUP
  local CASE_NEEDS_CAMOUFLAGE CASE_NEEDS_SERVER_TLS CASE_NEEDS_CERT CASE_CAMOUFLAGE_TLS
  local CASE_EXPECT CASE_UDP
  local udp_port
  local -a tls_version_args=()

  eval "$(case_flags "${case_name}")"
  index="$(case_index "${case_name}")"
  node_id=$((CASE_NODE_BASE + index))
  user_id=$((CASE_USER_BASE + index))
  group_id="${node_id}"
  raw_port=$((CASE_RAW_PORT_BASE + index))
  plugin_port=$((CASE_PLUGIN_PORT_BASE + index))
  target_port=$((CASE_TARGET_PORT_BASE + index * 2))
  mixed_port=$((CASE_TARGET_PORT_BASE + index * 2 + 1))
  # Well clear of the four per-case ports, which are packed two apart.
  udp_port=$((mixed_port + 10000))
  case_dir="${TMP_DIR}/${case_name}"
  mkdir -p "${case_dir}/data" "${case_dir}/mihomo" "${case_dir}/www"

  e2e_section "case ${case_name} (node ${node_id}, raw ${raw_port}, plugin ${plugin_port})"
  e2e_assert_port_free "${raw_port}" "${case_name} raw"
  e2e_assert_port_free "${plugin_port}" "${case_name} plugin"
  e2e_assert_port_free "${target_port}" "${case_name} target"
  e2e_assert_port_free "${mixed_port}" "${case_name} mixed"

  if [[ "${CASE_EXPECT}" == "profile-rejected" ]]; then
    local rejected_profile rejected_blob
    rejected_profile="$(profile_for_case "${case_name}" "${raw_port}" "${plugin_port}")"
    rejected_blob="$(encode_profile_blob "${rejected_profile}" || true)"
    if [[ "${rejected_blob}" == sscp:v1:* ]]; then
      e2e_die "${case_name}: panel stored a profile it is required to refuse"
    fi
    e2e_log "PASS ${case_name}: panel refused the profile"
    cleanup_case
    return 0
  fi

  seed_fixture \
    "${case_name}" \
    "${node_id}" \
    "${user_id}" \
    "${group_id}" \
    "${raw_port}" \
    "${plugin_port}"
  e2e_log "${case_name}: fixture seeded"

  expected_revision="$(plugin_config_revision "${node_id}")"
  [[ "${expected_revision}" == sha256:* ]] \
    || e2e_die "${case_name}: panel plugin-config did not return a revision"
  expected_feature="$(plugin_feature "${case_name}")"
  assert_plugin_config_etag "${node_id}"
  e2e_log "${case_name}: plugin-config revision=${expected_revision} feature=${expected_feature}"

  python3 - "${case_dir}/www/payload.bin" "${PAYLOAD_SIZE}" <<'PY'
import pathlib
import sys
path, size = sys.argv[1], int(sys.argv[2])
payload = bytes((index * 31 + 17) & 0xff for index in range(size))
pathlib.Path(path).write_bytes(payload)
PY
  sha256sum "${case_dir}/www/payload.bin" | cut -d' ' -f1 >"${case_dir}/expected.sha256"

  python3 -m http.server "${target_port}" \
    --bind 127.0.0.1 \
    --directory "${case_dir}/www" \
    >"${case_dir}/target.log" 2>&1 &
  PIDS+=("$!")
  wait_http "http://127.0.0.1:${target_port}/payload.bin" \
    || e2e_die "${case_name}: target server did not start"

  if [[ "${CASE_NEEDS_CERT}" == "1" ]]; then
    e2e_require_command openssl "openssl (TLS plugin cases)"
    openssl req -x509 -newkey rsa:2048 -nodes \
      -subj "/CN=localhost" \
      -days 1 \
      -keyout "${case_dir}/camouflage.key" \
      -out "${case_dir}/camouflage.crt" \
      >"${case_dir}/openssl-cert.log" 2>&1
  fi
  if [[ "${CASE_NEEDS_CAMOUFLAGE}" == "1" ]]; then
    e2e_assert_port_free 443 "camouflage TLS"
    case "${E2E_CAMOUFLAGE_TLS_VERSION:-${CASE_CAMOUFLAGE_TLS}}" in
      auto) ;;
      tls12) tls_version_args=(-tls1_2) ;;
      tls13) tls_version_args=(-tls1_3) ;;
      *) e2e_die "invalid E2E_CAMOUFLAGE_TLS_VERSION=${E2E_CAMOUFLAGE_TLS_VERSION}" ;;
    esac
    openssl s_server \
      -accept "127.0.0.1:443" \
      -cert "${case_dir}/camouflage.crt" \
      -key "${case_dir}/camouflage.key" \
      "${tls_version_args[@]}" \
      -www \
      -quiet \
      >"${case_dir}/camouflage.log" 2>&1 &
    PIDS+=("$!")
    wait_tcp 443 || e2e_die "${case_name}: local TLS camouflage server did not start"
  fi

  if [[ "${CASE_NEEDS_SERVER_TLS}" == "1" ]]; then
    write_shoes_config \
      "${case_dir}/shoes.yml" \
      "${case_dir}/data" \
      "${node_id}" \
      "ss-plugin-${case_name}" \
      "${case_dir}/camouflage.crt" \
      "${case_dir}/camouflage.key"
  else
    write_shoes_config "${case_dir}/shoes.yml" "${case_dir}/data" "${node_id}" "ss-plugin-${case_name}"
  fi
  "${SHOES_BIN}" run -c "${case_dir}/shoes.yml" >"${case_dir}/shoes.log" 2>&1 &
  PIDS+=("$!")
  if [[ "${CASE_EXPECT}" == "runtime-rejected" ]]; then
    if capability_ready_within \
      "${node_id}" \
      "${expected_revision}" \
      "${expected_feature}" \
      "${E2E_REJECT_WAIT_SECS:-10}"; then
      e2e_die "${case_name}: backend acknowledged a manifest it is required to refuse"
    fi
    e2e_log "PASS ${case_name}: backend refused the manifest"
    cleanup_case
    return 0
  fi

  wait_capability_ready "${node_id}" "${expected_revision}" "${expected_feature}"
  e2e_log "${case_name}: shoes ACKed a ready plugin generation"

  if [[ "${E2E_SS_PLUGIN_CLIENT}" == "subscription" ]]; then
    write_mihomo_config_from_subscription \
      "${case_dir}/mihomo.yml" \
      "${case_name}" \
      "${user_id}" \
      "${plugin_port}" \
      "${mixed_port}" \
      "${case_dir}/subscription.yml"
    e2e_log "${case_name}: client config taken from the panel subscription (UA ${E2E_MIHOMO_UA})"
  else
    write_mihomo_config \
      "${case_dir}/mihomo.yml" \
      "${case_name}" \
      "${plugin_port}" \
      "${mixed_port}" \
      "$(case_uuid "${user_id}")"
  fi
  "${MIHOMO_BIN}" -d "${case_dir}/mihomo" -f "${case_dir}/mihomo.yml" \
    >"${case_dir}/mihomo.log" 2>&1 &
  PIDS+=("$!")
  wait_tcp "${mixed_port}" || e2e_die "${case_name}: Mihomo mixed listener did not start"

  curl --silent --show-error --fail --max-time "${E2E_CURL_MAX_TIME_SECS}" \
    --noproxy "" \
    --proxy "socks5h://127.0.0.1:${mixed_port}" \
    "http://127.0.0.1:${target_port}/payload.bin" \
    --output "${case_dir}/actual.bin" \
    || e2e_die "${case_name}: Mihomo download through shoes failed"
  local expected actual
  expected="$(cat "${case_dir}/expected.sha256")"
  actual="$(sha256sum "${case_dir}/actual.bin" | cut -d' ' -f1)"
  [[ "${actual}" == "${expected}" ]] \
    || e2e_die "${case_name}: payload digest mismatch expected=${expected} actual=${actual}"
  e2e_log "PASS ${case_name}: ${PAYLOAD_SIZE} bytes, sha256=${actual}"

  if [[ "${CASE_EXPECT}" == "plugin-disabled" ]]; then
    assert_plugin_withdrawal \
      "${case_name}" \
      "${node_id}" \
      "${raw_port}" \
      "${plugin_port}" \
      "${target_port}" \
      "$((udp_port + 1))" \
      "$(case_uuid "${user_id}")" \
      "${case_dir}"
  fi

  if [[ "${CASE_UDP}" == "1" ]]; then
    e2e_assert_port_free "${udp_port}" "${case_name} udp echo"
    assert_udp_round_trip "${case_name}" "${mixed_port}" "${udp_port}" "${case_dir}"
  fi

  wait_traffic_accounted "${node_id}" "${user_id}" "${PAYLOAD_SIZE}"
  e2e_log "PASS ${case_name}: panel traffic accounting verified"
  cleanup_case
}

cleanup_fixtures() {
  local node_id
  local user_id
  local index
  local name
  IFS=',' read -r -a all <<<"${CASES}"
  index=0
  for name in "${all[@]}"; do
    node_id=$((CASE_NODE_BASE + index))
    user_id=$((CASE_USER_BASE + index))
    docker exec "${V2BOARD_MYSQL_CONTAINER}" mysql \
      -u"${V2BOARD_MYSQL_USER}" \
      -p"${V2BOARD_MYSQL_PASSWORD}" \
      "${V2BOARD_MYSQL_DATABASE}" \
      -e "DELETE FROM v2_server_shadowsocks WHERE id=${node_id};
          DELETE FROM v2_server_group WHERE id=${node_id};
          DELETE FROM v2_user WHERE id=${user_id};
          DELETE FROM v2_stat_user WHERE user_id=${user_id};
          DELETE FROM v2_stat_server WHERE server_id=${node_id} AND server_type='shadowsocks';" \
      >/dev/null 2>&1 || true
    docker exec "${V2BOARD_REDIS_CONTAINER}" redis-cli -n 1 DEL \
      "v2board_database_v2board_cache:SERVER_SHADOWSOCKS_CAPABILITY_STATUS_${node_id}" >/dev/null 2>&1 || true
    index=$((index + 1))
  done
}

cleanup() {
  cleanup_case
  if e2e_env_bool E2E_KEEP_FIXTURES 1; then
    e2e_log "keeping ss-plugin E2E fixtures (E2E_KEEP_FIXTURES=1)"
  else
    cleanup_fixtures
  fi
  if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" && "${E2E_KEEP_TMP:-0}" != "1" ]]; then
    rm -rf -- "${TMP_DIR}"
  elif [[ -n "${TMP_DIR}" ]]; then
    e2e_log "preserved ${TMP_DIR}"
  fi
}
trap cleanup EXIT INT TERM

main() {
  e2e_require_command curl "curl"
  e2e_require_command python3 "python3"
  e2e_require_command sha256sum "sha256sum"
  e2e_require_command openssl "openssl"

  docker ps --format '{{.Names}}' | grep -Fxq "${V2BOARD_WWW_CONTAINER}" \
    || e2e_die "missing running www container: ${V2BOARD_WWW_CONTAINER}"
  docker ps --format '{{.Names}}' | grep -Fxq "${V2BOARD_MYSQL_CONTAINER}" \
    || e2e_die "missing running mysql container: ${V2BOARD_MYSQL_CONTAINER}"
  docker ps --format '{{.Names}}' | grep -Fxq "${V2BOARD_REDIS_CONTAINER}" \
    || e2e_die "missing running redis container: ${V2BOARD_REDIS_CONTAINER}"
  e2e_http_probe "${V2BOARD_PANEL_URL}/api/v1/server/UniProxy/status?token=none&node_type=shadowsocks&node_id=1" || true

  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server token"

  if [[ -z "${SHOES_BIN}" ]]; then
    e2e_log "building current shoes source"
    cargo build --manifest-path "${ROOT_DIR}/Cargo.toml" --bin shoes
  elif [[ ! -x "${SHOES_BIN}" ]]; then
    e2e_die "SHOES_BIN is not executable: ${SHOES_BIN}"
  fi
  if [[ ! -x "${MIHOMO_BIN}" ]]; then
    e2e_die "missing external Mihomo client binary: ${MIHOMO_BIN} (set E2E_MIHOMO_BIN)"
  fi
  e2e_log "external client: $("${MIHOMO_BIN}" -v | head -1)"

  TMP_DIR="$(mktemp -d /tmp/shoes-ss-plugin-v2board.XXXXXX)"
  cat >"${TMP_DIR}/capability_check.py" <<'PY'
import re
import sys

expected_revision, expected_feature = sys.argv[1:]
raw = sys.stdin.read()
if not raw:
    raise SystemExit(1)

ready = re.search(r's:5:"ready";b:([01]);', raw)
if not ready or ready.group(1) != "1":
    raise SystemExit(1)
applied_revision = re.search(r's:16:"applied_revision";s:\d+:"([^"]*)"', raw)
if not applied_revision or applied_revision.group(1) != expected_revision:
    raise SystemExit(1)
features_block = re.search(r's:16:"applied_features";a:\d+:\{(.*?)\}', raw)
if not features_block:
    raise SystemExit(1)
features = re.findall(r's:\d+:"([^"]+)"', features_block.group(1))
if expected_feature not in features or "shadowsocks-plugin-runtime-v1" not in features:
    raise SystemExit(1)
PY

  IFS=',' read -r -a case_list <<<"${CASES}"
  local case_name
  for case_name in "${case_list[@]}"; do
    run_case "${case_name}"
  done
  e2e_log "all real-panel Shadowsocks plugin cases passed"
}

main "$@"
