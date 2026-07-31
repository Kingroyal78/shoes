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
CASES="${E2E_SS_PLUGIN_CASES:-obfs-http,obfs-tls,v2ray-ws,v2ray-wss,v2ray-ws-mux,v2ray-wss-mux,v2ray-http-upgrade,v2ray-https-upgrade,gost-ws,gost-wss,gost-ws-mux,gost-wss-mux,shadowtls-v1,shadowtls-v2,shadowtls-v3,restls,kcptun-v1,kcptun-v2}"
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

CASE_NODE_BASE=9601
CASE_USER_BASE=19601
CASE_RAW_PORT_BASE=18601
CASE_PLUGIN_PORT_BASE=18701
CASE_TARGET_PORT_BASE=18650

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
  local name="$1"
  if [[ "${name}" == v2ray-* ]]; then
    printf 'v2ray-plugin\n'
  elif [[ "${name}" == gost-* ]]; then
    printf 'gost-plugin\n'
  elif [[ "${name}" == shadowtls-* ]]; then
    printf 'shadow-tls\n'
  elif [[ "${name}" == kcptun-* ]]; then
    printf 'kcptun\n'
  elif [[ "${name}" == obfs-* ]]; then
    printf 'obfs\n'
  elif [[ "${name}" == restls ]]; then
    printf 'restls\n'
  else
    e2e_die "unknown case ${name}"
  fi
}

plugin_feature() {
  local kind
  kind="$(case_kind "$1")"
  case "${kind}" in
    v2ray-plugin) printf 'shadowsocks-plugin-v2ray-v1\n' ;;
    gost-plugin) printf 'shadowsocks-plugin-gost-v1\n' ;;
    shadow-tls) printf 'shadowsocks-plugin-shadow-tls-v1\n' ;;
    kcptun) printf 'shadowsocks-plugin-kcptun-v1\n' ;;
    obfs) printf 'shadowsocks-plugin-obfs-v1\n' ;;
    restls) printf 'shadowsocks-plugin-restls-v1\n' ;;
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

profile_for_case() {
  local case_name="$1"
  local raw_port="$2"
  local plugin_port="$3"
  python3 - \
    "${case_name}" \
    "${raw_port}" \
    "${plugin_port}" \
    "${CAMOUFLAGE_HOST}" \
    "${RESTLS_SCRIPT}" <<'PY'
import json
import sys

case, raw_port, plugin_port, camouflage_host, restls_script = sys.argv[1:]
raw_port, plugin_port = int(raw_port), int(plugin_port)

def options_for_case():
    if case.startswith("obfs-"):
        return {"mode": case.removeprefix("obfs-"), "host": "interop.test"}
    if case.startswith("v2ray-"):
        tls = case in ("v2ray-wss", "v2ray-wss-mux", "v2ray-https-upgrade")
        opts = {
            "mode": "websocket",
            "host": "interop.test",
            "path": "/interop",
            "tls": tls,
            "fingerprint": "",
            "skip_cert_verify": tls,
            "mux": case in ("v2ray-ws-mux", "v2ray-wss-mux"),
            "v2ray_http_upgrade": case in ("v2ray-http-upgrade", "v2ray-https-upgrade"),
            "v2ray_http_upgrade_fast_open": False,
        }
        return opts
    if case.startswith("gost-"):
        tls = case in ("gost-wss", "gost-wss-mux")
        return {
            "mode": "websocket",
            "host": "interop.test",
            "path": "/interop",
            "tls": tls,
            "fingerprint": "",
            "skip_cert_verify": tls,
            "mux": case in ("gost-ws-mux", "gost-wss-mux"),
        }
    if case.startswith("shadowtls-"):
        version = int(case[-1])
        opts = {"host": camouflage_host, "version": version}
        if version > 1:
            opts["password"] = "shadowtls-interop-password"
        return opts
    if case == "restls":
        return {
            "host": camouflage_host,
            "password": "restls-interop-password",
            "version_hint": "tls13",
            "restls_script": restls_script,
        }
    if case.startswith("kcptun-"):
        return {
            "key": "shoes-kcptun-interop",
            "crypt": "aes-128",
            "mode": "manual",
            "conn": 1,
            "autoexpire": 0,
            "scavengettl": 60,
            "mtu": 1350,
            "ratelimit": 0,
            "sndwnd": 256,
            "rcvwnd": 512,
            "datashard": 4,
            "parityshard": 2,
            "dscp": 0,
            "nocomp": False,
            "acknodelay": True,
            "nodelay": 1,
            "interval": 10,
            "resend": 2,
            "nc": 1,
            "sockbuf": 4194304,
            "smuxver": int(case[-1]),
            "smuxbuf": 4194304,
            "framesize": 8192,
            "streambuf": 1048576,
            "keepalive": 1,
        }
    raise SystemExit(f"unsupported case: {case}")

plugin = {
    "type": {
        "obfs-http": "obfs", "obfs-tls": "obfs",
    }.get(case, "v2ray-plugin" if case.startswith("v2ray-") else "gost-plugin" if case.startswith("gost-") else "shadow-tls" if case.startswith("shadowtls-") else "restls" if case == "restls" else "kcptun"),
    "endpoint_host": "127.0.0.1",
    "endpoint_port": plugin_port,
    "options": options_for_case(),
}
profile = {"version": 1, "plugin": plugin}
if case.startswith("shadowtls-") or case == "restls":
    profile["client_fingerprint"] = "chrome"
print(json.dumps(profile, separators=(",", ":")))
PY
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
(${user_id}, NULL, NULL, 'shoes-e2e-${case_name}@example.local', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '00000000-0000-4000-8000-0000000${node_id}', ${group_id}, NULL, NULL, 0, 1, 1, 'shoes-e2e-${case_name}', $((now + 86400)), 'shoes ss plugin e2e user', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
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
  python3 - \
    "${output}" \
    "${case_name}" \
    "${plugin_port}" \
    "${mixed_port}" \
    "${CAMOUFLAGE_HOST}" \
    "${password}" <<'PY'
import json
import pathlib
import sys

output, case, plugin_port, mixed_port, camouflage_host, password = sys.argv[1:]
plugin = ""
plugin_opts = []
if case.startswith("obfs-"):
    plugin = "obfs"
    plugin_opts = [
        f"mode: {case.removeprefix('obfs-')}",
        "host: interop.test",
    ]
elif case.startswith("v2ray-"):
    plugin = "v2ray-plugin"
    plugin_opts = [
        "mode: websocket",
        "host: interop.test",
        "path: /interop",
        f"tls: {'true' if case in ('v2ray-wss', 'v2ray-wss-mux', 'v2ray-https-upgrade') else 'false'}",
        f"skip-cert-verify: {'true' if case in ('v2ray-wss', 'v2ray-wss-mux', 'v2ray-https-upgrade') else 'false'}",
        f"mux: {'true' if case in ('v2ray-ws-mux', 'v2ray-wss-mux') else 'false'}",
        f"v2ray-http-upgrade: {'true' if case in ('v2ray-http-upgrade', 'v2ray-https-upgrade') else 'false'}",
    ]
elif case.startswith("gost-"):
    plugin = "gost-plugin"
    plugin_opts = [
        "mode: websocket",
        "host: interop.test",
        "path: /interop",
        f"tls: {'true' if case in ('gost-wss', 'gost-wss-mux') else 'false'}",
        f"skip-cert-verify: {'true' if case in ('gost-wss', 'gost-wss-mux') else 'false'}",
        f"mux: {'true' if case in ('gost-ws-mux', 'gost-wss-mux') else 'false'}",
    ]
elif case.startswith("kcptun-"):
    plugin = "kcptun"
    plugin_opts = [
        "key: shoes-kcptun-interop",
        "crypt: aes-128",
        "mode: manual",
        "conn: 1",
        "autoexpire: 0",
        "scavengettl: 60",
        "mtu: 1350",
        "ratelimit: 0",
        "sndwnd: 256",
        "rcvwnd: 512",
        "datashard: 4",
        "parityshard: 2",
        "dscp: 0",
        "nocomp: false",
        "acknodelay: true",
        "nodelay: 1",
        "interval: 10",
        "resend: 2",
        "nc: 1",
        "sockbuf: 4194304",
        f"smuxver: {case[-1]}",
        "smuxbuf: 4194304",
        "framesize: 8192",
        "streambuf: 1048576",
        "keepalive: 1",
    ]
elif case.startswith("shadowtls-"):
    plugin = "shadow-tls"
    plugin_opts = [
        f"host: {camouflage_host}",
        f"version: {case[-1]}",
        "password: shadowtls-interop-password",
        "skip-cert-verify: true",
    ]
elif case == "restls":
    plugin = "restls"
    plugin_opts = [
        f"host: {camouflage_host}",
        "password: restls-interop-password",
        "version-hint: tls13",
        f"restls-script: {json.dumps(__import__('os').environ.get('E2E_RESTLS_SCRIPT', ''))}",
        "skip-cert-verify: true",
    ]
else:
    raise SystemExit(f"unsupported Mihomo case: {case}")

opts_yaml = "\n".join(f"      {line}" for line in plugin_opts)
pathlib.Path(output).write_text(f"""\
mixed-port: {mixed_port}
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: info
ipv6: false
proxies:
  - name: e2e
    type: ss
    server: 127.0.0.1
    port: {plugin_port}
    cipher: aes-128-gcm
    password: {password}
    plugin: {plugin}
    plugin-opts:
{opts_yaml}
rules:
  - MATCH,e2e
""")
PY
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
  local needs_certificate=0
  local -a tls_version_args=()

  index="$(case_index "${case_name}")"
  node_id=$((CASE_NODE_BASE + index))
  user_id=$((CASE_USER_BASE + index))
  group_id="${node_id}"
  raw_port=$((CASE_RAW_PORT_BASE + index))
  plugin_port=$((CASE_PLUGIN_PORT_BASE + index))
  target_port=$((CASE_TARGET_PORT_BASE + index * 2))
  mixed_port=$((CASE_TARGET_PORT_BASE + index * 2 + 1))
  case_dir="${TMP_DIR}/${case_name}"
  mkdir -p "${case_dir}/data" "${case_dir}/mihomo" "${case_dir}/www"

  e2e_section "case ${case_name} (node ${node_id}, raw ${raw_port}, plugin ${plugin_port})"
  e2e_assert_port_free "${raw_port}" "${case_name} raw"
  e2e_assert_port_free "${plugin_port}" "${case_name} plugin"
  e2e_assert_port_free "${target_port}" "${case_name} target"
  e2e_assert_port_free "${mixed_port}" "${case_name} mixed"

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

  if [[ "${case_name}" == *wss* \
    || "${case_name}" == "v2ray-https-upgrade" \
    || "${case_name}" == shadowtls-* \
    || "${case_name}" == "restls" ]]; then
    needs_certificate=1
  fi
  if [[ "${needs_certificate}" == "1" ]]; then
    e2e_require_command openssl "openssl (TLS plugin cases)"
    openssl req -x509 -newkey rsa:2048 -nodes \
      -subj "/CN=localhost" \
      -days 1 \
      -keyout "${case_dir}/camouflage.key" \
      -out "${case_dir}/camouflage.crt" \
      >"${case_dir}/openssl-cert.log" 2>&1
  fi
  if [[ "${case_name}" == shadowtls-* || "${case_name}" == "restls" ]]; then
    e2e_assert_port_free 443 "camouflage TLS"
    case "${E2E_CAMOUFLAGE_TLS_VERSION:-auto}" in
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

  if [[ "${case_name}" == *wss* || "${case_name}" == "v2ray-https-upgrade" ]]; then
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
  wait_capability_ready "${node_id}" "${expected_revision}" "${expected_feature}"
  e2e_log "${case_name}: shoes ACKed a ready plugin generation"

  write_mihomo_config \
    "${case_dir}/mihomo.yml" \
    "${case_name}" \
    "${plugin_port}" \
    "${mixed_port}" \
    "00000000-0000-4000-8000-0000000${node_id}"
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
