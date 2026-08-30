#!/usr/bin/env bash
# Per-user dedicated egress IP, end to end against a real V2Board.
#
# Proves the one claim that matters: a user the panel sold a dedicated IP to
# leaves the box from that address, and the same user stops doing so as soon as
# the panel stops publishing it. The probe is an HTTP server that echoes the
# source address it observed, so the assertion is on what the peer actually saw
# rather than on anything shoes reports about itself.
#
# 127.0.0.0/8 is routable in its entirety on Linux, so the "extra" egress
# addresses need no interface setup.
#
# Read docs/v2board-docker-e2e.md before running.
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
V2BOARD_MYSQL_USER="${V2BOARD_MYSQL_USER:-root}"
V2BOARD_MYSQL_PASSWORD="${V2BOARD_MYSQL_PASSWORD:-v2boardisbest}"
V2BOARD_MYSQL_DATABASE="${V2BOARD_MYSQL_DATABASE:-v2board}"

SHOES_BIN="${SHOES_BIN:-}"
MIHOMO_BIN="${MIHOMO_BIN:-/tmp/mihomo}"

E2E_NODE_ID="${E2E_NODE_ID:-9701}"
E2E_NODE_TAG="${E2E_NODE_TAG:-dedicated-ip-e2e}"
E2E_GROUP_ID="${E2E_GROUP_ID:-9701}"
E2E_USER_ID="${E2E_USER_ID:-19701}"
E2E_USER_EMAIL="${E2E_USER_EMAIL:-shoes-e2e-dedicated-ip@example.local}"
E2E_USER_UUID="${E2E_USER_UUID:-8b4c1a62-d3c1-4a3f-9f99-bcb9f8e6f701}"
E2E_POOL_ID="${E2E_POOL_ID:-9701}"
E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_EGRESS_IP="${E2E_EGRESS_IP:-127.0.0.9}"
E2E_NODE_PORT="${E2E_NODE_PORT:-18801}"
E2E_PROXY_PORT="${E2E_PROXY_PORT:-18802}"
E2E_PROBE_PORT="${E2E_PROBE_PORT:-18803}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-3}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-5}"
E2E_SYNC_WAIT_SECS="${E2E_SYNC_WAIT_SECS:-20}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-0}"

TMP_DIR=""
PROBE_PID=""
SHOES_PID=""
MIHOMO_PID=""

usage() {
  cat <<USAGE
Usage: $(basename "$0")

Environment overrides:
  SHOES_BIN            path to a built shoes binary (default: cargo build)
  MIHOMO_BIN           vmess client used to drive traffic (default: /tmp/mihomo)
  E2E_EGRESS_IP        loopback address sold as the dedicated IP (default: 127.0.0.9)
  E2E_KEEP_FIXTURES    1 to leave the panel rows behind for inspection
USAGE
}

cleanup() {
  local status=$?
  for pid in "${MIHOMO_PID}" "${SHOES_PID}" "${PROBE_PID}"; do
    if [ -n "${pid}" ]; then kill "${pid}" 2>/dev/null || true; fi
  done
  wait 2>/dev/null || true
  maybe_cleanup_fixtures
  if [ -n "${TMP_DIR}" ] && [ -d "${TMP_DIR}" ]; then
    if [ "${status}" -eq 0 ]; then
      rm -rf "${TMP_DIR}"
    else
      e2e_warn "keeping ${TMP_DIR} for inspection"
    fi
  fi
  return "${status}"
}
trap cleanup EXIT

mysql_exec() {
  docker exec -i "${V2BOARD_MYSQL_CONTAINER}" \
    mysql -u"${V2BOARD_MYSQL_USER}" -p"${V2BOARD_MYSQL_PASSWORD}" \
    -D "${V2BOARD_MYSQL_DATABASE}" 2>/dev/null
}

mysql_query() {
  docker exec -i "${V2BOARD_MYSQL_CONTAINER}" \
    mysql -u"${V2BOARD_MYSQL_USER}" -p"${V2BOARD_MYSQL_PASSWORD}" \
    -D "${V2BOARD_MYSQL_DATABASE}" -N -B -e "$1" 2>/dev/null
}

discover_server_token() {
  local config="${V2BOARD_DIR}/config/v2board.php"
  [ -f "${config}" ] || e2e_die "cannot read ${config}"
  sed -n "s/.*'server_token' *=> *'\([^']*\)'.*/\1/p" "${config}" | head -n1
}

resolve_binaries() {
  if [ -z "${SHOES_BIN}" ]; then
    e2e_section "build shoes"
    (cd "${ROOT_DIR}" && cargo build)
    SHOES_BIN="${ROOT_DIR}/target/debug/shoes"
  fi
  [ -x "${SHOES_BIN}" ] || e2e_die "shoes binary not executable: ${SHOES_BIN}"
  [ -x "${MIHOMO_BIN}" ] || e2e_die "vmess client not executable: ${MIHOMO_BIN}"
}

check_environment() {
  for cmd in docker curl python3; do
    command -v "${cmd}" >/dev/null || e2e_die "missing dependency: ${cmd}"
  done
  docker inspect "${V2BOARD_MYSQL_CONTAINER}" >/dev/null 2>&1 \
    || e2e_die "v2board mysql container is not running"
  curl -fsS -o /dev/null "${V2BOARD_PANEL_URL}/" \
    || e2e_die "panel not reachable at ${V2BOARD_PANEL_URL}"
}

seed_fixtures() {
  local now expires_at
  now="$(date +%s)"
  expires_at="$((now + 86400))"

  e2e_section "seed panel fixtures"
  mysql_exec <<SQL
INSERT INTO v2_server_group (id, name, created_at, updated_at)
VALUES (${E2E_GROUP_ID}, 'shoes-e2e-dedicated-ip', ${now}, ${now})
ON DUPLICATE KEY UPDATE name=VALUES(name), updated_at=VALUES(updated_at);

INSERT INTO v2_server_vmess
(id, group_id, route_id, name, host, port, server_port, tls, tags, rate, network, networkSettings, tlsSettings, ruleSettings, dnsSettings, \`show\`, sort, created_at, updated_at)
VALUES
(${E2E_NODE_ID}, '["${E2E_GROUP_ID}"]', NULL, 'shoes-e2e-dedicated-ip', '${E2E_BIND_HOST}', '${E2E_NODE_PORT}', ${E2E_NODE_PORT}, 0, NULL, '1', 'tcp', '{}', '{}', '{}', '{}', 1, ${E2E_NODE_ID}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id), host=VALUES(host), port=VALUES(port),
  server_port=VALUES(server_port), network=VALUES(network), \`show\`=1,
  updated_at=VALUES(updated_at);

INSERT INTO v2_user
(id, email, password, balance, commission_type, commission_balance, t, u, d, transfer_enable, banned, is_admin, is_staff, uuid, group_id, remind_expire, remind_traffic, token, expired_at, created_at, updated_at)
VALUES
(${E2E_USER_ID}, '${E2E_USER_EMAIL}', 'e2e-password', 0, 0, 0, 0, 0, 0, 1073741824, 0, 0, 0, '${E2E_USER_UUID}', ${E2E_GROUP_ID}, 1, 1, MD5('${E2E_USER_EMAIL}'), ${expires_at}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0, u=0, d=0, t=0, transfer_enable=VALUES(transfer_enable),
  uuid=VALUES(uuid), group_id=VALUES(group_id), expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);

INSERT INTO v2_dedicated_ip_pool
(id, name, delivery, server_type, server_id, default_port, \`show\`, sort, month_price, max_per_user, created_at, updated_at)
VALUES
(${E2E_POOL_ID}, 'shoes-e2e-dedicated-ip', 'node_egress', 'vmess', ${E2E_NODE_ID}, 0, 1, 1, 100, 1, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  delivery=VALUES(delivery), server_type=VALUES(server_type),
  server_id=VALUES(server_id), \`show\`=1, updated_at=VALUES(updated_at);

DELETE FROM v2_dedicated_ip_assignment WHERE pool_id=${E2E_POOL_ID};
DELETE FROM v2_dedicated_ip WHERE pool_id=${E2E_POOL_ID};

INSERT INTO v2_dedicated_ip (pool_id, ip, port, status, created_at, updated_at)
VALUES (${E2E_POOL_ID}, '${E2E_EGRESS_IP}', 0, 'assigned', ${now}, ${now});

INSERT INTO v2_dedicated_ip_assignment
(pool_id, user_id, slot, ip_id, occupancy_key, ip_snapshot, port_snapshot, started_at, expired_at, created_at, updated_at)
SELECT ${E2E_POOL_ID}, ${E2E_USER_ID}, 1, id, CAST(id AS CHAR), ip, 0, ${now}, ${expires_at}, ${now}, ${now}
FROM v2_dedicated_ip WHERE pool_id=${E2E_POOL_ID} AND ip='${E2E_EGRESS_IP}';

DELETE FROM v2_stat_user WHERE user_id=${E2E_USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${E2E_NODE_ID} AND server_type='vmess';
SQL
}

assert_panel_publishes_the_binding() {
  local token="$1" observed
  e2e_section "panel publishes dedicated_ip on the user list"
  observed="$(curl -fsS "${V2BOARD_PANEL_URL}/api/v1/server/UniProxy/user?token=${token}&node_id=${E2E_NODE_ID}&node_type=vmess" \
    | python3 -c 'import json,sys
users = json.load(sys.stdin)["users"]
row = next((u for u in users if u["id"] == '"${E2E_USER_ID}"'), None)
print((row or {}).get("dedicated_ip", {}).get("ip", ""))')"
  [ "${observed}" = "${E2E_EGRESS_IP}" ] \
    || e2e_die "panel published dedicated_ip.ip='${observed}', expected '${E2E_EGRESS_IP}'"
  e2e_log "panel publishes ${observed}"
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

  cat >"${TMP_DIR}/mihomo.yaml" <<YAML
mixed-port: ${E2E_PROXY_PORT}
bind-address: "${E2E_BIND_HOST}"
allow-lan: false
mode: global
log-level: warning
ipv6: false
proxies:
  - name: dedicated-ip-e2e
    type: vmess
    server: ${E2E_BIND_HOST}
    port: ${E2E_NODE_PORT}
    uuid: ${E2E_USER_UUID}
    alterId: 0
    cipher: auto
    udp: false
proxy-groups:
  - name: GLOBAL
    type: select
    proxies:
      - dedicated-ip-e2e
YAML
}

start_services() {
  e2e_section "start local services"

  # Echoes the source address it observed. Binds 0.0.0.0 so it is reachable on
  # every loopback address the egress may use.
  python3 -c '
import http.server, socketserver, sys
port = int(sys.argv[1])
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = ("%s\n" % self.client_address[0]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("0.0.0.0", port), H).serve_forever()
' "${E2E_PROBE_PORT}" &
  PROBE_PID=$!

  "${SHOES_BIN}" run -c "${TMP_DIR}/shoes.yml" >"${TMP_DIR}/shoes.log" 2>&1 &
  SHOES_PID=$!

  "${MIHOMO_BIN}" -d "${TMP_DIR}/mihomo-data" -f "${TMP_DIR}/mihomo.yaml" \
    >"${TMP_DIR}/mihomo.log" 2>&1 &
  MIHOMO_PID=$!

  wait_for_port "${E2E_PROBE_PORT}" "probe"
  wait_for_port "${E2E_NODE_PORT}" "shoes vmess listener"
  wait_for_port "${E2E_PROXY_PORT}" "mihomo mixed inbound"
}

wait_for_port() {
  local port="$1" what="$2" deadline
  deadline=$(( $(date +%s) + 30 ))
  while [ "$(date +%s)" -lt "${deadline}" ]; do
    # Confined to the subshell on purpose: a bare `exec` redirection in the
    # parent would rewrite this shell's own file descriptors for good.
    if (: >"/dev/tcp/${E2E_BIND_HOST}/${port}") >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.3
  done
  e2e_die "${what} never listened on ${port}"
}

observed_source() {
  curl -fsS --max-time 15 --noproxy '' \
    --proxy "http://${E2E_BIND_HOST}:${E2E_PROXY_PORT}" \
    "http://${E2E_BIND_HOST}:${E2E_PROBE_PORT}/" | tr -d '\r\n'
}

# The user list is only re-read on the pull interval, so a panel change needs a
# bounded wait rather than a fixed sleep.
wait_for_source() {
  local expected="$1" deadline observed=""
  deadline=$(( $(date +%s) + E2E_SYNC_WAIT_SECS ))
  while [ "$(date +%s)" -lt "${deadline}" ]; do
    observed="$(observed_source || true)"
    [ "${observed}" = "${expected}" ] && { echo "${observed}"; return 0; }
    sleep 1
  done
  echo "${observed}"
  return 1
}

run_checks() {
  e2e_section "traffic leaves from the dedicated address"
  local observed
  if ! observed="$(wait_for_source "${E2E_EGRESS_IP}")"; then
    e2e_die "expected source ${E2E_EGRESS_IP}, observed '${observed}' (see ${TMP_DIR}/shoes.log)"
  fi
  e2e_log "source observed by the peer: ${observed}"

  e2e_section "revoking the assignment returns the user to the default source"
  mysql_exec <<SQL
UPDATE v2_dedicated_ip_assignment
SET released_at=UNIX_TIMESTAMP(), release_reason='e2e', ip_id=NULL,
    occupancy_key=CONCAT('released-', id)
WHERE pool_id=${E2E_POOL_ID} AND user_id=${E2E_USER_ID};
SQL
  if ! observed="$(wait_for_source "${E2E_BIND_HOST}")"; then
    e2e_die "expected the default source ${E2E_BIND_HOST} after revoke, observed '${observed}'"
  fi
  e2e_log "source after revoke: ${observed}"
}

maybe_cleanup_fixtures() {
  [ "${E2E_KEEP_FIXTURES}" = "1" ] && return 0
  mysql_exec <<SQL || true
DELETE FROM v2_dedicated_ip_assignment WHERE pool_id=${E2E_POOL_ID};
DELETE FROM v2_dedicated_ip WHERE pool_id=${E2E_POOL_ID};
DELETE FROM v2_dedicated_ip_pool WHERE id=${E2E_POOL_ID};
DELETE FROM v2_server_vmess WHERE id=${E2E_NODE_ID};
DELETE FROM v2_server_group WHERE id=${E2E_GROUP_ID};
DELETE FROM v2_stat_user WHERE user_id=${E2E_USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${E2E_NODE_ID} AND server_type='vmess';
DELETE FROM v2_user WHERE id=${E2E_USER_ID};
SQL
}

main() {
  if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
  fi

  check_environment
  resolve_binaries
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-dedicated-ip.XXXXXX)"

  local token
  token="$(discover_server_token)"
  [ -n "${token}" ] || e2e_die "could not read server_token from the panel config"

  seed_fixtures
  assert_panel_publishes_the_binding "${token}"
  write_configs "${token}"
  start_services
  run_checks

  e2e_section "PASS"
}

main "$@"
