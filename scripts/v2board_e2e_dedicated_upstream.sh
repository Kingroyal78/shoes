#!/usr/bin/env bash
# Per-user dedicated egress through a bought upstream proxy, end to end
# against a real V2Board.
#
# The claim under test: a user the panel sold an `upstream_proxy` IP to keeps
# connecting to the same node with the same credentials, and their traffic
# comes out of the upstream proxy's address instead of the node's own. The
# probe is an HTTP server that echoes the source address it observed, so the
# assertion is on what the peer actually saw.
#
# A real SOCKS5 proxy is stood up on a second loopback address to play the
# bought upstream, because the point of the test is that shoes really speaks
# SOCKS5 to it, not that it wrote the right struct.
#
# UDP is asserted to be *refused* rather than falling back to a direct dial:
# a fallback would put the node's own address on the wire, which is exactly
# what the buyer paid to avoid.
#
# 127.0.0.0/8 is routable in its entirety on Linux, so the extra addresses
# need no interface setup.
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
V2BOARD_WWW_CONTAINER="${V2BOARD_WWW_CONTAINER:-v2board-docker-www-1}"
V2BOARD_MYSQL_USER="${V2BOARD_MYSQL_USER:-root}"
V2BOARD_MYSQL_PASSWORD="${V2BOARD_MYSQL_PASSWORD:-v2boardisbest}"
V2BOARD_MYSQL_DATABASE="${V2BOARD_MYSQL_DATABASE:-v2board}"

SHOES_BIN="${SHOES_BIN:-}"
MIHOMO_BIN="${MIHOMO_BIN:-/tmp/mihomo}"

E2E_NODE_ID="${E2E_NODE_ID:-9702}"
E2E_NODE_TAG="${E2E_NODE_TAG:-dedicated-upstream-e2e}"
E2E_GROUP_ID="${E2E_GROUP_ID:-9702}"
E2E_USER_ID="${E2E_USER_ID:-19702}"
E2E_USER_EMAIL="${E2E_USER_EMAIL:-shoes-e2e-dedicated-upstream@example.local}"
E2E_USER_UUID="${E2E_USER_UUID:-8b4c1a62-d3c1-4a3f-9f99-bcb9f8e6f702}"
E2E_POOL_ID="${E2E_POOL_ID:-9702}"
E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
# The address the bought upstream proxy listens on, and therefore the address
# the buyer's traffic comes out of.
E2E_EGRESS_IP="${E2E_EGRESS_IP:-127.0.0.19}"
E2E_UPSTREAM_PORT="${E2E_UPSTREAM_PORT:-18814}"
E2E_UPSTREAM_USER="${E2E_UPSTREAM_USER:-e2e-upstream}"
E2E_UPSTREAM_PASS="${E2E_UPSTREAM_PASS:-e2e-upstream-secret}"
E2E_NODE_PORT="${E2E_NODE_PORT:-18811}"
E2E_PROXY_PORT="${E2E_PROXY_PORT:-18812}"
E2E_PROBE_PORT="${E2E_PROBE_PORT:-18813}"
E2E_PULL_INTERVAL_SECS="${E2E_PULL_INTERVAL_SECS:-3}"
E2E_PUSH_INTERVAL_SECS="${E2E_PUSH_INTERVAL_SECS:-5}"
E2E_SYNC_WAIT_SECS="${E2E_SYNC_WAIT_SECS:-20}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-0}"

TMP_DIR=""
PROBE_PID=""
UPSTREAM_PID=""
SHOES_PID=""
MIHOMO_PID=""

usage() {
  cat <<USAGE
Usage: $(basename "$0")

Environment overrides:
  SHOES_BIN            path to a built shoes binary (default: cargo build)
  MIHOMO_BIN           vmess client used to drive traffic (default: /tmp/mihomo)
  E2E_EGRESS_IP        loopback address the stand-in upstream proxy binds (default: 127.0.0.19)
  E2E_KEEP_FIXTURES    1 to leave the panel rows behind for inspection
USAGE
}

cleanup() {
  local status=$?
  for pid in "${MIHOMO_PID}" "${SHOES_PID}" "${PROBE_PID}" "${UPSTREAM_PID}"; do
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
VALUES (${E2E_GROUP_ID}, 'shoes-e2e-dedicated-upstream', ${now}, ${now})
ON DUPLICATE KEY UPDATE name=VALUES(name), updated_at=VALUES(updated_at);

INSERT INTO v2_server_vmess
(id, group_id, route_id, name, host, port, server_port, tls, tags, rate, network, networkSettings, tlsSettings, ruleSettings, dnsSettings, \`show\`, sort, created_at, updated_at)
VALUES
(${E2E_NODE_ID}, '["${E2E_GROUP_ID}"]', NULL, 'shoes-e2e-dedicated-upstream', '${E2E_BIND_HOST}', '${E2E_NODE_PORT}', ${E2E_NODE_PORT}, 0, NULL, '1', 'tcp', '{}', '{}', '{}', '{}', 1, ${E2E_NODE_ID}, ${now}, ${now})
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

DELETE FROM v2_stat_user WHERE user_id=${E2E_USER_ID};
DELETE FROM v2_stat_server WHERE server_id=${E2E_NODE_ID} AND server_type='vmess';
SQL

  # The pool, its upstream credential and the assignment go through the panel's
  # own services rather than raw SQL: the password has to be encrypted with this
  # deployment's DEDICATED_IP_CREDENTIAL_KEY, and a hand-written cipher blob
  # would prove nothing about whether the real one round-trips.
  php_app <<'PHP'
use App\Models\DedicatedIp;
use App\Models\DedicatedIpAssignment;
use App\Models\DedicatedIpPool;
use App\Services\DedicatedIpAdminService;
use App\Services\DedicatedIpService;

$poolId = (int)getenv('E2E_POOL_ID');
$userId = (int)getenv('E2E_USER_ID');

DedicatedIpAssignment::where('pool_id', $poolId)->delete();
DedicatedIp::where('pool_id', $poolId)->delete();
DedicatedIpPool::where('id', $poolId)->delete();

$pool = new DedicatedIpPool();
$pool->id = $poolId;
$pool->forceFill([
    'name' => 'shoes-e2e-dedicated-upstream',
    'delivery' => DedicatedIpPool::DELIVERY_UPSTREAM_PROXY,
    'protocol' => DedicatedIpPool::PROTOCOL_SOCKS5,
    'server_type' => 'vmess',
    'server_id' => (int)getenv('E2E_NODE_ID'),
    'default_port' => (int)getenv('E2E_UPSTREAM_PORT'),
    'show' => 1,
    'sort' => 1,
    'month_price' => 100,
    'max_per_user' => 1,
])->save();

$imported = (new DedicatedIpAdminService())->importIps($poolId, sprintf(
    '%s:%s:%s:%s',
    getenv('E2E_EGRESS_IP'),
    getenv('E2E_UPSTREAM_PORT'),
    getenv('E2E_UPSTREAM_USER'),
    getenv('E2E_UPSTREAM_PASS')
));
if ((int)$imported['imported'] !== 1) {
    throw new RuntimeException('import failed: ' . json_encode($imported));
}

(new DedicatedIpService())->allocate($poolId, $userId, 1, time() + 86400);
echo "seeded\n";
PHP
}

# Runs a PHP snippet inside the panel container with the framework booted, so
# it sees the deployment's real .env and encryption keys.
php_app() {
  local script
  script="$(cat)"
  docker exec -i -u www-data \
    -e "E2E_POOL_ID=${E2E_POOL_ID}" \
    -e "E2E_USER_ID=${E2E_USER_ID}" \
    -e "E2E_NODE_ID=${E2E_NODE_ID}" \
    -e "E2E_EGRESS_IP=${E2E_EGRESS_IP}" \
    -e "E2E_UPSTREAM_PORT=${E2E_UPSTREAM_PORT}" \
    -e "E2E_UPSTREAM_USER=${E2E_UPSTREAM_USER}" \
    -e "E2E_UPSTREAM_PASS=${E2E_UPSTREAM_PASS}" \
    "${V2BOARD_WWW_CONTAINER}" php -r "
require '/www/vendor/autoload.php';
\$app = require '/www/bootstrap/app.php';
\$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
${script}
" 2>&1 | tail -5
}

assert_panel_publishes_the_binding() {
  local token="$1" observed
  e2e_section "panel publishes mode=proxy with the dialing credentials"
  observed="$(curl -fsS "${V2BOARD_PANEL_URL}/api/v1/server/UniProxy/user?token=${token}&node_id=${E2E_NODE_ID}&node_type=vmess" \
    | python3 -c 'import json,sys
users = json.load(sys.stdin)["users"]
row = next((u for u in users if u["id"] == '"${E2E_USER_ID}"'), None)
d = (row or {}).get("dedicated_ip") or {}
print("%s|%s|%s|%s|%s|%s" % (
    d.get("mode",""), d.get("protocol",""), d.get("ip",""),
    d.get("port",""), d.get("username",""), d.get("password","")))')"

  local expected
  expected="proxy|socks5|${E2E_EGRESS_IP}|${E2E_UPSTREAM_PORT}|${E2E_UPSTREAM_USER}|${E2E_UPSTREAM_PASS}"
  [ "${observed}" = "${expected}" ] \
    || e2e_die "panel published '${observed}', expected '${expected}'"
  e2e_log "panel publishes the upstream, and the password round-trips the cipher"
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
  - name: dedicated-upstream-e2e
    type: vmess
    server: ${E2E_BIND_HOST}
    port: ${E2E_NODE_PORT}
    uuid: ${E2E_USER_UUID}
    alterId: 0
    cipher: auto
    udp: true
proxy-groups:
  - name: GLOBAL
    type: select
    proxies:
      - dedicated-upstream-e2e
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

  # The bought upstream. A real SOCKS5 server, so the test proves shoes speaks
  # the protocol to it rather than that it built the right struct. It binds the
  # sold address, which is therefore what the probe sees.
  python3 -c '
import select, socket, struct, sys, threading

host, port, user, password = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode(), sys.argv[4].encode()

def pump(a, b):
    try:
        while True:
            r, _, _ = select.select([a, b], [], [])
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        pass

def handle(conn):
    try:
        ver, nmethods = conn.recv(2)
        methods = conn.recv(nmethods)
        if 0x02 not in methods:
            conn.sendall(b"\x05\xff")
            return
        conn.sendall(b"\x05\x02")
        conn.recv(1)
        ulen = conn.recv(1)[0]
        got_user = conn.recv(ulen)
        plen = conn.recv(1)[0]
        got_pass = conn.recv(plen)
        if got_user != user or got_pass != password:
            conn.sendall(b"\x01\x01")
            return
        conn.sendall(b"\x01\x00")

        header = conn.recv(4)
        atyp = header[3]
        if atyp == 1:
            target = socket.inet_ntoa(conn.recv(4))
        elif atyp == 3:
            target = conn.recv(conn.recv(1)[0]).decode()
        else:
            target = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
        tport = struct.unpack("!H", conn.recv(2))[0]

        # A bought proxy exits from its own address; binding the source here
        # is what makes the probe able to tell "went through the upstream"
        # apart from "went direct".
        upstream = socket.create_connection(
            (target, tport), timeout=15, source_address=(host, 0)
        )
        conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))
        pump(conn, upstream)
        upstream.close()
    except Exception:
        pass
    finally:
        conn.close()

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((host, port))
srv.listen(64)
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
' "${E2E_EGRESS_IP}" "${E2E_UPSTREAM_PORT}" "${E2E_UPSTREAM_USER}" "${E2E_UPSTREAM_PASS}" &
  UPSTREAM_PID=$!

  "${SHOES_BIN}" run -c "${TMP_DIR}/shoes.yml" >"${TMP_DIR}/shoes.log" 2>&1 &
  SHOES_PID=$!

  "${MIHOMO_BIN}" -d "${TMP_DIR}/mihomo-data" -f "${TMP_DIR}/mihomo.yaml" \
    >"${TMP_DIR}/mihomo.log" 2>&1 &
  MIHOMO_PID=$!

  wait_for_port "${E2E_PROBE_PORT}" "probe"
  wait_for_port_on "${E2E_EGRESS_IP}" "${E2E_UPSTREAM_PORT}" "upstream socks5 proxy"
  wait_for_port "${E2E_NODE_PORT}" "shoes vmess listener"
  wait_for_port "${E2E_PROXY_PORT}" "mihomo mixed inbound"
}

wait_for_port() {
  wait_for_port_on "${E2E_BIND_HOST}" "$1" "$2"
}

wait_for_port_on() {
  local host="$1" port="$2" what="$3" deadline
  deadline=$(( $(date +%s) + 30 ))
  while [ "$(date +%s)" -lt "${deadline}" ]; do
    # Confined to the subshell on purpose: a bare `exec` redirection in the
    # parent would rewrite this shell's own file descriptors for good.
    if (: >"/dev/tcp/${host}/${port}") >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.3
  done
  e2e_die "${what} never listened on ${host}:${port}"
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
  e2e_section "traffic leaves through the bought upstream"
  local observed
  if ! observed="$(wait_for_source "${E2E_EGRESS_IP}")"; then
    e2e_die "expected source ${E2E_EGRESS_IP}, observed '${observed}' (see ${TMP_DIR}/shoes.log)"
  fi
  e2e_log "source observed by the peer: ${observed}"

  assert_udp_is_refused

  e2e_section "revoking the assignment returns the user to the default egress"
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

# A SOCKS5/HTTP upstream carries no UDP here, so the datagram has to be dropped.
# The failure this guards against is a silent fall-through to a direct dial,
# which would put the node's own address on the wire -- the one thing the buyer
# paid for it not to do. The probe therefore must see nothing at all.
assert_udp_is_refused() {
  e2e_section "UDP is refused rather than leaking the node address"
  local result
  result="$(python3 "${TMP_DIR}/udp_check.py" \
    "${E2E_BIND_HOST}" "${E2E_PROXY_PORT}" "${E2E_PROBE_PORT}")"

  case "${result}" in
    DROPPED|ASSOCIATE_REFUSED)
      e2e_log "UDP refused (${result})"
      ;;
    REPLIED:*)
      e2e_die "UDP was forwarded and the peer saw '${result#REPLIED:}'; an upstream-proxy egress must not fall back to a direct dial"
      ;;
    *)
      e2e_die "could not drive the UDP check: ${result}"
      ;;
  esac
}

write_udp_check() {
  cat >"${TMP_DIR}/udp_check.py" <<'UDPCHECK'
import socket, struct, sys

proxy_host, proxy_port, probe_port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])

# Mihomo's mixed inbound speaks SOCKS5, so UDP ASSOCIATE reaches the node the
# same way a real client's would.
t = socket.create_connection((proxy_host, proxy_port), timeout=10)
t.sendall(b"\x05\x01\x00")
if t.recv(2) != b"\x05\x00":
    print("NO_SOCKS")
    raise SystemExit

t.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))
rep = t.recv(10)
if len(rep) < 10 or rep[1] != 0:
    print("ASSOCIATE_REFUSED")
    raise SystemExit

relay_host = socket.inet_ntoa(rep[4:8])
relay_port = struct.unpack("!H", rep[8:10])[0]
if relay_host == "0.0.0.0":
    relay_host = proxy_host

u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(6)
u.sendto(
    b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", probe_port) + b"ping",
    (relay_host, relay_port),
)
try:
    data, _ = u.recvfrom(2048)
except socket.timeout:
    # Nothing came back, which is the whole point: the datagram never left.
    print("DROPPED")
else:
    print("REPLIED:" + data[10:].decode(errors="replace").strip())
finally:
    u.close()
    t.close()
UDPCHECK
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
  TMP_DIR="$(mktemp -d /tmp/shoes-v2board-dedicated-upstream.XXXXXX)"

  local token
  token="$(discover_server_token)"
  [ -n "${token}" ] || e2e_die "could not read server_token from the panel config"

  seed_fixtures
  assert_panel_publishes_the_binding "${token}"
  write_configs "${token}"
  write_udp_check
  start_services
  run_checks

  e2e_section "PASS"
}

main "$@"
