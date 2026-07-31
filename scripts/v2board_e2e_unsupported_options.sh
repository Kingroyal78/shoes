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
V2BOARD_REDIS_CONTAINER="${V2BOARD_REDIS_CONTAINER:-v2board-docker-redis-1}"
V2BOARD_MYSQL_USER="${V2BOARD_MYSQL_USER:-root}"
V2BOARD_MYSQL_PASSWORD="${V2BOARD_MYSQL_PASSWORD:-v2boardisbest}"
V2BOARD_MYSQL_DATABASE="${V2BOARD_MYSQL_DATABASE:-v2board}"

SHOES_BIN_EXPLICIT=0
if [[ -n "${SHOES_BIN:-}" ]]; then
  SHOES_BIN_EXPLICIT=1
fi
SHOES_BIN="${SHOES_BIN:-}"

E2E_BIND_HOST="${E2E_BIND_HOST:-127.0.0.1}"
E2E_KEEP_FIXTURES="${E2E_KEEP_FIXTURES:-1}"
E2E_CASES="${E2E_UNSUPPORTED_CASES:-vmess_xhttp_bad_mode,vmess_xhttp_download_settings,vmess_xhttp_server_max_header_bytes,vmess_kcp,vmess_quic,vless_xhttp_bad_mode,vless_xhttp_xmux,vless_xhttp_padding_bytes,grpc_multi_mode,vless_mlkem,vless_encryption_settings,v2node_xhttp_bad_mode,v2node_xhttp_padding_obfs,v2node_xhttp_stream_up_keepalive,trojan_http,v2node_trojan_http,v2node_trojan_xhttp,v2node_mlkem,v2node_vmess_encryption_settings,v2node_shadowsocks_ws,v2node_shadowsocks_encryption_settings,v2node_anytls_ws,tuic_bad_congestion_control,v2node_tuic_bad_congestion_control,vless_reality_missing_dest,vless_reality_missing_short_id,v2node_reality_missing_short_id,vless_reality_xver,vless_reality_ech,vless_tls_ech,ss_unknown_obfs,ss_xchacha,ss_none,hysteria_v1,hy2_no_obfs_password,hy2_gecko_no_obfs_password,v2node_hy2_gecko_no_obfs_password,hy2_unknown_obfs,v2node_hy2_unknown_obfs,hy2_password_only,naiveproxy_quic_bad_congestion_control,v2node_naive_bad_congestion_control,v2node_naive_tls_disabled,v2node_naive_custom_alpn}"

BASE_ID=9930
REALITY_PRIVATE_KEY="BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"

TMP_DIR=""
SERVER_TOKEN=""

CASE_NAME=""
CASE_NODE_ID=0
CASE_GROUP_ID=0
CASE_USER_ID=0
CASE_NODE_PORT=0
CASE_NODE_TYPE=""
CASE_V2_PROTOCOL=""
CASE_NETWORK="tcp"
CASE_NETWORK_SETTINGS="{}"
CASE_TLS=0
CASE_TLS_SETTINGS="{}"
CASE_ENCRYPTION="none"
CASE_ENCRYPTION_SETTINGS="{}"
CASE_SS_CIPHER="aes-128-gcm"
CASE_SS_OBFS="NULL"
CASE_HYSTERIA_VERSION=2
CASE_HYSTERIA_UP_MBPS=0
CASE_HYSTERIA_DOWN_MBPS=0
CASE_HYSTERIA_OBFS="NULL"
CASE_HYSTERIA_OBFS_PASSWORD="NULL"
CASE_NAIVE_ENABLE_QUIC=0
CASE_NAIVE_QUIC_CC="NULL"
CASE_TUIC_UDP_RELAY_MODE="NULL"
CASE_TUIC_ZERO_RTT=0
CASE_TUIC_CONGESTION_CONTROL="NULL"
CASE_EXPECTED=""

usage() {
  cat <<'EOF'
Usage:
  scripts/v2board_e2e_unsupported_options.sh

Runs real V2Board UniProxy sync-once checks for panel options that shoes must
reject explicitly instead of silently ignoring.

Optional:
  E2E_UNSUPPORTED_CASES=case_a,case_b
EOF
}

cleanup() {
  local status=$?
  set +e

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

resolve_binaries() {
  e2e_section "binaries"
  e2e_require_command docker
  e2e_require_command grep
  e2e_require_command openssl

  if [[ -z "${SHOES_BIN}" ]]; then
    SHOES_BIN="${ROOT_DIR}/target/debug/shoes"
    if ((SHOES_BIN_EXPLICIT == 0)); then
      e2e_run cargo build --manifest-path "${ROOT_DIR}/Cargo.toml"
    elif [[ ! -x "${SHOES_BIN}" ]]; then
      e2e_die "SHOES_BIN is not executable: ${SHOES_BIN}"
    fi
  fi
  [[ -x "${SHOES_BIN}" ]] || e2e_die "SHOES_BIN is not executable: ${SHOES_BIN}"
}

generate_tls_files() {
  e2e_section "tls fixture"
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -days 1 \
    -nodes \
    -subj "/CN=example.org" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "subjectAltName=DNS:example.org" \
    -keyout "${TMP_DIR}/tls.key" \
    -out "${TMP_DIR}/tls.crt" \
    >/dev/null 2>&1
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

set_case_defaults() {
  local name="$1"
  local index="$2"

  CASE_NAME="${name}"
  CASE_NODE_ID=$((BASE_ID + index))
  CASE_GROUP_ID="${CASE_NODE_ID}"
  CASE_USER_ID=$((19000 + CASE_NODE_ID))
  CASE_NODE_PORT=$((18300 + index))
  CASE_NODE_TYPE="vmess"
  CASE_V2_PROTOCOL=""
  CASE_NETWORK="tcp"
  CASE_NETWORK_SETTINGS="{}"
  CASE_TLS=0
  CASE_TLS_SETTINGS="{}"
  CASE_ENCRYPTION="none"
  CASE_ENCRYPTION_SETTINGS="{}"
  CASE_SS_CIPHER="aes-128-gcm"
  CASE_SS_OBFS="NULL"
  CASE_HYSTERIA_VERSION=2
  CASE_HYSTERIA_UP_MBPS=0
  CASE_HYSTERIA_DOWN_MBPS=0
  CASE_HYSTERIA_OBFS="NULL"
  CASE_HYSTERIA_OBFS_PASSWORD="NULL"
  CASE_NAIVE_ENABLE_QUIC=0
  CASE_NAIVE_QUIC_CC="NULL"
  CASE_TUIC_UDP_RELAY_MODE="NULL"
  CASE_TUIC_ZERO_RTT=0
  CASE_TUIC_CONGESTION_CONTROL="NULL"
  CASE_EXPECTED=""
}

setup_case() {
  set_case_defaults "$1" "$2"

  case "${CASE_NAME}" in
    vmess_xhttp_bad_mode)
      CASE_NETWORK="xhttp"
      CASE_NETWORK_SETTINGS='{"path":"/bad-xhttp","mode":"sideways"}'
      CASE_EXPECTED="xhttp mode \`sideways\` is not supported"
      ;;
    vmess_xhttp_download_settings)
      CASE_NETWORK="xhttp"
      CASE_NETWORK_SETTINGS='{"path":"/bad-xhttp","mode":"auto","extra":{"downloadSettings":{"address":"127.0.0.1","port":8443}}}'
      CASE_EXPECTED="xhttp downloadSettings is not supported"
      ;;
    vmess_xhttp_server_max_header_bytes)
      CASE_NETWORK="xhttp"
      CASE_NETWORK_SETTINGS='{"path":"/bad-xhttp","mode":"auto","serverMaxHeaderBytes":16384}'
      CASE_EXPECTED="xhttp serverMaxHeaderBytes is not supported"
      ;;
    vmess_kcp)
      CASE_NETWORK="kcp"
      CASE_EXPECTED="network \`kcp\` is not supported"
      ;;
    vmess_domainsocket)
      CASE_NETWORK="domainsocket"
      CASE_EXPECTED="network \`domainsocket\` is not supported"
      ;;
    vmess_quic)
      CASE_NETWORK="quic"
      CASE_EXPECTED="network \`quic\` is not supported"
      ;;
    vless_xhttp_bad_mode)
      CASE_NODE_TYPE="vless"
      CASE_NETWORK="xhttp"
      CASE_NETWORK_SETTINGS='{"path":"/bad-xhttp","mode":"sideways"}'
      CASE_EXPECTED="xhttp mode \`sideways\` is not supported"
      ;;
    vless_xhttp_xmux)
      CASE_NODE_TYPE="vless"
      CASE_NETWORK="xhttp"
      CASE_NETWORK_SETTINGS='{"path":"/bad-xhttp","mode":"auto","extra":{"xmux":{"maxConcurrency":8,"hKeepAlivePeriod":30}}}'
      CASE_EXPECTED="xhttp xmux is not supported"
      ;;
    vless_xhttp_padding_bytes)
      CASE_NODE_TYPE="vless"
      CASE_NETWORK="xhttp"
      CASE_NETWORK_SETTINGS='{"path":"/bad-xhttp","mode":"auto","extra":{"xPaddingBytes":{"from":100,"to":1000}}}'
      CASE_EXPECTED="xhttp xPaddingBytes is not supported"
      ;;
    vless_domainsocket)
      CASE_NODE_TYPE="vless"
      CASE_NETWORK="domainsocket"
      CASE_EXPECTED="network \`domainsocket\` is not supported"
      ;;
    grpc_multi_mode)
      CASE_NETWORK="grpc"
      CASE_NETWORK_SETTINGS='{"serviceName":"multi","multiMode":true}'
      CASE_EXPECTED="grpc multi_mode is modeled but not implemented yet"
      ;;
    vless_mlkem)
      CASE_NODE_TYPE="vless"
      CASE_ENCRYPTION="mlkem768x25519plus"
      CASE_EXPECTED="vless encryption \`mlkem768x25519plus\` is not supported"
      ;;
    vless_encryption_settings)
      CASE_NODE_TYPE="vless"
      CASE_ENCRYPTION_SETTINGS='{"mode":"native"}'
      CASE_EXPECTED="vless encryption_settings is not supported"
      ;;
    v2node_xhttp_bad_mode)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="vless"
      CASE_NETWORK="xhttp"
      CASE_NETWORK_SETTINGS='{"path":"/bad-xhttp","mode":"sideways"}'
      CASE_EXPECTED="xhttp mode \`sideways\` is not supported"
      ;;
    v2node_xhttp_padding_obfs)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="vless"
      CASE_NETWORK="xhttp"
      CASE_NETWORK_SETTINGS='{"path":"/bad-xhttp","mode":"auto","extra":{"xPaddingObfsMode":true}}'
      CASE_EXPECTED="xhttp xPaddingObfsMode is not supported"
      ;;
    v2node_xhttp_stream_up_keepalive)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="vless"
      CASE_NETWORK="xhttp"
      CASE_NETWORK_SETTINGS='{"path":"/bad-xhttp","mode":"auto","extra":{"scStreamUpServerSecs":{"from":20,"to":80}}}'
      CASE_EXPECTED="xhttp scStreamUpServerSecs is not supported"
      ;;
    trojan_http)
      CASE_NODE_TYPE="trojan"
      CASE_NETWORK="http"
      CASE_TLS=1
      CASE_NETWORK_SETTINGS='{"path":["/trojan-http"],"host":["example.org"]}'
      CASE_EXPECTED="v2ray http transport is only supported for VMess/VLESS nodes"
      ;;
    v2node_trojan_http)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="trojan"
      CASE_NETWORK="http"
      CASE_TLS=1
      CASE_NETWORK_SETTINGS='{"path":["/trojan-http"],"host":["example.org"]}'
      CASE_EXPECTED="v2ray http transport is only supported for VMess/VLESS nodes"
      ;;
    v2node_trojan_xhttp)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="trojan"
      CASE_NETWORK="xhttp"
      CASE_TLS=1
      CASE_EXPECTED="xhttp transport is only supported for VMess/VLESS nodes"
      ;;
    v2node_mlkem)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="vless"
      CASE_ENCRYPTION="mlkem768x25519plus"
      CASE_EXPECTED="vless encryption \`mlkem768x25519plus\` is not supported"
      ;;
    v2node_vmess_encryption_settings)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="vmess"
      CASE_NETWORK="tcp"
      CASE_ENCRYPTION_SETTINGS='{"mode":"native"}'
      CASE_EXPECTED="vmess encryption_settings is not supported"
      ;;
    v2node_shadowsocks_ws)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="shadowsocks"
      CASE_NETWORK="ws"
      CASE_NETWORK_SETTINGS='{"path":"/ss-ws"}'
      CASE_EXPECTED="shadowsocks requires plain tcp transport"
      ;;
    v2node_shadowsocks_encryption_settings)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="shadowsocks"
      CASE_NETWORK="tcp"
      CASE_ENCRYPTION_SETTINGS='{"mode":"native"}'
      CASE_EXPECTED="shadowsocks encryption_settings is not supported"
      ;;
    v2node_anytls_ws)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="anytls"
      CASE_NETWORK="ws"
      CASE_TLS=1
      CASE_TLS_SETTINGS='{"serverName":"example.org"}'
      CASE_NETWORK_SETTINGS='{"path":"/anytls-ws"}'
      CASE_EXPECTED="anytls requires plain tcp transport"
      ;;
    tuic_bad_congestion_control)
      CASE_NODE_TYPE="tuic"
      CASE_TLS=1
      CASE_TUIC_CONGESTION_CONTROL="'invalid-cc'"
      CASE_EXPECTED="unsupported tuic congestion_control \`invalid-cc\`"
      ;;
    v2node_tuic_bad_congestion_control)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="tuic"
      CASE_TLS=1
      CASE_TUIC_CONGESTION_CONTROL="'invalid-cc'"
      CASE_EXPECTED="unsupported tuic congestion_control \`invalid-cc\`"
      ;;
    vless_reality_missing_dest)
      CASE_NODE_TYPE="vless"
      CASE_TLS=2
      CASE_TLS_SETTINGS="{\"private_key\":\"${REALITY_PRIVATE_KEY}\",\"short_ids\":[\"abcd\"]}"
      CASE_EXPECTED="reality missing dest or server_name/server_port"
      ;;
    vless_reality_missing_short_id)
      CASE_NODE_TYPE="vless"
      CASE_TLS=2
      CASE_TLS_SETTINGS="{\"private_key\":\"${REALITY_PRIVATE_KEY}\",\"dest\":\"example.com:443\"}"
      CASE_EXPECTED="reality missing short_id"
      ;;
    v2node_reality_missing_short_id)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="vless"
      CASE_TLS=2
      CASE_TLS_SETTINGS="{\"private_key\":\"${REALITY_PRIVATE_KEY}\",\"dest\":\"example.com:443\"}"
      CASE_EXPECTED="reality missing short_id"
      ;;
    vless_reality_xver)
      CASE_NODE_TYPE="vless"
      CASE_TLS=2
      CASE_TLS_SETTINGS="{\"private_key\":\"${REALITY_PRIVATE_KEY}\",\"short_ids\":[\"abcd\"],\"dest\":\"example.com:443\",\"xver\":1}"
      CASE_EXPECTED="reality xver=1 is not supported"
      ;;
    vless_reality_ech)
      CASE_NODE_TYPE="vless"
      CASE_TLS=2
      CASE_TLS_SETTINGS="{\"private_key\":\"${REALITY_PRIVATE_KEY}\",\"short_ids\":[\"abcd\"],\"dest\":\"example.com:443\",\"ech\":\"custom\"}"
      CASE_EXPECTED="reality ECH is not supported"
      ;;
    vless_tls_ech)
      CASE_NODE_TYPE="vless"
      CASE_TLS=1
      CASE_TLS_SETTINGS='{"serverName":"tls.example.com","ech":"custom"}'
      CASE_EXPECTED="tls ECH is not supported"
      ;;
    ss_unknown_obfs)
      CASE_NODE_TYPE="shadowsocks"
      CASE_SS_OBFS="'tls'"
      CASE_EXPECTED="shadowsocks obfs plugin \`tls\` is not supported"
      ;;
    ss_xchacha)
      CASE_NODE_TYPE="shadowsocks"
      CASE_SS_CIPHER="xchacha20-ietf-poly1305"
      CASE_EXPECTED="unsupported shadowsocks cipher \`xchacha20-ietf-poly1305\`"
      ;;
    ss_none)
      CASE_NODE_TYPE="shadowsocks"
      CASE_SS_CIPHER="none"
      CASE_EXPECTED="unsupported shadowsocks cipher \`none\`"
      ;;
    hysteria_v1)
      CASE_NODE_TYPE="hysteria"
      CASE_HYSTERIA_VERSION=1
      CASE_EXPECTED="hysteria v1 is not supported"
      ;;
    hy2_no_obfs_password)
      CASE_NODE_TYPE="hysteria"
      CASE_HYSTERIA_OBFS="'salamander'"
      CASE_HYSTERIA_OBFS_PASSWORD="NULL"
      CASE_EXPECTED="hysteria2 salamander obfs requires obfs_password"
      ;;
    hy2_gecko_no_obfs_password)
      CASE_NODE_TYPE="hysteria"
      CASE_HYSTERIA_OBFS="'gecko'"
      CASE_HYSTERIA_OBFS_PASSWORD="NULL"
      CASE_EXPECTED="hysteria2 gecko obfs requires obfs_password"
      ;;
    v2node_hy2_gecko_no_obfs_password)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="hysteria2"
      CASE_TLS=1
      CASE_HYSTERIA_OBFS="'gecko'"
      CASE_HYSTERIA_OBFS_PASSWORD="NULL"
      CASE_EXPECTED="hysteria2 gecko obfs requires obfs_password"
      ;;
    hy2_unknown_obfs)
      CASE_NODE_TYPE="hysteria"
      CASE_HYSTERIA_OBFS="'shadow'"
      CASE_HYSTERIA_OBFS_PASSWORD="'secret'"
      CASE_EXPECTED="unsupported hysteria2 obfs \`shadow\`"
      ;;
    v2node_hy2_unknown_obfs)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="hysteria2"
      CASE_TLS=1
      CASE_HYSTERIA_OBFS="'shadow'"
      CASE_HYSTERIA_OBFS_PASSWORD="'secret'"
      CASE_EXPECTED="unsupported hysteria2 obfs \`shadow\`"
      ;;
    hy2_password_only)
      CASE_NODE_TYPE="hysteria"
      CASE_HYSTERIA_OBFS="NULL"
      CASE_HYSTERIA_OBFS_PASSWORD="'secret'"
      CASE_EXPECTED="hysteria2 obfs_password is set but obfs is empty"
      ;;
    naiveproxy_quic_bad_congestion_control)
      CASE_NODE_TYPE="naiveproxy"
      CASE_TLS=1
      CASE_NAIVE_ENABLE_QUIC=1
      CASE_NAIVE_QUIC_CC="'invalid-cc'"
      CASE_EXPECTED="unsupported naiveproxy quic_congestion_control \`invalid-cc\`"
      ;;
    v2node_naive_bad_congestion_control)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="naive"
      CASE_TLS=1
      CASE_TLS_SETTINGS='{"serverName":"example.org","alpn":["h3"]}'
      CASE_NETWORK="udp"
      CASE_TUIC_CONGESTION_CONTROL="'invalid-cc'"
      CASE_EXPECTED="unsupported naiveproxy quic_congestion_control \`invalid-cc\`"
      ;;
    v2node_naive_tls_disabled)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="naive"
      CASE_TLS=0
      CASE_NETWORK="tcp"
      CASE_EXPECTED="naiveproxy requires TLS"
      ;;
    v2node_naive_custom_alpn)
      CASE_NODE_TYPE="v2node"
      CASE_V2_PROTOCOL="naive"
      CASE_TLS=1
      CASE_TLS_SETTINGS='{"serverName":"example.org","alpn":["h3"]}'
      CASE_EXPECTED="naiveproxy custom TLS ALPN"
      ;;
    *)
      e2e_die "unknown unsupported case: ${CASE_NAME}"
      ;;
  esac
}

seed_group_and_user() {
  local now
  local expires_at
  local email
  local uuid

  now="$(date +%s)"
  expires_at="$((now + 86400))"
  email="shoes-unsupported-${CASE_NODE_ID}@example.local"
  uuid="$(printf '99999999-9999-4999-8999-%012d' "${CASE_NODE_ID}")"

  mysql_exec <<SQL
INSERT INTO v2_server_group
(id, name, created_at, updated_at)
VALUES
(${CASE_GROUP_ID}, 'shoes-unsupported-${CASE_NAME}', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  name=VALUES(name),
  updated_at=VALUES(updated_at);

INSERT INTO v2_user
(id, invite_user_id, telegram_id, email, language, password, password_algo, password_salt, balance, discount, commission_type, commission_rate, commission_balance, t, u, d, transfer_enable, device_limit, banned, is_admin, last_login_at, is_staff, last_login_ip, uuid, group_id, plan_id, speed_limit, auto_renewal, remind_expire, remind_traffic, token, expired_at, remarks, created_at, updated_at)
VALUES
(${CASE_USER_ID}, NULL, NULL, '${email}', NULL, 'e2e-password', NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0, 1073741824, NULL, 0, 0, NULL, 0, NULL, '${uuid}', ${CASE_GROUP_ID}, NULL, NULL, 0, 1, 1, MD5('${email}'), ${expires_at}, 'shoes unsupported ${CASE_NAME} e2e', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  banned=0,
  transfer_enable=VALUES(transfer_enable),
  u=0,
  d=0,
  t=0,
  uuid=VALUES(uuid),
  group_id=${CASE_GROUP_ID},
  speed_limit=NULL,
  device_limit=NULL,
  expired_at=VALUES(expired_at),
  updated_at=VALUES(updated_at);

DELETE FROM v2_stat_user WHERE user_id=${CASE_USER_ID};
SQL

  e2e_redis_hdel_user_traffic "${V2BOARD_REDIS_CONTAINER}" "${CASE_USER_ID}"
}

seed_node() {
  local now

  now="$(date +%s)"
  case "${CASE_NODE_TYPE}" in
    vmess)
      mysql_exec <<SQL
INSERT INTO v2_server_vmess
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tags, rate, network, rules, networkSettings, tlsSettings, ruleSettings, dnsSettings, \`show\`, sort, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, '["${CASE_GROUP_ID}"]', NULL, 'shoes-unsupported-${CASE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${CASE_NODE_PORT}', ${CASE_NODE_PORT}, ${CASE_TLS}, NULL, '1', '${CASE_NETWORK}', NULL, '${CASE_NETWORK_SETTINGS}', '${CASE_TLS_SETTINGS}', '{}', '{}', 1, ${CASE_NODE_ID}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  tls=VALUES(tls),
  network=VALUES(network),
  networkSettings=VALUES(networkSettings),
  tlsSettings=VALUES(tlsSettings),
  \`show\`=VALUES(\`show\`),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='vmess';
SQL
      ;;
    vless)
      mysql_exec <<SQL
INSERT INTO v2_server_vless
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tls, tls_settings, flow, network, network_settings, encryption, encryption_settings, tags, rate, \`show\`, sort, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, '["${CASE_GROUP_ID}"]', NULL, 'shoes-unsupported-${CASE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', ${CASE_NODE_PORT}, ${CASE_NODE_PORT}, ${CASE_TLS}, '${CASE_TLS_SETTINGS}', NULL, '${CASE_NETWORK}', '${CASE_NETWORK_SETTINGS}', '${CASE_ENCRYPTION}', '${CASE_ENCRYPTION_SETTINGS}', NULL, '1', 1, ${CASE_NODE_ID}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  tls=VALUES(tls),
  tls_settings=VALUES(tls_settings),
  network=VALUES(network),
  network_settings=VALUES(network_settings),
  encryption=VALUES(encryption),
  encryption_settings=VALUES(encryption_settings),
  \`show\`=VALUES(\`show\`),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='vless';
SQL
      ;;
    shadowsocks)
      mysql_exec <<SQL
INSERT INTO v2_server_shadowsocks
(id, group_id, route_id, parent_id, tags, name, country_code, city_name, city_id, rate, host, port, server_port, cipher, obfs, obfs_settings, gost_enable, gost_settings, \`show\`, sort, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, '["${CASE_GROUP_ID}"]', NULL, NULL, NULL, 'shoes-unsupported-${CASE_NAME}', 'US', 'Local', NULL, '1', '${E2E_BIND_HOST}', '${CASE_NODE_PORT}', ${CASE_NODE_PORT}, '${CASE_SS_CIPHER}', ${CASE_SS_OBFS}, NULL, 0, NULL, 1, ${CASE_NODE_ID}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  cipher=VALUES(cipher),
  obfs=VALUES(obfs),
  \`show\`=VALUES(\`show\`),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='shadowsocks';
SQL
      ;;
    trojan)
      mysql_exec <<SQL
INSERT INTO v2_server_trojan
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tags, rate, \`show\`, sort, network, network_settings, allow_insecure, server_name, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, '["${CASE_GROUP_ID}"]', NULL, 'shoes-unsupported-${CASE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${CASE_NODE_PORT}', ${CASE_NODE_PORT}, NULL, '1', 1, ${CASE_NODE_ID}, '${CASE_NETWORK}', '${CASE_NETWORK_SETTINGS}', 0, 'example.org', ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  network=VALUES(network),
  network_settings=VALUES(network_settings),
  allow_insecure=VALUES(allow_insecure),
  server_name=VALUES(server_name),
  \`show\`=VALUES(\`show\`),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='trojan';
SQL
      ;;
    hysteria)
      mysql_exec <<SQL
INSERT INTO v2_server_hysteria
(id, version, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tags, rate, \`show\`, sort, up_mbps, down_mbps, obfs, obfs_password, server_name, insecure, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, ${CASE_HYSTERIA_VERSION}, '["${CASE_GROUP_ID}"]', NULL, 'shoes-unsupported-${CASE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${CASE_NODE_PORT}', ${CASE_NODE_PORT}, NULL, '1', 1, ${CASE_NODE_ID}, ${CASE_HYSTERIA_UP_MBPS}, ${CASE_HYSTERIA_DOWN_MBPS}, ${CASE_HYSTERIA_OBFS}, ${CASE_HYSTERIA_OBFS_PASSWORD}, 'example.org', 0, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  version=VALUES(version),
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  up_mbps=VALUES(up_mbps),
  down_mbps=VALUES(down_mbps),
  obfs=VALUES(obfs),
  obfs_password=VALUES(obfs_password),
  \`show\`=VALUES(\`show\`),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='hysteria';
SQL
      ;;
    naiveproxy)
      mysql_exec <<SQL
INSERT INTO v2_server_naiveproxy
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tags, rate, \`show\`, sort, listen_ip, tls, server_name, enable_quic, quic_congestion_control, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, '["${CASE_GROUP_ID}"]', NULL, 'shoes-unsupported-${CASE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${CASE_NODE_PORT}', ${CASE_NODE_PORT}, NULL, '1', 1, ${CASE_NODE_ID}, '${E2E_BIND_HOST}', ${CASE_TLS}, 'example.org', ${CASE_NAIVE_ENABLE_QUIC}, ${CASE_NAIVE_QUIC_CC}, ${now}, ${now})
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
DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='naiveproxy';
SQL
      ;;
    tuic)
      mysql_exec <<SQL
INSERT INTO v2_server_tuic
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, port, server_port, tags, rate, \`show\`, sort, server_name, insecure, disable_sni, udp_relay_mode, zero_rtt_handshake, congestion_control, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, '["${CASE_GROUP_ID}"]', NULL, 'shoes-unsupported-${CASE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${CASE_NODE_PORT}', ${CASE_NODE_PORT}, NULL, '1', 1, ${CASE_NODE_ID}, 'example.org', 0, 0, ${CASE_TUIC_UDP_RELAY_MODE}, ${CASE_TUIC_ZERO_RTT}, ${CASE_TUIC_CONGESTION_CONTROL}, ${now}, ${now})
ON DUPLICATE KEY UPDATE
  group_id=VALUES(group_id),
  name=VALUES(name),
  host=VALUES(host),
  port=VALUES(port),
  server_port=VALUES(server_port),
  server_name=VALUES(server_name),
  insecure=VALUES(insecure),
  disable_sni=VALUES(disable_sni),
  udp_relay_mode=VALUES(udp_relay_mode),
  zero_rtt_handshake=VALUES(zero_rtt_handshake),
  congestion_control=VALUES(congestion_control),
  \`show\`=VALUES(\`show\`),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='tuic';
SQL
      ;;
    v2node)
      mysql_exec <<SQL
INSERT INTO v2_server_v2node
(id, group_id, route_id, name, country_code, city_name, city_id, parent_id, host, listen_ip, port, server_port, tags, rate, \`show\`, sort, protocol, tls, tls_settings, flow, network, network_settings, encryption, encryption_settings, disable_sni, udp_relay_mode, zero_rtt_handshake, congestion_control, cipher, up_mbps, down_mbps, obfs, obfs_password, padding_scheme, created_at, updated_at)
VALUES
(${CASE_NODE_ID}, '["${CASE_GROUP_ID}"]', NULL, 'shoes-unsupported-${CASE_NAME}', 'US', 'Local', NULL, NULL, '${E2E_BIND_HOST}', '${E2E_BIND_HOST}', '${CASE_NODE_PORT}', ${CASE_NODE_PORT}, NULL, '1', 1, ${CASE_NODE_ID}, '${CASE_V2_PROTOCOL}', ${CASE_TLS}, '${CASE_TLS_SETTINGS}', NULL, '${CASE_NETWORK}', '${CASE_NETWORK_SETTINGS}', '${CASE_ENCRYPTION}', '${CASE_ENCRYPTION_SETTINGS}', 0, ${CASE_TUIC_UDP_RELAY_MODE}, ${CASE_TUIC_ZERO_RTT}, ${CASE_TUIC_CONGESTION_CONTROL}, '${CASE_SS_CIPHER}', ${CASE_HYSTERIA_UP_MBPS}, ${CASE_HYSTERIA_DOWN_MBPS}, ${CASE_HYSTERIA_OBFS}, ${CASE_HYSTERIA_OBFS_PASSWORD}, NULL, ${now}, ${now})
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
  encryption_settings=VALUES(encryption_settings),
  udp_relay_mode=VALUES(udp_relay_mode),
  zero_rtt_handshake=VALUES(zero_rtt_handshake),
  congestion_control=VALUES(congestion_control),
  cipher=VALUES(cipher),
  up_mbps=VALUES(up_mbps),
  down_mbps=VALUES(down_mbps),
  obfs=VALUES(obfs),
  obfs_password=VALUES(obfs_password),
  \`show\`=VALUES(\`show\`),
  updated_at=VALUES(updated_at);
DELETE FROM v2_stat_server WHERE server_id=${CASE_NODE_ID} AND server_type='v2node';
SQL
      ;;
    *)
      e2e_die "unsupported node type for case ${CASE_NAME}: ${CASE_NODE_TYPE}"
      ;;
  esac
}

write_shoes_config() {
  cat >"${TMP_DIR}/${CASE_NAME}.shoes.yml" <<YAML
v2board:
  api_host: "${V2BOARD_PANEL_URL}"
  api_key: "${SERVER_TOKEN}"
  nodes:
    - tag: "${CASE_NAME}"
      node_id: ${CASE_NODE_ID}
      node_type: "${CASE_NODE_TYPE}"
      listen: "${E2E_BIND_HOST}"
runtime:
  data_dir: "${TMP_DIR}/${CASE_NAME}-shoes-data"
  pull_interval_secs: 2
  push_interval_secs: 2
tls:
  cert_file: "${TMP_DIR}/tls.crt"
  key_file: "${TMP_DIR}/tls.key"
log:
  level: "debug"
YAML
}

run_sync_once_expect_failure() {
  local log_file="${TMP_DIR}/${CASE_NAME}.sync.log"

  if "${SHOES_BIN}" sync-once -c "${TMP_DIR}/${CASE_NAME}.shoes.yml" -l - >"${log_file}" 2>&1; then
    cat "${log_file}" >&2
    e2e_die "${CASE_NAME}: sync-once unexpectedly succeeded"
  fi

  if ! grep -Fq "${CASE_EXPECTED}" "${log_file}"; then
    cat "${log_file}" >&2
    e2e_die "${CASE_NAME}: expected error containing: ${CASE_EXPECTED}"
  fi

  e2e_log "${CASE_NAME}: rejected as expected (${CASE_EXPECTED})"
}

cleanup_fixtures() {
  mysql_exec <<SQL
DELETE su FROM v2_stat_user su JOIN v2_user u ON su.user_id=u.id WHERE u.email LIKE 'shoes-unsupported-%@example.local';
DELETE FROM v2_user WHERE email LIKE 'shoes-unsupported-%@example.local';

DELETE ss FROM v2_stat_server ss JOIN v2_server_vmess n ON ss.server_type='vmess' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-unsupported-%';
DELETE ss FROM v2_stat_server ss JOIN v2_server_vless n ON ss.server_type='vless' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-unsupported-%';
DELETE ss FROM v2_stat_server ss JOIN v2_server_shadowsocks n ON ss.server_type='shadowsocks' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-unsupported-%';
DELETE ss FROM v2_stat_server ss JOIN v2_server_hysteria n ON ss.server_type='hysteria' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-unsupported-%';
DELETE ss FROM v2_stat_server ss JOIN v2_server_naiveproxy n ON ss.server_type='naiveproxy' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-unsupported-%';
DELETE ss FROM v2_stat_server ss JOIN v2_server_tuic n ON ss.server_type='tuic' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-unsupported-%';
DELETE ss FROM v2_stat_server ss JOIN v2_server_v2node n ON ss.server_type='v2node' AND ss.server_id=n.id WHERE n.name LIKE 'shoes-unsupported-%';

DELETE FROM v2_server_vmess WHERE name LIKE 'shoes-unsupported-%';
DELETE FROM v2_server_vless WHERE name LIKE 'shoes-unsupported-%';
DELETE FROM v2_server_shadowsocks WHERE name LIKE 'shoes-unsupported-%';
DELETE FROM v2_server_hysteria WHERE name LIKE 'shoes-unsupported-%';
DELETE FROM v2_server_naiveproxy WHERE name LIKE 'shoes-unsupported-%';
DELETE FROM v2_server_tuic WHERE name LIKE 'shoes-unsupported-%';
DELETE FROM v2_server_v2node WHERE name LIKE 'shoes-unsupported-%';
DELETE FROM v2_server_group WHERE name LIKE 'shoes-unsupported-%';
SQL
}

run_case() {
  setup_case "$1" "$2"

  e2e_section "case ${CASE_NAME}"
  seed_group_and_user
  seed_node
  write_shoes_config
  run_sync_once_expect_failure
}

main() {
  parse_args "$@"
  check_environment
  TMP_DIR="$(mktemp -d)"
  resolve_binaries
  generate_tls_files
  SERVER_TOKEN="$(discover_server_token)"
  [[ -n "${SERVER_TOKEN}" ]] || e2e_die "could not discover V2Board server_token"

  local -a cases
  local index
  IFS=',' read -r -a cases <<<"${E2E_CASES}"
  index=0
  for case_name in "${cases[@]}"; do
    [[ -n "${case_name}" ]] || continue
    run_case "${case_name}" "${index}"
    index=$((index + 1))
  done

  if ! e2e_env_bool E2E_KEEP_FIXTURES 1; then
    cleanup_fixtures
  fi

  e2e_section "done"
}

main "$@"
