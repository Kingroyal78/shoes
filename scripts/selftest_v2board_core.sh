#!/usr/bin/env bash
# shellcheck disable=SC2034
# CLI flags intentionally assign env-style globals that are read via indirect expansion.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/scripts"

# shellcheck source=scripts/v2board_e2e_common.sh
source "${SCRIPT_DIR}/v2board_e2e_common.sh"

trap e2e_on_error ERR

DEFAULT_V2BOARD_DOCKER_DIR="${ROOT_DIR}/../v2board-docker"
EXPECTED_V2BOARD_DOCKER_DIR="/root/cate/v2board-docker"
V2BOARD_DOCKER_DIR="${V2BOARD_DOCKER_DIR:-${DEFAULT_V2BOARD_DOCKER_DIR}}"

if [[ -d "${V2BOARD_DOCKER_DIR}" ]]; then
  V2BOARD_DOCKER_DIR="$(cd "${V2BOARD_DOCKER_DIR}" && pwd)"
fi

V2BOARD_COMPOSE_FILE="${V2BOARD_COMPOSE_FILE:-${V2BOARD_DOCKER_DIR}/docker-compose.yaml}"
V2BOARD_PANEL_URL="${V2BOARD_PANEL_URL:-http://127.0.0.1}"
CONFIG_PATH="${SHOES_CONFIG:-${ROOT_DIR}/config/config.yml.example}"
SHOES_E2E_NODE_MATRIX="${SHOES_E2E_NODE_MATRIX:-vless,vmess,trojan,shadowsocks,anytls,tuic,hysteria,v2node}"
SHOES_E2E_CLIENT_MATRIX_LIST="${SHOES_E2E_CLIENT_MATRIX_LIST:-sing-box,xray,clash-meta}"
SHOES_E2E_COMPOSE_STARTED=0
E2E_COMPOSE_CMD=()

usage() {
  cat <<'EOF'
Usage:
  scripts/selftest_v2board_core.sh [--help] [--compose-up] [--no-compose-up]
                                    [--sync-once] [--validate-only]

Production-grade skeleton for local v2board-docker E2E checks.

Environment:
  V2BOARD_DOCKER_DIR
      Sibling v2board-docker checkout. Defaults to ../v2board-docker,
      expected as /root/cate/v2board-docker in this workspace.
  V2BOARD_COMPOSE_FILE
      Compose file to use. Defaults to $V2BOARD_DOCKER_DIR/docker-compose.yaml.
  V2BOARD_PANEL_URL
      Panel URL used for optional readiness probing. Defaults to http://127.0.0.1.
  SHOES_CONFIG
      shoes YAML config for validate/sync-once. Defaults to config/config.yml.example.
  SHOES_BIN
      Optional prebuilt shoes binary. When unset, this script uses cargo run --bin shoes.
  SHOES_E2E_RELEASE
      Use cargo run --release --bin shoes when SHOES_BIN is unset. Defaults to 0.
  SHOES_E2E_COMPOSE_UP
      Run docker compose up -d before shoes checks. Defaults to 0.
  SHOES_E2E_COMPOSE_DOWN
      If this script started compose, run docker compose down on exit. Defaults to 0.
  SHOES_E2E_WAIT_FOR_PANEL
      Probe $V2BOARD_PANEL_URL after compose up. Defaults to $SHOES_E2E_COMPOSE_UP.
  SHOES_E2E_PANEL_TIMEOUT_SECS
      Panel readiness timeout. Defaults to 120.
  SHOES_E2E_VALIDATE
      Run shoes validate. Defaults to 1.
  SHOES_E2E_SYNC_ONCE
      Run shoes sync-once. Defaults to $SHOES_SYNC_ONCE for backwards compatibility,
      otherwise 0.
  SHOES_SYNC_ONCE
      Legacy alias for SHOES_E2E_SYNC_ONCE.
  SHOES_E2E_SEED
      Reserved seed hook for panel fixtures. Defaults to 0; enabling it fails until
      seed_panel_matrix() is implemented.
  SHOES_E2E_CLIENT_MATRIX
      Reserved client matrix hook. Defaults to 0; enabling it fails until
      run_client_matrix() is implemented.
  SHOES_E2E_NODE_MATRIX
      Reserved node/protocol matrix list. Defaults to vless,vmess,trojan,shadowsocks,anytls,tuic,hysteria,v2node.
      This is not executed until seed/client matrix hooks are implemented.
  SHOES_E2E_CLIENT_MATRIX_LIST
      Reserved client list. Defaults to sing-box,xray,clash-meta.
      This is not executed until seed/client matrix hooks are implemented.

Examples:
  scripts/selftest_v2board_core.sh
  SHOES_E2E_COMPOSE_UP=1 scripts/selftest_v2board_core.sh
  SHOES_CONFIG=/tmp/shoes-v2board.yml SHOES_E2E_SYNC_ONCE=1 scripts/selftest_v2board_core.sh
EOF
}

parse_args() {
  while (($#)); do
    case "$1" in
      -h | --help)
        usage
        exit 0
        ;;
      --compose-up)
        SHOES_E2E_COMPOSE_UP=1
        ;;
      --no-compose-up)
        SHOES_E2E_COMPOSE_UP=0
        ;;
      --sync-once)
        SHOES_E2E_SYNC_ONCE=1
        ;;
      --validate-only)
        SHOES_E2E_VALIDATE=1
        SHOES_E2E_SYNC_ONCE=0
        SHOES_E2E_SEED=0
        SHOES_E2E_CLIENT_MATRIX=0
        ;;
      *)
        e2e_die "unknown argument: $1"
        ;;
    esac
    shift
  done
}

cleanup() {
  local status=$?
  set +e

  if [[ "${SHOES_E2E_COMPOSE_STARTED}" == "1" ]] && e2e_env_bool SHOES_E2E_COMPOSE_DOWN 0; then
    e2e_section "compose cleanup"
    e2e_run "${E2E_COMPOSE_CMD[@]}" \
      -f "${V2BOARD_COMPOSE_FILE}" \
      --project-directory "${V2BOARD_DOCKER_DIR}" \
      down
  fi

  exit "${status}"
}

trap cleanup EXIT

validate_boolean_env() {
  e2e_validate_bool_env SHOES_E2E_RELEASE 0
  e2e_validate_bool_env SHOES_E2E_COMPOSE_UP 0
  e2e_validate_bool_env SHOES_E2E_COMPOSE_DOWN 0
  e2e_validate_bool_env SHOES_E2E_WAIT_FOR_PANEL "${SHOES_E2E_COMPOSE_UP:-0}"
  e2e_validate_bool_env SHOES_E2E_VALIDATE 1
  e2e_validate_bool_env SHOES_E2E_SYNC_ONCE "${SHOES_SYNC_ONCE:-0}"
  e2e_validate_bool_env SHOES_E2E_SEED 0
  e2e_validate_bool_env SHOES_E2E_CLIENT_MATRIX 0
}

print_config() {
  e2e_section "e2e configuration"
  e2e_log "ROOT_DIR=${ROOT_DIR}"
  e2e_log "V2BOARD_DOCKER_DIR=${V2BOARD_DOCKER_DIR}"
  e2e_log "V2BOARD_COMPOSE_FILE=${V2BOARD_COMPOSE_FILE}"
  e2e_log "V2BOARD_PANEL_URL=${V2BOARD_PANEL_URL}"
  e2e_log "SHOES_CONFIG=${CONFIG_PATH}"
  e2e_log "SHOES_BIN=${SHOES_BIN:-<cargo run --bin shoes>}"
  e2e_log "SHOES_E2E_NODE_MATRIX=${SHOES_E2E_NODE_MATRIX}"
  e2e_log "SHOES_E2E_CLIENT_MATRIX_LIST=${SHOES_E2E_CLIENT_MATRIX_LIST}"
}

preflight() {
  e2e_section "preflight"
  e2e_require_dir "${V2BOARD_DOCKER_DIR}" "sibling v2board-docker checkout"
  e2e_require_file "${V2BOARD_COMPOSE_FILE}" "v2board-docker compose file"

  if [[ "${V2BOARD_DOCKER_DIR}" != "${EXPECTED_V2BOARD_DOCKER_DIR}" ]]; then
    e2e_warn "using V2BOARD_DOCKER_DIR=${V2BOARD_DOCKER_DIR}; default workspace sibling is ${EXPECTED_V2BOARD_DOCKER_DIR}"
  fi

  if e2e_env_bool SHOES_E2E_VALIDATE 1 || e2e_env_bool SHOES_E2E_SYNC_ONCE "${SHOES_SYNC_ONCE:-0}"; then
    e2e_require_file "${CONFIG_PATH}" "shoes config"
  fi

  if [[ -n "${SHOES_BIN:-}" ]]; then
    if [[ "${SHOES_BIN}" == */* ]]; then
      [[ -x "${SHOES_BIN}" ]] || e2e_die "SHOES_BIN is not executable: ${SHOES_BIN}"
    else
      e2e_require_command "${SHOES_BIN}"
    fi
  else
    e2e_require_command cargo
  fi
}

run_shoes() {
  if [[ -n "${SHOES_BIN:-}" ]]; then
    e2e_run "${SHOES_BIN}" "$@"
    return
  fi

  if e2e_env_bool SHOES_E2E_RELEASE 0; then
    e2e_run cargo run --release --bin shoes -- "$@"
  else
    e2e_run cargo run --quiet --bin shoes -- "$@"
  fi
}

compose_up() {
  if ! e2e_env_bool SHOES_E2E_COMPOSE_UP 0; then
    e2e_log "compose start skipped; set SHOES_E2E_COMPOSE_UP=1 or pass --compose-up"
    return
  fi

  e2e_section "compose up"
  e2e_detect_compose || e2e_die "docker compose is required when SHOES_E2E_COMPOSE_UP=1"
  e2e_require_command docker

  e2e_run "${E2E_COMPOSE_CMD[@]}" \
    -f "${V2BOARD_COMPOSE_FILE}" \
    --project-directory "${V2BOARD_DOCKER_DIR}" \
    config --quiet
  e2e_run "${E2E_COMPOSE_CMD[@]}" \
    -f "${V2BOARD_COMPOSE_FILE}" \
    --project-directory "${V2BOARD_DOCKER_DIR}" \
    up -d
  SHOES_E2E_COMPOSE_STARTED=1

  e2e_run "${E2E_COMPOSE_CMD[@]}" \
    -f "${V2BOARD_COMPOSE_FILE}" \
    --project-directory "${V2BOARD_DOCKER_DIR}" \
    ps
}

wait_for_panel() {
  local timeout="${SHOES_E2E_PANEL_TIMEOUT_SECS:-120}"
  local start
  local now

  if ! e2e_env_bool SHOES_E2E_WAIT_FOR_PANEL "${SHOES_E2E_COMPOSE_UP:-0}"; then
    return
  fi

  e2e_section "panel readiness"
  e2e_log "probing ${V2BOARD_PANEL_URL} for up to ${timeout}s"
  start="$(date +%s)"

  while true; do
    if e2e_http_probe "${V2BOARD_PANEL_URL}"; then
      e2e_log "panel is reachable: ${V2BOARD_PANEL_URL}"
      return
    fi

    now="$(date +%s)"
    if ((now - start >= timeout)); then
      e2e_die "panel was not reachable within ${timeout}s: ${V2BOARD_PANEL_URL}"
    fi

    sleep 3
  done
}

validate_config() {
  if ! e2e_env_bool SHOES_E2E_VALIDATE 1; then
    e2e_log "shoes validate skipped; set SHOES_E2E_VALIDATE=1 to enable"
    return
  fi

  e2e_section "shoes validate"
  run_shoes validate -c "${CONFIG_PATH}"
}

seed_panel_matrix() {
  if ! e2e_env_bool SHOES_E2E_SEED 0; then
    e2e_log "seed matrix skipped; seed_panel_matrix() is reserved"
    return
  fi

  e2e_die "SHOES_E2E_SEED=1 requested, but seed_panel_matrix() is a reserved hook and is not implemented yet"
}

sync_once() {
  if ! e2e_env_bool SHOES_E2E_SYNC_ONCE "${SHOES_SYNC_ONCE:-0}"; then
    e2e_log "sync-once skipped; set SHOES_E2E_SYNC_ONCE=1 and SHOES_CONFIG=/path/to/config.yml"
    return
  fi

  e2e_section "shoes sync-once"
  run_shoes sync-once -c "${CONFIG_PATH}"
}

run_client_matrix() {
  if ! e2e_env_bool SHOES_E2E_CLIENT_MATRIX 0; then
    e2e_log "client matrix skipped; run_client_matrix() is reserved"
    return
  fi

  e2e_die "SHOES_E2E_CLIENT_MATRIX=1 requested, but run_client_matrix() is a reserved hook and is not implemented yet"
}

main() {
  parse_args "$@"
  validate_boolean_env
  print_config
  preflight

  cd "${ROOT_DIR}"
  compose_up
  wait_for_panel
  validate_config
  seed_panel_matrix
  sync_once
  run_client_matrix

  e2e_section "done"
}

main "$@"
