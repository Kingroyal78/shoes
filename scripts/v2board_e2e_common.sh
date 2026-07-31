#!/usr/bin/env bash

# shellcheck disable=SC2034
# E2E_COMPOSE_CMD is set here and consumed by the sourcing entrypoint.

e2e_timestamp() {
  date '+%Y-%m-%dT%H:%M:%S%z'
}

e2e_log() {
  printf '[%s] %s\n' "$(e2e_timestamp)" "$*" >&2
}

e2e_warn() {
  e2e_log "WARN: $*"
}

e2e_error() {
  e2e_log "ERROR: $*"
}

e2e_die() {
  e2e_error "$*"
  exit 1
}

e2e_section() {
  printf '\n==> %s\n' "$*" >&2
}

e2e_on_error() {
  local status=$?
  local source_file="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
  local source_line="${BASH_LINENO[0]:-unknown}"
  e2e_error "command failed (${status}) at ${source_file}:${source_line}: ${BASH_COMMAND}"
  exit "${status}"
}

e2e_bool() {
  local value="${1:-}"

  case "${value}" in
    1 | true | TRUE | True | yes | YES | Yes | y | Y | on | ON | On)
      return 0
      ;;
    '' | 0 | false | FALSE | False | no | NO | No | n | N | off | OFF | Off)
      return 1
      ;;
    *)
      e2e_die "invalid boolean value '${value}' (use 1/0, true/false, yes/no, on/off)"
      ;;
  esac
}

e2e_env_bool() {
  local name="$1"
  local default_value="${2:-0}"
  local value="${!name:-${default_value}}"

  e2e_bool "${value}"
}

e2e_validate_bool_env() {
  local name="$1"
  local default_value="${2:-0}"
  local value="${!name:-${default_value}}"

  e2e_bool "${value}" || true
}

e2e_run() {
  e2e_log "+ $*"
  "$@"
}

e2e_require_command() {
  local command_name="$1"

  command -v "${command_name}" >/dev/null 2>&1 || e2e_die "missing required command: ${command_name}"
}

e2e_require_dir() {
  local path="$1"
  local label="${2:-directory}"

  [[ -d "${path}" ]] || e2e_die "missing ${label}: ${path}"
}

e2e_require_file() {
  local path="$1"
  local label="${2:-file}"

  [[ -f "${path}" ]] || e2e_die "missing ${label}: ${path}"
}

e2e_detect_compose() {
  E2E_COMPOSE_CMD=()

  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    E2E_COMPOSE_CMD=(docker compose)
    return 0
  fi

  if command -v docker-compose >/dev/null 2>&1; then
    E2E_COMPOSE_CMD=(docker-compose)
    return 0
  fi

  return 1
}

e2e_http_probe() {
  local url="$1"

  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 5 -o /dev/null "${url}"
    return $?
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -q --timeout=5 --spider "${url}"
    return $?
  fi

  e2e_warn "neither curl nor wget is installed; cannot probe ${url}"
  return 2
}

e2e_listeners_on_port() {
  local port="$1"

  ss -ltnp 2>/dev/null | awk -v port="${port}" 'NR > 1 && $4 ~ ":" port "$" { print }'
}

e2e_udp_listeners_on_port() {
  local port="$1"

  ss -lunp 2>/dev/null | awk -v port="${port}" 'NR > 1 && $4 ~ ":" port "$" { print }'
}

e2e_assert_port_free() {
  local port="$1"
  local label="${2:-port}"
  local listeners

  listeners="$(e2e_listeners_on_port "${port}")"
  [[ -z "${listeners}" ]] || e2e_die "${label} port ${port} is already in use: ${listeners}"
}

e2e_assert_udp_port_free() {
  local port="$1"
  local label="${2:-udp port}"
  local listeners

  listeners="$(e2e_udp_listeners_on_port "${port}")"
  [[ -z "${listeners}" ]] || e2e_die "${label} UDP port ${port} is already in use: ${listeners}"
}

e2e_redis_hdel_user_traffic() {
  local redis_container="$1"
  local user_id="$2"
  local key_prefix

  for key_prefix in "" "v2board_database_"; do
    docker exec "${redis_container}" redis-cli HDEL "${key_prefix}v2board_upload_traffic" "${user_id}" >/dev/null
    docker exec "${redis_container}" redis-cli HDEL "${key_prefix}v2board_download_traffic" "${user_id}" >/dev/null
  done
}

e2e_drain_v2board_queues() {
  local www_container="$1"

  docker exec "${www_container}" \
    php artisan queue:work \
    --queue=traffic_fetch,stat \
    --stop-when-empty \
    --sleep=0 \
    --timeout=30 \
    --tries=1 \
    --no-interaction \
    >/dev/null
}
