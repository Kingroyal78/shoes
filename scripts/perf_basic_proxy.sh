#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/scripts"

# shellcheck source=scripts/v2board_e2e_common.sh
source "${SCRIPT_DIR}/v2board_e2e_common.sh"

trap e2e_on_error ERR

PERF_BIND_HOST="${PERF_BIND_HOST:-127.0.0.1}"
PERF_HTTP_TARGET_PORT="${PERF_HTTP_TARGET_PORT:-19209}"
PERF_PROXY_PORT="${PERF_PROXY_PORT:-19210}"
PERF_PAYLOAD_KIB="${PERF_PAYLOAD_KIB:-1024}"
PERF_REQUESTS="${PERF_REQUESTS:-1000}"
PERF_CONCURRENCY="${PERF_CONCURRENCY:-50}"
PERF_WARMUP_REQUESTS="${PERF_WARMUP_REQUESTS:-20}"
PERF_WARMUP_CONCURRENCY="${PERF_WARMUP_CONCURRENCY:-4}"
PERF_SAMPLE_INTERVAL_SECS="${PERF_SAMPLE_INTERVAL_SECS:-0.01}"
PERF_CASES="${PERF_CASES:-http:http:http socks:socks:socks mixed-http:mixed:http mixed-socks:mixed:socks}"
PERF_DIRECT_BASELINE="${PERF_DIRECT_BASELINE:-1}"
PERF_SHOES_LOG_LEVEL="${PERF_SHOES_LOG_LEVEL:-warn}"
PERF_BUILD_RELEASE="${PERF_BUILD_RELEASE:-1}"
PERF_SERVER_BIN="${PERF_SERVER_BIN:-}"
PERF_CLIENT_BIN="${PERF_CLIENT_BIN:-}"
PERF_TARGET_BIN="${PERF_TARGET_BIN:-}"
PERF_OUTPUT="${PERF_OUTPUT:-}"
PERF_MIN_THROUGHPUT_MIB_S="${PERF_MIN_THROUGHPUT_MIB_S:-}"
PERF_MAX_P95_MS="${PERF_MAX_P95_MS:-}"

TMP_DIR=""
HTTP_PID=""
PROXY_PID=""
SAMPLER_PID=""

usage() {
  cat <<'EOF'
Usage:
  scripts/perf_basic_proxy.sh

Runs repeatable loopback proxy performance checks and emits one JSON object per
case. Override with env vars, for example:
  PERF_REQUESTS=1000 PERF_CONCURRENCY=50 PERF_CASES="http:http:http" scripts/perf_basic_proxy.sh

Each PERF_CASES item is label:proxy_protocol:client_protocol.
Supported proxy_protocol values match shoes-basic-proxy-e2e-server.
Supported client_protocol values: http, socks. A direct target baseline runs
first by default; disable it with PERF_DIRECT_BASELINE=0.
Optional gates:
  PERF_MIN_THROUGHPUT_MIB_S=50
  PERF_MAX_P95_MS=25
EOF
}

cleanup() {
  local status=$?
  set +e
  stop_sampler
  stop_proxy
  if [[ -n "${HTTP_PID}" ]] && kill -0 "${HTTP_PID}" 2>/dev/null; then
    kill "${HTTP_PID}" 2>/dev/null || true
    wait "${HTTP_PID}" 2>/dev/null || true
  fi
  if [[ "${status}" -ne 0 && -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    e2e_warn "temporary perf logs kept for failure analysis: ${TMP_DIR}"
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

resolve_binaries() {
  e2e_section "binaries"
  e2e_require_command cargo
  e2e_require_command python3
  e2e_require_command ss
  e2e_require_command awk
  e2e_require_command getconf

  if e2e_bool "${PERF_BUILD_RELEASE}"; then
    PERF_SERVER_BIN="${PERF_SERVER_BIN:-${ROOT_DIR}/target/release/shoes-basic-proxy-e2e-server}"
    PERF_CLIENT_BIN="${PERF_CLIENT_BIN:-${ROOT_DIR}/target/release/shoes-basic-proxy-perf-client}"
    PERF_TARGET_BIN="${PERF_TARGET_BIN:-${ROOT_DIR}/target/release/shoes-static-http-perf-server}"
    e2e_run cargo build \
      --manifest-path "${ROOT_DIR}/Cargo.toml" \
      --release \
      --features e2e-client,internal-bench \
      --bin shoes-basic-proxy-e2e-server \
      --bin shoes-basic-proxy-perf-client \
      --bin shoes-static-http-perf-server
  else
    PERF_SERVER_BIN="${PERF_SERVER_BIN:-${ROOT_DIR}/target/debug/shoes-basic-proxy-e2e-server}"
    PERF_CLIENT_BIN="${PERF_CLIENT_BIN:-${ROOT_DIR}/target/debug/shoes-basic-proxy-perf-client}"
    PERF_TARGET_BIN="${PERF_TARGET_BIN:-${ROOT_DIR}/target/debug/shoes-static-http-perf-server}"
    e2e_run cargo build \
      --manifest-path "${ROOT_DIR}/Cargo.toml" \
      --features e2e-client,internal-bench \
      --bin shoes-basic-proxy-e2e-server \
      --bin shoes-basic-proxy-perf-client \
      --bin shoes-static-http-perf-server
  fi

  [[ -x "${PERF_SERVER_BIN}" ]] || e2e_die "PERF_SERVER_BIN is not executable: ${PERF_SERVER_BIN}"
  [[ -x "${PERF_CLIENT_BIN}" ]] || e2e_die "PERF_CLIENT_BIN is not executable: ${PERF_CLIENT_BIN}"
  [[ -x "${PERF_TARGET_BIN}" ]] || e2e_die "PERF_TARGET_BIN is not executable: ${PERF_TARGET_BIN}"

  if [[ -n "${PERF_OUTPUT}" ]]; then
    : >"${PERF_OUTPUT}"
  fi
}

wait_for_tcp_port() {
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
    if [[ -n "${HTTP_PID}" ]] && ! kill -0 "${HTTP_PID}" 2>/dev/null; then
      e2e_die "${label} process exited before listening on ${port}"
    fi
    if [[ -n "${PROXY_PID}" ]] && ! kill -0 "${PROXY_PID}" 2>/dev/null; then
      e2e_die "${label} process exited before listening on ${port}"
    fi
    now="$(date +%s)"
    if ((now - start >= timeout)); then
      e2e_die "${label} did not listen on port ${port} within ${timeout}s"
    fi
    sleep 0.2
  done
}

start_http_target() {
  e2e_section "http target"
  e2e_assert_port_free "${PERF_HTTP_TARGET_PORT}" "perf http target"
  "${PERF_TARGET_BIN}" \
    --listen "${PERF_BIND_HOST}:${PERF_HTTP_TARGET_PORT}" \
    --payload-kib "${PERF_PAYLOAD_KIB}" \
    >"${TMP_DIR}/http-target.log" 2>&1 &
  HTTP_PID=$!
  wait_for_tcp_port "${PERF_HTTP_TARGET_PORT}" "perf http target"
}

start_proxy() {
  local protocol="$1"

  stop_proxy
  e2e_assert_port_free "${PERF_PROXY_PORT}" "${protocol} perf proxy"
  RUST_LOG="${PERF_SHOES_LOG_LEVEL}" "${PERF_SERVER_BIN}" \
    --listen "${PERF_BIND_HOST}:${PERF_PROXY_PORT}" \
    --protocol "${protocol}" \
    >"${TMP_DIR}/${protocol}-proxy.log" 2>&1 &
  PROXY_PID=$!
  wait_for_tcp_port "${PERF_PROXY_PORT}" "${protocol} perf proxy"
}

stop_proxy() {
  if [[ -n "${PROXY_PID}" ]] && kill -0 "${PROXY_PID}" 2>/dev/null; then
    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true
  fi
  PROXY_PID=""
}

stop_sampler() {
  if [[ -n "${SAMPLER_PID}" ]] && kill -0 "${SAMPLER_PID}" 2>/dev/null; then
    touch "${TMP_DIR}/sampler.stop" 2>/dev/null || true
    wait "${SAMPLER_PID}" 2>/dev/null || true
  fi
  SAMPLER_PID=""
}

read_proc_ticks() {
  local pid="$1"
  awk '{print $14 + $15}' "/proc/${pid}/stat"
}

start_sampler() {
  local pid="$1"
  local port="$2"
  local output="$3"
  local stop_file="${TMP_DIR}/sampler.stop"

  rm -f "${stop_file}"
  (
    max_rss=0
    max_conn=0
    samples=0
    while kill -0 "${pid}" 2>/dev/null && [[ ! -f "${stop_file}" ]]; do
      rss="$(awk '/VmRSS:/ {print $2}' "/proc/${pid}/status" 2>/dev/null || printf '0')"
      conn="$(ss -tan state established 2>/dev/null \
        | awk -v port=":${port}" 'NR > 1 && ($4 ~ port "$" || $5 ~ port "$") { count++ } END { print count + 0 }')"
      if ((rss > max_rss)); then
        max_rss="${rss}"
      fi
      if ((conn > max_conn)); then
        max_conn="${conn}"
      fi
      samples=$((samples + 1))
      printf '{"proxy_max_rss_kb":%s,"proxy_peak_established_connections":%s,"resource_samples":%s}\n' \
        "${max_rss}" "${max_conn}" "${samples}" >"${output}"
      sleep "${PERF_SAMPLE_INTERVAL_SECS}"
    done
  ) &
  SAMPLER_PID=$!
}

run_client() {
  local client_protocol="$1"
  local requests="$2"
  local concurrency="$3"

  "${PERF_CLIENT_BIN}" \
    --proxy-host "${PERF_BIND_HOST}" \
    --proxy-port "${PERF_PROXY_PORT}" \
    --protocol "${client_protocol}" \
    --target-host "${PERF_BIND_HOST}" \
    --target-port "${PERF_HTTP_TARGET_PORT}" \
    --path /payload.bin \
    --requests "${requests}" \
    --concurrency "${concurrency}"
}

merge_metric() {
  local label="$1"
  local proxy_protocol="$2"
  local client_protocol="$3"
  local client_json="$4"
  local resource_json="$5"
  local proxy_cpu_ms="$6"

  CASE_LABEL="${label}" \
  PROXY_PROTOCOL="${proxy_protocol}" \
  CLIENT_PROTOCOL="${client_protocol}" \
  CLIENT_JSON="${client_json}" \
  RESOURCE_JSON="${resource_json}" \
  PROXY_CPU_MS="${proxy_cpu_ms}" \
  PERF_PAYLOAD_KIB="${PERF_PAYLOAD_KIB}" \
  python3 <<'PY'
import json
import os

metric = json.loads(os.environ["CLIENT_JSON"])
resources = json.loads(os.environ["RESOURCE_JSON"])
metric.update(resources)
metric["case"] = os.environ["CASE_LABEL"]
metric["proxy_protocol"] = os.environ["PROXY_PROTOCOL"]
metric["client_protocol"] = os.environ["CLIENT_PROTOCOL"]
metric["payload_kib"] = int(os.environ["PERF_PAYLOAD_KIB"])
metric["proxy_cpu_ms"] = int(os.environ["PROXY_CPU_MS"])
if metric["elapsed_ms"] > 0:
    metric["proxy_cpu_pct_of_one_core"] = round(metric["proxy_cpu_ms"] * 100.0 / metric["elapsed_ms"], 3)
print(json.dumps(metric, separators=(",", ":"), sort_keys=True))
PY
}

emit_metric() {
  local metric="$1"

  if [[ -n "${PERF_OUTPUT}" ]]; then
    printf '%s\n' "${metric}" | tee -a "${PERF_OUTPUT}"
  else
    printf '%s\n' "${metric}"
  fi
}

assert_thresholds() {
  local metric="$1"

  METRIC_JSON="${metric}" \
  PERF_MIN_THROUGHPUT_MIB_S="${PERF_MIN_THROUGHPUT_MIB_S}" \
  PERF_MAX_P95_MS="${PERF_MAX_P95_MS}" \
  python3 <<'PY'
import os
import sys
import json

metric = json.loads(os.environ["METRIC_JSON"])
minimum = os.environ["PERF_MIN_THROUGHPUT_MIB_S"]
if minimum and metric["throughput_mib_s"] < float(minimum):
    raise SystemExit(
        f"{metric['case']}: throughput_mib_s {metric['throughput_mib_s']} < {minimum}"
    )
maximum = os.environ["PERF_MAX_P95_MS"]
if maximum and metric["latency_p95_ms"] > float(maximum):
    raise SystemExit(
        f"{metric['case']}: latency_p95_ms {metric['latency_p95_ms']} > {maximum}"
    )
sys.exit(0)
PY
}

run_case() {
  local label="$1"
  local proxy_protocol="$2"
  local client_protocol="$3"
  local ticks_before
  local ticks_after
  local clk_tck
  local cpu_ms
  local client_json
  local resource_json
  local resource_path="${TMP_DIR}/${label}.resources.json"
  local metric

  e2e_section "perf ${label}"
  start_proxy "${proxy_protocol}"
  run_client "${client_protocol}" "${PERF_WARMUP_REQUESTS}" "${PERF_WARMUP_CONCURRENCY}" \
    >"${TMP_DIR}/${label}.warmup.json"

  printf '{"proxy_max_rss_kb":0,"proxy_peak_established_connections":0,"resource_samples":0}\n' \
    >"${resource_path}"
  ticks_before="$(read_proc_ticks "${PROXY_PID}")"
  start_sampler "${PROXY_PID}" "${PERF_PROXY_PORT}" "${resource_path}"
  client_json="$(run_client "${client_protocol}" "${PERF_REQUESTS}" "${PERF_CONCURRENCY}")"
  stop_sampler
  ticks_after="$(read_proc_ticks "${PROXY_PID}")"
  clk_tck="$(getconf CLK_TCK)"
  cpu_ms=$(((ticks_after - ticks_before) * 1000 / clk_tck))
  resource_json="$(cat "${resource_path}")"
  metric="$(merge_metric "${label}" "${proxy_protocol}" "${client_protocol}" "${client_json}" "${resource_json}" "${cpu_ms}")"
  emit_metric "${metric}"
  assert_thresholds "${metric}"
  stop_proxy
}

run_cases() {
  local spec
  local label
  local proxy_protocol
  local client_protocol

  for spec in ${PERF_CASES}; do
    IFS=: read -r label proxy_protocol client_protocol <<<"${spec}"
    [[ -n "${label}" && -n "${proxy_protocol}" && -n "${client_protocol}" ]] \
      || e2e_die "invalid PERF_CASES item: ${spec}"
    run_case "${label}" "${proxy_protocol}" "${client_protocol}"
  done
}

run_direct_baseline() {
  local client_json
  local metric

  if ! e2e_bool "${PERF_DIRECT_BASELINE}"; then
    return
  fi

  e2e_section "perf direct"
  run_client "direct" "${PERF_WARMUP_REQUESTS}" "${PERF_WARMUP_CONCURRENCY}" \
    >"${TMP_DIR}/direct.warmup.json"
  client_json="$(run_client "direct" "${PERF_REQUESTS}" "${PERF_CONCURRENCY}")"
  metric="$(merge_metric "direct" "none" "direct" "${client_json}" \
    '{"proxy_max_rss_kb":0,"proxy_peak_established_connections":0,"resource_samples":0}' 0)"
  emit_metric "${metric}"
  assert_thresholds "${metric}"
}

main() {
  parse_args "$@"
  TMP_DIR="$(mktemp -d /tmp/shoes-basic-proxy-perf.XXXXXX)"
  resolve_binaries
  start_http_target
  run_direct_baseline
  run_cases
  e2e_section "basic proxy perf passed"
}

main "$@"
