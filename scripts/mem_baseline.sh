#!/usr/bin/env bash
set -Eeuo pipefail

# Memory baseline for the shoes proxy core.
#
# Phases:
#   idle   - warm process, measure steady-state RSS + jemalloc heap
#   churn  - repeated short-lived connection cycles, watch peak RSS
#   quiet  - no load; verify RSS / jemalloc "allocated" fall back
#   soak   - sustained concurrent load; measure RSS growth rate (slope)
#
# Emits one JSON report with VmRSS trend + jemalloc allocated/retained so a
# real heap leak (allocated keeps growing) is distinguishable from allocator
# retention (only retained grows).
#
# Usage:
#   scripts/mem_baseline.sh
#
# Env overrides:
#   MEM_BIND_HOST MEM_TARGET_PORT MEM_PROXY_PORT MEM_PAYLOAD_KIB
#   MEM_CHURN_BATCHES MEM_BATCH_REQS MEM_CONCURRENCY
#   MEM_IDLE_SECS MEM_QUIET_SECS MEM_SOAK_SECS MEM_SAMPLE_INTERVAL_SECS
#   MEM_PROXY_PROTOCOL (socks|http) MEM_BUILD_RELEASE MEM_OUTPUT

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/scripts"

# shellcheck source=scripts/v2board_e2e_common.sh
source "${SCRIPT_DIR}/v2board_e2e_common.sh"

trap e2e_on_error ERR

MEM_BIND_HOST="${MEM_BIND_HOST:-127.0.0.1}"
MEM_HTTP_TARGET_PORT="${MEM_HTTP_TARGET_PORT:-19309}"
MEM_PROXY_PORT="${MEM_PROXY_PORT:-19310}"
MEM_PAYLOAD_KIB="${MEM_PAYLOAD_KIB:-64}"
MEM_PROXY_PROTOCOL="${MEM_PROXY_PROTOCOL:-socks}"
MEM_CHURN_BATCHES="${MEM_CHURN_BATCHES:-10}"
MEM_BATCH_REQS="${MEM_BATCH_REQS:-200}"
MEM_CONCURRENCY="${MEM_CONCURRENCY:-50}"
MEM_IDLE_SECS="${MEM_IDLE_SECS:-15}"
MEM_QUIET_SECS="${MEM_QUIET_SECS:-20}"
MEM_SOAK_SECS="${MEM_SOAK_SECS:-60}"
MEM_SAMPLE_INTERVAL_SECS="${MEM_SAMPLE_INTERVAL_SECS:-2}"
MEM_ALLOC_STATS_INTERVAL_SECS="${MEM_ALLOC_STATS_INTERVAL_SECS:-5}"
MEM_BUILD_RELEASE="${MEM_BUILD_RELEASE:-1}"
MEM_OUTPUT="${MEM_OUTPUT:-}"
MEM_TMP_DIR="${MEM_TMP_DIR:-}"

TMP_DIR=""
HTTP_PID=""
PROXY_PID=""
SAMPLER_PID=""

cleanup() {
  local status=$?
  set +e
  if [[ -n "${SAMPLER_PID}" ]] && kill -0 "${SAMPLER_PID}" 2>/dev/null; then
    kill "${SAMPLER_PID}" 2>/dev/null || true
    wait "${SAMPLER_PID}" 2>/dev/null || true
  fi
  if [[ -n "${PROXY_PID}" ]] && kill -0 "${PROXY_PID}" 2>/dev/null; then
    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true
  fi
  if [[ -n "${HTTP_PID}" ]] && kill -0 "${HTTP_PID}" 2>/dev/null; then
    kill "${HTTP_PID}" 2>/dev/null || true
    wait "${HTTP_PID}" 2>/dev/null || true
  fi
  if [[ -n "${MEM_TMP_DIR}" ]]; then
    e2e_log "mem baseline artifacts kept at: ${MEM_TMP_DIR}"
  elif [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    rm -rf "${TMP_DIR}"
  fi
  exit "${status}"
}

trap cleanup EXIT

resolve_binaries() {
  e2e_require_command cargo
  e2e_require_command python3
  e2e_require_command ss
  e2e_require_command awk

  if e2e_bool "${MEM_BUILD_RELEASE}"; then
    SERVER_BIN="${SERVER_BIN:-${ROOT_DIR}/target/release/shoes-basic-proxy-e2e-server}"
    CLIENT_BIN="${CLIENT_BIN:-${ROOT_DIR}/target/release/shoes-basic-proxy-perf-client}"
    TARGET_BIN="${TARGET_BIN:-${ROOT_DIR}/target/release/shoes-static-http-perf-server}"
    e2e_run cargo build \
      --manifest-path "${ROOT_DIR}/Cargo.toml" \
      --release \
      --features e2e-client,internal-bench \
      --bin shoes-basic-proxy-e2e-server \
      --bin shoes-basic-proxy-perf-client \
      --bin shoes-static-http-perf-server
  else
    SERVER_BIN="${SERVER_BIN:-${ROOT_DIR}/target/debug/shoes-basic-proxy-e2e-server}"
    CLIENT_BIN="${CLIENT_BIN:-${ROOT_DIR}/target/debug/shoes-basic-proxy-perf-client}"
    TARGET_BIN="${TARGET_BIN:-${ROOT_DIR}/target/debug/shoes-static-http-perf-server}"
    e2e_run cargo build \
      --manifest-path "${ROOT_DIR}/Cargo.toml" \
      --features e2e-client,internal-bench \
      --bin shoes-basic-proxy-e2e-server \
      --bin shoes-basic-proxy-perf-client \
      --bin shoes-static-http-perf-server
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

start_target() {
  e2e_section "http target"
  e2e_assert_port_free "${MEM_HTTP_TARGET_PORT}" "mem http target"
  "${TARGET_BIN}" \
    --listen "${MEM_BIND_HOST}:${MEM_HTTP_TARGET_PORT}" \
    --payload-kib "${MEM_PAYLOAD_KIB}" \
    >"${TMP_DIR}/http-target.log" 2>&1 &
  HTTP_PID=$!
  wait_for_tcp_port "${MEM_HTTP_TARGET_PORT}" "mem http target"
}

start_proxy() {
  e2e_section "mem proxy (${MEM_PROXY_PROTOCOL})"
  e2e_assert_port_free "${MEM_PROXY_PORT}" "mem proxy"
  SHOES_ALLOCATOR_STATS_INTERVAL_SECS="${MEM_ALLOC_STATS_INTERVAL_SECS}" \
  RUST_LOG="${MEM_RUST_LOG:-info}" \
  "${SERVER_BIN}" \
    --listen "${MEM_BIND_HOST}:${MEM_PROXY_PORT}" \
    --protocol "${MEM_PROXY_PROTOCOL}" \
    >"${TMP_DIR}/proxy.log" 2>&1 &
  PROXY_PID=$!
  wait_for_tcp_port "${MEM_PROXY_PORT}" "mem proxy"
}

stop_proxy() {
  if [[ -n "${PROXY_PID}" ]] && kill -0 "${PROXY_PID}" 2>/dev/null; then
    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true
  fi
  PROXY_PID=""
}

rss_kb() {
  awk '/VmRSS:/ {print $2}' "/proc/${PROXY_PID}/status" 2>/dev/null || printf '0'
}

run_churn_batch() {
  "${CLIENT_BIN}" \
    --proxy-host "${MEM_BIND_HOST}" \
    --proxy-port "${MEM_PROXY_PORT}" \
    --protocol "${MEM_PROXY_PROTOCOL}" \
    --target-host "${MEM_BIND_HOST}" \
    --target-port "${MEM_HTTP_TARGET_PORT}" \
    --path /payload.bin \
    --requests "${MEM_BATCH_REQS}" \
    --concurrency "${MEM_CONCURRENCY}" \
    >"${TMP_DIR}/churn-client.log" 2>&1
}

# Sample RSS + jemalloc counters into a pipe-separated time series file.
start_sampler() {
  local output="$1"
  : >"${output}"
  (
    while kill -0 "${PROXY_PID}" 2>/dev/null; do
      printf '%s %s\n' "$(date +%s)" "$(rss_kb)" >>"${output}"
      sleep "${MEM_SAMPLE_INTERVAL_SECS}"
    done
  ) &
  SAMPLER_PID=$!
}

main() {
  local tmp_dir
  local series_file
  local metric

  if [[ -n "${MEM_TMP_DIR}" ]]; then
    tmp_dir="${MEM_TMP_DIR}"
    mkdir -p "${tmp_dir}"
  else
    tmp_dir="$(mktemp -d)"
  fi
  TMP_DIR="${tmp_dir}"
  series_file="${TMP_DIR}/rss.series"

  resolve_binaries
  start_target
  start_proxy
  start_sampler "${series_file}"

  e2e_section "phase: idle (${MEM_IDLE_SECS}s)"
  sleep "${MEM_IDLE_SECS}"

  e2e_section "phase: churn (${MEM_CHURN_BATCHES} batches x ${MEM_BATCH_REQS})"
  for _ in $(seq 1 "${MEM_CHURN_BATCHES}"); do
    run_churn_batch
  done

  e2e_section "phase: quiet (${MEM_QUIET_SECS}s, verify fallback)"
  sleep "${MEM_QUIET_SECS}"

  e2e_section "phase: soak (${MEM_SOAK_SECS}s sustained)"
  local soak_secs="${MEM_SOAK_SECS}"
  local start_ts
  start_ts="$(date +%s)"
  (
    while true; do
      run_churn_batch || true
      if (( $(date +%s) - start_ts >= soak_secs )); then
        break
      fi
    done
  ) &
  local soak_pid=$!
  sleep "${soak_secs}"
  kill "${soak_pid}" 2>/dev/null || true
  wait "${soak_pid}" 2>/dev/null || true

  e2e_section "phase: final quiet (${MEM_QUIET_SECS}s)"
  sleep "${MEM_QUIET_SECS}"

  if [[ -n "${SAMPLER_PID}" ]] && kill -0 "${SAMPLER_PID}" 2>/dev/null; then
    kill "${SAMPLER_PID}" 2>/dev/null || true
    wait "${SAMPLER_PID}" 2>/dev/null || true
    SAMPLER_PID=""
  fi

  stop_proxy

  e2e_section "analysis"
  metric="$(
    SERIES="${series_file}" \
    PROXY_LOG="${TMP_DIR}/proxy.log" \
    IDLE_SECS="${MEM_IDLE_SECS}" \
    QUIET_SECS="${MEM_QUIET_SECS}" \
    SOAK_SECS="${MEM_SOAK_SECS}" \
    CHURN_BATCHES="${MEM_CHURN_BATCHES}" \
    BATCH_REQS="${MEM_BATCH_REQS}" \
    SAMPLE_INTERVAL="${MEM_SAMPLE_INTERVAL_SECS}" \
    python3 <<'PY'
import json
import os
import re
import statistics

series = []
with open(os.environ["SERIES"]) as fh:
    for line in fh:
        parts = line.split()
        if len(parts) == 2:
            series.append((int(parts[0]), int(parts[1])))

idle_secs = int(os.environ["IDLE_SECS"])
quiet_secs = int(os.environ["QUIET_SECS"])
soak_secs = int(os.environ["SOAK_SECS"])
batches = int(os.environ["CHURN_BATCHES"])
batch_reqs = int(os.environ["BATCH_REQS"])

jemalloc = []
with open(os.environ["PROXY_LOG"]) as fh:
    for line in fh:
        m = re.search(
            r"jemalloc bytes: allocated=(\d+) active=(\d+) resident=(\d+) mapped=(\d+) retained=(\d+)",
            line,
        )
        if m:
            jemalloc.append(tuple(int(x) for x in m.groups()))

t0 = series[0][0] if series else 0
def phase_slice(name, start_rel, end_rel):
    lo = t0 + start_rel
    hi = t0 + end_rel
    return [rss for (ts, rss) in series if lo <= ts <= hi]

idle_rss = phase_slice("idle", 0, idle_secs)
churn_rss = phase_slice("churn", idle_secs, idle_secs + quiet_secs + soak_secs)
churn_start = idle_secs
churn_end = idle_secs + quiet_secs + soak_secs
quiet1_rss = phase_slice("quiet1", idle_secs, idle_secs + quiet_secs)
soak_rss = phase_slice("soak", idle_secs + quiet_secs, idle_secs + quiet_secs + soak_secs)
final_rss = phase_slice("final", idle_secs + quiet_secs + soak_secs, idle_secs + 2 * quiet_secs + soak_secs)

report = {
    "start_rss_kb": series[0][1] if series else 0,
    "idle_end_rss_kb": idle_rss[-1] if idle_rss else 0,
    "idle_rss_median_kb": int(statistics.median(idle_rss)) if idle_rss else 0,
    "churn_peak_rss_kb": max(churn_rss) if churn_rss else 0,
    "quiet1_end_rss_kb": quiet1_rss[-1] if quiet1_rss else 0,
    "soak_end_rss_kb": soak_rss[-1] if soak_rss else 0,
    "final_quiet_rss_kb": final_rss[-1] if final_rss else 0,
    "churn_overhead_kb": (max(churn_rss) - idle_rss[-1]) if idle_rss and churn_rss else 0,
    "fallback_after_churn_kb": (quiet1_rss[-1] - idle_rss[-1]) if idle_rss and quiet1_rss else 0,
    "connections_exercised": batches * batch_reqs,
}

# A real heap leak keeps RSS high after load stops. If RSS returns toward the
# pre-load level during the final quiet phase, the load-time growth is
# transient (stacks/arenas), not a leak.
if final_rss and idle_rss and soak_rss:
    report["soak_to_final_fallback_kb"] = soak_rss[-1] - final_rss[-1]
    report["final_over_idle_rss_kb"] = final_rss[-1] - idle_rss[-1]
else:
    report["soak_to_final_fallback_kb"] = None
    report["final_over_idle_rss_kb"] = None

# RSS slope over the second half of the soak phase (kB per minute): the leak
# indicator. The first half is excluded because it contains the load ramp.
if len(soak_rss) >= 4:
    half = len(soak_rss) // 2
    soak_rss = soak_rss[half:]
    n = len(soak_rss)
    xs = list(range(n))
    mean_x = sum(xs) / n
    mean_y = sum(soak_rss) / n
    slope_per_sample = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, soak_rss)) / max(
        sum((x - mean_x) ** 2 for x in xs), 1e-9
    )
    samples_per_min = 60.0 / float(os.environ.get("SAMPLE_INTERVAL", 2))
    report["soak_rss_growth_kb_per_min"] = round(slope_per_sample * samples_per_min, 1)
else:
    report["soak_rss_growth_kb_per_min"] = None

if jemalloc:
    report["jemalloc_start_allocated_kb"] = jemalloc[0][0] // 1024
    report["jemalloc_end_allocated_kb"] = jemalloc[-1][0] // 1024
    report["jemalloc_start_retained_kb"] = jemalloc[0][4] // 1024
    report["jemalloc_end_retained_kb"] = jemalloc[-1][4] // 1024
    report["jemalloc_allocated_delta_kb"] = (jemalloc[-1][0] - jemalloc[0][0]) // 1024
    report["jemalloc_samples"] = len(jemalloc)

print(json.dumps(report, separators=(",", ":"), sort_keys=True))
PY
  )"

  if [[ -n "${MEM_OUTPUT}" ]]; then
    printf '%s\n' "${metric}" | tee -a "${MEM_OUTPUT}"
  else
    printf '%s\n' "${metric}"
  fi
  e2e_log "mem baseline finished"
}

main
