#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=scripts/e2e_ss_plugins_mihomo.sh
source "${ROOT_DIR}/scripts/e2e_ss_plugins_mihomo.sh"
trap - EXIT INT TERM

fail() {
  printf '[ss-plugin-provenance-test] FAIL: %s\n' "$*" >&2
  exit 1
}

# The regression case runs inside the Shoes checkout, which is itself a Git
# repository. An empty source path must not resolve that unrelated HEAD.
MIHOMO_SOURCE=""
output="$(log_mihomo_source_commit)"
[[ -z "${output}" ]] || fail "empty MIHOMO_SOURCE emitted provenance: ${output}"

fixture="$(mktemp -d /tmp/shoes-mihomo-source.XXXXXX)"
trap 'rm -rf -- "${fixture}"' EXIT
git -C "${fixture}" init --quiet
git -C "${fixture}" config user.email "shoes-test@example.invalid"
git -C "${fixture}" config user.name "Shoes Test"
printf 'fixture\n' >"${fixture}/README"
git -C "${fixture}" add README
git -C "${fixture}" commit --quiet -m fixture

MIHOMO_SOURCE="${fixture}"
revision="$(git -C "${fixture}" rev-parse --verify HEAD)"
output="$(log_mihomo_source_commit)"
expected="[ss-plugin-interop] Mihomo source commit: ${revision}"
[[ "${output}" == "${expected}" ]] \
  || fail "valid MIHOMO_SOURCE produced '${output}', expected '${expected}'"

printf '[ss-plugin-provenance-test] PASS\n'
