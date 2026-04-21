#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/build/finalis-tests"
LOG_DIR="${ROOT_DIR}/build/network-regression"
mkdir -p "${LOG_DIR}"

if [[ ! -x "${BIN}" ]]; then
  echo "missing test binary: ${BIN}" >&2
  exit 1
fi

echo "running network regression loop (10 runs)"
for i in $(seq 1 10); do
  LOG="${LOG_DIR}/run-${i}.log"
  echo "[${i}/10] ${BIN}"
  "${BIN}" >"${LOG}" 2>&1 || true
  if rg -q "\\[fail\\] test_testnet_seed_bootstrap_and_catchup|\\[fail\\] test_observer_reports_ok_on_two_lightservers" "${LOG}"; then
    echo "network regression failed on run ${i}" >&2
    rg "\\[fail\\] test_testnet_seed_bootstrap_and_catchup|\\[fail\\] test_observer_reports_ok_on_two_lightservers" "${LOG}" >&2 || true
    exit 1
  fi
done

echo "network regression passed (10/10)"
