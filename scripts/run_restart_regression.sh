#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/build/finalis-tests"
RUNS="${RUNS:-50}"
LOG_DIR="${LOG_DIR:-/tmp/finalis-restart-regression}"

if [[ ! -x "${BIN}" ]]; then
  echo "missing binary: ${BIN}" >&2
  exit 1
fi

mkdir -p "${LOG_DIR}"

echo "running restart determinism regression (${RUNS} runs)"
for i in $(seq 1 "${RUNS}"); do
  echo "[${i}/${RUNS}]"
  FINALIS_TEST_FILTER=test_restart_determinism_and_continued_finalization \
  FINALIS_RESTART_DEBUG=1 \
    "${BIN}" >"${LOG_DIR}/run-${i}.log" 2>&1
done
echo "restart determinism regression passed (${RUNS}/${RUNS})"
