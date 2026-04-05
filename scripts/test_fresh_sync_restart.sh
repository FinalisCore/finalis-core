#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/build/finalis-tests"

if [[ ! -x "${BIN}" ]]; then
  echo "missing binary: ${BIN}" >&2
  echo "build it first with: cmake --build build --target finalis-tests -j\$(nproc)" >&2
  exit 1
fi

run_case() {
  local name="$1"
  echo
  echo "==> ${name}"
  FINALIS_TEST_FILTER="${name}" "${BIN}"
}

echo "Finalis fresh sync / restart reliability proof"
echo "binary: ${BIN}"

run_case test_second_fresh_node_adopts_bootstrap_validator_and_syncs
run_case test_adopted_bootstrap_identity_persists_across_restart_before_first_block
run_case test_restart_determinism_and_continued_finalization
run_case test_single_validator_restart_recovers_missing_required_epoch_committee_state

echo
echo "All fresh sync / restart proof checks passed."
echo "For repeated restart stress, also run:"
echo "  scripts/run_restart_regression.sh"
