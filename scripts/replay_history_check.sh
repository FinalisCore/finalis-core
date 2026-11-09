#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Replays a recorded chain from genesis with the current build and checks it reaches the
# recorded tip. Catches consensus changes that reject old blocks (v2.2.13 rejected testnet-3
# block 37 on fresh sync; running nodes never noticed because they never re-validate history).
#
# The snapshot carries every transition and certificate; the node imports it, then starts
# offline with --no-fast-start, which re-derives the whole state from genesis (load_state,
# "availability-state-ready source=canonical-replay") instead of trusting the imported rows.
#
# Usage: scripts/replay_history_check.sh <build_dir> <snapshot.bin> <expected_height> <expected_hash_hex> [timeout_s]

set -euo pipefail

BUILD_DIR="${1:?build dir}"
SNAPSHOT="${2:?snapshot file}"
EXPECTED_HEIGHT="${3:?expected height}"
EXPECTED_HASH="${4:?expected transition hash (hex)}"
TIMEOUT_S="${5:-3600}"

NODE="${BUILD_DIR}/finalis-node"
CLI="${BUILD_DIR}/finalis-cli"
for bin in "${NODE}" "${CLI}"; do
  [[ -x "${bin}" ]] || { echo "missing ${bin}" >&2; exit 2; }
done

WORK="$(mktemp -d)"
NODE_PID=""
cleanup() {
  if [[ -n "${NODE_PID}" ]] && kill -0 "${NODE_PID}" 2>/dev/null; then
    kill "${NODE_PID}" 2>/dev/null || true
    for _ in $(seq 1 120); do kill -0 "${NODE_PID}" 2>/dev/null || break; sleep 1; done
    kill -9 "${NODE_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORK}"
}
trap cleanup EXIT

LOG="${WORK}/node.log"
fail() {
  echo "REPLAY FAILED: $*" >&2
  echo "--- last node log lines ---" >&2
  tail -n 60 "${LOG}" >&2 || true
  exit 1
}

"${CLI}" --testnet fast_sync --db "${WORK}/db" --snapshot "${SNAPSHOT}" --force

"${NODE}" --testnet --db "${WORK}/db" --bind 127.0.0.1 --port "${FINALIS_REPLAY_PORT:-39599}" --disable-p2p --no-fast-start >"${LOG}" 2>&1 &
NODE_PID=$!

deadline=$((SECONDS + TIMEOUT_S))
while :; do
  if grep -q -E 'node init failed|load_state failed' "${LOG}"; then
    fail "node rejected recorded history"
  fi
  if ! kill -0 "${NODE_PID}" 2>/dev/null; then
    fail "node exited during replay"
  fi
  if grep -q 'startup-progress phase=load-state-done' "${LOG}" && grep -q -E '^testnet h=' "${LOG}"; then
    break
  fi
  (( SECONDS < deadline )) || fail "timeout after ${TIMEOUT_S}s"
  sleep 5
done

grep -q 'source=canonical-replay' "${LOG}" || fail "state was not re-derived from genesis (fast start used?)"
status_line="$(grep -E '^testnet h=' "${LOG}" | head -n 1)"
height="$(sed -n 's/^testnet h=\([0-9]*\).*/\1/p' <<<"${status_line}")"
short_hash="$(sed -n 's/.* transition=\([0-9a-f]*\).*/\1/p' <<<"${status_line}")"
[[ "${height}" == "${EXPECTED_HEIGHT}" ]] || fail "replayed to height ${height}, expected ${EXPECTED_HEIGHT}"
[[ -n "${short_hash}" && "${EXPECTED_HASH}" == "${short_hash}"* ]] || fail "tip ${short_hash} does not match ${EXPECTED_HASH}"

echo "replay ok: height=${height} transition=${short_hash} (${SECONDS}s)"
