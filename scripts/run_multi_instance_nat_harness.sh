#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
NODE_BIN="${NODE_BIN:-${BUILD_DIR}/finalis-node}"
CLI_BIN="${CLI_BIN:-${BUILD_DIR}/finalis-cli}"
WORK_DIR="${WORK_DIR:-/tmp/finalis-multi-instance-harness-$(date +%s)}"

if [[ ! -x "${NODE_BIN}" ]]; then
  echo "[harness] missing node binary: ${NODE_BIN}" >&2
  exit 1
fi
if [[ ! -x "${CLI_BIN}" ]]; then
  echo "[harness] missing cli binary: ${CLI_BIN}" >&2
  exit 1
fi

BASE_PORT="${BASE_PORT:-$((28000 + RANDOM % 1500))}"
PORT_A="${PORT_A:-${BASE_PORT}}"
PORT_B="${PORT_B:-$((BASE_PORT + 1))}"
PORT_C="${PORT_C:-$((BASE_PORT + 2))}"
PORT_C_REBIND="${PORT_C_REBIND:-$((BASE_PORT + 3))}"
BOOTSTRAP_OUTBOUND_TARGET="${BOOTSTRAP_OUTBOUND_TARGET:-0}"
FOLLOWER_OUTBOUND_TARGET="${FOLLOWER_OUTBOUND_TARGET:-6}"

PIDS=()
NODE_A_DB="${WORK_DIR}/node-a"
NODE_B_DB="${WORK_DIR}/node-b"
NODE_C_DB="${WORK_DIR}/node-c"

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT

mkdir -p "${WORK_DIR}" "${NODE_A_DB}" "${NODE_B_DB}" "${NODE_C_DB}"

GENESIS_TEMPLATE="${WORK_DIR}/bootstrap-template-genesis.json"
cat > "${GENESIS_TEMPLATE}" <<'EOF'
{
  "version": 1,
  "network_name": "mainnet",
  "protocol_version": 1,
  "network_id_hex": "fe561911730912cced1e83bc273fab13",
  "magic": 1234567890,
  "genesis_time_unix": 1735689600,
  "initial_height": 0,
  "initial_validators": [],
  "initial_active_set_size": 0,
  "initial_committee_params": {
    "min_committee": 1,
    "max_committee": 128,
    "sizing_rule": "min(MAX_COMMITTEE,ACTIVE_SIZE)",
    "C": 1
  },
  "monetary_params_ref": "monetary-policy-7m-hard-cap",
  "seeds": [],
  "note": "single-node-bootstrap-template"
}
EOF

echo "[harness] work_dir=${WORK_DIR}"
echo "[harness] ports: A=${PORT_A} B=${PORT_B} C=${PORT_C} C_rebind=${PORT_C_REBIND}"
echo "[harness] outbound-targets: bootstrap=${BOOTSTRAP_OUTBOUND_TARGET} followers=${FOLLOWER_OUTBOUND_TARGET}"
echo "[harness] pass criteria:"
echo "  1) nodes B/C each reach >=2 healthy peers during steady state"
echo "  2) with C stopped, B still advances >=3 blocks and keeps >=1 healthy peer"
echo "  3) after C restarts on a new port, C catches to within 2 blocks of B and has >=1 healthy peer"

start_node() {
  local name="$1"
  local db="$2"
  local port="$3"
  local peers="$4"
  local outbound_target="$5"
  local log_file="${WORK_DIR}/${name}.log"

  local args=(
    "--db" "${db}"
    "--genesis" "${GENESIS_TEMPLATE}"
    "--allow-unsafe-genesis-override"
    "--bind" "127.0.0.1"
    "--port" "${port}"
    "--listen"
    "--no-dns-seeds"
    "--outbound-target" "${outbound_target}"
  )
  if [[ -n "${peers}" ]]; then
    args+=("--peers" "${peers}")
  fi

  "${NODE_BIN}" "${args[@]}" >"${log_file}" 2>&1 &
  local pid=$!
  PIDS+=("${pid}")
  echo "[harness] started ${name} pid=${pid} db=${db} port=${port}"
}

stop_node_by_db() {
  local db="$1"
  local new_pids=()
  for pid in "${PIDS[@]:-}"; do
    if ! kill -0 "${pid}" 2>/dev/null; then
      continue
    fi
    if tr '\0' ' ' <"/proc/${pid}/cmdline" 2>/dev/null | grep -Fq -- "--db ${db}"; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
      echo "[harness] stopped pid=${pid} db=${db}"
    else
      new_pids+=("${pid}")
    fi
  done
  PIDS=("${new_pids[@]}")
}

extract_field() {
  local db="$1"
  local field="$2"
  local out
  out="$("${CLI_BIN}" sync_doctor --db "${db}" --tail 120 2>/dev/null || true)"
  awk -F= -v key="${field}" '$1==key {print $2}' <<<"${out}" | tail -n1
}

tip_height() {
  local db="$1"
  local h
  h="$(extract_field "${db}" "local_height")"
  if [[ "${h:-}" =~ ^[0-9]+$ ]]; then
    echo "${h}"
    return 0
  fi
  # Fallback for older builds lacking sync_doctor/local_height.
  local out
  out="$("${CLI_BIN}" tip --db "${db}" 2>/dev/null || true)"
  awk -F'[ =]' '/^height=/{print $2}' <<<"${out}" | tail -n1
}

wait_height_at_least() {
  local db="$1"
  local target="$2"
  local timeout_s="$3"
  local start_ts
  start_ts="$(date +%s)"
  while true; do
    local h
    h="$(tip_height "${db}")"
    if [[ -n "${h}" && "${h}" =~ ^[0-9]+$ && "${h}" -ge "${target}" ]]; then
      return 0
    fi
    if (( "$(date +%s)" - start_ts > timeout_s )); then
      echo "[harness] timeout waiting db=${db} for height>=${target}; last_height=${h:-none}" >&2
      return 1
    fi
    sleep 1
  done
}

wait_catchup_within() {
  local lag_max="$1"
  local timeout_s="$2"
  local start_ts
  start_ts="$(date +%s)"
  while true; do
    local hb hc
    hb="$(tip_height "${NODE_B_DB}")"
    hc="$(tip_height "${NODE_C_DB}")"
    if [[ "${hb}" =~ ^[0-9]+$ && "${hc}" =~ ^[0-9]+$ ]]; then
      if (( hb >= hc )) && (( hb - hc <= lag_max )); then
        return 0
      fi
    fi
    if (( "$(date +%s)" - start_ts > timeout_s )); then
      echo "[harness] catchup timeout B=${hb:-none} C=${hc:-none} lag_max=${lag_max}" >&2
      return 1
    fi
    sleep 1
  done
}

start_node "node-a" "${NODE_A_DB}" "${PORT_A}" "" "${BOOTSTRAP_OUTBOUND_TARGET}"
sleep 2
start_node "node-b" "${NODE_B_DB}" "${PORT_B}" "127.0.0.1:${PORT_A}" "${FOLLOWER_OUTBOUND_TARGET}"
sleep 1
start_node "node-c" "${NODE_C_DB}" "${PORT_C}" "127.0.0.1:${PORT_A},127.0.0.1:${PORT_B}" "${FOLLOWER_OUTBOUND_TARGET}"

wait_height_at_least "${NODE_A_DB}" 12 150
wait_height_at_least "${NODE_B_DB}" 8 150
wait_height_at_least "${NODE_C_DB}" 8 150

healthy_b="$(extract_field "${NODE_B_DB}" "healthy_peer_count")"
healthy_c="$(extract_field "${NODE_C_DB}" "healthy_peer_count")"
if [[ ! "${healthy_b:-}" =~ ^[0-9]+$ || ! "${healthy_c:-}" =~ ^[0-9]+$ ]]; then
  echo "[harness] failed to read healthy peer counts (B=${healthy_b:-none} C=${healthy_c:-none})" >&2
  exit 2
fi
if (( healthy_b < 2 || healthy_c < 2 )); then
  echo "[harness] steady-state peer criterion failed: B=${healthy_b} C=${healthy_c}" >&2
  exit 2
fi
echo "[harness] steady-state peers ok: B=${healthy_b} C=${healthy_c}"

hb_before_churn="$(tip_height "${NODE_B_DB}")"
stop_node_by_db "${NODE_C_DB}"
sleep 20
hb_after_churn="$(tip_height "${NODE_B_DB}")"
healthy_b_churn="$(extract_field "${NODE_B_DB}" "healthy_peer_count")"
if [[ ! "${hb_before_churn:-}" =~ ^[0-9]+$ || ! "${hb_after_churn:-}" =~ ^[0-9]+$ ]]; then
  echo "[harness] failed to read B height across churn" >&2
  exit 3
fi
if (( hb_after_churn - hb_before_churn < 3 )); then
  echo "[harness] churn liveness failed: B advanced only $((hb_after_churn - hb_before_churn)) blocks" >&2
  exit 3
fi
if [[ ! "${healthy_b_churn:-}" =~ ^[0-9]+$ || "${healthy_b_churn}" -lt 1 ]]; then
  echo "[harness] churn peer criterion failed: B healthy peers=${healthy_b_churn:-none}" >&2
  exit 3
fi
echo "[harness] churn liveness ok: B advanced=$((hb_after_churn - hb_before_churn)) healthy=${healthy_b_churn}"

start_node "node-c-rebind" "${NODE_C_DB}" "${PORT_C_REBIND}" "127.0.0.1:${PORT_A},127.0.0.1:${PORT_B}" "${FOLLOWER_OUTBOUND_TARGET}"
wait_catchup_within 2 150
healthy_c_rebind="$(extract_field "${NODE_C_DB}" "healthy_peer_count")"
if [[ ! "${healthy_c_rebind:-}" =~ ^[0-9]+$ || "${healthy_c_rebind}" -lt 1 ]]; then
  echo "[harness] rebind criterion failed: C healthy peers=${healthy_c_rebind:-none}" >&2
  exit 4
fi

echo "[harness] PASS"
echo "[harness] final heights: A=$(tip_height "${NODE_A_DB}") B=$(tip_height "${NODE_B_DB}") C=$(tip_height "${NODE_C_DB}")"
echo "[harness] sync_doctor B:"
"${CLI_BIN}" sync_doctor --db "${NODE_B_DB}" --tail 80 || true
echo "[harness] sync_doctor C:"
"${CLI_BIN}" sync_doctor --db "${NODE_C_DB}" --tail 80 || true
