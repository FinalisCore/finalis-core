#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS="${HARNESS:-${ROOT_DIR}/scripts/run_multi_instance_nat_harness.sh}"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
CLI_BIN="${CLI_BIN:-${BUILD_DIR}/finalis-cli}"
SOAK_DIR="${SOAK_DIR:-/tmp/finalis-soak-$(date +%s)}"

ITERATIONS="${ITERATIONS:-20}"
MIN_PASS_RATE_PCT="${MIN_PASS_RATE_PCT:-95}"
MAX_FAILS="${MAX_FAILS:-1}"
MIN_FINAL_HEALTHY_PEERS="${MIN_FINAL_HEALTHY_PEERS:-1}"
MAX_FINALIZED_LAG="${MAX_FINALIZED_LAG:-4}"
STOP_ON_FIRST_FAIL="${STOP_ON_FIRST_FAIL:-0}"

REPORT_JSON="${REPORT_JSON:-${SOAK_DIR}/soak_report.json}"
REPORT_MD="${REPORT_MD:-${SOAK_DIR}/soak_report.md}"

if [[ ! -x "${HARNESS}" ]]; then
  echo "[soak] missing harness script: ${HARNESS}" >&2
  exit 1
fi
if [[ ! -x "${CLI_BIN}" ]]; then
  echo "[soak] missing cli binary: ${CLI_BIN}" >&2
  exit 1
fi
if [[ ! "${ITERATIONS}" =~ ^[0-9]+$ ]] || (( ITERATIONS < 1 )); then
  echo "[soak] ITERATIONS must be >= 1" >&2
  exit 1
fi

mkdir -p "${SOAK_DIR}" "$(dirname "${REPORT_JSON}")" "$(dirname "${REPORT_MD}")"

timestamp_utc() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

extract_kv() {
  local text="$1"
  local key="$2"
  awk -F= -v k="${key}" '$1==k {print $2}' <<<"${text}" | tail -n1
}

read_sync_field() {
  local db="$1"
  local key="$2"
  local out
  out="$("${CLI_BIN}" sync_doctor --db "${db}" --tail 120 2>/dev/null || true)"
  extract_kv "${out}" "${key}"
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "${s}"
}

pass_count=0
fail_count=0
slo_violation_count=0
executed_runs=0

run_json_items=()
run_md_lines=()

overall_start_epoch="$(date +%s)"
overall_start_iso="$(timestamp_utc)"

echo "[soak] start=${overall_start_iso} iterations=${ITERATIONS} out=${SOAK_DIR}"
echo "[soak] thresholds: min_pass_rate=${MIN_PASS_RATE_PCT}% max_fails=${MAX_FAILS} min_final_healthy=${MIN_FINAL_HEALTHY_PEERS} max_finalized_lag=${MAX_FINALIZED_LAG}"

for ((i=1; i<=ITERATIONS; ++i)); do
  ((executed_runs+=1))
  run_dir="${SOAK_DIR}/run-${i}"
  run_log="${run_dir}.log"
  mkdir -p "${run_dir}"

  start_epoch="$(date +%s)"
  start_iso="$(timestamp_utc)"
  echo "[soak] run=${i}/${ITERATIONS} start=${start_iso}"

  set +e
  WORK_DIR="${run_dir}" "${HARNESS}" >"${run_log}" 2>&1
  rc=$?
  set -e

  end_epoch="$(date +%s)"
  end_iso="$(timestamp_utc)"
  dur=$((end_epoch - start_epoch))

  stage="ok"
  case "${rc}" in
    0) stage="ok" ;;
    2) stage="steady_state_peer_criterion" ;;
    3) stage="churn_liveness_criterion" ;;
    4) stage="rebind_catchup_criterion" ;;
    *) stage="harness_runtime_error" ;;
  esac

  final_healthy_b=""
  final_healthy_c=""
  final_lag_b=""
  readiness_codes_b=""
  run_slo_ok=1
  run_slo_notes=()

  if (( rc == 0 )); then
    final_healthy_b="$(read_sync_field "${run_dir}/node-b" "healthy_peer_count")"
    final_healthy_c="$(read_sync_field "${run_dir}/node-c" "healthy_peer_count")"
    final_lag_b="$(read_sync_field "${run_dir}/node-b" "finalized_lag")"
    readiness_codes_b="$(read_sync_field "${run_dir}/node-b" "readiness_failure_codes_csv")"

    if [[ ! "${final_healthy_b:-}" =~ ^[0-9]+$ ]] || (( final_healthy_b < MIN_FINAL_HEALTHY_PEERS )); then
      run_slo_ok=0
      run_slo_notes+=("node_b_healthy_peer_below_threshold")
    fi
    if [[ ! "${final_healthy_c:-}" =~ ^[0-9]+$ ]] || (( final_healthy_c < MIN_FINAL_HEALTHY_PEERS )); then
      run_slo_ok=0
      run_slo_notes+=("node_c_healthy_peer_below_threshold")
    fi
    if [[ "${final_lag_b:-}" =~ ^[0-9]+$ ]] && (( final_lag_b > MAX_FINALIZED_LAG )); then
      run_slo_ok=0
      run_slo_notes+=("node_b_finalized_lag_above_threshold")
    fi
    if [[ -n "${readiness_codes_b}" ]] && [[ "${readiness_codes_b}" == *"chain_id_mismatch"* ]]; then
      run_slo_ok=0
      run_slo_notes+=("node_b_chain_id_mismatch")
    fi
  fi

  if (( rc == 0 && run_slo_ok == 1 )); then
    ((pass_count+=1))
    echo "[soak] run=${i} status=PASS duration=${dur}s"
  else
    ((fail_count+=1))
    if (( rc == 0 && run_slo_ok == 0 )); then
      ((slo_violation_count+=1))
      stage="slo_violation"
    fi
    echo "[soak] run=${i} status=FAIL rc=${rc} stage=${stage} duration=${dur}s"
    if (( STOP_ON_FIRST_FAIL == 1 )); then
      echo "[soak] stop_on_first_fail=1; stopping early"
      ITERATIONS="${i}"
    fi
  fi

  notes_csv="none"
  failure_reason=""
  if ((${#run_slo_notes[@]} > 0)); then
    notes_csv="$(IFS=,; echo "${run_slo_notes[*]}")"
  fi
  if (( rc != 0 )); then
    failure_reason="$(tail -n 1 "${run_log}" 2>/dev/null || true)"
  fi

  run_json_items+=("{\"run\":${i},\"start\":\"${start_iso}\",\"end\":\"${end_iso}\",\"duration_seconds\":${dur},\"harness_exit_code\":${rc},\"stage\":\"${stage}\",\"slo_ok\":$([[ ${run_slo_ok} -eq 1 ]] && echo true || echo false),\"node_b_healthy_peer_count\":${final_healthy_b:-null},\"node_c_healthy_peer_count\":${final_healthy_c:-null},\"node_b_finalized_lag\":${final_lag_b:-null},\"node_b_readiness_failure_codes_csv\":\"$(json_escape "${readiness_codes_b}")\",\"slo_notes\":\"$(json_escape "${notes_csv}")\",\"failure_reason\":\"$(json_escape "${failure_reason}")\",\"log_path\":\"$(json_escape "${run_log}")\"}")
  run_md_lines+=("| ${i} | ${stage} | ${rc} | ${dur}s | ${final_healthy_b:-n/a} | ${final_healthy_c:-n/a} | ${final_lag_b:-n/a} | ${notes_csv} | ${failure_reason:-none} |")

  if (( STOP_ON_FIRST_FAIL == 1 && fail_count > 0 )); then
    break
  fi
done

overall_end_epoch="$(date +%s)"
overall_end_iso="$(timestamp_utc)"
overall_dur=$((overall_end_epoch - overall_start_epoch))

pass_rate_pct="$(awk -v p="${pass_count}" -v t="${executed_runs}" 'BEGIN { if (t==0) { print "0.00" } else { printf "%.2f", (100.0*p)/t } }')"

overall_ok=1
if (( fail_count > MAX_FAILS )); then overall_ok=0; fi
pass_rate_ok="$(awk -v r="${pass_rate_pct}" -v min="${MIN_PASS_RATE_PCT}" 'BEGIN { if (r + 0.0 + 1e-9 >= min + 0.0) print 1; else print 0; }')"
if (( pass_rate_ok == 0 )); then overall_ok=0; fi

runs_json="$(IFS=,; echo "${run_json_items[*]}")"
cat > "${REPORT_JSON}" <<EOF
{
  "started_at": "${overall_start_iso}",
  "ended_at": "${overall_end_iso}",
  "duration_seconds": ${overall_dur},
  "iterations": ${executed_runs},
  "pass_count": ${pass_count},
  "fail_count": ${fail_count},
  "slo_violation_count": ${slo_violation_count},
  "pass_rate_pct": ${pass_rate_pct},
  "thresholds": {
    "min_pass_rate_pct": ${MIN_PASS_RATE_PCT},
    "max_fails": ${MAX_FAILS},
    "min_final_healthy_peers": ${MIN_FINAL_HEALTHY_PEERS},
    "max_finalized_lag": ${MAX_FINALIZED_LAG}
  },
  "overall_ok": $([[ ${overall_ok} -eq 1 ]] && echo true || echo false),
  "runs": [${runs_json}]
}
EOF

{
  echo "# Multi-Instance NAT Soak Report"
  echo
  echo "- started_at: ${overall_start_iso}"
  echo "- ended_at: ${overall_end_iso}"
  echo "- duration_seconds: ${overall_dur}"
  echo "- iterations: ${executed_runs}"
  echo "- pass_count: ${pass_count}"
  echo "- fail_count: ${fail_count}"
  echo "- slo_violation_count: ${slo_violation_count}"
  echo "- pass_rate_pct: ${pass_rate_pct}"
  echo "- overall_ok: $([[ ${overall_ok} -eq 1 ]] && echo yes || echo no)"
  echo
  echo "## Thresholds"
  echo
  echo "- min_pass_rate_pct: ${MIN_PASS_RATE_PCT}"
  echo "- max_fails: ${MAX_FAILS}"
  echo "- min_final_healthy_peers: ${MIN_FINAL_HEALTHY_PEERS}"
  echo "- max_finalized_lag: ${MAX_FINALIZED_LAG}"
  echo
  echo "## Runs"
  echo
  echo "| run | stage | rc | duration | node_b_healthy | node_c_healthy | node_b_lag | notes | failure_reason |"
  echo "| --- | ----- | -- | -------- | -------------- | -------------- | ---------- | ----- | -------------- |"
  for line in "${run_md_lines[@]}"; do
    echo "${line}"
  done
} > "${REPORT_MD}"

echo "[soak] report_json=${REPORT_JSON}"
echo "[soak] report_md=${REPORT_MD}"
echo "[soak] summary iterations=${executed_runs} pass=${pass_count} fail=${fail_count} pass_rate=${pass_rate_pct}% overall_ok=$([[ ${overall_ok} -eq 1 ]] && echo yes || echo no)"

if (( overall_ok == 1 )); then
  exit 0
fi
exit 2
