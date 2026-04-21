#!/usr/bin/env bash
# SPDX-License-Identifier: MIT


set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/exchange_sanity_test.sh --rpc <url> [--rpc2 <url>] [--txid <known-finalized-txid>] [--wait-seconds <n>]

Environment fallbacks:
  FINALIS_RPC_URL
  FINALIS_RPC_URL_2
  FINALIS_KNOWN_FINALIZED_TXID

Checks:
  - get_status on the primary endpoint
  - finalized-state fields are present and parseable
  - chain identity fields are present and internally sane
  - finalized height does not regress across two polls
  - optional endpoint agreement on finalized height/hash
  - optional get_tx_status check for a known finalized txid
EOF
}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

pass() {
  echo "PASS: $*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

rpc_url="${FINALIS_RPC_URL:-}"
rpc2_url="${FINALIS_RPC_URL_2:-}"
txid="${FINALIS_KNOWN_FINALIZED_TXID:-}"
wait_seconds=3

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc)
      [[ $# -ge 2 ]] || fail "--rpc requires a value"
      rpc_url="$2"
      shift 2
      ;;
    --rpc2)
      [[ $# -ge 2 ]] || fail "--rpc2 requires a value"
      rpc2_url="$2"
      shift 2
      ;;
    --txid)
      [[ $# -ge 2 ]] || fail "--txid requires a value"
      txid="$2"
      shift 2
      ;;
    --wait-seconds)
      [[ $# -ge 2 ]] || fail "--wait-seconds requires a value"
      wait_seconds="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n "$rpc_url" ]] || fail "primary RPC URL is required via --rpc or FINALIS_RPC_URL"
[[ "$wait_seconds" =~ ^[0-9]+$ ]] || fail "--wait-seconds must be a non-negative integer"

need_cmd curl
need_cmd jq

rpc_call() {
  local url="$1"
  local body="$2"
  curl --silent --show-error --fail \
    -H 'Content-Type: application/json' \
    --data "$body" \
    "$url"
}

extract_status_summary() {
  local json="$1"
  printf '%s' "$json" | jq -e -r '
    .result as $r
    | [
        ($r.network_name // empty),
        ($r.network_id // empty),
        ($r.genesis_hash // empty),
        ($r.chain_id_ok | tostring),
        ($r.version // empty),
        ($r.finalized_height | tostring),
        ($r.finalized_transition_hash // empty),
        ($r.sync.mode // empty)
      ]
    | @tsv
  '
}

echo "Checking primary endpoint: $rpc_url"
status_body_1="$(rpc_call "$rpc_url" '{"jsonrpc":"2.0","id":1,"method":"get_status","params":{}}')" || fail "get_status failed on primary endpoint"
status_summary_1="$(extract_status_summary "$status_body_1")" || fail "primary get_status response is missing finalized-state fields"

IFS=$'\t' read -r network_name network_id genesis_hash chain_id_ok version finalized_height_1 finalized_transition_hash_1 sync_mode_1 <<<"$status_summary_1"

[[ -n "$network_name" ]] || fail "primary endpoint returned empty network_name"
[[ -n "$network_id" && ${#network_id} -eq 32 ]] || fail "primary endpoint returned invalid network_id"
[[ -n "$genesis_hash" && ${#genesis_hash} -eq 64 ]] || fail "primary endpoint returned invalid genesis_hash"
[[ "$chain_id_ok" == "true" ]] || fail "primary endpoint reported chain_id_ok=false"
[[ -n "$version" ]] || fail "primary endpoint returned empty version"
[[ "$finalized_height_1" =~ ^[0-9]+$ ]] || fail "primary endpoint returned invalid finalized_height"
[[ -n "$finalized_transition_hash_1" && ${#finalized_transition_hash_1} -eq 64 ]] || fail "primary endpoint returned invalid finalized_transition_hash"
[[ "$sync_mode_1" == "finalized_only" ]] || fail "primary endpoint sync.mode is not finalized_only"

pass "primary get_status returned finalized-only state for network=$network_name version=$version height=$finalized_height_1 chain_id_ok=true"

if [[ "$wait_seconds" -gt 0 ]]; then
  sleep "$wait_seconds"
fi

status_body_2="$(rpc_call "$rpc_url" '{"jsonrpc":"2.0","id":2,"method":"get_status","params":{}}')" || fail "second get_status failed on primary endpoint"
status_summary_2="$(extract_status_summary "$status_body_2")" || fail "second get_status response is missing finalized-state fields"
IFS=$'\t' read -r _ _ _ chain_id_ok_2 _ finalized_height_2 finalized_transition_hash_2 _ <<<"$status_summary_2"

[[ "$chain_id_ok_2" == "true" ]] || fail "second get_status reported chain_id_ok=false"
[[ "$finalized_height_2" =~ ^[0-9]+$ ]] || fail "second finalized_height is invalid"
if (( finalized_height_2 < finalized_height_1 )); then
  fail "finalized height regressed on primary endpoint: $finalized_height_1 -> $finalized_height_2"
fi
pass "primary finalized height did not regress across two polls ($finalized_height_1 -> $finalized_height_2)"

if [[ -n "$rpc2_url" ]]; then
  echo "Checking secondary endpoint: $rpc2_url"
  status_body_3="$(rpc_call "$rpc2_url" '{"jsonrpc":"2.0","id":3,"method":"get_status","params":{}}')" || fail "get_status failed on secondary endpoint"
  status_summary_3="$(extract_status_summary "$status_body_3")" || fail "secondary get_status response is missing finalized-state fields"
  IFS=$'\t' read -r network_name_2 network_id_2 genesis_hash_2 chain_id_ok_3 version_2 finalized_height_3 finalized_transition_hash_3 sync_mode_2 <<<"$status_summary_3"

  [[ "$sync_mode_2" == "finalized_only" ]] || fail "secondary endpoint sync.mode is not finalized_only"
  [[ "$network_name_2" == "$network_name" ]] || fail "endpoint network mismatch: $network_name vs $network_name_2"
  [[ "$network_id_2" == "$network_id" ]] || fail "endpoint network_id mismatch: $network_id vs $network_id_2"
  [[ "$genesis_hash_2" == "$genesis_hash" ]] || fail "endpoint genesis_hash mismatch: $genesis_hash vs $genesis_hash_2"
  [[ "$chain_id_ok_3" == "true" ]] || fail "secondary endpoint reported chain_id_ok=false"
  [[ "$finalized_height_3" == "$finalized_height_2" ]] || fail "endpoint finalized height mismatch: $finalized_height_2 vs $finalized_height_3"
  [[ "$finalized_transition_hash_3" == "$finalized_transition_hash_2" ]] || fail "endpoint finalized transition hash mismatch at compared height"

  pass "primary and secondary endpoints agree on finalized height/transition hash at height=$finalized_height_2"
  if [[ "$version_2" != "$version" ]]; then
    echo "WARN: endpoint version mismatch: primary=$version secondary=$version_2"
  else
    pass "primary and secondary endpoints report the same version: $version"
  fi
fi

if [[ -n "$txid" ]]; then
  [[ "$txid" =~ ^[0-9a-fA-F]{64}$ ]] || fail "known txid must be 64 hex characters"
  echo "Checking finalized tx status for txid: $txid"
  tx_body="$(rpc_call "$rpc_url" "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"get_tx_status\",\"params\":{\"txid\":\"$txid\"}}")" || fail "get_tx_status failed for txid=$txid"
  tx_summary="$(printf '%s' "$tx_body" | jq -e -r '[.result.status, (.result.finalized | tostring), (.result.credit_safe | tostring)] | @tsv')" || fail "get_tx_status response is missing expected fields"
  IFS=$'\t' read -r tx_status tx_finalized tx_credit_safe <<<"$tx_summary"

  [[ "$tx_status" == "finalized" ]] || fail "tx status is not finalized: $tx_status"
  [[ "$tx_finalized" == "true" ]] || fail "tx finalized field is not true"
  [[ "$tx_credit_safe" == "true" ]] || fail "tx credit_safe field is not true"
  pass "known txid is finalized and credit-safe"
else
  echo "INFO: no txid supplied; skipping finalized transaction status check"
fi

pass "exchange sanity checks completed"
