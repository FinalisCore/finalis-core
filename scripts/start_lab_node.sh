#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

NODE_NAME="${NODE_NAME:-}"
NODE_IP="${NODE_IP:-}"
NODE_PORT="${NODE_PORT:-}"
LIGHTSERVER_PORT="${LIGHTSERVER_PORT:-}"
DB_DIR="${DB_DIR:-}"
KEY_FILE="${KEY_FILE:-}"
KEY_PASS="${KEY_PASS:-}"
GENESIS_PATH="${GENESIS_PATH:-${ROOT_DIR}/mainnet/genesis.bin}"
PEERS_CSV="${PEERS_CSV:-}"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
NODE_BIN="${NODE_BIN:-${BUILD_DIR}/finalis-node}"
CLI_BIN="${CLI_BIN:-${BUILD_DIR}/finalis-cli}"
ALLOW_UNSAFE_GENESIS_OVERRIDE="${ALLOW_UNSAFE_GENESIS_OVERRIDE:-1}"
CREATE_KEY_IF_MISSING="${CREATE_KEY_IF_MISSING:-1}"
WITH_LIGHTSERVER="${WITH_LIGHTSERVER:-1}"

usage() {
  cat <<'EOF'
Usage:
  scripts/start_lab_node.sh a
  scripts/start_lab_node.sh b
  scripts/start_lab_node.sh c

Environment overrides:
  ROOT_DIR
  BUILD_DIR
  GENESIS_PATH
  ALLOW_UNSAFE_GENESIS_OVERRIDE=1
  CREATE_KEY_IF_MISSING=1

This script is for disposable LAN testing only.
It starts a fixed-peer node mesh using fresh lab DB paths instead of ~/.finalis/mainnet.
EOF
}

configure_named_node() {
  case "${1}" in
    a|A)
      NODE_NAME="a"
      NODE_IP="${NODE_IP:-192.168.0.103}"
      NODE_PORT="${NODE_PORT:-30333}"
      LIGHTSERVER_PORT="${LIGHTSERVER_PORT:-19444}"
      DB_DIR="${DB_DIR:-$HOME/.finalis/lab-a}"
      KEY_FILE="${KEY_FILE:-${DB_DIR}/keystore/validator.json}"
      KEY_PASS="${KEY_PASS:-passA}"
      PEERS_CSV="${PEERS_CSV:-192.168.0.106:30334,192.168.0.104:30335}"
      ;;
    b|B)
      NODE_NAME="b"
      NODE_IP="${NODE_IP:-192.168.0.106}"
      NODE_PORT="${NODE_PORT:-30334}"
      LIGHTSERVER_PORT="${LIGHTSERVER_PORT:-19445}"
      DB_DIR="${DB_DIR:-$HOME/.finalis/lab-b}"
      KEY_FILE="${KEY_FILE:-${DB_DIR}/keystore/validator.json}"
      KEY_PASS="${KEY_PASS:-passB}"
      PEERS_CSV="${PEERS_CSV:-192.168.0.103:30333,192.168.0.104:30335}"
      ;;
    c|C)
      NODE_NAME="c"
      NODE_IP="${NODE_IP:-192.168.0.104}"
      NODE_PORT="${NODE_PORT:-30335}"
      LIGHTSERVER_PORT="${LIGHTSERVER_PORT:-19446}"
      DB_DIR="${DB_DIR:-$HOME/.finalis/lab-c}"
      KEY_FILE="${KEY_FILE:-${DB_DIR}/keystore/validator.json}"
      KEY_PASS="${KEY_PASS:-passC}"
      PEERS_CSV="${PEERS_CSV:-192.168.0.103:30333,192.168.0.106:30334}"
      ;;
    *)
      echo "unknown node '${1}'" >&2
      usage >&2
      exit 1
      ;;
  esac
}

require_file() {
  local path="$1"
  local label="$2"
  if [[ ! -f "${path}" ]]; then
    echo "${label} not found: ${path}" >&2
    exit 1
  fi
}

ensure_key() {
  mkdir -p "$(dirname "${KEY_FILE}")"
  if [[ -f "${KEY_FILE}" ]]; then
    return 0
  fi
  if [[ "${CREATE_KEY_IF_MISSING}" != "1" ]]; then
    echo "validator key missing: ${KEY_FILE}" >&2
    exit 1
  fi
  echo "[lab] creating validator key: ${KEY_FILE}"
  "${CLI_BIN}" wallet_create --out "${KEY_FILE}" --pass "${KEY_PASS}"
}

print_summary() {
  cat <<EOF
[lab] node=${NODE_NAME}
[lab] ip=${NODE_IP}
[lab] db=${DB_DIR}
[lab] genesis=${GENESIS_PATH}
[lab] p2p_port=${NODE_PORT}
[lab] lightserver_port=${LIGHTSERVER_PORT}
[lab] peers=${PEERS_CSV}
[lab] key=${KEY_FILE}
EOF
}

main() {
  if [[ $# -ne 1 ]]; then
    usage >&2
    exit 1
  fi

  configure_named_node "$1"

  require_file "${NODE_BIN}" "finalis-node binary"
  require_file "${CLI_BIN}" "finalis-cli binary"
  require_file "${GENESIS_PATH}" "genesis artifact"
  ensure_key
  mkdir -p "${DB_DIR}"

  print_summary

  cmd=(
    "${NODE_BIN}"
    "--db" "${DB_DIR}"
    "--genesis" "${GENESIS_PATH}"
    "--listen"
    "--bind" "0.0.0.0"
    "--port" "${NODE_PORT}"
    "--validator-key-file" "${KEY_FILE}"
    "--validator-passphrase" "${KEY_PASS}"
    "--peers" "${PEERS_CSV}"
    "--no-dns-seeds"
  )

  if [[ "${ALLOW_UNSAFE_GENESIS_OVERRIDE}" == "1" ]]; then
    cmd+=("--allow-unsafe-genesis-override")
  fi

  if [[ "${WITH_LIGHTSERVER}" == "1" ]]; then
    cmd+=(
      "--with-lightserver"
      "--lightserver-bind" "0.0.0.0"
      "--lightserver-port" "${LIGHTSERVER_PORT}"
    )
  fi

  echo "[lab] starting finalis-node"
  exec "${cmd[@]}"
}

main "$@"
