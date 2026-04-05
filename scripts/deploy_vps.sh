#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/deploy_vps.sh <user@host> [remote_dir] [--start]

Examples:
  scripts/deploy_vps.sh root@203.0.113.10
  scripts/deploy_vps.sh root@203.0.113.10 /root/finalis-core --start

What it does:
  1) Builds local binaries (Release)
  2) Copies binaries to <remote_dir>/build on VPS
  3) Optionally starts a public node on VPS (--start)
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

TARGET_HOST="$1"
shift || true

REMOTE_DIR="~/finalis-core"
START_NODE=0

for arg in "$@"; do
  if [[ "$arg" == "--start" ]]; then
    START_NODE=1
  elif [[ "$arg" == "--help" || "$arg" == "-h" ]]; then
    usage
    exit 0
  else
    REMOTE_DIR="$arg"
  fi
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build"

echo "[deploy] Building local binaries..."
cmake -S "${REPO_ROOT}" -B "${BUILD_DIR}" -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build "${BUILD_DIR}" -j"$(nproc)" --target finalis-node finalis-lightserver finalis-cli

echo "[deploy] Preparing remote directories on ${TARGET_HOST}..."
ssh "${TARGET_HOST}" "mkdir -p ${REMOTE_DIR}/build"

echo "[deploy] Uploading binaries..."
scp "${BUILD_DIR}/finalis-node" "${TARGET_HOST}:${REMOTE_DIR}/build/finalis-node"
scp "${BUILD_DIR}/finalis-lightserver" "${TARGET_HOST}:${REMOTE_DIR}/build/finalis-lightserver"
scp "${BUILD_DIR}/finalis-cli" "${TARGET_HOST}:${REMOTE_DIR}/build/finalis-cli"

echo "[deploy] Marking binaries executable..."
ssh "${TARGET_HOST}" "chmod +x ${REMOTE_DIR}/build/finalis-node ${REMOTE_DIR}/build/finalis-lightserver ${REMOTE_DIR}/build/finalis-cli"

if [[ "${START_NODE}" -eq 1 ]]; then
  echo "[deploy] Starting finalis-node on VPS (nohup, public)..."
  ssh "${TARGET_HOST}" "pkill -f '${REMOTE_DIR}/build/finalis-node --public' || true"
  ssh "${TARGET_HOST}" "nohup ${REMOTE_DIR}/build/finalis-node --public > ${REMOTE_DIR}/node.log 2>&1 &"
  echo "[deploy] Started. Tail logs with:"
  echo "ssh ${TARGET_HOST} 'tail -f ${REMOTE_DIR}/node.log'"
fi

echo "[deploy] Done."
