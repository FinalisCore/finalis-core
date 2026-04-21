#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
OUT_DIR="${1:-${ROOT_DIR}/tests/fixtures}"

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -G Ninja
cmake --build "${BUILD_DIR}" --target checkpoint-fixture-export -j1
"${BUILD_DIR}/checkpoint-fixture-export" "${OUT_DIR}"

echo "Generated checkpoint/comparator fixtures under ${OUT_DIR}"
