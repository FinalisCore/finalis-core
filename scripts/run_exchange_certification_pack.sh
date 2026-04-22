#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-${ROOT_DIR}/artifacts/exchange-certification}"
mkdir -p "${OUT_DIR}"

echo "[cert] building tests"
cmake --build "${ROOT_DIR}/build" --target finalis-tests -j"$(nproc)" > "${OUT_DIR}/build.log" 2>&1

echo "[cert] running partner contract tests"
FINALIS_TEST_FILTER=explorer_partner "${ROOT_DIR}/build/finalis-tests" > "${OUT_DIR}/explorer_partner.log" 2>&1

echo "[cert] running v1 alias contract tests"
FINALIS_TEST_FILTER=api_v1 "${ROOT_DIR}/build/finalis-tests" > "${OUT_DIR}/api_v1.log" 2>&1

echo "[cert] running webhook gc/dlq tests"
FINALIS_TEST_FILTER=gc_prunes "${ROOT_DIR}/build/finalis-tests" > "${OUT_DIR}/gc_prunes.log" 2>&1

cat > "${OUT_DIR}/SUMMARY.txt" <<EOF
Exchange Certification Pack Evidence
Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Logs:
- build.log
- explorer_partner.log
- api_v1.log
- gc_prunes.log
EOF

echo "[cert] complete: ${OUT_DIR}"
