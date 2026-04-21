#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

"${ROOT_DIR}/scripts/generate_checkpoint_fixtures.sh" "${TMP_DIR}"

diff -ru "${ROOT_DIR}/tests/fixtures" "${TMP_DIR}"

echo "Checkpoint/comparator fixtures are up to date."
