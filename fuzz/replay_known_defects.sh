#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Replays the minimized reproducers of open defects (fuzz/known_defects/<target>/*.bin, see
# tests/KNOWN_DEFECTS.md) through the standalone fuzz binaries in BUILD_DIR, each input against a
# fresh node. Exit status 1 while any reproducer still fails (the defect is present), 0 once all of
# them pass; a fixed defect's reproducer then moves to the target's seed corpus as a regression case.
# Usage: fuzz/replay_known_defects.sh [BUILD_DIR]   (default: build)
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${1:-build}"
artifacts="$(mktemp -d)"
trap 'rm -rf -- "${artifacts:?}"' EXIT

reproduced=0
for dir in "${root}"/fuzz/known_defects/*/; do
  target="$(basename "${dir}")"
  bin="${build_dir}/${target}"
  if [[ ! -x "${bin}" ]]; then
    echo "missing ${bin}" >&2
    exit 2
  fi
  for input in "${dir}"*.bin; do
    if out="$(FINALIS_TEST_QUIET_LOGS=1 FINALIS_FUZZ_ARTIFACT_DIR="${artifacts}" "${bin}" "${input}" 2>&1)"; then
      echo "${target}/$(basename "${input}"): no longer reproduces"
    else
      echo "${target}/$(basename "${input}"): REPRODUCES $(grep -o 'oracle=[a-z-]*' <<<"${out}" | head -1)"
      reproduced=1
    fi
  done
done
exit "${reproduced}"
