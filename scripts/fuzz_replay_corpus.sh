#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Replays the committed seed corpora (fuzz/seed_corpus/<target>.zip) through the fuzz smoke binaries
# in BUILD_DIR, so every input that once reached new code is re-checked on each build.
# Usage: scripts/fuzz_replay_corpus.sh [BUILD_DIR]   (default: build)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${1:-build}"
work="$(mktemp -d)"
trap 'rm -rf -- "${work:?}"' EXIT

status=0
for zip in "${root}"/fuzz/seed_corpus/*.zip; do
  target="$(basename "${zip}" .zip)"
  bin="${build_dir}/${target}"
  if [[ ! -x "${bin}" ]]; then
    echo "missing ${bin}" >&2
    status=1
    continue
  fi
  mkdir -p "${work}/${target}"
  unzip -q -o "${zip}" -d "${work}/${target}"
  count="$(find "${work}/${target}" -type f | wc -l)"
  if find "${work}/${target}" -type f -print0 | xargs -0 -r "${bin}" > /dev/null; then
    echo "${target}: ${count} inputs ok"
  else
    echo "${target}: FAILED" >&2
    status=1
  fi
done
exit "${status}"
