#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

set -euo pipefail

# Validates SPDX license headers on selected repository files.
# Usage:
#   scripts/check_spdx_headers.sh <file> [<file> ...]
#
# The check is intentionally limited to source/header/script files and ignores
# generated/build/vendor paths.

if [[ "$#" -eq 0 ]]; then
  echo "No files provided; nothing to check."
  exit 0
fi

required="SPDX-License-Identifier: MIT"
failed=0

is_target_file() {
  local f="$1"

  # Skip known generated/build/vendor areas.
  case "$f" in
    build/*|third_party/*|.git/*|.vscode/*)
      return 1
      ;;
  esac

  case "$f" in
    *.c|*.cc|*.cpp|*.cxx|*.h|*.hh|*.hpp|*.hxx|*.ipp|*.inl|*.py|*.sh|CMakeLists.txt|*.cmake)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

for file in "$@"; do
  if [[ ! -f "$file" ]]; then
    continue
  fi

  if ! is_target_file "$file"; then
    continue
  fi

  # Header should be near top-of-file; first 8 lines balances strictness and
  # compatibility with shebangs and include guards.
  if ! head -n 8 "$file" | grep -q "$required"; then
    echo "Missing SPDX header: $file"
    failed=1
  fi
done

if [[ "$failed" -ne 0 ]]; then
  echo
  echo "SPDX header check failed. Expected header line near top of file:"
  echo "  $required"
  exit 1
fi

echo "SPDX header check passed."
