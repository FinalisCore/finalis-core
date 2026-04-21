#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
printf '[bootstrap-build] %s\n' "bootstrap_build.sh is deprecated; forwarding to scripts/start.sh"
exec "${SCRIPT_DIR}/start.sh" "$@"
