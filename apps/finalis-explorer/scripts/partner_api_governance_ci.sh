#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

base_ref="${1:-origin/main}"
head_ref="${2:-HEAD}"

python3 apps/finalis-explorer/scripts/check_partner_api_governance.py \
  --base-ref "$base_ref" \
  --head-ref "$head_ref"
