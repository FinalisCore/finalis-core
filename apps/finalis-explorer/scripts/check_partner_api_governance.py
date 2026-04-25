#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
import subprocess
import sys


def main() -> int:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    canonical = os.path.join(repo_root, "scripts", "check_partner_api_governance.py")
    proc = subprocess.run([sys.executable, canonical, *sys.argv[1:]])
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
