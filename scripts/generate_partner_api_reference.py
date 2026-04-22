#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys


def parse_ops(spec_text: str):
    lines = spec_text.splitlines()
    in_paths = False
    path = ""
    ops = []
    i = 0
    while i < len(lines):
        line = lines[i]
        s = line.strip()
        ind = len(line) - len(line.lstrip(" "))
        if s == "paths:" and ind == 0:
            in_paths = True
            i += 1
            continue
        if in_paths and ind == 0 and s.endswith(":") and s != "paths:":
            break
        if not in_paths:
            i += 1
            continue
        if ind == 2 and s.startswith("/") and s.endswith(":"):
            path = s[:-1]
            i += 1
            continue
        m = re.match(r"^(get|post|put|patch|delete):$", s)
        if ind == 4 and m and path:
            method = m.group(1).upper()
            summary = ""
            public = False
            j = i + 1
            while j < len(lines):
                l2 = lines[j]
                s2 = l2.strip()
                ind2 = len(l2) - len(l2.lstrip(" "))
                if ind2 <= 4:
                    break
                if s2.startswith("summary:"):
                    summary = s2.split(":", 1)[1].strip()
                if s2 == "security: []":
                    public = True
                j += 1
            ops.append((method, path, summary, "public" if public else "auth"))
            i = j
            continue
        i += 1
    return ops


def render(ops) -> str:
    out = []
    out.append("# Partner API Reference")
    out.append("")
    out.append("_Generated from `openapi/finalis-partner-v1.yaml`. Do not edit manually._")
    out.append("")
    out.append("| Method | Path | Auth | Summary |")
    out.append("|---|---|---|---|")
    for method, path, summary, auth in ops:
        out.append(f"| `{method}` | `{path}` | `{auth}` | {summary} |")
    out.append("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate partner API markdown reference from OpenAPI.")
    parser.add_argument("--spec", default="openapi/finalis-partner-v1.yaml")
    parser.add_argument("--out", default="docs/PARTNER_API_REFERENCE.md")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    spec = Path(args.spec)
    out = Path(args.out)
    if not spec.exists():
        print(f"spec not found: {spec}", file=sys.stderr)
        return 2
    generated = render(parse_ops(spec.read_text(encoding="utf-8")))
    if args.check:
        if not out.exists() or out.read_text(encoding="utf-8") != generated:
            print("partner API reference drift detected; run scripts/generate_partner_api_reference.py", file=sys.stderr)
            return 1
        return 0
    out.write_text(generated, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
