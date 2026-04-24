#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Set, Tuple

OPENAPI_PATH = "openapi/finalis-partner-v1.yaml"
CHANGELOG_PATH = "apps/finalis-explorer/PARTNER_API_CHANGELOG.md"
DEPRECATIONS_PATH = "apps/finalis-explorer/PARTNER_API_DEPRECATIONS.md"
EXPLORER_MAIN_PATH = "apps/finalis-explorer/main.cpp"


@dataclass
class Contract:
    version: str
    operations: Set[str]
    deprecated_operations: Set[str]


def run_git(*args: str) -> str:
    proc = subprocess.run(["git", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def read_file_at_ref(ref: str, path: str) -> str:
    return run_git("show", f"{ref}:{path}")


def changed_files(base_ref: str, head_ref: str) -> Set[str]:
    out = run_git("diff", "--name-only", base_ref, head_ref)
    return {line.strip() for line in out.splitlines() if line.strip()}


def parse_semver(version: str) -> Tuple[int, int, int]:
    m = re.match(r"^([0-9]+)\.([0-9]+)\.([0-9]+)$", version)
    if not m:
        raise ValueError(f"invalid semver: {version}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def semver_gt(a: str, b: str) -> bool:
    return parse_semver(a) > parse_semver(b)


def parse_contract(spec: str) -> Contract:
    lines = spec.splitlines()
    version = ""
    for line in lines:
        m = re.match(r"^\s*version:\s*([0-9]+\.[0-9]+\.[0-9]+)\s*$", line)
        if m:
            version = m.group(1)
            break
    if not version:
        raise ValueError("OpenAPI info.version missing or invalid")

    in_paths = False
    current_path = ""
    current_op = ""
    operations: Set[str] = set()
    deprecated_ops: Set[str] = set()

    for raw in lines:
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip(" "))

        if stripped == "paths:" and indent == 0:
            in_paths = True
            continue
        if in_paths and indent == 0 and stripped.endswith(":") and stripped != "paths:":
            break
        if not in_paths:
            continue

        if indent == 2 and stripped.startswith("/") and stripped.endswith(":"):
            current_path = stripped[:-1]
            current_op = ""
            continue

        method_match = re.match(r"^(get|post|put|patch|delete):$", stripped)
        if indent == 4 and method_match and current_path:
            method = method_match.group(1).upper()
            current_op = f"{method} {current_path}"
            operations.add(current_op)
            continue

        if indent >= 6 and stripped == "deprecated: true" and current_op:
            deprecated_ops.add(current_op)

    return Contract(version=version, operations=operations, deprecated_operations=deprecated_ops)


def top_changelog_entry(changelog_text: str) -> Tuple[str, str]:
    lines = changelog_text.splitlines()
    start = -1
    for i, line in enumerate(lines):
        if line.startswith("## "):
            start = i
            break
    if start == -1:
        return "", ""
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].startswith("## "):
            end = j
            break
    return lines[start], "\n".join(lines[start + 1 : end]).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Explorer partner API governance checks")
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head-ref", required=True)
    args = parser.parse_args()

    errors: List[str] = []

    try:
        files = changed_files(args.base_ref, args.head_ref)
        old_spec = read_file_at_ref(args.base_ref, OPENAPI_PATH)
        new_spec = read_file_at_ref(args.head_ref, OPENAPI_PATH)
        old = parse_contract(old_spec)
        new = parse_contract(new_spec)
    except Exception as exc:
        print(f"explorer-partner-governance: initialization failed: {exc}", file=sys.stderr)
        return 2

    if old_spec == new_spec:
        print("explorer-partner-governance: OpenAPI unchanged; passing.")
        return 0

    added_ops = sorted(new.operations - old.operations)
    removed_ops = sorted(old.operations - new.operations)
    deprecated_added = sorted(new.deprecated_operations - old.deprecated_operations)

    print(f"explorer-partner-governance: base={old.version} head={new.version}")
    if added_ops:
        print("  added operations:")
        for op in added_ops:
            print(f"    + {op}")
    if removed_ops:
        print("  removed operations:")
        for op in removed_ops:
            print(f"    - {op}")
    if deprecated_added:
        print("  newly deprecated operations:")
        for op in deprecated_added:
            print(f"    ~ {op}")

    if not semver_gt(new.version, old.version):
        errors.append(f"{OPENAPI_PATH}: info.version must increase when spec changes ({old.version} -> {new.version}).")

    if CHANGELOG_PATH not in files:
        errors.append(f"{CHANGELOG_PATH} must be updated whenever {OPENAPI_PATH} changes.")
    else:
        try:
            changelog = read_file_at_ref(args.head_ref, CHANGELOG_PATH)
            header, body = top_changelog_entry(changelog)
            if not header:
                errors.append(f"{CHANGELOG_PATH} must contain a top '## vX.Y.Z - YYYY-MM-DD' entry.")
            else:
                if f"v{new.version}" not in header:
                    errors.append(f"{CHANGELOG_PATH}: top entry must reference v{new.version}; found '{header}'.")
                if not re.search(r"\d{4}-\d{2}-\d{2}", header):
                    errors.append(f"{CHANGELOG_PATH}: top entry must include an ISO date (YYYY-MM-DD).")
                if len(body.strip()) < 20:
                    errors.append(f"{CHANGELOG_PATH}: top entry body is too short; include concrete API deltas.")
        except Exception as exc:
            errors.append(f"unable to read {CHANGELOG_PATH} at head ref: {exc}")

    breaking = bool(removed_ops)
    if breaking or deprecated_added:
        if DEPRECATIONS_PATH not in files:
            errors.append(f"{DEPRECATIONS_PATH} must be updated when operations are removed/deprecated.")
        else:
            try:
                deprecations = read_file_at_ref(args.head_ref, DEPRECATIONS_PATH)
                if "Sunset:" not in deprecations or "Deprecation header:" not in deprecations:
                    errors.append(f"{DEPRECATIONS_PATH} must declare 'Deprecation header:' and 'Sunset:' fields.")
            except Exception as exc:
                errors.append(f"unable to read {DEPRECATIONS_PATH} at head ref: {exc}")

    if (breaking or deprecated_added):
        try:
            explorer_main = read_file_at_ref(args.head_ref, EXPLORER_MAIN_PATH)
            if "Deprecation" not in explorer_main or "Sunset" not in explorer_main:
                errors.append(
                    f"{EXPLORER_MAIN_PATH} must emit Deprecation/Sunset headers when deprecations are introduced."
                )
        except Exception as exc:
            errors.append(f"unable to read {EXPLORER_MAIN_PATH} at head ref: {exc}")

    if errors:
        print("explorer-partner-governance: FAILED", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("explorer-partner-governance: passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
