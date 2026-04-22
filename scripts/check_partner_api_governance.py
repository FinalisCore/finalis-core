#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple


OPENAPI_PATH = "openapi/finalis-partner-v1.yaml"
CHANGELOG_PATH = "docs/PARTNER_API_CHANGELOG.md"
DEPRECATIONS_PATH = "docs/PARTNER_API_DEPRECATIONS.md"


@dataclass
class OperationContract:
    required_headers: Set[str] = field(default_factory=set)
    request_required_fields: Set[str] = field(default_factory=set)
    response_codes: Set[str] = field(default_factory=set)
    public: bool = False


@dataclass
class Contract:
    version: str
    operations: Dict[str, OperationContract]


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


def parse_required_list(line: str) -> Set[str]:
    m = re.search(r"required:\s*\[(.*?)\]\s*$", line.strip())
    if not m:
        return set()
    raw = m.group(1).strip()
    if not raw:
        return set()
    return {item.strip().strip("'\"") for item in raw.split(",") if item.strip()}


def parse_openapi_contract(text: str) -> Contract:
    lines = text.splitlines()
    version = ""
    for line in lines:
        m = re.match(r"^\s*version:\s*([0-9]+\.[0-9]+\.[0-9]+)\s*$", line)
        if m:
            version = m.group(1)
            break
    if not version:
        raise ValueError("openapi info.version is missing or not semver")

    operations: Dict[str, OperationContract] = {}

    in_paths = False
    current_path = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if stripped == "paths:" and indent == 0:
            in_paths = True
            i += 1
            continue
        if in_paths and indent == 0 and stripped.endswith(":") and stripped != "paths:":
            break
        if not in_paths:
            i += 1
            continue

        if indent == 2 and stripped.startswith("/") and stripped.endswith(":"):
            current_path = stripped[:-1]
            i += 1
            continue

        m_method = re.match(r"^(get|post|put|patch|delete):$", stripped)
        if indent == 4 and m_method and current_path:
            method = m_method.group(1)
            key = f"{method.upper()} {current_path}"
            op = OperationContract()

            j = i + 1
            while j < len(lines):
                nxt = lines[j]
                nxt_stripped = nxt.strip()
                nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                if nxt_indent <= 4:
                    break

                if nxt_stripped == "security: []":
                    op.public = True

                m_resp = re.match(r"^'([0-9]{3})':$", nxt_stripped)
                if m_resp:
                    op.response_codes.add(m_resp.group(1))

                j += 1

            block = lines[i + 1 : j]
            parse_operation_block(block, op)
            operations[key] = op
            i = j
            continue

        i += 1

    return Contract(version=version, operations=operations)


def parse_operation_block(block: List[str], op: OperationContract) -> None:
    idx = 0
    while idx < len(block):
        line = block[idx].strip()
        if line == "parameters:":
            idx += 1
            while idx < len(block):
                item = block[idx]
                item_indent = len(item) - len(item.lstrip(" "))
                stripped = item.strip()
                if item_indent <= 6:
                    break
                if stripped.startswith("- in:"):
                    in_value = stripped.split(":", 1)[1].strip()
                    name_value = ""
                    required = False
                    idx += 1
                    while idx < len(block):
                        sub = block[idx]
                        sub_indent = len(sub) - len(sub.lstrip(" "))
                        sub_stripped = sub.strip()
                        if sub_indent <= item_indent:
                            break
                        if sub_stripped.startswith("name:"):
                            name_value = sub_stripped.split(":", 1)[1].strip().strip("'\"")
                        if sub_stripped == "required: true":
                            required = True
                        idx += 1
                    if in_value == "header" and required and name_value:
                        op.required_headers.add(name_value)
                    continue
                idx += 1
            continue

        if line == "requestBody:":
            idx += 1
            while idx < len(block):
                body_line = block[idx]
                body_indent = len(body_line) - len(body_line.lstrip(" "))
                body_stripped = body_line.strip()
                if body_indent <= 6:
                    break
                reqs = parse_required_list(body_stripped)
                if reqs:
                    op.request_required_fields.update(reqs)
                idx += 1
            continue
        idx += 1


def parse_semver(v: str) -> Tuple[int, int, int]:
    m = re.match(r"^([0-9]+)\.([0-9]+)\.([0-9]+)$", v.strip())
    if not m:
        raise ValueError(f"invalid semver: {v}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def semver_gt(a: str, b: str) -> bool:
    return parse_semver(a) > parse_semver(b)


def classify_breaking(old: Contract, new: Contract) -> List[str]:
    reasons: List[str] = []
    old_ops = set(old.operations.keys())
    new_ops = set(new.operations.keys())
    removed_ops = sorted(old_ops - new_ops)
    if removed_ops:
        reasons.append("removed operations: " + ", ".join(removed_ops))

    for key in sorted(old_ops & new_ops):
        prev = old.operations[key]
        curr = new.operations[key]

        removed_success = sorted(code for code in prev.response_codes if code.startswith("2") and code not in curr.response_codes)
        if removed_success:
            reasons.append(f"{key}: removed success response codes {','.join(removed_success)}")

        added_req_headers = sorted(curr.required_headers - prev.required_headers)
        if added_req_headers:
            reasons.append(f"{key}: added required headers {','.join(added_req_headers)}")

        added_req_fields = sorted(curr.request_required_fields - prev.request_required_fields)
        if added_req_fields:
            reasons.append(f"{key}: added required request fields {','.join(added_req_fields)}")

        if prev.public and not curr.public:
            reasons.append(f"{key}: changed from public to authenticated")

    return reasons


def first_changelog_entry(changelog_text: str) -> Tuple[str, str]:
    lines = changelog_text.splitlines()
    header_idx = -1
    header = ""
    for i, line in enumerate(lines):
        if line.startswith("## "):
            header_idx = i
            header = line
            break
    if header_idx == -1:
        return "", ""
    end = len(lines)
    for j in range(header_idx + 1, len(lines)):
        if lines[j].startswith("## "):
            end = j
            break
    body = "\n".join(lines[header_idx + 1 : end]).strip()
    return header, body


def main() -> int:
    parser = argparse.ArgumentParser(description="Enforce Finalis partner API governance checks.")
    parser.add_argument("--base-ref", required=True, help="Base git ref/sha for comparison")
    parser.add_argument("--head-ref", required=True, help="Head git ref/sha for comparison")
    args = parser.parse_args()

    try:
        files = changed_files(args.base_ref, args.head_ref)
        new_spec = read_file_at_ref(args.head_ref, OPENAPI_PATH)
        new_contract = parse_openapi_contract(new_spec)
    except Exception as exc:
        print(f"partner-api-governance: failed to initialize check: {exc}", file=sys.stderr)
        return 2

    # Detect whether the file existed at base. If not, this is a clean first
    # introduction of the spec — no breaking-change analysis applies.
    try:
        old_spec = read_file_at_ref(args.base_ref, OPENAPI_PATH)
        old_contract = parse_openapi_contract(old_spec)
        openapi_is_new = False
    except Exception:
        old_spec = ""
        old_contract = None
        openapi_is_new = True

    openapi_changed = OPENAPI_PATH in files and old_spec != new_spec
    if not openapi_changed and not openapi_is_new:
        print("partner-api-governance: OpenAPI unchanged; governance gate passed.")
        return 0

    errors: List[str] = []

    if openapi_is_new:
        # First introduction of the spec: no breaking-change analysis, no
        # version-increment check (there is no old version to compare against).
        # Changelog must still be present and reference the new version.
        breaking_reasons = []
        is_breaking = False
        print(f"partner-api-governance: new OpenAPI spec introduced at v{new_contract.version}")
    else:
        breaking_reasons = classify_breaking(old_contract, new_contract)
        is_breaking = len(breaking_reasons) > 0

        if not semver_gt(new_contract.version, old_contract.version):
            errors.append(
                f"info.version must be incremented when OpenAPI changes (base={old_contract.version}, head={new_contract.version})."
            )

        if is_breaking:
            old_major, _, _ = parse_semver(old_contract.version)
            new_major, _, _ = parse_semver(new_contract.version)
            if new_major <= old_major:
                errors.append(
                    f"breaking API changes require major version bump (base={old_contract.version}, head={new_contract.version})."
                )
            if DEPRECATIONS_PATH not in files:
                errors.append(f"{DEPRECATIONS_PATH} must be updated for breaking API changes.")

        print(f"partner-api-governance: base={old_contract.version} head={new_contract.version} breaking={is_breaking}")
        if is_breaking:
            for reason in breaking_reasons:
                print(f"  - breaking: {reason}")

    if CHANGELOG_PATH not in files:
        errors.append(f"{CHANGELOG_PATH} must be updated whenever {OPENAPI_PATH} changes.")

    if CHANGELOG_PATH in files:
        try:
            changelog = read_file_at_ref(args.head_ref, CHANGELOG_PATH)
        except Exception as exc:
            errors.append(f"unable to read {CHANGELOG_PATH} at {args.head_ref}: {exc}")
            changelog = ""
        if changelog:
            header, body = first_changelog_entry(changelog)
            if not header:
                errors.append(f"{CHANGELOG_PATH} must contain a topmost '## ... vX.Y.Z' entry.")
            else:
                if f"v{new_contract.version}" not in header:
                    errors.append(
                        f"top changelog entry must target current OpenAPI version v{new_contract.version}; found: {header}"
                    )
                if is_breaking and "BREAKING" not in (header + "\n" + body):
                    errors.append(
                        f"top changelog entry for v{new_contract.version} must include 'BREAKING' for breaking changes."
                    )

    if errors:
        print("partner-api-governance: FAILED", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("partner-api-governance: passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
