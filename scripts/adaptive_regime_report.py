#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any


def load_payload_from_file(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if "result" in data and isinstance(data["result"], dict):
        return data["result"]
    if isinstance(data, dict):
        return data
    raise ValueError("adaptive telemetry file must contain a JSON object")


def load_payload_from_rpc(rpc_url: str, limit: int) -> dict[str, Any]:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "get_adaptive_telemetry",
            "params": {"limit": limit},
        }
    ).encode("utf-8")
    request = urllib.request.Request(rpc_url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if "error" in payload:
        raise RuntimeError(f"rpc error: {payload['error']}")
    result = payload.get("result")
    if not isinstance(result, dict):
        raise ValueError("rpc result missing adaptive telemetry payload")
    return result


def render_text(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    snapshots = payload.get("snapshots", [])
    latest = snapshots[-1] if snapshots else {}
    lines = [
        "# Adaptive Regime Report",
        "",
        "## Current",
        f"- epoch_start_height: {latest.get('epoch_start_height')}",
        f"- qualified_depth: {latest.get('qualified_depth')}",
        f"- adaptive_target_committee_size: {latest.get('adaptive_target_committee_size')}",
        f"- adaptive_min_eligible: {latest.get('adaptive_min_eligible')}",
        f"- adaptive_min_bond: {latest.get('adaptive_min_bond')}",
        f"- slack: {latest.get('slack')}",
        f"- checkpoint_derivation_mode: {latest.get('checkpoint_derivation_mode')}",
        f"- checkpoint_fallback_reason: {latest.get('checkpoint_fallback_reason')}",
        f"- fallback_sticky: {latest.get('fallback_sticky')}",
        "",
        "## Rolling",
        f"- window_epochs: {payload.get('window_epochs')}",
        f"- sample_count: {summary.get('sample_count')}",
        f"- fallback_rate_bps: {summary.get('fallback_rate_bps')}",
        f"- sticky_fallback_rate_bps: {summary.get('sticky_fallback_rate_bps')}",
        "",
        "## Flags",
        f"- near_threshold_operation: {summary.get('near_threshold_operation')}",
        f"- prolonged_expand_buildup: {summary.get('prolonged_expand_buildup')}",
        f"- prolonged_contract_buildup: {summary.get('prolonged_contract_buildup')}",
        f"- repeated_sticky_fallback: {summary.get('repeated_sticky_fallback')}",
        f"- depth_collapse_after_bond_increase: {summary.get('depth_collapse_after_bond_increase')}",
        "",
        "## Recent Epochs",
    ]
    for entry in snapshots:
        lines.append(
            "- epoch={epoch_start_height} depth={qualified_depth} target={adaptive_target_committee_size} "
            "min_eligible={adaptive_min_eligible} min_bond={adaptive_min_bond} slack={slack} "
            "mode={checkpoint_derivation_mode} reason={checkpoint_fallback_reason} "
            "expand_streak={target_expand_streak} contract_streak={target_contract_streak}".format(**entry)
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Report adaptive checkpoint telemetry.")
    parser.add_argument("--input", type=Path, help="Path to get_adaptive_telemetry JSON payload")
    parser.add_argument("--rpc-url", help="RPC URL to query get_adaptive_telemetry")
    parser.add_argument("--limit", type=int, default=16, help="Number of epochs to request/report")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)

    if not args.input and not args.rpc_url:
        parser.error("either --input or --rpc-url is required")

    if args.input:
        payload = load_payload_from_file(args.input)
    else:
        payload = load_payload_from_rpc(args.rpc_url, args.limit)

    if args.json:
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_text(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
