#!/usr/bin/env python3
from __future__ import annotations

import csv
from pathlib import Path
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.generate_depth_boundary_report import minimum_slack_for
from scripts.protocol_attack_sim import (
    CURRENT_LIKE_PROFILE,
    PROFILE_A,
    PROFILE_B,
    CandidateProfile,
    build_replay_expanded_honest_depth,
    percent,
    run_scenario,
    write_json,
    write_markdown,
)


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "analysis" / "parameter_recommendation_replay_expanded_depth"
SLACK_RANGE = tuple(range(-1, 11))


def row_for(profile: CandidateProfile, slack: int, fixture_count: int, depth_scale: int, summary) -> dict[str, Any]:
    return {
        "profile": profile.name,
        "committee_size": profile.committee_size,
        "min_eligible": profile.min_eligible,
        "eligible_slack_operators": slack,
        "fallback_rate_pct": percent(summary.fallback_rate),
        "sticky_rate_pct": percent(summary.sticky_fallback_rate),
        "epochs_at_exact_threshold": summary.epochs_at_exact_threshold,
        "epochs_below_threshold": summary.epochs_below_threshold,
        "epochs_at_recovery_threshold": summary.epochs_at_recovery_threshold,
        "committee_share_pct": percent(summary.average_coalition_committee_share),
        "proposer_share_pct": percent(summary.proposer_share),
        "avg_hhi": round(summary.average_hhi, 6),
        "fixture_count": fixture_count,
        "calibrated_depth_scale": depth_scale,
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def verdict(row: dict[str, Any]) -> str:
    if row["profile"] == CURRENT_LIKE_PROFILE.name:
        return "reference baseline"
    if row["minimum_slack_for_zero_fallback"] <= 1 and row["minimum_slack_for_clear_threshold_margin"] <= 2:
        return "expanded-depth-favorable"
    if row["minimum_slack_for_zero_fallback"] <= 3 and row["minimum_slack_for_clear_threshold_margin"] <= 4:
        return "expanded-depth-costly"
    return "not justified yet"


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    profiles = (CURRENT_LIKE_PROFILE, PROFILE_A, PROFILE_B)
    sweep_rows: list[dict[str, Any]] = []
    summary_rows: list[dict[str, Any]] = []

    for profile in profiles:
        local_rows: list[dict[str, Any]] = []
        for slack in SLACK_RANGE:
            scenario = build_replay_expanded_honest_depth(
                committee_size=profile.committee_size,
                min_eligible=profile.min_eligible,
                eligible_slack_operators=slack,
                dynamic_min_bond_coins=profile.dynamic_min_bond_coins,
                availability_min_bond_coins=profile.availability_min_bond_coins,
                calibrated_depth_scale=3,
            )
            summary = run_scenario(scenario)
            row = row_for(
                profile,
                slack,
                len(scenario.threshold_controls["calibration_fixture_names"]),
                int(scenario.threshold_controls["calibrated_depth_scale"]),
                summary,
            )
            sweep_rows.append(row)
            local_rows.append(row)

        zero_fallback = minimum_slack_for(
            local_rows,
            lambda row: row["fallback_rate_pct"] == 0.0 and row["sticky_rate_pct"] == 0.0,
        )
        clear_margin = minimum_slack_for(
            local_rows,
            lambda row: row["fallback_rate_pct"] == 0.0
            and row["sticky_rate_pct"] == 0.0
            and row["epochs_at_exact_threshold"] == 0
            and row["epochs_below_threshold"] == 0,
        )
        boundary_row = next(row for row in local_rows if row["eligible_slack_operators"] == zero_fallback)
        out = {
            "profile": profile.name,
            "committee_size": profile.committee_size,
            "min_eligible": profile.min_eligible,
            "minimum_slack_for_zero_fallback": zero_fallback,
            "minimum_slack_for_clear_threshold_margin": clear_margin,
            "committee_share_pct_at_zero_fallback_boundary": boundary_row["committee_share_pct"],
            "proposer_share_pct_at_zero_fallback_boundary": boundary_row["proposer_share_pct"],
            "avg_hhi_at_zero_fallback_boundary": boundary_row["avg_hhi"],
            "fixture_count": boundary_row["fixture_count"],
            "calibrated_depth_scale": boundary_row["calibrated_depth_scale"],
        }
        out["verdict"] = verdict(out)
        summary_rows.append(out)

    write_json(OUT_DIR / "replay_expanded_depth_sweep.json", sweep_rows)
    write_json(OUT_DIR / "replay_expanded_depth_summary.json", summary_rows)
    write_csv(OUT_DIR / "replay_expanded_depth_summary.csv", summary_rows)

    lines = [
        "# Replay-Expanded Honest-Depth Memo",
        "",
        "This memo is based only on the replay-expanded honest-depth sweep in this directory.",
        "",
        "## Calibration Source",
        "",
        "- The family expands operator archetypes from the committed C++ checkpoint fixture corpus.",
        "- It is still simulator dynamics on top of those archetypes, but it avoids treating the tiny fixture count itself as the whole operator population.",
        "",
        "## Profile Comparison",
        "",
        "| profile | committee size | min eligible | min slack for zero fallback | min slack for clear margin | committee share at zero-fallback boundary | proposer share at zero-fallback boundary | verdict |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in summary_rows:
        lines.append(
            f"| {row['profile']} | {row['committee_size']} | {row['min_eligible']} | "
            f"{row['minimum_slack_for_zero_fallback']} | {row['minimum_slack_for_clear_threshold_margin']} | "
            f"{row['committee_share_pct_at_zero_fallback_boundary']:.2f}% | "
            f"{row['proposer_share_pct_at_zero_fallback_boundary']:.2f}% | {row['verdict']} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- Supported by current outputs: this family measures the same slack boundary against a larger replay-derived population than the raw fixture-shaped family.",
            "- Remaining uncertainty: calibration still comes from checkpoint-fixture archetypes rather than a long finalized-history replay sample.",
        ]
    )
    write_markdown(OUT_DIR / "replay_expanded_depth_memo.md", "\n".join(lines) + "\n")
    write_markdown(OUT_DIR / "replay_expanded_depth_table.md", "\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
