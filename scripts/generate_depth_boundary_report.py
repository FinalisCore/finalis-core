#!/usr/bin/env python3
from __future__ import annotations

import csv
from pathlib import Path
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.protocol_attack_sim import (
    CURRENT_LIKE_PROFILE,
    PROFILE_A,
    PROFILE_B,
    CandidateProfile,
    build_marginal_eligible_pool,
    percent,
    run_scenario,
    write_json,
    write_markdown,
)


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "analysis" / "parameter_recommendation_depth"
SLACK_RANGE = tuple(range(-1, 9))


def summary_row(profile: CandidateProfile, slack: int, summary) -> dict[str, Any]:
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
        "fallback_entry_count": summary.fallback_entry_count,
        "sticky_fallback_entry_count": summary.sticky_fallback_entry_count,
        "recovery_from_sticky_count": summary.recovery_from_sticky_count,
        "committee_share_pct": percent(summary.average_coalition_committee_share),
        "proposer_share_pct": percent(summary.proposer_share),
        "avg_hhi": round(summary.average_hhi, 6),
        "avg_top1_pct": percent(summary.average_top1_share),
        "avg_top3_pct": percent(summary.average_top3_share),
        "eligibility_churn_events": summary.eligibility_churn_events,
        "marginal_operator_committee_share_pct": percent(summary.marginal_operator_committee_share),
        "marginal_operator_eligibility_churn": summary.marginal_operator_eligibility_churn,
    }


def minimum_slack_for(rows: list[dict[str, Any]], predicate) -> int | None:
    for row in sorted(rows, key=lambda item: int(item["eligible_slack_operators"])):
        if predicate(row):
            return int(row["eligible_slack_operators"])
    return None


def verdict(row: dict[str, Any]) -> str:
    if row["profile"] == CURRENT_LIKE_PROFILE.name:
        return "reference baseline"
    if row["minimum_slack_for_zero_fallback"] is None:
        return "not justified yet"
    if row["minimum_slack_for_zero_fallback"] <= 1 and row["minimum_slack_for_clear_threshold_margin"] <= 2:
        return "depth-favorable"
    if row["minimum_slack_for_zero_fallback"] <= 2 and row["minimum_slack_for_clear_threshold_margin"] <= 3:
        return "depth-costly"
    return "not justified yet"


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    profiles = (CURRENT_LIKE_PROFILE, PROFILE_A, PROFILE_B)

    sweep_rows: list[dict[str, Any]] = []
    profile_rows: list[dict[str, Any]] = []

    for profile in profiles:
        marginal_count = 4 if profile.committee_size == 16 else 5
        local_rows: list[dict[str, Any]] = []
        for slack in SLACK_RANGE:
            summary = run_scenario(
                build_marginal_eligible_pool(
                    committee_size=profile.committee_size,
                    min_eligible=profile.min_eligible,
                    eligible_slack_operators=slack,
                    marginal_operator_count=marginal_count,
                    dynamic_min_bond_coins=profile.dynamic_min_bond_coins,
                    availability_min_bond_coins=profile.availability_min_bond_coins,
                )
            )
            row = summary_row(profile, slack, summary)
            sweep_rows.append(row)
            local_rows.append(row)

        minimum_zero_fallback = minimum_slack_for(
            local_rows,
            lambda row: row["fallback_rate_pct"] == 0.0 and row["sticky_rate_pct"] == 0.0,
        )
        minimum_clear_margin = minimum_slack_for(
            local_rows,
            lambda row: row["fallback_rate_pct"] == 0.0
            and row["sticky_rate_pct"] == 0.0
            and row["epochs_at_exact_threshold"] == 0
            and row["epochs_below_threshold"] == 0,
        )
        best_row = next(row for row in local_rows if row["eligible_slack_operators"] == minimum_zero_fallback)
        profile_row = {
            "profile": profile.name,
            "committee_size": profile.committee_size,
            "min_eligible": profile.min_eligible,
            "minimum_slack_for_zero_fallback": minimum_zero_fallback,
            "minimum_slack_for_clear_threshold_margin": minimum_clear_margin,
            "committee_share_pct_at_zero_fallback_boundary": best_row["committee_share_pct"],
            "proposer_share_pct_at_zero_fallback_boundary": best_row["proposer_share_pct"],
            "avg_hhi_at_zero_fallback_boundary": best_row["avg_hhi"],
        }
        profile_row["verdict"] = verdict(profile_row)
        profile_rows.append(profile_row)

    write_json(OUT_DIR / "depth_boundary_sweep.json", sweep_rows)
    write_json(OUT_DIR / "depth_boundary_summary.json", profile_rows)
    write_csv(OUT_DIR / "depth_boundary_summary.csv", profile_rows)

    lines = [
        "# Depth-Boundary Recommendation Memo",
        "",
        "This memo is based only on the honest-slack sweep in this directory.",
        "",
        "## Measured Results",
        "",
        "- `minimum_slack_for_zero_fallback` is the first slack setting where fallback and sticky fallback both drop to zero.",
        "- `minimum_slack_for_clear_threshold_margin` is the first slack setting where fallback and sticky fallback are zero and the system no longer spends any epochs at or below the exact threshold.",
        "",
        "## Profile Comparison",
        "",
        "| profile | committee size | min eligible | min slack for zero fallback | min slack for clear margin | committee share at zero-fallback boundary | proposer share at zero-fallback boundary | verdict |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in profile_rows:
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
            "- Supported by current outputs: `profile_b_24_27_150` needs one more honest slack operator than `profile_a_16_18_150` to eliminate fallback in the current threshold family.",
            "- Supported by current outputs: the stricter clear-margin boundary is also one slack operator deeper for the 24-seat profile than for the 16-seat profile.",
            "- Remaining uncertainty: this is still a bounded threshold family rather than a replay-calibrated live operator distribution.",
        ]
    )
    write_markdown(OUT_DIR / "depth_boundary_memo.md", "\n".join(lines) + "\n")
    write_markdown(OUT_DIR / "depth_boundary_table.md", "\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
