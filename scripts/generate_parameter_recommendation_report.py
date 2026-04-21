#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.protocol_attack_sim import (
    CURRENT_LIKE_PROFILE,
    PROFILE_A,
    PROFILE_B,
    ScenarioSummary,
    apply_override,
    build_large_availability_griefing_adversary,
    build_large_join_exit_boundary_adversary,
    build_large_split_operator_adversary,
    build_large_sticky_fallback_threshold_manipulator,
    candidate_profiles,
    percent,
    render_markdown_report,
    run_scenario,
    write_json,
    write_markdown,
)


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "analysis" / "parameter_recommendation"


def summary_row(summary: ScenarioSummary) -> dict[str, Any]:
    return {
        "scenario": summary.scenario,
        "strategy_family": summary.strategy_family,
        "bond_share_pct": percent(summary.coalition_bond_share),
        "committee_share_pct": percent(summary.average_coalition_committee_share),
        "proposer_share_pct": percent(summary.proposer_share),
        "committee_share_delta_vs_bond_share_pct": percent(summary.committee_share_delta_vs_bond_share),
        "split_amplification_ratio": round(summary.split_amplification_ratio, 6),
        "fallback_rate_pct": percent(summary.fallback_rate),
        "sticky_rate_pct": percent(summary.sticky_fallback_rate),
        "avg_fallback_duration_epochs": round(summary.average_fallback_duration, 4),
        "max_fallback_duration_epochs": summary.max_fallback_duration,
        "avg_recovery_time_epochs": round(summary.average_recovery_time, 4),
        "avg_hhi": round(summary.average_hhi, 6),
        "avg_top1_pct": percent(summary.average_top1_share),
        "avg_top3_pct": percent(summary.average_top3_share),
        "max_operator_committee_share_pct": percent(summary.max_operator_committee_share),
        "avg_activation_latency_epochs": round(summary.average_activation_latency, 4),
        "eligibility_churn_events": summary.eligibility_churn_events,
        "epochs_at_exact_threshold": summary.epochs_at_exact_threshold,
        "epochs_below_threshold": summary.epochs_below_threshold,
        "epochs_at_recovery_threshold": summary.epochs_at_recovery_threshold,
        "fallback_entry_count": summary.fallback_entry_count,
        "sticky_fallback_entry_count": summary.sticky_fallback_entry_count,
        "recovery_from_sticky_count": summary.recovery_from_sticky_count,
        "marginal_operator_committee_share_pct": percent(summary.marginal_operator_committee_share),
        "marginal_operator_eligibility_churn": summary.marginal_operator_eligibility_churn,
        "operators_filtered_by_bond_floor": summary.operators_filtered_by_bond_floor,
        "operators_filtered_by_availability": summary.operators_filtered_by_availability,
        "bond_threshold_binding_rate_pct": percent(summary.bond_threshold_binding_rate),
        "warmup_blocking_rate_pct": percent(summary.warmup_blocking_rate),
        "cooldown_blocking_rate_pct": percent(summary.cooldown_blocking_rate),
    }


def profile_verdict(profile_name: str, row: dict[str, Any]) -> str:
    if row["fallback_rate_pct"] > 5.0 or row["sticky_rate_pct"] > 5.0:
        return "not justified yet"
    if row["split_amplification_ratio"] <= 1.15 and row["committee_share_delta_vs_bond_share_pct"] <= 5.0:
        return "preferred now" if profile_name == PROFILE_A.name else "conditionally viable"
    return "conditionally viable"


def write_comparison_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    import csv

    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "profile",
        "split_committee_share_pct",
        "split_proposer_share_pct",
        "split_amplification_ratio",
        "split_avg_hhi",
        "fallback_rate_pct",
        "sticky_rate_pct",
        "avg_fallback_duration_epochs",
        "avg_recovery_time_epochs",
        "griefing_fallback_rate_pct",
        "griefing_sticky_rate_pct",
        "griefing_committee_share_pct",
        "boundary_avg_activation_latency_epochs",
        "boundary_committee_share_pct",
        "boundary_eligibility_churn_events",
        "verdict",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def build_profile_evaluation(profile) -> dict[str, Any]:
    split = run_scenario(apply_override(build_large_split_operator_adversary(
        committee_size=profile.committee_size,
        min_eligible=profile.min_eligible,
        dynamic_min_bond_coins=profile.dynamic_min_bond_coins,
        availability_min_bond_coins=profile.availability_min_bond_coins,
        validator_warmup_blocks=profile.validator_warmup_blocks,
        validator_cooldown_blocks=profile.validator_cooldown_blocks,
        split_count=4,
    ), "adversary_bond_share", 0.25))
    fallback = run_scenario(build_large_sticky_fallback_threshold_manipulator(
        committee_size=profile.committee_size,
        min_eligible=profile.min_eligible,
        dynamic_min_bond_coins=profile.dynamic_min_bond_coins,
        availability_min_bond_coins=profile.availability_min_bond_coins,
        validator_warmup_blocks=profile.validator_warmup_blocks,
        validator_cooldown_blocks=profile.validator_cooldown_blocks,
    ))
    grief = run_scenario(apply_override(build_large_availability_griefing_adversary(
        committee_size=profile.committee_size,
        min_eligible=profile.min_eligible,
        dynamic_min_bond_coins=profile.dynamic_min_bond_coins,
        availability_min_bond_coins=profile.availability_min_bond_coins,
        validator_warmup_blocks=profile.validator_warmup_blocks,
        validator_cooldown_blocks=profile.validator_cooldown_blocks,
    ), "adversary_bond_share", 0.25))
    boundary = run_scenario(build_large_join_exit_boundary_adversary(
        committee_size=profile.committee_size,
        min_eligible=profile.min_eligible,
        dynamic_min_bond_coins=profile.dynamic_min_bond_coins,
        availability_min_bond_coins=profile.availability_min_bond_coins,
        validator_warmup_blocks=profile.validator_warmup_blocks,
        validator_cooldown_blocks=profile.validator_cooldown_blocks,
    ))
    return {
        "profile": profile.name,
        "protocol": asdict(profile.protocol()),
        "split": summary_row(split),
        "fallback": summary_row(fallback),
        "griefing": summary_row(grief),
        "boundary": summary_row(boundary),
    }


def build_measured_memo(profile_rows: list[dict[str, Any]]) -> str:
    preferred = next((row for row in profile_rows if row["verdict"] == "preferred now"), None)
    lines: list[str] = [
        "# Parameter Recommendation Memo",
        "",
        "This memo is based only on bounded simulator outputs produced in this run.",
        "",
        "## Measured Result",
        "",
        f"- Preferred profile by current bounded outputs: `{preferred['profile']}`." if preferred else "- No profile satisfied the current automatic preferred-now gate.",
        "- The table below is the authoritative summary for this run.",
        "",
        "## Inference From Measured Result",
        "",
        "- Use the decision table below to compare concentration, fallback, and timing tradeoffs without extrapolating beyond the bounded scenario family.",
        "",
        "## Remaining Uncertainty",
        "",
        "- These outputs come from the simulator's bounded large-population scenario family, not from a live network trace or full retained-prefix audit replay.",
        "- Any profile that depends on materially deeper honest operator pools remains unvalidated outside the current bounded assumptions.",
        "",
        "## Decision Table",
        "",
        "| profile | split amp | split committee share | fallback rate | sticky rate | griefing fallback rate | boundary activation latency | verdict |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in profile_rows:
        lines.append(
            f"| {row['profile']} | {row['split_amplification_ratio']:.3f} | {row['split_committee_share_pct']:.2f}% | "
            f"{row['fallback_rate_pct']:.2f}% | {row['sticky_rate_pct']:.2f}% | {row['griefing_fallback_rate_pct']:.2f}% | "
            f"{row['boundary_avg_activation_latency_epochs']:.2f} | {row['verdict']} |"
        )
    lines.extend(
        [
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    split_results = []
    for committee_size in (16, 24):
        min_eligible = committee_size + 2
        for dynamic_min_bond in (100.0, 150.0, 200.0):
            for split_count in (1, 2, 3, 4, 6):
                summary = run_scenario(
                    apply_override(
                        build_large_split_operator_adversary(
                            committee_size=committee_size,
                            min_eligible=min_eligible,
                            dynamic_min_bond_coins=dynamic_min_bond,
                            availability_min_bond_coins=dynamic_min_bond,
                            validator_warmup_blocks=100,
                            validator_cooldown_blocks=100,
                            split_count=split_count,
                        ),
                        "adversary_bond_share",
                        0.25,
                    )
                )
                split_results.append(
                    {
                        "committee_size": committee_size,
                        "operator_split_count": split_count,
                        "dynamic_min_bond_coins": dynamic_min_bond,
                        **summary_row(summary),
                    }
                )
    write_json(OUT_DIR / "split_amplification_sweep.json", split_results)

    fallback_results = []
    for committee_size in (16, 24):
        for delta in (0, 1, 2, 3):
            min_eligible = committee_size + delta
            summary = run_scenario(
                build_large_sticky_fallback_threshold_manipulator(
                    committee_size=committee_size,
                    min_eligible=min_eligible,
                    dynamic_min_bond_coins=150.0,
                    availability_min_bond_coins=150.0,
                    validator_warmup_blocks=100 if committee_size == 16 else 128,
                    validator_cooldown_blocks=100 if committee_size == 16 else 128,
                )
            )
            fallback_results.append(
                {
                    "committee_size": committee_size,
                    "min_eligible": min_eligible,
                    "offset_from_committee_size": delta,
                    **summary_row(summary),
                }
            )
    write_json(OUT_DIR / "fallback_stability_sweep.json", fallback_results)

    grief_results = []
    for profile in candidate_profiles().values():
        for share in (0.2, 0.25, 0.3, 0.35):
            summary = run_scenario(
                apply_override(
                    build_large_availability_griefing_adversary(
                        committee_size=profile.committee_size,
                        min_eligible=profile.min_eligible,
                        dynamic_min_bond_coins=profile.dynamic_min_bond_coins,
                        availability_min_bond_coins=profile.availability_min_bond_coins,
                        validator_warmup_blocks=profile.validator_warmup_blocks,
                        validator_cooldown_blocks=profile.validator_cooldown_blocks,
                    ),
                    "adversary_bond_share",
                    share,
                )
            )
            grief_results.append(
                {
                    "profile": profile.name,
                    "adversary_bond_share": share,
                    **summary_row(summary),
                }
            )
    write_json(OUT_DIR / "availability_griefing_sweep.json", grief_results)

    boundary_results = []
    for committee_size in (16, 24):
        min_eligible = 18 if committee_size == 16 else 27
        dynamic_min_bond = 150.0
        availability_min_bond = 150.0
        for warmup in (100, 128):
            for cooldown in (100, 128):
                summary = run_scenario(
                    build_large_join_exit_boundary_adversary(
                        committee_size=committee_size,
                        min_eligible=min_eligible,
                        dynamic_min_bond_coins=dynamic_min_bond,
                        availability_min_bond_coins=availability_min_bond,
                        validator_warmup_blocks=warmup,
                        validator_cooldown_blocks=cooldown,
                    )
                )
                boundary_results.append(
                    {
                        "committee_size": committee_size,
                        "min_eligible": min_eligible,
                        "validator_warmup_blocks": warmup,
                        "validator_cooldown_blocks": cooldown,
                        **summary_row(summary),
                    }
                )
    write_json(OUT_DIR / "boundary_timing_sweep.json", boundary_results)

    profile_evaluations = [build_profile_evaluation(profile) for profile in candidate_profiles().values()]
    write_json(OUT_DIR / "profile_evaluations.json", profile_evaluations)

    comparison_rows = []
    for evaluation in profile_evaluations:
        row = {
            "profile": evaluation["profile"],
            "split_committee_share_pct": evaluation["split"]["committee_share_pct"],
            "split_proposer_share_pct": evaluation["split"]["proposer_share_pct"],
            "split_amplification_ratio": evaluation["split"]["split_amplification_ratio"],
            "split_avg_hhi": evaluation["split"]["avg_hhi"],
            "fallback_rate_pct": evaluation["fallback"]["fallback_rate_pct"],
            "sticky_rate_pct": evaluation["fallback"]["sticky_rate_pct"],
            "avg_fallback_duration_epochs": evaluation["fallback"]["avg_fallback_duration_epochs"],
            "avg_recovery_time_epochs": evaluation["fallback"]["avg_recovery_time_epochs"],
            "griefing_fallback_rate_pct": evaluation["griefing"]["fallback_rate_pct"],
            "griefing_sticky_rate_pct": evaluation["griefing"]["sticky_rate_pct"],
            "griefing_committee_share_pct": evaluation["griefing"]["committee_share_pct"],
            "boundary_avg_activation_latency_epochs": evaluation["boundary"]["avg_activation_latency_epochs"],
            "boundary_committee_share_pct": evaluation["boundary"]["committee_share_pct"],
            "boundary_eligibility_churn_events": evaluation["boundary"]["eligibility_churn_events"],
        }
        row["verdict"] = profile_verdict(evaluation["profile"], row)
        comparison_rows.append(row)
    write_comparison_csv(OUT_DIR / "profile_comparison.csv", comparison_rows)
    memo = build_measured_memo(comparison_rows)
    write_markdown(OUT_DIR / "recommendation_memo.md", memo)
    write_markdown(OUT_DIR / "profile_comparison.md", render_markdown_report([run_scenario(
        build_large_split_operator_adversary(
            committee_size=profile.committee_size,
            min_eligible=profile.min_eligible,
            dynamic_min_bond_coins=profile.dynamic_min_bond_coins,
            availability_min_bond_coins=profile.availability_min_bond_coins,
            validator_warmup_blocks=profile.validator_warmup_blocks,
            validator_cooldown_blocks=profile.validator_cooldown_blocks,
            split_count=4,
        )
    ) for profile in candidate_profiles().values()]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
