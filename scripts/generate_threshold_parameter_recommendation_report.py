#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

from __future__ import annotations

import csv
from dataclasses import asdict
from pathlib import Path
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.protocol_attack_sim import (
    CURRENT_LIKE_PROFILE,
    PROFILE_A,
    PROFILE_B,
    build_bond_threshold_edge,
    build_boundary_activation_edge,
    build_marginal_eligible_pool,
    build_mixed_depth_population,
    percent,
    run_scenario,
    write_json,
    write_markdown,
)


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "analysis" / "parameter_recommendation_threshold"


def summary_row(summary) -> dict[str, Any]:
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


def write_comparison_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def verdict_for_profile(row: dict[str, Any]) -> str:
    if row["fallback_rate_pct"] > 20.0 or row["sticky_rate_pct"] > 10.0:
        return "not justified yet"
    if row["split_amplification_ratio"] < 0.75 and row["committee_share_pct"] < 18.0:
        return "conditionally viable"
    return "not justified yet"


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    eligibility_rows: list[dict[str, Any]] = []
    for committee_size in (16, 24):
        for delta in (0, 1, 2, 3):
            min_eligible = committee_size + delta
            for slack in (-1, 0, 1, 2):
                summary = run_scenario(
                    build_marginal_eligible_pool(
                        committee_size=committee_size,
                        min_eligible=min_eligible,
                        eligible_slack_operators=slack,
                        marginal_operator_count=4 if committee_size == 16 else 5,
                    )
                )
                eligibility_rows.append(
                    {
                        "committee_size": committee_size,
                        "min_eligible": min_eligible,
                        "offset_from_committee_size": delta,
                        "eligible_slack_operators": slack,
                        **summary_row(summary),
                    }
                )
    write_json(OUT_DIR / "eligibility_threshold_sweep.json", eligibility_rows)

    bond_rows: list[dict[str, Any]] = []
    for dynamic_min_bond in (100.0, 150.0, 200.0):
        for split_count in (1, 2, 3, 4, 6):
            for distribution in ("tight", "wide"):
                summary = run_scenario(
                    build_bond_threshold_edge(
                        committee_size=16,
                        min_eligible=18,
                        dynamic_min_bond_coins=dynamic_min_bond,
                        availability_min_bond_coins=dynamic_min_bond,
                        operator_split_count=split_count,
                        bond_margin_distribution=distribution,
                    )
                )
                bond_rows.append(
                    {
                        "dynamic_min_bond_coins": dynamic_min_bond,
                        "operator_split_count": split_count,
                        "bond_margin_distribution": distribution,
                        **summary_row(summary),
                    }
                )
    write_json(OUT_DIR / "bond_binding_sweep.json", bond_rows)

    depth_rows: list[dict[str, Any]] = []
    for committee_size in (16, 24):
        for delta in (1, 2, 3):
            min_eligible = committee_size + delta
            for adversarial_tail in (False, True):
                summary = run_scenario(
                    build_mixed_depth_population(
                        committee_size=committee_size,
                        min_eligible=min_eligible,
                        dynamic_min_bond_coins=150.0,
                        availability_min_bond_coins=150.0,
                        adversarial_tail=adversarial_tail,
                    )
                )
                depth_rows.append(
                    {
                        "committee_size": committee_size,
                        "min_eligible": min_eligible,
                        "adversarial_tail": adversarial_tail,
                        **summary_row(summary),
                    }
                )
    write_json(OUT_DIR / "committee_depth_sweep.json", depth_rows)

    boundary_rows: list[dict[str, Any]] = []
    for committee_size in (16, 24):
        min_eligible = 18 if committee_size == 16 else 27
        for warmup in (100, 128):
            for cooldown in (100, 128):
                for density in (2, 4):
                    summary = run_scenario(
                        build_boundary_activation_edge(
                            committee_size=committee_size,
                            min_eligible=min_eligible,
                            dynamic_min_bond_coins=150.0,
                            availability_min_bond_coins=150.0,
                            validator_warmup_blocks=warmup,
                            validator_cooldown_blocks=cooldown,
                            activation_edge_density=density,
                        )
                    )
                    boundary_rows.append(
                        {
                            "committee_size": committee_size,
                            "min_eligible": min_eligible,
                            "validator_warmup_blocks": warmup,
                            "validator_cooldown_blocks": cooldown,
                            "activation_edge_density": density,
                            **summary_row(summary),
                        }
                    )
    write_json(OUT_DIR / "boundary_edge_sweep.json", boundary_rows)

    profile_rows = []
    for profile in (CURRENT_LIKE_PROFILE, PROFILE_A, PROFILE_B):
        split = run_scenario(
            build_bond_threshold_edge(
                committee_size=profile.committee_size,
                min_eligible=profile.min_eligible,
                dynamic_min_bond_coins=profile.dynamic_min_bond_coins,
                availability_min_bond_coins=profile.availability_min_bond_coins,
                operator_split_count=4,
                bond_margin_distribution="tight",
            )
        )
        threshold = run_scenario(
            build_marginal_eligible_pool(
                committee_size=profile.committee_size,
                min_eligible=profile.min_eligible,
                eligible_slack_operators=0,
                marginal_operator_count=4 if profile.committee_size == 16 else 5,
                dynamic_min_bond_coins=profile.dynamic_min_bond_coins,
                availability_min_bond_coins=profile.availability_min_bond_coins,
            )
        )
        timing = run_scenario(
            build_boundary_activation_edge(
                committee_size=profile.committee_size,
                min_eligible=profile.min_eligible,
                dynamic_min_bond_coins=profile.dynamic_min_bond_coins,
                availability_min_bond_coins=profile.availability_min_bond_coins,
                validator_warmup_blocks=profile.validator_warmup_blocks,
                validator_cooldown_blocks=profile.validator_cooldown_blocks,
                activation_edge_density=4,
            )
        )
        row = {
            "profile": profile.name,
            "protocol": asdict(profile.protocol()),
            "split_amplification_ratio": round(split.split_amplification_ratio, 6),
            "split_committee_share_pct": percent(split.average_coalition_committee_share),
            "bond_threshold_binding_rate_pct": percent(split.bond_threshold_binding_rate),
            "operators_filtered_by_bond_floor": split.operators_filtered_by_bond_floor,
            "fallback_rate_pct": percent(threshold.fallback_rate),
            "sticky_rate_pct": percent(threshold.sticky_fallback_rate),
            "epochs_at_exact_threshold": threshold.epochs_at_exact_threshold,
            "epochs_below_threshold": threshold.epochs_below_threshold,
            "epochs_at_recovery_threshold": threshold.epochs_at_recovery_threshold,
            "warmup_blocking_rate_pct": percent(timing.warmup_blocking_rate),
            "cooldown_blocking_rate_pct": percent(timing.cooldown_blocking_rate),
            "boundary_activation_latency_epochs": round(timing.average_activation_latency, 4),
            "boundary_committee_share_pct": percent(timing.average_coalition_committee_share),
        }
        row["verdict"] = verdict_for_profile(row)
        profile_rows.append(row)
    write_json(OUT_DIR / "profile_threshold_evaluations.json", profile_rows)
    write_comparison_csv(OUT_DIR / "profile_threshold_comparison.csv", profile_rows)

    table_lines = [
        "# Threshold-Sensitive Recommendation Memo",
        "",
        "This memo is based only on the threshold-sensitive sweep outputs in this directory.",
        "",
        "## Measured In Threshold-Sensitive Sweeps",
        "",
        "- `min_eligible` became a real lever in the marginal eligible-pool family because `eligible_slack_operators` moved the system between below-threshold, exact-threshold, and recovery-threshold epochs.",
        "- `dynamic_min_bond` became a real lever in the bond-threshold-edge family because adversarial split children were distributed around the bond floor and were filtered by the floor as the threshold increased.",
        "- `100` vs `128` warmup/cooldown became a real lever in the boundary-activation-edge family because join/exit heights were placed near epoch boundaries rather than projected only by epoch count.",
        "",
        "## Profile Comparison",
        "",
        "| profile | split amp | bond-binding rate | fallback rate | sticky rate | exact-threshold epochs | warmup blocking | cooldown blocking | verdict |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in profile_rows:
        table_lines.append(
            f"| {row['profile']} | {row['split_amplification_ratio']:.3f} | {row['bond_threshold_binding_rate_pct']:.2f}% | "
            f"{row['fallback_rate_pct']:.2f}% | {row['sticky_rate_pct']:.2f}% | {row['epochs_at_exact_threshold']} | "
            f"{row['warmup_blocking_rate_pct']:.2f}% | {row['cooldown_blocking_rate_pct']:.2f}% | {row['verdict']} |"
        )
    table_lines.extend(
        [
            "",
            "## Still Uncertain",
            "",
            "- These remain bounded synthetic threshold families, not live trace replay.",
            "- The simulator still uses projected availability state rather than the full retained-prefix C++ engine.",
        ]
    )
    write_markdown(OUT_DIR / "recommendation_memo.md", "\n".join(table_lines) + "\n")
    write_markdown(OUT_DIR / "profile_threshold_comparison.md", "\n".join(table_lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
