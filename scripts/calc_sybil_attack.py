# SPDX-License-Identifier: MIT

"""
Historical sybil/economics exploration script.

This file predates the canonical finalized-record and operator-grouped
quantitative model implemented in `scripts/attack_model.py`.

It is retained for reference, but now reuses the current v2+ ticket bonus and
difficulty-control assumptions from `scripts/sybil_model.py` so its output can
still be compared against the live finalized-committee path.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from scripts.sybil_model import (
    BASE_UNITS_PER_COIN,
    DEFAULT_TICKET_DIFFICULTY_BITS,
    DEFAULT_TICKET_BONUS_CAP_BPS,
    EpochMetrics,
    adjust_ticket_difficulty_bits,
    adjust_ticket_difficulty_bits_v2,
    effective_weight,
    simulate_epochs,
    split_bond,
    ticket_pow_bonus_bps_from_zero_bits,
)


@dataclass(frozen=True)
class SimulationConfig:
    honest_total_bond_coins: float = 100_000.0
    attacker_total_bond_coins: float = 25_000.0
    honest_split_count: int = 256
    attacker_split_count: int = 16
    honest_distribution: str = "equal"
    attacker_distribution: str = "equal"
    committee_size: int = 128
    epochs: int = 1000
    seed: int = 42
    adaptive_difficulty: bool = True
    initial_difficulty_bits: int = DEFAULT_TICKET_DIFFICULTY_BITS
    fixed_difficulty_bits: int | None = None
    epoch_average_round_x1000: int = 0
    epoch_average_participation_bps: int = 10_000
    attacker_ticket_sample_multiplier: float = 1.0
    honest_ticket_sample_multiplier: float = 1.0
    attacker_split_sweep: tuple[int, ...] = ()
    json_out: str | None = None
    csv_out: str | None = None


def coins_to_units(coins: float) -> int:
    return int(round(coins * BASE_UNITS_PER_COIN))


def mean_or_zero(values: list[float]) -> float:
    return statistics.fmean(values) if values else 0.0


def percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    pos = (len(sorted_values) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = pos - lo
    return sorted_values[lo] * (1.0 - frac) + sorted_values[hi] * frac


def parse_positive_int_csv(text: str) -> tuple[int, ...]:
    out = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        value = int(part)
        if value <= 0:
            raise ValueError("split sweep entries must be positive")
        out.append(value)
    return tuple(out)


def build_epoch_metrics_schedule(config: SimulationConfig) -> list[EpochMetrics]:
    return [
        EpochMetrics(
            average_round_x1000=config.epoch_average_round_x1000,
            average_participation_bps=config.epoch_average_participation_bps,
        )
        for _ in range(config.epochs)
    ]


def scenario_label(selection_mode: str, attacker_operator_mode: str) -> str:
    if selection_mode == "identity_weighted":
        return "identity_weighted_baseline"
    if attacker_operator_mode == "same_operator":
        return "operator_aggregated_same_operator"
    return "operator_aggregated_distinct_operators"


def run_single_scenario(
    config: SimulationConfig,
    attacker_split_count: int,
    *,
    selection_mode: str,
    attacker_operator_mode: str,
) -> dict[str, Any]:
    attacker_units = coins_to_units(config.attacker_total_bond_coins)
    honest_units = coins_to_units(config.honest_total_bond_coins)
    attacker_bonds = split_bond(attacker_units, attacker_split_count, config.attacker_distribution)
    honest_bonds = split_bond(honest_units, config.honest_split_count, config.honest_distribution)
    results = simulate_epochs(
        attacker_bonds=attacker_bonds,
        honest_bonds=honest_bonds,
        committee_size=config.committee_size,
        epoch_count=config.epochs,
        initial_difficulty_bits=config.initial_difficulty_bits,
        adaptive_difficulty=config.adaptive_difficulty,
        fixed_difficulty_bits=config.fixed_difficulty_bits,
        attacker_ticket_sample_multiplier=config.attacker_ticket_sample_multiplier,
        honest_ticket_sample_multiplier=config.honest_ticket_sample_multiplier,
        epoch_metrics_schedule=build_epoch_metrics_schedule(config),
        attacker_operator_mode=attacker_operator_mode,
        honest_operator_mode="distinct_operators",
        selection_mode=selection_mode,
        seed=config.seed + attacker_split_count,
    )

    committee_shares = [r.attacker_committee_share for r in results]
    proposer_shares = [1.0 if r.attacker_round0_proposer else 0.0 for r in results]
    reward_shares = [r.attacker_reward_share for r in results]
    difficulty_series = [float(r.difficulty_bits) for r in results]
    without_pow_shares = [r.attacker_committee_share_without_pow for r in results]
    bond_share = results[0].attacker_bond_share if results else 0.0
    effective_weight_share = results[0].attacker_effective_weight_share if results else 0.0
    operator_share = results[0].attacker_operator_share if results else 0.0
    split_gain = (mean_or_zero(committee_shares) / bond_share) if bond_share > 0 else 0.0
    pow_delta = mean_or_zero(committee_shares) - mean_or_zero(without_pow_shares)

    return {
        "scenario": scenario_label(selection_mode, attacker_operator_mode),
        "selection_mode": selection_mode,
        "attacker_operator_mode": attacker_operator_mode,
        "attacker_split_count": attacker_split_count,
        "attacker_total_bond_coins": config.attacker_total_bond_coins,
        "honest_total_bond_coins": config.honest_total_bond_coins,
        "attacker_bond_share": bond_share,
        "attacker_operator_share": operator_share,
        "attacker_effective_weight_share": effective_weight_share,
        "attacker_committee_share_mean": mean_or_zero(committee_shares),
        "attacker_committee_share_p95": percentile(sorted(committee_shares), 0.95),
        "attacker_proposer_share_mean": mean_or_zero(proposer_shares),
        "attacker_reward_share_mean": mean_or_zero(reward_shares),
        "attacker_quorum_probability": mean_or_zero([1.0 if r.attacker_quorum else 0.0 for r in results]),
        "attacker_committee_share_without_pow_mean": mean_or_zero(without_pow_shares),
        "pow_committee_share_delta": pow_delta,
        "difficulty_bits_mean": mean_or_zero(difficulty_series),
        "difficulty_bits_last": difficulty_series[-1] if difficulty_series else 0.0,
        "max_attacker_bonus_bps_mean": mean_or_zero([float(r.max_attacker_bonus_bps) for r in results]),
        "max_honest_bonus_bps_mean": mean_or_zero([float(r.max_honest_bonus_bps) for r in results]),
        "relative_committee_gain_vs_bond_share": split_gain,
        "attacker_validator_count": attacker_split_count,
        "honest_validator_count": config.honest_split_count,
    }


def run_simulation(config: SimulationConfig) -> dict[str, Any]:
    split_counts = config.attacker_split_sweep or (config.attacker_split_count,)
    scenarios: list[dict[str, Any]] = []
    for split_count in split_counts:
        scenarios.append(
            run_single_scenario(
                config,
                split_count,
                selection_mode="identity_weighted",
                attacker_operator_mode="distinct_operators",
            )
        )
        scenarios.append(
            run_single_scenario(
                config,
                split_count,
                selection_mode="operator_aggregated",
                attacker_operator_mode="same_operator",
            )
        )
        scenarios.append(
            run_single_scenario(
                config,
                split_count,
                selection_mode="operator_aggregated",
                attacker_operator_mode="distinct_operators",
            )
        )

    baseline_by_scenario: dict[str, dict[str, Any]] = {}
    for row in scenarios:
        baseline_by_scenario.setdefault(row["scenario"], row)
    for row in scenarios:
        baseline = baseline_by_scenario[row["scenario"]]
        row["relative_gain_vs_first_split"] = (
            row["attacker_committee_share_mean"] / baseline["attacker_committee_share_mean"]
            if baseline["attacker_committee_share_mean"] > 0
            else 0.0
        )

    return {
        "config": asdict(config),
        "derived_protocol_constants": {
            "effective_weight_formula": "max(1, floor(sqrt(total_operator_bond_units)))",
            "ticket_bonus_cap_bps": DEFAULT_TICKET_BONUS_CAP_BPS,
            "default_difficulty_bits": DEFAULT_TICKET_DIFFICULTY_BITS,
            "example_bonus_at_threshold_bps": ticket_pow_bonus_bps_from_zero_bits(
                DEFAULT_TICKET_DIFFICULTY_BITS, DEFAULT_TICKET_DIFFICULTY_BITS
            ),
            "example_effective_weight_1000_coins": effective_weight(1000 * BASE_UNITS_PER_COIN),
            "difficulty_preview_next_epoch": adjust_ticket_difficulty_bits_v2(
                config.initial_difficulty_bits,
                config.attacker_split_count + config.honest_split_count,
                config.committee_size,
                config.epoch_average_round_x1000,
                config.epoch_average_participation_bps,
                0,
                0,
            )[0],
            "difficulty_preview_next_epoch_single_step": adjust_ticket_difficulty_bits(
                config.initial_difficulty_bits,
                config.attacker_split_count + config.honest_split_count,
                config.committee_size,
                config.epoch_average_round_x1000,
                config.epoch_average_participation_bps,
            ),
        },
        "scenarios": scenarios,
    }


def print_summary(summary: dict[str, Any]) -> None:
    config = summary["config"]
    print("Live Finalis Sybil Simulation")
    print()
    print("Protocol mirror")
    print("  Committee truth: finalized checkpoint")
    print("  Primary weight: sqrt(total operator bond)")
    print("  Ticket PoW role: bounded secondary modifier, one contribution per operator")
    print(f"  Adaptive difficulty: {'on' if config['adaptive_difficulty'] else 'off'}")
    print()
    print(
        "scenario                              split  bond_share  oper_share  eff_wt    committee  proposer  reward  no_pow  pow_d"
    )
    for row in summary["scenarios"]:
        print(
            f"{row['scenario'][:35]:<35}  "
            f"{row['attacker_split_count']:>5}  "
            f"{row['attacker_bond_share'] * 100:>9.2f}%  "
            f"{row['attacker_operator_share'] * 100:>9.2f}%  "
            f"{row['attacker_effective_weight_share'] * 100:>6.2f}%  "
            f"{row['attacker_committee_share_mean'] * 100:>8.2f}%  "
            f"{row['attacker_proposer_share_mean'] * 100:>7.2f}%  "
            f"{row['attacker_reward_share_mean'] * 100:>6.2f}%  "
            f"{row['attacker_committee_share_without_pow_mean'] * 100:>6.2f}%  "
            f"{row['pow_committee_share_delta'] * 100:>5.2f}%"
        )


def maybe_write_json(path: str | None, summary: dict[str, Any]) -> None:
    if not path:
        return
    Path(path).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def maybe_write_csv(path: str | None, summary: dict[str, Any]) -> None:
    if not path:
        return
    rows = summary["scenarios"]
    if not rows:
        return
    with Path(path).open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monte Carlo simulator aligned to the live operator-aggregated Finalis model.")
    parser.add_argument("--honest-total-bond-coins", type=float, default=SimulationConfig.honest_total_bond_coins)
    parser.add_argument("--attacker-total-bond-coins", type=float, default=SimulationConfig.attacker_total_bond_coins)
    parser.add_argument("--honest-split-count", type=int, default=SimulationConfig.honest_split_count)
    parser.add_argument("--attacker-split-count", type=int, default=SimulationConfig.attacker_split_count)
    parser.add_argument("--attacker-split-sweep", type=str, default="")
    parser.add_argument("--honest-distribution", choices=["equal", "front_loaded", "tail_loaded"], default=SimulationConfig.honest_distribution)
    parser.add_argument("--attacker-distribution", choices=["equal", "front_loaded", "tail_loaded"], default=SimulationConfig.attacker_distribution)
    parser.add_argument("--committee-size", type=int, default=SimulationConfig.committee_size)
    parser.add_argument("--epochs", type=int, default=SimulationConfig.epochs)
    parser.add_argument("--seed", type=int, default=SimulationConfig.seed)
    parser.add_argument("--adaptive-difficulty", action="store_true", default=SimulationConfig.adaptive_difficulty)
    parser.add_argument("--no-adaptive-difficulty", action="store_false", dest="adaptive_difficulty")
    parser.add_argument("--initial-difficulty-bits", type=int, default=SimulationConfig.initial_difficulty_bits)
    parser.add_argument("--fixed-difficulty-bits", type=int, default=None)
    parser.add_argument("--epoch-average-round-x1000", type=int, default=SimulationConfig.epoch_average_round_x1000)
    parser.add_argument("--epoch-average-participation-bps", type=int, default=SimulationConfig.epoch_average_participation_bps)
    parser.add_argument("--attacker-ticket-sample-multiplier", type=float, default=SimulationConfig.attacker_ticket_sample_multiplier)
    parser.add_argument("--honest-ticket-sample-multiplier", type=float, default=SimulationConfig.honest_ticket_sample_multiplier)
    parser.add_argument("--json-out", type=str, default=None)
    parser.add_argument("--csv-out", type=str, default=None)
    return parser.parse_args()


def build_config(args: argparse.Namespace) -> SimulationConfig:
    sweep = parse_positive_int_csv(args.attacker_split_sweep) if args.attacker_split_sweep else ()
    return SimulationConfig(
        honest_total_bond_coins=args.honest_total_bond_coins,
        attacker_total_bond_coins=args.attacker_total_bond_coins,
        honest_split_count=args.honest_split_count,
        attacker_split_count=args.attacker_split_count,
        honest_distribution=args.honest_distribution,
        attacker_distribution=args.attacker_distribution,
        committee_size=args.committee_size,
        epochs=args.epochs,
        seed=args.seed,
        adaptive_difficulty=args.adaptive_difficulty,
        initial_difficulty_bits=args.initial_difficulty_bits,
        fixed_difficulty_bits=args.fixed_difficulty_bits,
        epoch_average_round_x1000=args.epoch_average_round_x1000,
        epoch_average_participation_bps=args.epoch_average_participation_bps,
        attacker_ticket_sample_multiplier=args.attacker_ticket_sample_multiplier,
        honest_ticket_sample_multiplier=args.honest_ticket_sample_multiplier,
        attacker_split_sweep=sweep,
        json_out=args.json_out,
        csv_out=args.csv_out,
    )


def main() -> None:
    args = parse_args()
    config = build_config(args)
    summary = run_simulation(config)
    print_summary(summary)
    maybe_write_json(config.json_out, summary)
    maybe_write_csv(config.csv_out, summary)


if __name__ == "__main__":
    main()
