#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

"""
Attack/economics model for the current operator-grouped finalized-committee path.

Defaults here should track the live v2+ ticket bonus schedule closely enough to
make comparative sweeps meaningful against current `finalis-core` behavior.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import json
import math
import os
import random
from dataclasses import asdict, dataclass
from functools import cmp_to_key
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

try:
    import matplotlib.pyplot as plt
except ImportError as exc:  # pragma: no cover
    raise SystemExit("matplotlib is required for scripts/attack_model.py") from exc


BASE_UNITS_PER_COIN = 100_000_000
DEFAULT_TARGET_VALIDATORS = 16
DEFAULT_MIN_BOND_COINS = 100.0
DEFAULT_MIN_BOND_FLOOR_COINS = 50.0
DEFAULT_MIN_BOND_CEILING_COINS = 500.0
DEFAULT_CAP_MULTIPLE = 10.0
DEFAULT_TICKET_BONUS_CAP_BPS = 2_500
DEFAULT_TICKET_DIFFICULTY_BITS = 8
DEFAULT_TICKET_ATTEMPTS = 4096
DEFAULT_AVERAGE_BOND_MULTIPLE = 10.0
DEFAULT_POWERLAW_ALPHA = 1.2
DEFAULT_THRESHOLD_SWARM_MARGIN = 0.05
DEFAULT_ROUND_HORIZON = 8
DEFAULT_FIRST_ROUND_WINDOW = 3
DEFAULT_MIN_BOND_SWEEP = (50.0, 75.0, 100.0, 125.0, 150.0, 200.0)
DEFAULT_CAP_MULTIPLE_SWEEP = (4.0, 6.0, 8.0, 10.0, 12.0, 16.0)
DEFAULT_FAMILY_COMPARISON = ("current", "threshold_sqrt", "threshold_seatbudget_sqrt")
DEFAULT_SPLIT_AMPLIFICATION_POINTS = (8, 16)


@dataclass(frozen=True)
class AttackModelConfig:
    committee_size: int
    operators: int
    adversary_bond_share: float
    split_count: int
    distribution: str
    ticket_mode: str
    economics_model: str
    min_bond_coins: float
    cap_multiple: float
    runs: int
    p_online: float
    p_delivery: float
    p_proposer_live: float
    output_dir: Path
    seed: int | None
    jobs: int = 1
    quorum_threshold: int | None = None
    target_validators: int = DEFAULT_TARGET_VALIDATORS
    min_bond_floor_coins: float = DEFAULT_MIN_BOND_FLOOR_COINS
    min_bond_ceiling_coins: float = DEFAULT_MIN_BOND_CEILING_COINS
    ticket_bonus_cap_bps: int = DEFAULT_TICKET_BONUS_CAP_BPS
    ticket_difficulty_bits: int = DEFAULT_TICKET_DIFFICULTY_BITS
    ticket_attempts: int = DEFAULT_TICKET_ATTEMPTS
    average_bond_multiple: float = DEFAULT_AVERAGE_BOND_MULTIPLE
    powerlaw_alpha: float = DEFAULT_POWERLAW_ALPHA
    threshold_swarm_margin: float = DEFAULT_THRESHOLD_SWARM_MARGIN
    round_horizon: int = DEFAULT_ROUND_HORIZON
    first_round_window: int = DEFAULT_FIRST_ROUND_WINDOW
    min_bond_sweep: tuple[float, ...] = DEFAULT_MIN_BOND_SWEEP
    cap_multiple_sweep: tuple[float, ...] = DEFAULT_CAP_MULTIPLE_SWEEP


@dataclass(frozen=True)
class Operator:
    operator_id: str
    is_adversary: bool
    raw_bond_units: int
    active: bool
    threshold_bond_units: int
    effective_bond_units: int
    effective_weight: int
    ticket_bonus_bps: int
    selection_strength: int


@dataclass(frozen=True)
class ViabilityPoint:
    bond_multiple: float
    raw_bond_coins: float
    active: bool
    effective_bond_coins: float
    effective_weight: int
    selection_strength: int


@dataclass(frozen=True)
class AnalyticalResult:
    economics_model: str
    committee_size: int
    quorum_threshold: int
    halt_threshold: int
    safety_break_threshold: int
    byzantine_risk_threshold: int
    active_operator_count: int
    threshold_bond_coins: float
    cap_bond_coins: float
    expected_adversarial_seats: float
    expected_adversarial_proposer_share: float


@dataclass(frozen=True)
class MonteCarloResult:
    expected_adversarial_seats: float
    probability_halt: float
    probability_safety_break: float
    probability_byzantine_risk: float
    expected_adversarial_proposer_share: float
    probability_adversary_proposer_in_first_window: float
    first_window_rounds: int
    expected_rounds_to_finalization: float | None
    probability_finalize_within_horizon: float
    stall_probability: float
    expected_ticket_bonus_bps_adversary: float
    expected_ticket_bonus_bps_honest: float
    expected_strength_share_adversary: float
    expected_committee_top1_strength_share: float
    expected_committee_top3_strength_share: float
    expected_committee_strength_hhi: float


@dataclass(frozen=True)
class MonteCarloChunkResult:
    runs: int
    first_window_rounds: int
    adversarial_seat_sum: float
    halt_events: int
    safety_events: int
    byzantine_events: int
    adversarial_proposer_events: int
    early_proposer_events: int
    finalized_round_count: int
    finalized_round_sum: float
    stall_count: int
    strength_share_sum: float
    adv_bonus_sum: float
    honest_bonus_sum: float
    top1_share_sum: float
    top3_share_sum: float
    hhi_sum: float


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def positive_int(text: str) -> int:
    value = int(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def positive_int_or_zero(text: str) -> int:
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return value


def positive_float(text: str) -> float:
    value = float(text)
    if value <= 0.0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def bounded_probability(text: str) -> float:
    value = float(text)
    if value < 0.0 or value > 1.0:
        raise argparse.ArgumentTypeError("must be in [0, 1]")
    return value


def bounded_share(text: str) -> float:
    value = float(text)
    if value <= 0.0 or value >= 1.0:
        raise argparse.ArgumentTypeError("must be in (0, 1)")
    return value


def parse_float_csv(text: str) -> tuple[float, ...]:
    out: list[float] = []
    for part in text.split(","):
        item = part.strip()
        if not item:
            continue
        value = float(item)
        if value <= 0.0:
            raise argparse.ArgumentTypeError("sweep values must be positive")
        out.append(value)
    if not out:
        raise argparse.ArgumentTypeError("expected at least one sweep value")
    return tuple(out)


def quorum_threshold(committee_size: int) -> int:
    return (2 * committee_size) // 3 + 1


def halt_threshold(committee_size: int, quorum_size: int) -> int:
    return committee_size - quorum_size + 1


def safety_break_threshold(quorum_size: int) -> int:
    return quorum_size


def byzantine_risk_threshold(committee_size: int) -> int:
    return math.ceil(committee_size / 3.0)


def int_sqrt(value: int) -> int:
    return math.isqrt(max(0, value))


def clamp(value: float, lo: float, hi: float) -> float:
    return min(hi, max(lo, value))


def coins_to_units(coins: float) -> int:
    return max(0, int(round(coins * BASE_UNITS_PER_COIN)))


def units_to_coins(units: int) -> float:
    return float(units) / float(BASE_UNITS_PER_COIN)


def hash64_prefix(hash_bytes: bytes) -> int:
    return int.from_bytes(hash_bytes[:8], "big")


def leading_zero_bits_u64(value: int) -> int:
    if value == 0:
        return 64
    return 64 - value.bit_length()


def sample_best_zero_bits(attempts: int, rng: random.Random) -> int:
    attempts = max(1, attempts)
    u = (rng.getrandbits(64) + 1) / float(1 << 64)
    min_uniform = 1.0 - math.pow(1.0 - u, 1.0 / attempts)
    best_hash64 = min((1 << 64) - 1, max(0, int(min_uniform * (1 << 64))))
    return leading_zero_bits_u64(best_hash64)


def ticket_bonus_bps_from_zero_bits(zero_bits: int, difficulty_bits: int, cap_bps: int) -> int:
    if zero_bits < difficulty_bits:
        return 0
    surplus = zero_bits - difficulty_bits
    smooth = int_sqrt(surplus + 1)
    return min(cap_bps, 500 + 400 * smooth)


def adjusted_ticket_bonus_bps(raw_bond_units: int, ticket_bonus_bps: int) -> int:
    bonded_coins = max(1, raw_bond_units // BASE_UNITS_PER_COIN)
    bonus_scale = 1 + int_sqrt(bonded_coins)
    return max(0, ticket_bonus_bps) // bonus_scale


def current_threshold_bond_coins(config: AttackModelConfig, active_operator_count: int) -> float:
    scaled = config.min_bond_coins * math.sqrt(config.target_validators / max(1, active_operator_count))
    return clamp(scaled, config.min_bond_floor_coins, config.min_bond_ceiling_coins)


def threshold_bond_coins(config: AttackModelConfig, active_operator_count: int) -> float:
    if config.economics_model == "current":
        return current_threshold_bond_coins(config, active_operator_count)
    return config.min_bond_coins


def cap_bond_coins(config: AttackModelConfig, active_operator_count: int) -> float:
    return threshold_bond_coins(config, active_operator_count) * config.cap_multiple


def operator_profile(config: AttackModelConfig, active_operator_count: int, raw_bond_units: int) -> tuple[bool, int, int, int]:
    threshold_units = coins_to_units(threshold_bond_coins(config, active_operator_count))
    cap_units = coins_to_units(cap_bond_coins(config, active_operator_count))
    if raw_bond_units < threshold_units:
        return False, threshold_units, min(raw_bond_units, cap_units), 0
    effective_units = min(raw_bond_units, cap_units)
    if config.economics_model == "current":
        weight = max(1, int_sqrt(effective_units))
    elif config.economics_model == "threshold_sqrt":
        weight = 1 + int_sqrt(max(0, effective_units - threshold_units))
    elif config.economics_model == "threshold_seatbudget_sqrt":
        # Require one full threshold unit to qualify and the next unit to start
        # contributing seat-budget weight. This removes the free unit at threshold.
        seat_budget = max(0, (effective_units // max(1, threshold_units)) - 1)
        weight = int_sqrt(seat_budget)
    else:  # pragma: no cover
        raise ValueError(f"unsupported economics model: {config.economics_model}")
    return True, threshold_units, effective_units, max(0, weight)


def selection_strength(raw_bond_units: int, effective_weight: int, ticket_bonus_bps: int) -> int:
    if effective_weight <= 0:
        return 0
    return max(1, effective_weight) * (10_000 + adjusted_ticket_bonus_bps(raw_bond_units, ticket_bonus_bps))


def allocate_equal(total_units: int, count: int) -> list[int]:
    if count <= 0:
        return []
    base = total_units // count
    remainder = total_units - base * count
    return [base + (1 if i < remainder else 0) for i in range(count)]


def allocate_powerlaw(total_units: int, count: int, alpha: float) -> list[int]:
    if count <= 0:
        return []
    weights = [1.0 / math.pow(i + 1, alpha) for i in range(count)]
    total_weight = sum(weights)
    out: list[int] = []
    assigned = 0
    for idx, weight in enumerate(weights):
        if idx == count - 1:
            amount = total_units - assigned
        else:
            amount = int(total_units * weight / total_weight)
            assigned += amount
        out.append(max(0, amount))
    return out


def allocate_threshold_swarm(total_units: int, count: int, threshold_units: int, margin: float) -> list[int]:
    if count <= 0:
        return []
    target_units = max(threshold_units, int(round(threshold_units * (1.0 + margin))))
    if total_units < target_units * count:
        return allocate_equal(total_units, count)
    out = [target_units for _ in range(count)]
    out[-1] += total_units - target_units * count
    return out


def total_bond_units_for_population(config: AttackModelConfig, active_operator_count: int) -> int:
    base_bond = threshold_bond_coins(config, active_operator_count)
    return coins_to_units(base_bond * active_operator_count * config.average_bond_multiple)


def ticket_bonus_for_operator(config: AttackModelConfig, rng: random.Random) -> int:
    if config.ticket_mode == "off":
        return 0
    zero_bits = sample_best_zero_bits(config.ticket_attempts, rng)
    return ticket_bonus_bps_from_zero_bits(zero_bits, config.ticket_difficulty_bits, config.ticket_bonus_cap_bps)


def make_operator_population(config: AttackModelConfig, rng: random.Random) -> list[Operator]:
    honest_count = config.operators - config.split_count
    if honest_count <= 0:
        raise ValueError("split_count must be strictly smaller than operators")

    active_operator_count = config.operators
    total_bond_units = total_bond_units_for_population(config, active_operator_count)
    adversary_total_units = int(round(total_bond_units * config.adversary_bond_share))
    honest_total_units = max(0, total_bond_units - adversary_total_units)
    threshold_units = coins_to_units(threshold_bond_coins(config, active_operator_count))

    if config.distribution == "uniform":
        honest_bonds = allocate_equal(honest_total_units, honest_count)
        adversary_bonds = allocate_equal(adversary_total_units, config.split_count)
    elif config.distribution == "powerlaw":
        honest_bonds = allocate_powerlaw(honest_total_units, honest_count, config.powerlaw_alpha)
        adversary_bonds = allocate_powerlaw(adversary_total_units, config.split_count, config.powerlaw_alpha)
    elif config.distribution == "threshold_swarm":
        honest_bonds = allocate_equal(honest_total_units, honest_count)
        adversary_bonds = allocate_threshold_swarm(
            adversary_total_units, config.split_count, threshold_units, config.threshold_swarm_margin
        )
    else:  # pragma: no cover
        raise ValueError(f"unsupported distribution: {config.distribution}")

    operators: list[Operator] = []
    for idx, raw_units in enumerate(honest_bonds):
        active, threshold_units_used, effective_units, weight = operator_profile(config, active_operator_count, raw_units)
        bonus_bps = ticket_bonus_for_operator(config, rng)
        operators.append(
            Operator(
                operator_id=f"honest-{idx}",
                is_adversary=False,
                raw_bond_units=raw_units,
                active=active,
                threshold_bond_units=threshold_units_used,
                effective_bond_units=effective_units,
                effective_weight=weight,
                ticket_bonus_bps=bonus_bps,
                selection_strength=selection_strength(raw_units, weight, bonus_bps),
            )
        )
    for idx, raw_units in enumerate(adversary_bonds):
        active, threshold_units_used, effective_units, weight = operator_profile(config, active_operator_count, raw_units)
        bonus_bps = ticket_bonus_for_operator(config, rng)
        operators.append(
            Operator(
                operator_id=f"adversary-{idx}",
                is_adversary=True,
                raw_bond_units=raw_units,
                active=active,
                threshold_bond_units=threshold_units_used,
                effective_bond_units=effective_units,
                effective_weight=weight,
                ticket_bonus_bps=bonus_bps,
                selection_strength=selection_strength(raw_units, weight, bonus_bps),
            )
        )
    return operators


def operator_committee_hash(seed: bytes, operator: Operator) -> bytes:
    return sha256d(b"SC-COMMITTEE-V3" + seed + operator.operator_id.encode("utf-8"))


def compare_committee_rank(a: Operator, b: Operator, seed: bytes) -> int:
    hash_a = operator_committee_hash(seed, a)
    hash_b = operator_committee_hash(seed, b)
    lhs = hash64_prefix(hash_a) * b.selection_strength
    rhs = hash64_prefix(hash_b) * a.selection_strength
    if lhs != rhs:
        return -1 if lhs < rhs else 1
    if hash_a != hash_b:
        return -1 if hash_a < hash_b else 1
    return -1 if a.operator_id < b.operator_id else (1 if a.operator_id > b.operator_id else 0)


def select_committee(operators: list[Operator], committee_size: int, seed: bytes) -> list[Operator]:
    active = [operator for operator in operators if operator.selection_strength > 0]
    ranked = list(active)
    ranked.sort(key=cmp_to_key(lambda a, b: compare_committee_rank(a, b, seed)))
    return ranked[: min(committee_size, len(ranked))]


def committee_root(committee: Sequence[Operator]) -> bytes:
    payload = b"FINALIS_COMMITTEE_V1"
    for member in committee:
        encoded = member.operator_id.encode("utf-8")
        payload += len(encoded).to_bytes(8, "little") + encoded
    return sha256d(payload)


def proposer_schedule(committee: Sequence[Operator], seed: bytes) -> list[Operator]:
    root = committee_root(committee)
    scored: list[tuple[bytes, Operator]] = []
    for member in committee:
        score = sha256d(b"FINALIS_PROPOSER_V1" + seed + root + member.operator_id.encode("utf-8"))
        scored.append((score, member))
    scored.sort(key=lambda item: (item[0], item[1].operator_id))
    return [member for _, member in scored]


def summarize_operators(operators: Sequence[Operator]) -> tuple[float, float, float]:
    total_strength = sum(operator.selection_strength for operator in operators)
    adversarial_strength = sum(operator.selection_strength for operator in operators if operator.is_adversary)
    adv_bonus_values = [operator.ticket_bonus_bps for operator in operators if operator.is_adversary]
    honest_bonus_values = [operator.ticket_bonus_bps for operator in operators if not operator.is_adversary]
    return (
        adversarial_strength / total_strength if total_strength > 0 else 0.0,
        sum(adv_bonus_values) / len(adv_bonus_values) if adv_bonus_values else 0.0,
        sum(honest_bonus_values) / len(honest_bonus_values) if honest_bonus_values else 0.0,
    )


def committee_concentration_metrics(committee: Sequence[Operator]) -> tuple[float, float, float]:
    strengths = [float(operator.selection_strength) for operator in committee if operator.selection_strength > 0]
    if not strengths:
        return (0.0, 0.0, 0.0)
    total_strength = sum(strengths)
    shares = sorted((strength / total_strength for strength in strengths), reverse=True)
    top1 = shares[0]
    top3 = sum(shares[:3])
    hhi = sum(share * share for share in shares)
    return (top1, top3, hhi)


def simulate_liveness(
    committee: Sequence[Operator], config: AttackModelConfig, schedule: Sequence[Operator], rng: random.Random
) -> tuple[bool, int | None]:
    q = config.quorum_threshold or quorum_threshold(config.committee_size)
    if not schedule:
        return False, None
    vote_success_probability = config.p_online * config.p_delivery
    for round_index in range(config.round_horizon):
        proposer = schedule[round_index % len(schedule)]
        if proposer.is_adversary:
            continue
        if rng.random() > config.p_proposer_live:
            continue
        delivered_votes = 0
        for member in committee:
            if member.is_adversary:
                continue
            if rng.random() <= vote_success_probability:
                delivered_votes += 1
        if delivered_votes >= q:
            return True, round_index + 1
    return False, None


def run_monte_carlo_chunk_with_start(config: AttackModelConfig, start_index: int, runs: int, base_seed: int) -> MonteCarloChunkResult:
    q = config.quorum_threshold or quorum_threshold(config.committee_size)
    halt_size = halt_threshold(config.committee_size, q)
    safety_size = safety_break_threshold(q)
    byzantine_size = byzantine_risk_threshold(config.committee_size)
    first_window = min(config.first_round_window, config.round_horizon)

    adversarial_seat_sum = 0.0
    halt_events = 0
    safety_events = 0
    byzantine_events = 0
    adversarial_proposer_events = 0
    early_proposer_events = 0
    finalized_round_count = 0
    finalized_round_sum = 0.0
    stall_count = 0
    strength_share_sum = 0.0
    adv_bonus_sum = 0.0
    honest_bonus_sum = 0.0
    top1_share_sum = 0.0
    top3_share_sum = 0.0
    hhi_sum = 0.0

    for offset in range(runs):
        run_index = start_index + offset
        run_seed = base_seed + 1_000_003 * (run_index + 1)
        rng = random.Random(run_seed)
        epoch_seed = rng.getrandbits(256).to_bytes(32, "big")
        operators = make_operator_population(config, rng)
        committee = select_committee(operators, config.committee_size, epoch_seed)
        schedule = proposer_schedule(committee, epoch_seed)
        adversary_seats = sum(1 for member in committee if member.is_adversary)
        top1_share, top3_share, hhi = committee_concentration_metrics(committee)
        strength_share, adv_bonus, honest_bonus = summarize_operators(operators)

        adversarial_seat_sum += adversary_seats
        halt_events += int(adversary_seats >= halt_size)
        safety_events += int(adversary_seats >= safety_size)
        byzantine_events += int(adversary_seats >= byzantine_size)
        adversarial_proposer_events += int(bool(schedule) and schedule[0].is_adversary)
        early_proposer_events += int(any(member.is_adversary for member in schedule[:first_window]))
        strength_share_sum += strength_share
        adv_bonus_sum += adv_bonus
        honest_bonus_sum += honest_bonus
        top1_share_sum += top1_share
        top3_share_sum += top3_share
        hhi_sum += hhi

        finalized, rounds = simulate_liveness(committee, config, schedule, rng)
        if finalized and rounds is not None:
            finalized_round_count += 1
            finalized_round_sum += rounds
        else:
            stall_count += 1

    return MonteCarloChunkResult(
        runs=runs,
        first_window_rounds=first_window,
        adversarial_seat_sum=adversarial_seat_sum,
        halt_events=halt_events,
        safety_events=safety_events,
        byzantine_events=byzantine_events,
        adversarial_proposer_events=adversarial_proposer_events,
        early_proposer_events=early_proposer_events,
        finalized_round_count=finalized_round_count,
        finalized_round_sum=finalized_round_sum,
        stall_count=stall_count,
        strength_share_sum=strength_share_sum,
        adv_bonus_sum=adv_bonus_sum,
        honest_bonus_sum=honest_bonus_sum,
        top1_share_sum=top1_share_sum,
        top3_share_sum=top3_share_sum,
        hhi_sum=hhi_sum,
    )


def aggregate_monte_carlo_chunks(chunks: Sequence[MonteCarloChunkResult]) -> MonteCarloResult:
    if not chunks:
        raise ValueError("no Monte Carlo chunks to aggregate")
    total_runs = sum(chunk.runs for chunk in chunks)
    finalized_round_count = sum(chunk.finalized_round_count for chunk in chunks)
    finalized_round_sum = sum(chunk.finalized_round_sum for chunk in chunks)
    total_stalls = sum(chunk.stall_count for chunk in chunks)
    return MonteCarloResult(
        expected_adversarial_seats=sum(chunk.adversarial_seat_sum for chunk in chunks) / total_runs,
        probability_halt=sum(chunk.halt_events for chunk in chunks) / total_runs,
        probability_safety_break=sum(chunk.safety_events for chunk in chunks) / total_runs,
        probability_byzantine_risk=sum(chunk.byzantine_events for chunk in chunks) / total_runs,
        expected_adversarial_proposer_share=sum(chunk.adversarial_proposer_events for chunk in chunks) / total_runs,
        probability_adversary_proposer_in_first_window=sum(chunk.early_proposer_events for chunk in chunks) / total_runs,
        first_window_rounds=chunks[0].first_window_rounds,
        expected_rounds_to_finalization=finalized_round_sum / finalized_round_count if finalized_round_count else None,
        probability_finalize_within_horizon=(total_runs - total_stalls) / total_runs,
        stall_probability=total_stalls / total_runs,
        expected_ticket_bonus_bps_adversary=sum(chunk.adv_bonus_sum for chunk in chunks) / total_runs,
        expected_ticket_bonus_bps_honest=sum(chunk.honest_bonus_sum for chunk in chunks) / total_runs,
        expected_strength_share_adversary=sum(chunk.strength_share_sum for chunk in chunks) / total_runs,
        expected_committee_top1_strength_share=sum(chunk.top1_share_sum for chunk in chunks) / total_runs,
        expected_committee_top3_strength_share=sum(chunk.top3_share_sum for chunk in chunks) / total_runs,
        expected_committee_strength_hhi=sum(chunk.hhi_sum for chunk in chunks) / total_runs,
    )


def monte_carlo_chunk_task(config: AttackModelConfig, runs: int, start_index: int) -> MonteCarloChunkResult:
    return run_monte_carlo_chunk_with_start(config, start_index, runs, config.seed or 0)


def split_runs(total_runs: int, jobs: int) -> list[tuple[int, int]]:
    worker_count = max(1, min(jobs, total_runs))
    base = total_runs // worker_count
    remainder = total_runs % worker_count
    ranges: list[tuple[int, int]] = []
    start = 0
    for index in range(worker_count):
        runs = base + (1 if index < remainder else 0)
        ranges.append((start, runs))
        start += runs
    return ranges


def run_monte_carlo_parallel(config: AttackModelConfig) -> MonteCarloResult:
    jobs = config.jobs if config.jobs > 0 else max(1, os.cpu_count() or 1)
    if jobs <= 1 or config.runs <= 1:
        return aggregate_monte_carlo_chunks(
            [run_monte_carlo_chunk_with_start(config, 0, config.runs, config.seed or 0)]
        )
    chunk_ranges = split_runs(config.runs, jobs)
    chunks: list[MonteCarloChunkResult] = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=len(chunk_ranges)) as executor:
        futures = [
            executor.submit(monte_carlo_chunk_task, config, runs, start_index)
            for start_index, runs in chunk_ranges
            if runs > 0
        ]
        for future in futures:
            chunks.append(future.result())
    return aggregate_monte_carlo_chunks(chunks)


def analytical_thresholds(config: AttackModelConfig) -> AnalyticalResult:
    q = config.quorum_threshold or quorum_threshold(config.committee_size)
    active_operator_count = config.operators
    operators = make_operator_population(config, random.Random(config.seed or 0))
    total_strength = sum(operator.selection_strength for operator in operators)
    adversarial_strength = sum(operator.selection_strength for operator in operators if operator.is_adversary)
    expected_seats = config.committee_size * adversarial_strength / total_strength if total_strength > 0 else 0.0
    return AnalyticalResult(
        economics_model=config.economics_model,
        committee_size=config.committee_size,
        quorum_threshold=q,
        halt_threshold=halt_threshold(config.committee_size, q),
        safety_break_threshold=safety_break_threshold(q),
        byzantine_risk_threshold=byzantine_risk_threshold(config.committee_size),
        active_operator_count=active_operator_count,
        threshold_bond_coins=threshold_bond_coins(config, active_operator_count),
        cap_bond_coins=cap_bond_coins(config, active_operator_count),
        expected_adversarial_seats=expected_seats,
        expected_adversarial_proposer_share=expected_seats / config.committee_size if config.committee_size else 0.0,
    )


def mutate_config(config: AttackModelConfig, **changes: Any) -> AttackModelConfig:
    payload = asdict(config)
    payload.update(changes)
    payload["output_dir"] = config.output_dir
    payload["min_bond_sweep"] = tuple(payload["min_bond_sweep"])
    payload["cap_multiple_sweep"] = tuple(payload["cap_multiple_sweep"])
    return AttackModelConfig(**payload)


def honest_viability_proxy(config: AttackModelConfig) -> list[dict[str, Any]]:
    active_operator_count = config.operators
    out: list[dict[str, Any]] = []
    for multiple in (1.0, 1.5, 2.0):
        raw_bond_coins = config.min_bond_coins * multiple
        active, threshold_units_used, effective_units, weight = operator_profile(
            config, active_operator_count, coins_to_units(raw_bond_coins)
        )
        strength = selection_strength(coins_to_units(raw_bond_coins), weight, 0)
        out.append(
            asdict(
                ViabilityPoint(
                    bond_multiple=multiple,
                    raw_bond_coins=raw_bond_coins,
                    active=active,
                    effective_bond_coins=units_to_coins(effective_units),
                    effective_weight=weight,
                    selection_strength=strength,
                )
            )
        )
    return out


def result_row_from_result(
    config: AttackModelConfig, sweep_name: str, x_value: float, result: MonteCarloResult
) -> dict[str, Any]:
    return {
        "sweep": sweep_name,
        "x": x_value,
        "economics_model": config.economics_model,
        "min_bond_coins": config.min_bond_coins,
        "cap_multiple": config.cap_multiple,
        "ticket_mode": config.ticket_mode,
        "distribution": config.distribution,
        "split_count": config.split_count,
        "expected_adversarial_seats": result.expected_adversarial_seats,
        "probability_halt": result.probability_halt,
        "probability_safety_break": result.probability_safety_break,
        "probability_byzantine_risk": result.probability_byzantine_risk,
        "expected_adversarial_proposer_share": result.expected_adversarial_proposer_share,
        "probability_adversary_proposer_in_first_window": result.probability_adversary_proposer_in_first_window,
        "stall_probability": result.stall_probability,
        "probability_finalize_within_horizon": result.probability_finalize_within_horizon,
        "expected_committee_top1_strength_share": result.expected_committee_top1_strength_share,
        "expected_committee_top3_strength_share": result.expected_committee_top3_strength_share,
        "expected_committee_strength_hhi": result.expected_committee_strength_hhi,
    }


def compute_split_amplification(base_seats: float, candidate_seats: float) -> float:
    if base_seats <= 0.0:
        return 0.0
    return candidate_seats / base_seats


def split_amplification_for_config(config: AttackModelConfig, result: MonteCarloResult | None = None) -> dict[str, float]:
    candidate = result if result is not None else run_monte_carlo_parallel(config)
    # Use the same seed stream as the candidate scenario so the ratio reflects
    # economics differences rather than unrelated Monte Carlo drift.
    baseline = run_monte_carlo_parallel(mutate_config(config, split_count=1, seed=config.seed))
    return {
        "expected_adversarial_seats_ratio": compute_split_amplification(
            baseline.expected_adversarial_seats, candidate.expected_adversarial_seats
        ),
        "halt_probability_ratio": compute_split_amplification(baseline.probability_halt, candidate.probability_halt),
    }


def build_sweep(
    config: AttackModelConfig,
    *,
    sweep_name: str,
    x_values: Sequence[float],
    mutate: Callable[[AttackModelConfig, float], AttackModelConfig],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    base_seed = config.seed or 0
    previous_row: dict[str, Any] | None = None
    previous_x: float | None = None
    for index, x_value in enumerate(x_values):
        swept = mutate(config, float(x_value))
        paired_seed = base_seed if sweep_name in {"split_count", "min_bond_coins", "cap_multiple"} else base_seed + index + 10_000
        result = run_monte_carlo_parallel(mutate_config(swept, seed=paired_seed))
        row = result_row_from_result(swept, sweep_name, float(x_value), result)
        if sweep_name in {"min_bond_coins", "cap_multiple"}:
            split_amp = split_amplification_for_config(swept, result)
            row["split_amplification_expected_seats"] = split_amp["expected_adversarial_seats_ratio"]
            row["split_amplification_halt_probability"] = split_amp["halt_probability_ratio"]
        else:
            row["split_amplification_expected_seats"] = 0.0
            row["split_amplification_halt_probability"] = 0.0
        if previous_row is not None and previous_x is not None and x_value != previous_x:
            dx = float(x_value) - previous_x
            row["marginal_expected_seat_gain_per_added_operator"] = (
                (row["expected_adversarial_seats"] - previous_row["expected_adversarial_seats"]) / dx
                if sweep_name == "split_count"
                else 0.0
            )
            row["marginal_halt_probability_gain_per_added_operator"] = (
                (row["probability_halt"] - previous_row["probability_halt"]) / dx if sweep_name == "split_count" else 0.0
            )
        else:
            row["marginal_expected_seat_gain_per_added_operator"] = 0.0
            row["marginal_halt_probability_gain_per_added_operator"] = 0.0
        rows.append(row)
        previous_row = row
        previous_x = float(x_value)
    if sweep_name == "split_count":
        base_row = next((row for row in rows if int(row["x"]) == 1), None)
        if base_row is not None and base_row["expected_adversarial_seats"] > 0:
            for row in rows:
                row["split_amplification_expected_seats"] = (
                    row["expected_adversarial_seats"] / base_row["expected_adversarial_seats"]
                )
                row["split_amplification_halt_probability"] = compute_split_amplification(
                    base_row["probability_halt"], row["probability_halt"]
                )
    return rows


def family_comparison(config: AttackModelConfig) -> dict[str, Any]:
    comparison: dict[str, Any] = {}
    for index, model in enumerate(DEFAULT_FAMILY_COMPARISON):
        family_cfg = mutate_config(config, economics_model=model, seed=(config.seed or 0) + 100_000 * (index + 1))
        analytical = analytical_thresholds(family_cfg)
        result = run_monte_carlo_parallel(family_cfg)
        amplification: dict[str, Any] = {}
        base_result = run_monte_carlo_parallel(mutate_config(family_cfg, split_count=1, seed=family_cfg.seed))
        for split_count in DEFAULT_SPLIT_AMPLIFICATION_POINTS:
            amp_cfg = mutate_config(family_cfg, split_count=split_count, seed=family_cfg.seed)
            amp_result = run_monte_carlo_parallel(amp_cfg)
            amplification[str(split_count)] = {
                "expected_adversarial_seats_ratio": compute_split_amplification(
                    base_result.expected_adversarial_seats, amp_result.expected_adversarial_seats
                ),
                "probability_halt_ratio": compute_split_amplification(base_result.probability_halt, amp_result.probability_halt),
            }
        comparison[model] = {
            "analytical": asdict(analytical),
            "monte_carlo": asdict(result),
            "split_amplification": amplification,
            "honest_viability_proxy": honest_viability_proxy(family_cfg),
        }
    return comparison


def plot_line(x: Sequence[float], y: Sequence[float], xlabel: str, ylabel: str, title: str, path: Path) -> None:
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.plot(list(x), list(y), marker="o", linewidth=1.8)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    if not rows:
        return
    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def parse_args() -> AttackModelConfig:
    parser = argparse.ArgumentParser(description="Finalis Core quantitative attack model")
    parser.add_argument("--committee-size", type=positive_int, required=True)
    parser.add_argument("--quorum-threshold", type=positive_int, default=None)
    parser.add_argument("--operators", type=positive_int, required=True)
    parser.add_argument("--adversary-bond-share", type=bounded_share, required=True)
    parser.add_argument("--split-count", type=positive_int, required=True)
    parser.add_argument("--distribution", choices=["uniform", "powerlaw", "threshold_swarm"], required=True)
    parser.add_argument("--ticket-mode", choices=["off", "current"], default="current")
    parser.add_argument(
        "--economics-model",
        choices=["current", "threshold_sqrt", "threshold_seatbudget_sqrt"],
        default="current",
    )
    parser.add_argument("--min-bond-coins", type=positive_float, default=DEFAULT_MIN_BOND_COINS)
    parser.add_argument("--base-min-bond-coins", dest="min_bond_coins", type=positive_float)
    parser.add_argument("--cap-multiple", type=positive_float, default=DEFAULT_CAP_MULTIPLE)
    parser.add_argument("--max-effective-bond-multiple", dest="cap_multiple", type=positive_float)
    parser.add_argument("--runs", type=positive_int, default=10_000)
    parser.add_argument("--p-online", type=bounded_probability, default=0.98)
    parser.add_argument("--p-delivery", type=bounded_probability, default=0.98)
    parser.add_argument("--p-proposer-live", type=bounded_probability, default=0.98)
    parser.add_argument("--jobs", type=positive_int_or_zero, default=1)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--target-validators", type=positive_int, default=DEFAULT_TARGET_VALIDATORS)
    parser.add_argument("--min-bond-floor-coins", type=positive_float, default=DEFAULT_MIN_BOND_FLOOR_COINS)
    parser.add_argument("--min-bond-ceiling-coins", type=positive_float, default=DEFAULT_MIN_BOND_CEILING_COINS)
    parser.add_argument("--ticket-bonus-cap-bps", type=positive_int, default=DEFAULT_TICKET_BONUS_CAP_BPS)
    parser.add_argument("--ticket-difficulty-bits", type=positive_int, default=DEFAULT_TICKET_DIFFICULTY_BITS)
    parser.add_argument("--ticket-attempts", type=positive_int, default=DEFAULT_TICKET_ATTEMPTS)
    parser.add_argument("--average-bond-multiple", type=positive_float, default=DEFAULT_AVERAGE_BOND_MULTIPLE)
    parser.add_argument("--powerlaw-alpha", type=positive_float, default=DEFAULT_POWERLAW_ALPHA)
    parser.add_argument("--threshold-swarm-margin", type=positive_float, default=DEFAULT_THRESHOLD_SWARM_MARGIN)
    parser.add_argument("--round-horizon", type=positive_int, default=DEFAULT_ROUND_HORIZON)
    parser.add_argument("--first-round-window", type=positive_int, default=DEFAULT_FIRST_ROUND_WINDOW)
    parser.add_argument("--min-bond-sweep", type=parse_float_csv, default=DEFAULT_MIN_BOND_SWEEP)
    parser.add_argument("--cap-multiple-sweep", type=parse_float_csv, default=DEFAULT_CAP_MULTIPLE_SWEEP)
    args = parser.parse_args()

    config = AttackModelConfig(
        committee_size=args.committee_size,
        quorum_threshold=args.quorum_threshold,
        operators=args.operators,
        adversary_bond_share=args.adversary_bond_share,
        split_count=args.split_count,
        distribution=args.distribution,
        ticket_mode=args.ticket_mode,
        economics_model=args.economics_model,
        min_bond_coins=args.min_bond_coins,
        cap_multiple=args.cap_multiple,
        runs=args.runs,
        p_online=args.p_online,
        p_delivery=args.p_delivery,
        p_proposer_live=args.p_proposer_live,
        jobs=args.jobs,
        output_dir=args.output_dir,
        seed=args.seed,
        target_validators=args.target_validators,
        min_bond_floor_coins=args.min_bond_floor_coins,
        min_bond_ceiling_coins=args.min_bond_ceiling_coins,
        ticket_bonus_cap_bps=args.ticket_bonus_cap_bps,
        ticket_difficulty_bits=args.ticket_difficulty_bits,
        ticket_attempts=args.ticket_attempts,
        average_bond_multiple=args.average_bond_multiple,
        powerlaw_alpha=args.powerlaw_alpha,
        threshold_swarm_margin=args.threshold_swarm_margin,
        round_horizon=args.round_horizon,
        first_round_window=args.first_round_window,
        min_bond_sweep=tuple(args.min_bond_sweep),
        cap_multiple_sweep=tuple(args.cap_multiple_sweep),
    )
    validate_config(config)
    return config


def validate_config(config: AttackModelConfig) -> None:
    if config.split_count >= config.operators:
        raise SystemExit("--split-count must be strictly smaller than --operators")
    if config.committee_size > config.operators:
        raise SystemExit("--committee-size must be <= --operators")
    q = config.quorum_threshold or quorum_threshold(config.committee_size)
    if q > config.committee_size:
        raise SystemExit("quorum threshold cannot exceed committee size")
    if config.cap_multiple < 1.0:
        raise SystemExit("--cap-multiple must be >= 1")
    if config.ticket_mode == "current" and config.ticket_bonus_cap_bps <= 0:
        raise SystemExit("ticket bonus cap must be positive when ticket mode is current")
    if config.first_round_window > config.round_horizon:
        raise SystemExit("--first-round-window must be <= --round-horizon")
    if config.jobs < 0:
        raise SystemExit("--jobs must be >= 0")
    if config.economics_model == "current" and config.min_bond_floor_coins > config.min_bond_ceiling_coins:
        raise SystemExit("min bond floor cannot exceed min bond ceiling")


def print_summary(
    config: AttackModelConfig,
    analytical: AnalyticalResult,
    monte_carlo: MonteCarloResult,
    split_amplification: dict[str, Any],
    viability_proxy: Sequence[dict[str, Any]],
    ticket_delta: dict[str, float],
) -> None:
    print("Finalis Core Quantitative Attack Model")
    print()
    print(f"economics model              : {config.economics_model}")
    print(f"committee size               : {analytical.committee_size}")
    print(f"quorum threshold             : {analytical.quorum_threshold}")
    print(f"halt threshold               : {analytical.halt_threshold}")
    print(f"safety-break threshold       : {analytical.safety_break_threshold}")
    print(f"byzantine risk threshold     : {analytical.byzantine_risk_threshold}")
    print(f"threshold bond (coins)       : {analytical.threshold_bond_coins:.4f}")
    print(f"cap bond (coins)             : {analytical.cap_bond_coins:.4f}")
    print()
    print(f"expected adversarial seats   : {monte_carlo.expected_adversarial_seats:.4f}")
    print(f"halt probability             : {monte_carlo.probability_halt:.6f}")
    print(f"safety-break probability     : {monte_carlo.probability_safety_break:.6f}")
    print(f"byzantine-risk probability   : {monte_carlo.probability_byzantine_risk:.6f}")
    print(f"adversarial proposer share   : {monte_carlo.expected_adversarial_proposer_share:.6f}")
    print(
        f"adversary proposer in first {monte_carlo.first_window_rounds} rounds"
        f" : {monte_carlo.probability_adversary_proposer_in_first_window:.6f}"
    )
    print(f"committee top1 strength share: {monte_carlo.expected_committee_top1_strength_share:.6f}")
    print(f"committee top3 strength share: {monte_carlo.expected_committee_top3_strength_share:.6f}")
    print(f"committee strength hhi       : {monte_carlo.expected_committee_strength_hhi:.6f}")
    print(f"finalize within horizon      : {monte_carlo.probability_finalize_within_horizon:.6f}")
    print(f"stall probability            : {monte_carlo.stall_probability:.6f}")
    if monte_carlo.expected_rounds_to_finalization is None:
        print("expected rounds to finalize  : none within horizon")
    else:
        print(f"expected rounds to finalize  : {monte_carlo.expected_rounds_to_finalization:.4f}")
    print()
    for split_count in DEFAULT_SPLIT_AMPLIFICATION_POINTS:
        key = str(split_count)
        if key in split_amplification:
            print(
                f"split amplification seats x{split_count:>2}:"
                f" {split_amplification[key]['expected_adversarial_seats_ratio']:.6f}"
            )
    print()
    for point in viability_proxy:
        print(
            f"honest viability {point['bond_multiple']:.1f}m: "
            f"active={int(point['active'])} weight={point['effective_weight']} "
            f"strength={point['selection_strength']}"
        )
    print()
    print(f"ticket seat delta (current-off)   : {ticket_delta['expected_adversarial_seats']:.6f}")
    print(f"ticket halt delta (current-off)   : {ticket_delta['probability_halt']:.6f}")
    print(f"ticket byz-risk delta (current-off): {ticket_delta['probability_byzantine_risk']:.6f}")


def main() -> None:
    config = parse_args()
    config.output_dir.mkdir(parents=True, exist_ok=True)

    analytical = analytical_thresholds(config)
    monte_carlo = run_monte_carlo_parallel(config)
    viability_proxy = honest_viability_proxy(config)

    off_result = run_monte_carlo_parallel(mutate_config(config, ticket_mode="off", seed=(config.seed or 0) + 1_000_000))
    current_result = run_monte_carlo_parallel(
        mutate_config(config, ticket_mode="current", seed=(config.seed or 0) + 2_000_000)
    )
    ticket_delta = {
        "expected_adversarial_seats": current_result.expected_adversarial_seats - off_result.expected_adversarial_seats,
        "probability_halt": current_result.probability_halt - off_result.probability_halt,
        "probability_safety_break": current_result.probability_safety_break - off_result.probability_safety_break,
        "probability_byzantine_risk": current_result.probability_byzantine_risk - off_result.probability_byzantine_risk,
        "expected_adversarial_proposer_share": current_result.expected_adversarial_proposer_share
        - off_result.expected_adversarial_proposer_share,
    }

    bond_share_sweep = [round(value, 2) for value in [0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]]
    split_count_sweep = [float(value) for value in range(1, min(config.operators - 1, max(config.split_count * 2, 16)) + 1)]
    online_sweep = [round(value, 2) for value in [0.60, 0.70, 0.80, 0.85, 0.90, 0.95, 0.98, 0.99]]

    share_rows = build_sweep(
        config,
        sweep_name="bond_share",
        x_values=bond_share_sweep,
        mutate=lambda cfg, value: mutate_config(cfg, adversary_bond_share=value),
    )
    split_rows = build_sweep(
        config,
        sweep_name="split_count",
        x_values=split_count_sweep,
        mutate=lambda cfg, value: mutate_config(cfg, split_count=int(value)),
    )
    liveness_rows = build_sweep(
        config,
        sweep_name="p_online",
        x_values=online_sweep,
        mutate=lambda cfg, value: mutate_config(cfg, p_online=value),
    )
    min_bond_rows = build_sweep(
        mutate_config(config, ticket_mode="off"),
        sweep_name="min_bond_coins",
        x_values=config.min_bond_sweep,
        mutate=lambda cfg, value: mutate_config(cfg, min_bond_coins=value),
    )
    cap_multiple_rows = build_sweep(
        mutate_config(config, ticket_mode="off"),
        sweep_name="cap_multiple",
        x_values=config.cap_multiple_sweep,
        mutate=lambda cfg, value: mutate_config(cfg, cap_multiple=value),
    )

    split_amplification = {}
    base_split_row = next((row for row in split_rows if int(row["x"]) == 1), None)
    if base_split_row is not None:
        for split_count in DEFAULT_SPLIT_AMPLIFICATION_POINTS:
            row = next((candidate for candidate in split_rows if int(candidate["x"]) == split_count), None)
            if row is None:
                continue
            split_amplification[str(split_count)] = {
                "expected_adversarial_seats_ratio": row["split_amplification_expected_seats"],
                "probability_halt_ratio": row["split_amplification_halt_probability"],
            }

    family_rows = family_comparison(config)

    summary = {
        "config": {**asdict(config), "output_dir": str(config.output_dir)},
        "analytical": asdict(analytical),
        "monte_carlo": asdict(monte_carlo),
        "honest_viability_proxy": viability_proxy,
        "split_amplification": split_amplification,
        "ticket_counterfactual": {
            "off": asdict(off_result),
            "current": asdict(current_result),
            "delta_current_minus_off": ticket_delta,
        },
        "family_comparison": family_rows,
        "approximations": [
            "committee selection is modeled as deterministic rank-by-hash-over-strength, not weighted random sampling",
            "ticket_mode=current uses bounded operator-level ticket search approximation, not exhaustive enumeration",
            "committee concentration is approximated using strength-share concentration within sampled committees",
            "honest viability is a threshold-operator proxy, not a decentralization proof",
            "split amplification compares expected adversarial seats and halt probability to the split_count=1 baseline",
        ],
        "sweeps": {
            "bond_share": share_rows,
            "split_count": split_rows,
            "p_online": liveness_rows,
            "min_bond_coins": min_bond_rows,
            "cap_multiple": cap_multiple_rows,
        },
    }

    main_row = result_row_from_result(config, "main", config.adversary_bond_share, monte_carlo)
    main_row["ticket_security_delta_halt"] = ticket_delta["probability_halt"]
    main_row["ticket_security_delta_byzantine_risk"] = ticket_delta["probability_byzantine_risk"]
    main_row["ticket_security_delta_proposer_share"] = ticket_delta["expected_adversarial_proposer_share"]
    main_row["split_amplification_expected_seats"] = split_amplification.get(str(config.split_count), {}).get(
        "expected_adversarial_seats_ratio", 1.0 if config.split_count == 1 else 0.0
    )

    scenario_rows = [main_row]
    scenario_rows.extend(share_rows)
    scenario_rows.extend(split_rows)
    scenario_rows.extend(liveness_rows)
    scenario_rows.extend(min_bond_rows)
    scenario_rows.extend(cap_multiple_rows)

    write_json(config.output_dir / "summary.json", summary)
    write_csv(config.output_dir / "scenario_results.csv", scenario_rows)

    plot_line(
        [row["x"] for row in split_rows],
        [row["expected_adversarial_seats"] for row in split_rows],
        "Adversary split count",
        "Expected adversarial committee seats",
        "Split Count vs Expected Adversarial Committee Seats",
        config.output_dir / "split_count_vs_expected_adversarial_seats.png",
    )
    plot_line(
        [row["x"] for row in split_rows],
        [row["probability_halt"] for row in split_rows],
        "Adversary split count",
        "Probability adversarial seats >= halt threshold",
        "Split Count vs Halt Probability",
        config.output_dir / "split_count_vs_halt_probability.png",
    )
    plot_line(
        [row["x"] for row in min_bond_rows],
        [row["split_amplification_expected_seats"] for row in min_bond_rows],
        "Minimum bond (coins)",
        "Split amplification (expected seats)",
        "Minimum Bond vs Split Amplification",
        config.output_dir / "min_bond_vs_split_amplification.png",
    )
    plot_line(
        [row["x"] for row in cap_multiple_rows],
        [row["split_amplification_expected_seats"] for row in cap_multiple_rows],
        "Cap multiple",
        "Split amplification (expected seats)",
        "Cap Multiple vs Split Amplification",
        config.output_dir / "cap_multiple_vs_split_amplification.png",
    )

    print_summary(config, analytical, monte_carlo, split_amplification, viability_proxy, ticket_delta)
    print()
    print(f"wrote: {config.output_dir / 'summary.json'}")
    print(f"wrote: {config.output_dir / 'scenario_results.csv'}")


if __name__ == "__main__":
    main()
