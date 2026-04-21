# SPDX-License-Identifier: MIT

"""
Deterministic Monte Carlo model for finalized-committee sybil pressure.

This script is intended to stay roughly aligned with the current live
operator-grouped finalized-committee path in `finalis-core`. In particular it
models the bounded v2+ ticket search, the current ticket bonus curve, and the
streak-based difficulty controller used by the live committee builder.
"""

from __future__ import annotations

import hashlib
import math
import random
from dataclasses import dataclass
from functools import cmp_to_key
from typing import Sequence


BASE_UNITS_PER_COIN = 100_000_000
EPOCH_TICKET_MAX_NONCE = 4095
LEGACY_MIN_TICKET_DIFFICULTY_BITS = 4
V2_MIN_TICKET_DIFFICULTY_BITS = 8
DEFAULT_TICKET_DIFFICULTY_BITS = 8
V2_MAX_TICKET_DIFFICULTY_BITS = 12
DEFAULT_TICKET_BONUS_CAP_BPS = 2500


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def int_sqrt(value: int) -> int:
    return math.isqrt(max(0, value))


def effective_weight(bonded_amount: int) -> int:
    return max(1, int_sqrt(bonded_amount))


def hash64_prefix(hash_bytes: bytes) -> int:
    return int.from_bytes(hash_bytes[:8], "big")


def leading_zero_bits(hash_bytes: bytes) -> int:
    zeros = 0
    for byte in hash_bytes:
        if byte == 0:
            zeros += 8
            continue
        for bit in range(7, -1, -1):
            if ((byte >> bit) & 1) == 0:
                zeros += 1
            else:
                return zeros
    return zeros


def leading_zero_bits_u64(value: int) -> int:
    if value == 0:
        return 64
    return 64 - value.bit_length()


def ticket_pow_bonus_bps_from_zero_bits(
    zero_bits: int, difficulty_bits: int, bonus_cap_bps: int = DEFAULT_TICKET_BONUS_CAP_BPS
) -> int:
    if zero_bits < difficulty_bits:
        return 0
    surplus = zero_bits - difficulty_bits
    smooth = int_sqrt(surplus + 1)
    return min(bonus_cap_bps, 500 + smooth * 400)


def quorum_relative_participation_bps(signature_count: int, quorum_size: int) -> int:
    denom = max(1, quorum_size)
    num = min(signature_count, denom)
    return (num * 10_000) // denom


def adjust_ticket_difficulty_bits(
    previous_bits: int,
    active_validator_count: int,
    committee_capacity: int,
    average_round_x1000: int,
    average_participation_bps: int,
    min_bits: int = V2_MIN_TICKET_DIFFICULTY_BITS,
    max_bits: int = V2_MAX_TICKET_DIFFICULTY_BITS,
) -> int:
    """
    Single-step conservative approximation kept for older callers.

    The live node uses the streak-based v2+ controller below. This helper stays
    available as a compact preview, but its bounds now match the current live
    path instead of the older 4..20-bit range.
    """
    out = min(max_bits, max(min_bits, previous_bits))
    delta = 0
    if (
        active_validator_count > committee_capacity
        and average_round_x1000 <= 1250
        and average_participation_bps >= 9500
    ):
        delta += 1
    if average_round_x1000 >= 2500 and average_participation_bps < 8500:
        delta -= 1
    if delta > 0 and out < max_bits:
        out += 1
    if delta < 0 and out > min_bits:
        out -= 1
    return out


def adjust_ticket_difficulty_bits_v2(
    previous_bits: int,
    active_validator_count: int,
    committee_capacity: int,
    average_round_x1000: int,
    average_participation_bps: int,
    healthy_streak: int,
    unhealthy_streak: int,
    min_bits: int = V2_MIN_TICKET_DIFFICULTY_BITS,
    max_bits: int = V2_MAX_TICKET_DIFFICULTY_BITS,
) -> tuple[int, int, int, str]:
    out = min(max_bits, max(min_bits, previous_bits))
    is_healthy = (
        active_validator_count > committee_capacity
        and average_round_x1000 <= 1250
        and average_participation_bps >= 9500
    )
    is_unhealthy = average_round_x1000 >= 2500 and average_participation_bps < 8500

    if is_healthy:
        healthy_streak += 1
        unhealthy_streak = 0
        if healthy_streak >= 2 and out < max_bits:
            out += 1
            healthy_streak = 0
        return out, healthy_streak, unhealthy_streak, "healthy"

    if is_unhealthy:
        unhealthy_streak += 1
        healthy_streak = 0
        if unhealthy_streak >= 3 and out > min_bits:
            out -= 1
            unhealthy_streak = 0
        return out, healthy_streak, unhealthy_streak, "unhealthy"

    return out, 0, 0, "mixed"


@dataclass(frozen=True)
class BestTicket:
    work_hash: bytes
    hash64: int
    zero_bits: int
    nonce: int


@dataclass(frozen=True)
class Validator:
    pubkey: bytes
    operator_id: bytes
    bonded_amount: int
    effective_weight: int
    ticket_work_hash: bytes
    ticket_hash64: int
    ticket_zero_bits: int
    ticket_nonce: int
    ticket_bonus_bps: int
    is_attacker: bool
    sample_count: int


@dataclass(frozen=True)
class Candidate:
    pubkey: bytes
    selection_id: bytes
    bonded_amount: int
    effective_weight: int
    ticket_work_hash: bytes
    ticket_hash64: int
    ticket_zero_bits: int
    ticket_nonce: int
    ticket_bonus_bps: int
    is_attacker: bool
    validator_count: int


@dataclass(frozen=True)
class EpochMetrics:
    average_round_x1000: int
    average_participation_bps: int


@dataclass(frozen=True)
class EpochResult:
    epoch_index: int
    difficulty_bits: int
    attacker_committee_seats: int
    honest_committee_seats: int
    committee_size: int
    attacker_round0_proposer: bool
    attacker_quorum: bool
    attacker_bond_share: float
    attacker_effective_weight_share: float
    attacker_committee_share: float
    attacker_reward_share: float
    attacker_committee_share_without_pow: float
    attacker_proposer_share_without_pow: float
    max_attacker_bonus_bps: int
    max_honest_bonus_bps: int
    attacker_operator_share: float


def committee_quorum_size(committee_size: int) -> int:
    return (2 * committee_size) // 3 + 1


def make_pubkey(label: str) -> bytes:
    return sha256d(label.encode("utf-8"))


def make_operator_id(label: str) -> bytes:
    return sha256d(f"operator:{label}".encode("utf-8"))


def split_bond(total_units: int, count: int, mode: str) -> list[int]:
    if count <= 0:
        return []
    if total_units <= 0:
        return [0 for _ in range(count)]
    if mode == "equal":
        base = total_units // count
        remainder = total_units - (base * count)
        return [base + (1 if i < remainder else 0) for i in range(count)]
    if mode == "front_loaded":
        weights = [count - i for i in range(count)]
    elif mode == "tail_loaded":
        weights = [i + 1 for i in range(count)]
    else:
        raise ValueError(f"unsupported bond distribution mode: {mode}")
    total_weight = sum(weights)
    out = []
    assigned = 0
    for i, weight in enumerate(weights):
        if i == count - 1:
            amount = total_units - assigned
        else:
            amount = (total_units * weight) // total_weight
            assigned += amount
        out.append(amount)
    return out


def _sample_min_hash64(sample_count: int, rng: random.Random) -> int:
    sample_count = max(1, sample_count)
    u = (rng.getrandbits(64) + 1) / float(1 << 64)
    minimum = 1.0 - math.pow(1.0 - u, 1.0 / sample_count)
    return min((1 << 64) - 1, max(0, int(minimum * (1 << 64))))


def sample_best_ticket(sample_count: int, rng: random.Random) -> BestTicket:
    hash64 = _sample_min_hash64(sample_count, rng)
    prefix = hash64.to_bytes(8, "big")
    suffix = rng.getrandbits(192).to_bytes(24, "big")
    work_hash = prefix + suffix
    nonce = rng.randrange(max(1, sample_count))
    return BestTicket(
        work_hash=work_hash,
        hash64=hash64,
        zero_bits=leading_zero_bits_u64(hash64),
        nonce=nonce,
    )


def candidate_strength(candidate: Candidate) -> int:
    base_weight = candidate.effective_weight if candidate.effective_weight else effective_weight(candidate.bonded_amount)
    bounded_bonus = min(candidate.ticket_bonus_bps, DEFAULT_TICKET_BONUS_CAP_BPS)
    bonded_coins = max(1, candidate.bonded_amount // BASE_UNITS_PER_COIN)
    bonus_scale = 1 + int_sqrt(bonded_coins)
    adjusted_bonus = bounded_bonus // bonus_scale
    return max(1, base_weight * (10_000 + adjusted_bonus))


def _compare_candidates(a: Candidate, b: Candidate, seed: bytes) -> int:
    hash_a = sha256d(b"SC-COMMITTEE-V3" + seed + (a.selection_id if a.selection_id else a.pubkey))
    hash_b = sha256d(b"SC-COMMITTEE-V3" + seed + (b.selection_id if b.selection_id else b.pubkey))
    hash64_a = hash64_prefix(hash_a)
    hash64_b = hash64_prefix(hash_b)
    lhs = hash64_a * candidate_strength(b)
    rhs = hash64_b * candidate_strength(a)
    if lhs != rhs:
        return -1 if lhs < rhs else 1
    if hash_a != hash_b:
        return -1 if hash_a < hash_b else 1
    if a.pubkey != b.pubkey:
        return -1 if a.pubkey < b.pubkey else 1
    return 0


def select_finalized_committee(candidates: Sequence[Candidate], seed: bytes, committee_size: int) -> list[Candidate]:
    ranked = list(candidates)
    ranked.sort(key=cmp_to_key(lambda a, b: _compare_candidates(a, b, seed)))
    return ranked[: min(committee_size, len(ranked))]


def _committee_root(committee: Sequence[Candidate]) -> bytes:
    parts: list[bytes] = []
    for member in committee:
        parts.append(member.pubkey + member.ticket_work_hash + member.ticket_nonce.to_bytes(8, "little"))
    payload = b"FINALIS_COMMITTEE_V1" + b"".join(len(p).to_bytes(8, "little") + p for p in parts)
    return sha256d(payload)


def _proposer_seed(epoch_anchor: bytes, height: int, committee_root: bytes) -> bytes:
    return sha256d(b"FINALIS_PROPOSER_V1" + epoch_anchor + height.to_bytes(8, "little") + committee_root)


def proposer_schedule(committee: Sequence[Candidate], epoch_anchor: bytes, height: int) -> list[Candidate]:
    committee_root = _committee_root(committee)
    seed = _proposer_seed(epoch_anchor, height, committee_root)
    scored = []
    for member in committee:
        scored.append((sha256d(seed + member.pubkey), member))
    scored.sort(key=lambda item: (item[0], item[1].pubkey))
    return [member for _, member in scored]


def reward_share_for_committee(committee: Sequence[Candidate], proposer: Candidate | None) -> float:
    if not committee:
        return 0.0
    quorum = committee_quorum_size(len(committee))
    signer_set = sorted(committee, key=lambda c: c.pubkey)[:quorum]
    scores: dict[bytes, int] = {}
    attacker_by_pub = {c.pubkey: c.is_attacker for c in committee}
    for signer in signer_set:
        scores[signer.pubkey] = scores.get(signer.pubkey, 0) + signer.effective_weight
    if proposer is not None:
        scores[proposer.pubkey] = scores.get(proposer.pubkey, 0) + proposer.effective_weight
    total = sum(scores.values())
    if total == 0:
        return 0.0
    attacker = sum(score for pub, score in scores.items() if attacker_by_pub.get(pub, False))
    return attacker / total


def aggregate_operator_candidates(validators: Sequence[Validator]) -> list[Candidate]:
    aggregates: dict[bytes, dict[str, object]] = {}
    for validator in validators:
        operator_id = validator.operator_id if validator.operator_id else validator.pubkey
        agg = aggregates.get(operator_id)
        if agg is None:
            aggregates[operator_id] = {
                "representative": validator,
                "total_bonded_amount": validator.bonded_amount,
                "validator_count": 1,
                "is_attacker": validator.is_attacker,
            }
            continue
        agg["total_bonded_amount"] = int(agg["total_bonded_amount"]) + validator.bonded_amount
        agg["validator_count"] = int(agg["validator_count"]) + 1
        rep = agg["representative"]
        assert isinstance(rep, Validator)
        if validator.ticket_work_hash < rep.ticket_work_hash or (
            validator.ticket_work_hash == rep.ticket_work_hash and validator.pubkey < rep.pubkey
        ):
            agg["representative"] = validator

    out: list[Candidate] = []
    for operator_id, agg in aggregates.items():
        rep = agg["representative"]
        assert isinstance(rep, Validator)
        total_bonded_amount = int(agg["total_bonded_amount"])
        out.append(
            Candidate(
                pubkey=rep.pubkey,
                selection_id=operator_id,
                bonded_amount=total_bonded_amount,
                effective_weight=effective_weight(total_bonded_amount),
                ticket_work_hash=rep.ticket_work_hash,
                ticket_hash64=rep.ticket_hash64,
                ticket_zero_bits=rep.ticket_zero_bits,
                ticket_nonce=rep.ticket_nonce,
                ticket_bonus_bps=rep.ticket_bonus_bps,
                is_attacker=bool(agg["is_attacker"]),
                validator_count=int(agg["validator_count"]),
            )
        )
    out.sort(key=lambda c: c.pubkey)
    return out


def identity_weighted_candidates(validators: Sequence[Validator]) -> list[Candidate]:
    return [
        Candidate(
            pubkey=v.pubkey,
            selection_id=v.pubkey,
            bonded_amount=v.bonded_amount,
            effective_weight=v.effective_weight,
            ticket_work_hash=v.ticket_work_hash,
            ticket_hash64=v.ticket_hash64,
            ticket_zero_bits=v.ticket_zero_bits,
            ticket_nonce=v.ticket_nonce,
            ticket_bonus_bps=v.ticket_bonus_bps,
            is_attacker=v.is_attacker,
            validator_count=1,
        )
        for v in validators
    ]


def build_validators(
    attacker_bonds: Sequence[int],
    honest_bonds: Sequence[int],
    difficulty_bits: int,
    attacker_ticket_sample_multiplier: float,
    honest_ticket_sample_multiplier: float,
    attacker_operator_mode: str,
    honest_operator_mode: str,
    rng: random.Random,
) -> list[Validator]:
    validators: list[Validator] = []

    def operator_id_for(prefix: str, index: int, mode: str) -> bytes:
        if mode == "same_operator":
            return make_operator_id(f"{prefix}-shared")
        if mode == "distinct_operators":
            return make_operator_id(f"{prefix}-{index}")
        raise ValueError(f"unsupported operator mode: {mode}")

    for i, bond in enumerate(attacker_bonds):
        sample_count = max(1, int(round((EPOCH_TICKET_MAX_NONCE + 1) * attacker_ticket_sample_multiplier)))
        ticket = sample_best_ticket(sample_count, rng)
        validators.append(
            Validator(
                pubkey=make_pubkey(f"attacker-{i}"),
                operator_id=operator_id_for("attacker-operator", i, attacker_operator_mode),
                bonded_amount=bond,
                effective_weight=effective_weight(bond),
                ticket_work_hash=ticket.work_hash,
                ticket_hash64=ticket.hash64,
                ticket_zero_bits=ticket.zero_bits,
                ticket_nonce=ticket.nonce,
                ticket_bonus_bps=ticket_pow_bonus_bps_from_zero_bits(ticket.zero_bits, difficulty_bits),
                is_attacker=True,
                sample_count=sample_count,
            )
        )
    for i, bond in enumerate(honest_bonds):
        sample_count = max(1, int(round((EPOCH_TICKET_MAX_NONCE + 1) * honest_ticket_sample_multiplier)))
        ticket = sample_best_ticket(sample_count, rng)
        validators.append(
            Validator(
                pubkey=make_pubkey(f"honest-{i}"),
                operator_id=operator_id_for("honest-operator", i, honest_operator_mode),
                bonded_amount=bond,
                effective_weight=effective_weight(bond),
                ticket_work_hash=ticket.work_hash,
                ticket_hash64=ticket.hash64,
                ticket_zero_bits=ticket.zero_bits,
                ticket_nonce=ticket.nonce,
                ticket_bonus_bps=ticket_pow_bonus_bps_from_zero_bits(ticket.zero_bits, difficulty_bits),
                is_attacker=False,
                sample_count=sample_count,
            )
        )
    validators.sort(key=lambda v: v.pubkey)
    return validators


def simulate_epochs(
    *,
    attacker_bonds: Sequence[int],
    honest_bonds: Sequence[int],
    committee_size: int,
    epoch_count: int,
    initial_difficulty_bits: int = DEFAULT_TICKET_DIFFICULTY_BITS,
    adaptive_difficulty: bool = True,
    fixed_difficulty_bits: int | None = None,
    attacker_ticket_sample_multiplier: float = 1.0,
    honest_ticket_sample_multiplier: float = 1.0,
    epoch_metrics_schedule: Sequence[EpochMetrics] | None = None,
    attacker_operator_mode: str = "same_operator",
    honest_operator_mode: str = "distinct_operators",
    selection_mode: str = "operator_aggregated",
    seed: int = 1,
) -> list[EpochResult]:
    rng = random.Random(seed)
    results: list[EpochResult] = []
    previous_difficulty = initial_difficulty_bits
    healthy_streak = 0
    unhealthy_streak = 0
    active_validator_count = len(attacker_bonds) + len(honest_bonds)
    attacker_bond_total = sum(attacker_bonds)
    honest_bond_total = sum(honest_bonds)
    total_bond = max(1, attacker_bond_total + honest_bond_total)

    for epoch_index in range(epoch_count):
        if fixed_difficulty_bits is not None:
            difficulty_bits = fixed_difficulty_bits
        elif adaptive_difficulty:
            metrics = epoch_metrics_schedule[epoch_index] if epoch_metrics_schedule else EpochMetrics(0, 10_000)
            difficulty_bits, healthy_streak, unhealthy_streak, _ = adjust_ticket_difficulty_bits_v2(
                previous_difficulty,
                active_validator_count,
                committee_size,
                metrics.average_round_x1000,
                metrics.average_participation_bps,
                healthy_streak,
                unhealthy_streak,
            )
        else:
            difficulty_bits = previous_difficulty
        previous_difficulty = difficulty_bits

        epoch_seed = sha256d(f"epoch-seed-{seed}-{epoch_index}".encode("utf-8"))
        validators = build_validators(
            attacker_bonds,
            honest_bonds,
            difficulty_bits,
            attacker_ticket_sample_multiplier,
            honest_ticket_sample_multiplier,
            attacker_operator_mode,
            honest_operator_mode,
            rng,
        )
        if selection_mode == "operator_aggregated":
            candidates = aggregate_operator_candidates(validators)
        elif selection_mode == "identity_weighted":
            candidates = identity_weighted_candidates(validators)
        else:
            raise ValueError(f"unsupported selection mode: {selection_mode}")

        candidates_no_pow = [
            Candidate(
                pubkey=c.pubkey,
                selection_id=c.selection_id,
                bonded_amount=c.bonded_amount,
                effective_weight=c.effective_weight,
                ticket_work_hash=c.ticket_work_hash,
                ticket_hash64=c.ticket_hash64,
                ticket_zero_bits=c.ticket_zero_bits,
                ticket_nonce=c.ticket_nonce,
                ticket_bonus_bps=0,
                is_attacker=c.is_attacker,
                validator_count=c.validator_count,
            )
            for c in candidates
        ]

        committee = select_finalized_committee(candidates, epoch_seed, min(committee_size, len(candidates)))
        committee_no_pow = select_finalized_committee(candidates_no_pow, epoch_seed, min(committee_size, len(candidates_no_pow)))
        schedule = proposer_schedule(committee, epoch_seed, epoch_index + 1) if committee else []
        schedule_no_pow = proposer_schedule(committee_no_pow, epoch_seed, epoch_index + 1) if committee_no_pow else []
        attacker_seats = sum(1 for c in committee if c.is_attacker)
        honest_seats = len(committee) - attacker_seats
        attacker_seats_no_pow = sum(1 for c in committee_no_pow if c.is_attacker)
        proposer = schedule[0] if schedule else None
        proposer_no_pow = schedule_no_pow[0] if schedule_no_pow else None
        total_effective_weight = sum(c.effective_weight for c in candidates)
        attacker_effective_weight = sum(c.effective_weight for c in candidates if c.is_attacker)
        attacker_operator_share = sum(1 for c in candidates if c.is_attacker) / max(1, len(candidates))

        results.append(
            EpochResult(
                epoch_index=epoch_index,
                difficulty_bits=difficulty_bits,
                attacker_committee_seats=attacker_seats,
                honest_committee_seats=honest_seats,
                committee_size=len(committee),
                attacker_round0_proposer=bool(proposer and proposer.is_attacker),
                attacker_quorum=attacker_seats >= committee_quorum_size(len(committee)) if committee else False,
                attacker_bond_share=attacker_bond_total / total_bond,
                attacker_effective_weight_share=(attacker_effective_weight / max(1, total_effective_weight)),
                attacker_committee_share=(attacker_seats / len(committee)) if committee else 0.0,
                attacker_reward_share=reward_share_for_committee(committee, proposer),
                attacker_committee_share_without_pow=(attacker_seats_no_pow / len(committee_no_pow)) if committee_no_pow else 0.0,
                attacker_proposer_share_without_pow=1.0 if proposer_no_pow and proposer_no_pow.is_attacker else 0.0,
                max_attacker_bonus_bps=max((c.ticket_bonus_bps for c in candidates if c.is_attacker), default=0),
                max_honest_bonus_bps=max((c.ticket_bonus_bps for c in candidates if not c.is_attacker), default=0),
                attacker_operator_share=attacker_operator_share,
            )
        )
    return results
