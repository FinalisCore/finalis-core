#!/usr/bin/env python3
"""
Live-protocol-faithful adversarial simulator for the finalized checkpoint path.

This models the live rules documented in:
- docs/spec/CHECKPOINT_DERIVATION_SPEC.md
- docs/spec/AVAILABILITY_STATE_COMPLETENESS.md
- docs/LIVE_PROTOCOL.md

Scope:
- epoch-boundary checkpoint derivation
- finalized-history-driven validator lifecycle at epoch granularity
- operator-native committee derivation
- BPoAR-gated eligibility with live fallback/hysteresis semantics
- deterministic committee selection and proposer ordering

Explicit abstractions:
- validator warmup/cooldown are projected from live block counts into epoch lags
- availability state transitions are driven by deterministic scenario plans rather
  than raw retained-prefix/audit-response bytes
- deterministic ticket search is modeled with the live v2 tag and bounded nonce
  range, but not by reusing live C++ types directly
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from dataclasses import asdict, dataclass, field, replace
from functools import cmp_to_key
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.sybil_model import (
    BASE_UNITS_PER_COIN,
    DEFAULT_TICKET_DIFFICULTY_BITS,
    effective_weight as sqrt_effective_weight,
)


DEFAULT_EPOCH_SIZE = 32
DEFAULT_WARMUP_BLOCKS = 100
DEFAULT_COOLDOWN_BLOCKS = 100
DEFAULT_MAX_EFFECTIVE_BOND_MULTIPLE = 10
DEFAULT_TICKET_BONUS_CAP_BPS = 1_000
DEFAULT_MIN_BOND_COINS = 100.0
DEFAULT_AVAILABILITY_MIN_BOND_COINS = 100.0
DEFAULT_AVAILABILITY_MIN_ELIGIBLE = 3
DEFAULT_COMMITTEE_SIZE = 4
DEFAULT_EPOCHS = 8
DEFAULT_NONCE_LIMIT = 4096
CHECKPOINT_FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "checkpoint"

MODE_NORMAL = "NORMAL"
MODE_FALLBACK = "FALLBACK"

REASON_NONE = "NONE"
REASON_INSUFFICIENT = "INSUFFICIENT_ELIGIBLE_OPERATORS"
REASON_STICKY = "HYSTERESIS_RECOVERY_PENDING"

STATUS_WARMUP = "WARMUP"
STATUS_ACTIVE = "ACTIVE"
STATUS_PROBATION = "PROBATION"
STATUS_EJECTED = "EJECTED"

VALID_AVAILABILITY_STATUSES = {STATUS_WARMUP, STATUS_ACTIVE, STATUS_PROBATION, STATUS_EJECTED}
VALID_JOIN_SOURCES = {"GENESIS", "POST_GENESIS"}


@dataclass(frozen=True)
class RankedCandidate:
    pubkey: bytes
    selection_id: bytes
    bonded_amount: int
    capped_bonded_amount: int
    effective_weight: int
    ticket_work_hash: bytes
    ticket_nonce: int
    ticket_bonus_bps: int
    ticket_bonus_cap_bps: int
    actor_id: str
    adversarial: bool
    validator_count: int


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def coins_to_units(coins: float) -> int:
    return max(0, int(round(coins * BASE_UNITS_PER_COIN)))


def units_to_coins(units: int) -> float:
    return float(units) / float(BASE_UNITS_PER_COIN)


def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // max(1, b)


def percent(value: float) -> float:
    return round(value * 100.0, 4)


def clamp(value: float, lo: float, hi: float) -> float:
    return min(hi, max(lo, value))


@dataclass(frozen=True)
class ProtocolParameters:
    epoch_size: int = DEFAULT_EPOCH_SIZE
    committee_size: int = DEFAULT_COMMITTEE_SIZE
    min_eligible: int = DEFAULT_AVAILABILITY_MIN_ELIGIBLE
    dynamic_min_bond_coins: float = DEFAULT_MIN_BOND_COINS
    availability_min_bond_coins: float = DEFAULT_AVAILABILITY_MIN_BOND_COINS
    validator_warmup_blocks: int = DEFAULT_WARMUP_BLOCKS
    validator_cooldown_blocks: int = DEFAULT_COOLDOWN_BLOCKS
    max_effective_bond_multiple: int = DEFAULT_MAX_EFFECTIVE_BOND_MULTIPLE
    ticket_bonus_cap_bps: int = DEFAULT_TICKET_BONUS_CAP_BPS
    ticket_difficulty_bits: int = DEFAULT_TICKET_DIFFICULTY_BITS
    ticket_nonce_limit: int = DEFAULT_NONCE_LIMIT

    def validate(self) -> None:
        if self.epoch_size <= 0:
            raise ValueError("epoch_size must be positive")
        if self.committee_size <= 0:
            raise ValueError("committee_size must be positive")
        if self.min_eligible <= 0:
            raise ValueError("min_eligible must be positive")
        if self.dynamic_min_bond_coins <= 0:
            raise ValueError("dynamic_min_bond_coins must be positive")
        if self.availability_min_bond_coins <= 0:
            raise ValueError("availability_min_bond_coins must be positive")
        if self.validator_warmup_blocks < 0 or self.validator_cooldown_blocks < 0:
            raise ValueError("warmup/cooldown blocks must be non-negative")
        if self.max_effective_bond_multiple <= 0:
            raise ValueError("max_effective_bond_multiple must be positive")
        if self.ticket_bonus_cap_bps < 0:
            raise ValueError("ticket_bonus_cap_bps must be non-negative")
        if self.ticket_difficulty_bits < 0:
            raise ValueError("ticket_difficulty_bits must be non-negative")
        if self.ticket_nonce_limit <= 0:
            raise ValueError("ticket_nonce_limit must be positive")

    @property
    def dynamic_min_bond_units(self) -> int:
        return coins_to_units(self.dynamic_min_bond_coins)

    @property
    def availability_min_bond_units(self) -> int:
        return coins_to_units(self.availability_min_bond_coins)

    @property
    def warmup_epochs(self) -> int:
        return ceil_div(self.validator_warmup_blocks, self.epoch_size)

    @property
    def cooldown_epochs(self) -> int:
        return ceil_div(self.validator_cooldown_blocks, self.epoch_size)

    @property
    def effective_bond_cap_units(self) -> int:
        return self.dynamic_min_bond_units * self.max_effective_bond_multiple


@dataclass(frozen=True)
class ActorSpec:
    actor_id: str
    adversarial: bool = False

    def validate(self) -> None:
        if not self.actor_id:
            raise ValueError("actor_id must be non-empty")


@dataclass(frozen=True)
class ValidatorSpec:
    validator_id: str
    operator_id: str
    actor_id: str
    bond_coins: float
    join_epoch: int = 0
    exit_epoch: int | None = None
    join_height: int | None = None
    exit_height: int | None = None
    join_source: str = "GENESIS"

    def validate(self) -> None:
        if not self.validator_id:
            raise ValueError("validator_id must be non-empty")
        if not self.operator_id:
            raise ValueError("operator_id must be non-empty")
        if not self.actor_id:
            raise ValueError("actor_id must be non-empty")
        if self.bond_coins <= 0:
            raise ValueError("validator bond must be positive")
        if self.join_epoch < 0:
            raise ValueError("join_epoch must be non-negative")
        if self.exit_epoch is not None and self.exit_epoch < self.join_epoch:
            raise ValueError("exit_epoch cannot be earlier than join_epoch")
        if self.join_height is not None and self.join_height < 0:
            raise ValueError("join_height must be non-negative")
        if self.exit_height is not None and self.exit_height < 0:
            raise ValueError("exit_height must be non-negative")
        if self.join_height is not None and self.join_source == "GENESIS" and self.join_height != 0:
            raise ValueError("genesis validators must have join_height 0 when provided")
        if self.exit_height is not None and self.join_height is not None and self.exit_height < self.join_height:
            raise ValueError("exit_height cannot be earlier than join_height")
        if self.join_source not in VALID_JOIN_SOURCES:
            raise ValueError(f"unsupported join_source: {self.join_source}")


@dataclass(frozen=True)
class OperatorSpec:
    operator_id: str
    actor_id: str
    default_status: str = STATUS_ACTIVE
    status_by_epoch: dict[int, str] = field(default_factory=dict)
    score_ok_by_epoch: dict[int, bool] = field(default_factory=dict)
    bond_ok_by_epoch: dict[int, bool] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.operator_id:
            raise ValueError("operator_id must be non-empty")
        if not self.actor_id:
            raise ValueError("actor_id must be non-empty")
        if self.default_status not in VALID_AVAILABILITY_STATUSES:
            raise ValueError(f"unsupported default_status: {self.default_status}")
        for epoch, status in self.status_by_epoch.items():
            if epoch <= 0:
                raise ValueError("status_by_epoch keys must be positive epochs")
            if status not in VALID_AVAILABILITY_STATUSES:
                raise ValueError(f"unsupported status value: {status}")
        for epoch in self.score_ok_by_epoch:
            if epoch <= 0:
                raise ValueError("score_ok_by_epoch keys must be positive epochs")
        for epoch in self.bond_ok_by_epoch:
            if epoch <= 0:
                raise ValueError("bond_ok_by_epoch keys must be positive epochs")


@dataclass(frozen=True)
class SimulationScenario:
    name: str
    description: str
    epochs: int
    protocol: ProtocolParameters
    actors: tuple[ActorSpec, ...]
    operators: tuple[OperatorSpec, ...]
    validators: tuple[ValidatorSpec, ...]
    seed_label: str = "finalis-protocol-sim"
    strategy_family: str = "baseline"
    baseline_scenario: str | None = None
    hypothetical_knobs: tuple[str, ...] = ()
    threshold_controls: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.name:
            raise ValueError("scenario name must be non-empty")
        if self.epochs <= 0:
            raise ValueError("epochs must be positive")
        self.protocol.validate()
        actor_ids = {actor.actor_id for actor in self.actors}
        if len(actor_ids) != len(self.actors):
            raise ValueError("duplicate actor_id")
        operator_ids = {operator.operator_id for operator in self.operators}
        if len(operator_ids) != len(self.operators):
            raise ValueError("duplicate operator_id")
        validator_ids = {validator.validator_id for validator in self.validators}
        if len(validator_ids) != len(self.validators):
            raise ValueError("duplicate validator_id")
        for actor in self.actors:
            actor.validate()
        for operator in self.operators:
            operator.validate()
            if operator.actor_id not in actor_ids:
                raise ValueError(f"operator {operator.operator_id} references unknown actor {operator.actor_id}")
        for validator in self.validators:
            validator.validate()
            if validator.actor_id not in actor_ids:
                raise ValueError(f"validator {validator.validator_id} references unknown actor {validator.actor_id}")
            if validator.operator_id not in operator_ids:
                raise ValueError(f"validator {validator.validator_id} references unknown operator {validator.operator_id}")


@dataclass(frozen=True)
class EpochOperatorResult:
    operator_id: str
    actor_id: str
    adversarial: bool
    bonded_units: int
    capped_bonded_units: int
    effective_weight: int
    validator_count: int
    base_eligible_validator_count: int
    availability_status: str
    availability_score_ok: bool
    availability_bond_ok: bool
    availability_eligible: bool
    selected: bool
    proposer: bool


@dataclass(frozen=True)
class EpochResult:
    epoch: int
    derivation_mode: str
    fallback_reason: str
    fallback_sticky: bool
    eligible_operator_count: int
    min_eligible_operators: int
    committee_operator_ids: tuple[str, ...]
    proposer_operator_id: str | None
    coalition_committee_share: float
    coalition_proposer_share: float
    committee_hhi: float
    committee_top1_share: float
    committee_top3_share: float
    operators: tuple[EpochOperatorResult, ...]
    join_activations: tuple[str, ...]
    exits_removed: tuple[str, ...]


@dataclass(frozen=True)
class ScenarioSummary:
    scenario: str
    strategy_family: str
    baseline_scenario: str | None
    epochs: int
    protocol: dict[str, Any]
    coalition_bond_share: float
    coalition_operator_share: float
    average_coalition_committee_share: float
    proposer_share: float
    committee_share_delta_vs_bond_share: float
    split_amplification_ratio: float
    fallback_epochs: int
    fallback_rate: float
    sticky_fallback_epochs: int
    sticky_fallback_rate: float
    fallback_entry_count: int
    average_fallback_duration: float
    max_fallback_duration: int
    average_recovery_time: float
    average_hhi: float
    average_top1_share: float
    average_top3_share: float
    max_operator_committee_share: float
    activation_latency_epochs: dict[str, int]
    average_activation_latency: float
    eligibility_churn_events: int
    epochs_at_exact_threshold: int
    epochs_below_threshold: int
    epochs_at_recovery_threshold: int
    sticky_fallback_entry_count: int
    recovery_from_sticky_count: int
    marginal_operator_committee_share: float
    marginal_operator_eligibility_churn: int
    operators_filtered_by_bond_floor: int
    operators_filtered_by_availability: int
    bond_threshold_binding_rate: float
    warmup_blocking_rate: float
    cooldown_blocking_rate: float
    per_epoch: list[dict[str, Any]]


@dataclass(frozen=True)
class CandidateProfile:
    name: str
    committee_size: int
    min_eligible: int
    dynamic_min_bond_coins: float
    availability_min_bond_coins: float
    validator_warmup_blocks: int
    validator_cooldown_blocks: int

    def protocol(self) -> ProtocolParameters:
        return ProtocolParameters(
            committee_size=self.committee_size,
            min_eligible=self.min_eligible,
            dynamic_min_bond_coins=self.dynamic_min_bond_coins,
            availability_min_bond_coins=self.availability_min_bond_coins,
            validator_warmup_blocks=self.validator_warmup_blocks,
            validator_cooldown_blocks=self.validator_cooldown_blocks,
        )


def actor_id_bytes(actor_id: str) -> bytes:
    return sha256d(f"actor:{actor_id}".encode("utf-8"))


def operator_id_bytes(operator_id: str) -> bytes:
    return sha256d(f"operator:{operator_id}".encode("utf-8"))


def validator_pubkey_bytes(validator_id: str) -> bytes:
    return sha256d(f"validator:{validator_id}".encode("utf-8"))


def epoch_seed(seed_label: str, epoch: int) -> bytes:
    return sha256d(f"epoch-seed:{seed_label}:{epoch}".encode("utf-8"))


def u64le(value: int) -> bytes:
    return int(value).to_bytes(8, "little", signed=False)


def varbytes(data: bytes) -> bytes:
    length = len(data)
    if length < 0xFD:
        return bytes([length]) + data
    if length <= 0xFFFF:
        return b"\xFD" + length.to_bytes(2, "little") + data
    if length <= 0xFFFFFFFF:
        return b"\xFE" + length.to_bytes(4, "little") + data
    return b"\xFF" + length.to_bytes(8, "little") + data


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


def ticket_pow_bonus_bps_from_zero_bits(zero_bits: int, difficulty_bits: int, cap_bps: int) -> int:
    if zero_bits < difficulty_bits:
        return 0
    surplus = zero_bits - difficulty_bits
    smooth = math.isqrt(max(0, surplus + 1))
    return min(cap_bps, 500 + smooth * 400)


def best_operator_ticket(operator_id: str, epoch: int, params: ProtocolParameters, seed_label: str) -> tuple[bytes, int, int]:
    operator_bytes = operator_id_bytes(operator_id)
    anchor = epoch_seed(seed_label, epoch)
    best_hash: bytes | None = None
    best_nonce = 0
    for nonce in range(params.ticket_nonce_limit):
        payload = (
            b"SC-EPOCH-TICKET-V2"
            + u64le(epoch)
            + anchor
            + operator_bytes
            + u64le(nonce)
        )
        work_hash = sha256d(payload)
        if best_hash is None or work_hash < best_hash:
            best_hash = work_hash
            best_nonce = nonce
    assert best_hash is not None
    zero_bits = leading_zero_bits(best_hash)
    bonus = ticket_pow_bonus_bps_from_zero_bits(zero_bits, params.ticket_difficulty_bits, params.ticket_bonus_cap_bps)
    return best_hash, best_nonce, bonus


def representative_validator(validators: Sequence[ValidatorSpec]) -> ValidatorSpec:
    return sorted(validators, key=lambda item: (validator_pubkey_bytes(item.validator_id), item.validator_id))[0]


def availability_status_for_epoch(spec: OperatorSpec, epoch: int) -> str:
    return spec.status_by_epoch.get(epoch, spec.default_status)


def availability_score_ok_for_epoch(spec: OperatorSpec, epoch: int) -> bool:
    return spec.score_ok_by_epoch.get(epoch, True)


def epoch_start_height(epoch: int, params: ProtocolParameters) -> int:
    return ((epoch - 1) * params.epoch_size) + 1


def lifecycle_active_for_epoch(validator: ValidatorSpec, epoch: int, params: ProtocolParameters) -> bool:
    boundary_height = epoch_start_height(epoch, params)
    if validator.join_height is not None or validator.exit_height is not None:
        joined_height = 0 if validator.join_source == "GENESIS" else (validator.join_height or epoch_start_height(validator.join_epoch, params))
        activation_height = 1 if validator.join_source == "GENESIS" else joined_height + params.validator_warmup_blocks
        if boundary_height < activation_height:
            return False
        if validator.exit_height is None:
            return True
        removal_height = validator.exit_height + params.validator_cooldown_blocks
        return boundary_height < removal_height
    warmup_epochs = params.warmup_epochs
    cooldown_epochs = params.cooldown_epochs
    activation_epoch = 1 if validator.join_source == "GENESIS" else validator.join_epoch + warmup_epochs
    if epoch < activation_epoch:
        return False
    if validator.exit_epoch is None:
        return True
    removal_epoch = validator.exit_epoch + cooldown_epochs
    return epoch < removal_epoch


def base_eligible_for_epoch(validator: ValidatorSpec, epoch: int, params: ProtocolParameters) -> bool:
    if not lifecycle_active_for_epoch(validator, epoch, params):
        return False
    bonded_units = coins_to_units(validator.bond_coins)
    if validator.join_source == "GENESIS":
        return bonded_units > 0
    return bonded_units >= params.dynamic_min_bond_units


def availability_eligible(status: str, score_ok: bool, bond_ok: bool) -> bool:
    return status == STATUS_ACTIVE and score_ok and bond_ok


def derive_mode_reason(previous_mode: str, eligible_count: int, min_eligible: int) -> tuple[str, str]:
    if previous_mode == MODE_NORMAL:
        if eligible_count < min_eligible:
            return MODE_FALLBACK, REASON_INSUFFICIENT
        return MODE_NORMAL, REASON_NONE
    if eligible_count >= min_eligible + 1:
        return MODE_NORMAL, REASON_NONE
    if eligible_count == min_eligible:
        return MODE_FALLBACK, REASON_STICKY
    return MODE_FALLBACK, REASON_INSUFFICIENT


def candidate_for_operator(
    operator_id: str,
    validators: Sequence[ValidatorSpec],
    actor_map: Mapping[str, ActorSpec],
    epoch: int,
    params: ProtocolParameters,
    seed_label: str,
) -> RankedCandidate:
    rep = representative_validator(validators)
    total_bond_units = sum(coins_to_units(v.bond_coins) for v in validators)
    capped_bond_units = min(total_bond_units, params.effective_bond_cap_units)
    ticket_hash, ticket_nonce, bonus_bps = best_operator_ticket(operator_id, epoch, params, seed_label)
    actor = actor_map[rep.actor_id]
    return RankedCandidate(
        pubkey=validator_pubkey_bytes(rep.validator_id),
        selection_id=operator_id_bytes(operator_id),
        bonded_amount=total_bond_units,
        capped_bonded_amount=capped_bond_units,
        effective_weight=sqrt_effective_weight(capped_bond_units),
        ticket_work_hash=ticket_hash,
        ticket_nonce=ticket_nonce,
        ticket_bonus_bps=bonus_bps,
        ticket_bonus_cap_bps=params.ticket_bonus_cap_bps,
        actor_id=rep.actor_id,
        adversarial=actor.adversarial,
        validator_count=len(validators),
    )


def finalized_committee_candidate_hash(seed: bytes, selection_id: bytes) -> bytes:
    return sha256d(b"SC-COMMITTEE-V3" + seed + selection_id)


def hash64_prefix(hash_bytes: bytes) -> int:
    return int.from_bytes(hash_bytes[:8], "big")


def finalized_committee_candidate_strength(candidate: RankedCandidate) -> int:
    base_weight = candidate.effective_weight if candidate.effective_weight else sqrt_effective_weight(candidate.bonded_amount)
    bounded_bonus = min(candidate.ticket_bonus_bps, candidate.ticket_bonus_cap_bps)
    bonded_coins = max(1, candidate.bonded_amount // BASE_UNITS_PER_COIN)
    bonus_scale = 1 + math.isqrt(bonded_coins)
    adjusted_bonus = bounded_bonus // bonus_scale
    return max(1, base_weight * (10_000 + adjusted_bonus))


def compare_ranked_candidates(a: RankedCandidate, b: RankedCandidate, seed: bytes) -> int:
    a_selection_id = a.selection_id if a.selection_id else a.pubkey
    b_selection_id = b.selection_id if b.selection_id else b.pubkey
    a_hash = finalized_committee_candidate_hash(seed, a_selection_id)
    b_hash = finalized_committee_candidate_hash(seed, b_selection_id)
    a_hash64 = hash64_prefix(a_hash)
    b_hash64 = hash64_prefix(b_hash)
    lhs = a_hash64 * finalized_committee_candidate_strength(b)
    rhs = b_hash64 * finalized_committee_candidate_strength(a)
    if lhs != rhs:
        return -1 if lhs < rhs else 1
    if a_hash != b_hash:
        return -1 if a_hash < b_hash else 1
    if a_selection_id != b_selection_id:
        return -1 if a_selection_id < b_selection_id else 1
    if a.pubkey != b.pubkey:
        return -1 if a.pubkey < b.pubkey else 1
    if a.effective_weight != b.effective_weight:
        return -1 if a.effective_weight > b.effective_weight else 1
    if a.capped_bonded_amount != b.capped_bonded_amount:
        return -1 if a.capped_bonded_amount > b.capped_bonded_amount else 1
    if a.bonded_amount != b.bonded_amount:
        return -1 if a.bonded_amount > b.bonded_amount else 1
    if a.ticket_bonus_bps != b.ticket_bonus_bps:
        return -1 if a.ticket_bonus_bps > b.ticket_bonus_bps else 1
    if a.ticket_work_hash != b.ticket_work_hash:
        return -1 if a.ticket_work_hash < b.ticket_work_hash else 1
    if a.ticket_nonce != b.ticket_nonce:
        return -1 if a.ticket_nonce < b.ticket_nonce else 1
    if a.ticket_bonus_cap_bps != b.ticket_bonus_cap_bps:
        return -1 if a.ticket_bonus_cap_bps < b.ticket_bonus_cap_bps else 1
    return -1 if a.selection_id < b.selection_id else (1 if a.selection_id > b.selection_id else 0)


def rank_finalized_committee_candidates(candidates: Sequence[RankedCandidate], seed: bytes) -> list[RankedCandidate]:
    return sorted(candidates, key=cmp_to_key(lambda a, b: compare_ranked_candidates(a, b, seed)))


def select_finalized_committee(candidates: Sequence[RankedCandidate], seed: bytes, committee_size: int) -> list[RankedCandidate]:
    ranked = rank_finalized_committee_candidates(candidates, seed)
    return ranked[: min(committee_size, len(ranked))]


def compute_committee_root(committee: Sequence[RankedCandidate]) -> bytes:
    parts = []
    for entry in committee:
        parts.append(varbytes(entry.pubkey + entry.ticket_work_hash + u64le(entry.ticket_nonce)))
    return sha256d(b"SELFCOIN_COMMITTEE_V1" + b"".join(parts))


def compute_proposer_seed(epoch_anchor: bytes, height: int, committee_root: bytes) -> bytes:
    return sha256d(b"SELFCOIN_PROPOSER_V1" + epoch_anchor + u64le(height) + committee_root)


def proposer_schedule(committee: Sequence[RankedCandidate], epoch_anchor: bytes, height: int) -> list[RankedCandidate]:
    proposer_seed = compute_proposer_seed(epoch_anchor, height, compute_committee_root(committee))
    ranked = sorted(
        ((sha256d(proposer_seed + entry.pubkey), entry) for entry in committee),
        key=lambda item: (item[0], item[1].pubkey),
    )
    return [entry for _, entry in ranked]


def proposer_share_by_actor(committee: Sequence[RankedCandidate], proposer: RankedCandidate | None, candidate_actor: Mapping[bytes, str]) -> dict[str, float]:
    if not committee:
        return {}
    quorum = (2 * len(committee)) // 3 + 1
    signers = sorted(committee, key=lambda c: c.pubkey)[:quorum]
    scores: dict[str, int] = {}
    for signer in signers:
        actor_id = candidate_actor[signer.pubkey]
        scores[actor_id] = scores.get(actor_id, 0) + signer.effective_weight
    if proposer is not None:
        actor_id = candidate_actor[proposer.pubkey]
        scores[actor_id] = scores.get(actor_id, 0) + proposer.effective_weight
    total = sum(scores.values())
    if total == 0:
        return {}
    return {actor_id: score / total for actor_id, score in scores.items()}


def concentration_hhi(shares: Iterable[float]) -> float:
    return sum(share * share for share in shares)


def top_k_share(shares: Iterable[float], k: int) -> float:
    ranked = sorted(shares, reverse=True)
    return sum(ranked[:k])


def operator_share_map(committee_operator_ids: Sequence[str]) -> dict[str, float]:
    total = max(1, len(committee_operator_ids))
    counts: dict[str, int] = {}
    for operator_id in committee_operator_ids:
        counts[operator_id] = counts.get(operator_id, 0) + 1
    return {operator_id: count / total for operator_id, count in counts.items()}


def run_scenario(scenario: SimulationScenario) -> ScenarioSummary:
    scenario.validate()
    params = scenario.protocol
    actor_map = {actor.actor_id: actor for actor in scenario.actors}
    operator_map = {operator.operator_id: operator for operator in scenario.operators}
    validators_by_operator: dict[str, list[ValidatorSpec]] = {}
    for validator in scenario.validators:
        validators_by_operator.setdefault(validator.operator_id, []).append(validator)

    coalition_bond_units = sum(
        coins_to_units(v.bond_coins) for v in scenario.validators if actor_map[v.actor_id].adversarial
    )
    total_bond_units = max(1, sum(coins_to_units(v.bond_coins) for v in scenario.validators))
    coalition_bond_share = coalition_bond_units / total_bond_units
    coalition_operator_share = (
        sum(1 for operator in scenario.operators if actor_map[operator.actor_id].adversarial) / max(1, len(scenario.operators))
    )

    previous_mode = MODE_FALLBACK
    committee_history: list[EpochResult] = []
    seen_active: dict[str, bool] = {validator.validator_id: False for validator in scenario.validators}
    activation_latency: dict[str, int] = {}
    fallback_durations: list[int] = []
    current_fallback_duration = 0
    recovery_times: list[int] = []
    pending_recovery = False
    previous_eligible_operators: set[str] = set()
    eligibility_churn_events = 0
    epochs_at_exact_threshold = 0
    epochs_below_threshold = 0
    epochs_at_recovery_threshold = 0
    sticky_fallback_entry_count = 0
    recovery_from_sticky_count = 0
    previous_sticky = False
    marginal_operator_ids = set(str(item) for item in scenario.threshold_controls.get("marginal_operator_ids", []))
    marginal_operator_committee_share_sum = 0.0
    marginal_operator_eligibility_churn = 0
    previous_marginal_eligible: set[str] = set()
    operators_filtered_by_bond_floor = 0
    operators_filtered_by_availability = 0
    epochs_with_bond_binding = 0
    warmup_blocked_checks = 0
    warmup_total_checks = 0
    cooldown_blocked_checks = 0
    cooldown_total_checks = 0

    for epoch in range(1, scenario.epochs + 1):
        availability_eligible_ops: set[str] = set()
        candidate_pool: list[tuple[str, RankedCandidate]] = []
        operator_results: list[EpochOperatorResult] = []
        join_activations: list[str] = []
        exits_removed: list[str] = []
        bond_binding_this_epoch = False

        for validator in scenario.validators:
            now_active = lifecycle_active_for_epoch(validator, epoch, params)
            if validator.join_source == "POST_GENESIS":
                warmup_total_checks += 1
                if not now_active:
                    joined_height = validator.join_height if validator.join_height is not None else epoch_start_height(validator.join_epoch, params)
                    boundary_height = epoch_start_height(epoch, params)
                    if boundary_height < joined_height + params.validator_warmup_blocks:
                        warmup_blocked_checks += 1
            if validator.exit_epoch is not None or validator.exit_height is not None:
                cooldown_total_checks += 1
                if now_active:
                    exit_height = validator.exit_height if validator.exit_height is not None else epoch_start_height(validator.exit_epoch or 0, params)
                    boundary_height = epoch_start_height(epoch, params)
                    if boundary_height < exit_height + params.validator_cooldown_blocks and boundary_height >= exit_height:
                        cooldown_blocked_checks += 1
            if now_active and not seen_active[validator.validator_id]:
                seen_active[validator.validator_id] = True
                if validator.join_source == "POST_GENESIS":
                    activation_latency[validator.validator_id] = epoch - validator.join_epoch
                    join_activations.append(validator.validator_id)
            if not now_active and seen_active[validator.validator_id]:
                exits_removed.append(validator.validator_id)

        for operator_id, spec in operator_map.items():
            base_eligible_validators = [
                validator
                for validator in validators_by_operator.get(operator_id, [])
                if base_eligible_for_epoch(validator, epoch, params)
            ]
            total_bond_units = sum(
                coins_to_units(validator.bond_coins)
                for validator in validators_by_operator.get(operator_id, [])
                if lifecycle_active_for_epoch(validator, epoch, params)
            )
            status = availability_status_for_epoch(spec, epoch)
            score_ok = availability_score_ok_for_epoch(spec, epoch)
            bond_ok = spec.bond_ok_by_epoch.get(epoch, total_bond_units >= params.availability_min_bond_units)
            is_availability_eligible = availability_eligible(status, score_ok, bond_ok)
            if is_availability_eligible:
                availability_eligible_ops.add(operator_id)
            operator_results.append(
                EpochOperatorResult(
                    operator_id=operator_id,
                    actor_id=spec.actor_id,
                    adversarial=actor_map[spec.actor_id].adversarial,
                    bonded_units=total_bond_units,
                    capped_bonded_units=min(total_bond_units, params.effective_bond_cap_units),
                    effective_weight=sqrt_effective_weight(min(total_bond_units, params.effective_bond_cap_units))
                    if total_bond_units > 0
                    else 0,
                    validator_count=len(validators_by_operator.get(operator_id, [])),
                    base_eligible_validator_count=len(base_eligible_validators),
                    availability_status=status,
                    availability_score_ok=score_ok,
                    availability_bond_ok=bond_ok,
                    availability_eligible=is_availability_eligible,
                    selected=False,
                    proposer=False,
                )
            )

        eligible_count = len(sorted(availability_eligible_ops))
        mode, reason = derive_mode_reason(previous_mode, eligible_count, params.min_eligible)
        fallback_sticky = mode == MODE_FALLBACK and reason == REASON_STICKY
        if eligible_count == params.min_eligible:
            epochs_at_exact_threshold += 1
        if eligible_count < params.min_eligible:
            epochs_below_threshold += 1
        if eligible_count == params.min_eligible + 1:
            epochs_at_recovery_threshold += 1
        if fallback_sticky and not previous_sticky:
            sticky_fallback_entry_count += 1
        if previous_sticky and mode == MODE_NORMAL:
            recovery_from_sticky_count += 1
        current_eligible_operators = set(availability_eligible_ops)
        eligibility_churn_events += len(current_eligible_operators.symmetric_difference(previous_eligible_operators))
        current_marginal_eligible = {operator_id for operator_id in current_eligible_operators if operator_id in marginal_operator_ids}
        marginal_operator_eligibility_churn += len(current_marginal_eligible.symmetric_difference(previous_marginal_eligible))
        previous_eligible_operators = current_eligible_operators
        previous_marginal_eligible = current_marginal_eligible

        for operator_id, spec in operator_map.items():
            base_eligible_validators = [
                validator
                for validator in validators_by_operator.get(operator_id, [])
                if base_eligible_for_epoch(validator, epoch, params)
            ]
            lifecycle_active_validators = [
                validator for validator in validators_by_operator.get(operator_id, []) if lifecycle_active_for_epoch(validator, epoch, params)
            ]
            if lifecycle_active_validators and not base_eligible_validators:
                operators_filtered_by_bond_floor += 1
                bond_binding_this_epoch = True
            if not base_eligible_validators:
                continue
            operator_status = availability_status_for_epoch(spec, epoch)
            score_ok = availability_score_ok_for_epoch(spec, epoch)
            total_bond_units = sum(coins_to_units(validator.bond_coins) for validator in base_eligible_validators)
            bond_ok = spec.bond_ok_by_epoch.get(epoch, total_bond_units >= params.availability_min_bond_units)
            operator_availability_eligible = availability_eligible(operator_status, score_ok, bond_ok)
            if mode == MODE_NORMAL and not operator_availability_eligible:
                operators_filtered_by_availability += 1
                continue
            candidate_pool.append(
                (
                    operator_id,
                    candidate_for_operator(operator_id, base_eligible_validators, actor_map, epoch, params, scenario.seed_label),
                )
            )

        candidates = [candidate for _, candidate in sorted(candidate_pool, key=lambda item: item[0])]
        committee = select_finalized_committee(candidates, epoch_seed(scenario.seed_label, epoch), params.committee_size)
        schedule = proposer_schedule(committee, epoch_seed(scenario.seed_label, epoch), epoch)
        proposer = schedule[0] if schedule else None
        candidate_actor: dict[bytes, str] = {}
        selection_to_operator: dict[bytes, str] = {}
        for operator_id, candidate in candidate_pool:
            rep = representative_validator(
                [
                    validator
                    for validator in validators_by_operator.get(operator_id, [])
                    if base_eligible_for_epoch(validator, epoch, params)
                ]
            )
            candidate_actor[candidate.pubkey] = rep.actor_id
            selection_to_operator[candidate.selection_id] = operator_id

        committee_operator_ids = tuple(selection_to_operator[c.selection_id] for c in committee)
        committee_actor_shares: dict[str, float] = {}
        for candidate in committee:
            actor_id = candidate_actor[candidate.pubkey]
            committee_actor_shares[actor_id] = committee_actor_shares.get(actor_id, 0.0) + 1.0 / max(1, len(committee))
        proposer_actor_shares = proposer_share_by_actor(committee, proposer, candidate_actor)
        coalition_committee_share = sum(
            share for actor_id, share in committee_actor_shares.items() if actor_map[actor_id].adversarial
        )
        coalition_proposer_share = sum(
            share for actor_id, share in proposer_actor_shares.items() if actor_map[actor_id].adversarial
        )
        operator_shares = operator_share_map(committee_operator_ids)
        marginal_operator_committee_share_sum += sum(
            share for operator_id, share in operator_shares.items() if operator_id in marginal_operator_ids
        )

        operator_result_index = {item.operator_id: item for item in operator_results}
        selected_ops = set(committee_operator_ids)
        proposer_op = selection_to_operator.get(proposer.selection_id) if proposer is not None else None
        operator_results = [
            replace(item, selected=item.operator_id in selected_ops, proposer=item.operator_id == proposer_op)
            for item in sorted(operator_results, key=lambda op: op.operator_id)
        ]

        if mode == MODE_FALLBACK:
            current_fallback_duration += 1
            pending_recovery = True
        else:
            if current_fallback_duration > 0:
                fallback_durations.append(current_fallback_duration)
                current_fallback_duration = 0
            if pending_recovery:
                recovery_times.append(1)
                pending_recovery = False

        committee_history.append(
            EpochResult(
                epoch=epoch,
                derivation_mode=mode,
                fallback_reason=reason,
                fallback_sticky=fallback_sticky,
                eligible_operator_count=eligible_count,
                min_eligible_operators=params.min_eligible,
                committee_operator_ids=committee_operator_ids,
                proposer_operator_id=proposer_op,
                coalition_committee_share=coalition_committee_share,
                coalition_proposer_share=coalition_proposer_share,
                committee_hhi=concentration_hhi(operator_shares.values()),
                committee_top1_share=top_k_share(operator_shares.values(), 1),
                committee_top3_share=top_k_share(operator_shares.values(), 3),
                operators=tuple(operator_results),
                join_activations=tuple(sorted(join_activations)),
                exits_removed=tuple(sorted(exits_removed)),
            )
        )
        previous_mode = mode
        previous_sticky = fallback_sticky
        if bond_binding_this_epoch:
            epochs_with_bond_binding += 1

    if current_fallback_duration > 0:
        fallback_durations.append(current_fallback_duration)

    fallback_epochs = sum(1 for epoch in committee_history if epoch.derivation_mode == MODE_FALLBACK)
    sticky_epochs = sum(1 for epoch in committee_history if epoch.fallback_sticky)
    fallback_entry_count = sum(
        1
        for index, epoch in enumerate(committee_history)
        if epoch.derivation_mode == MODE_FALLBACK and (index == 0 or committee_history[index - 1].derivation_mode != MODE_FALLBACK)
    )

    max_operator_committee_share = 0.0
    for epoch in committee_history:
        shares = operator_share_map(epoch.committee_operator_ids).values()
        if shares:
            max_operator_committee_share = max(max_operator_committee_share, max(shares))

    return ScenarioSummary(
        scenario=scenario.name,
        strategy_family=scenario.strategy_family,
        baseline_scenario=scenario.baseline_scenario,
        epochs=scenario.epochs,
        protocol=asdict(params),
        coalition_bond_share=coalition_bond_share,
        coalition_operator_share=coalition_operator_share,
        average_coalition_committee_share=sum(epoch.coalition_committee_share for epoch in committee_history) / scenario.epochs,
        proposer_share=sum(epoch.coalition_proposer_share for epoch in committee_history) / scenario.epochs,
        committee_share_delta_vs_bond_share=(
            sum(epoch.coalition_committee_share for epoch in committee_history) / scenario.epochs
        )
        - coalition_bond_share,
        split_amplification_ratio=(
            (sum(epoch.coalition_committee_share for epoch in committee_history) / scenario.epochs) / coalition_bond_share
            if coalition_bond_share > 0
            else 0.0
        ),
        fallback_epochs=fallback_epochs,
        fallback_rate=fallback_epochs / scenario.epochs,
        sticky_fallback_epochs=sticky_epochs,
        sticky_fallback_rate=sticky_epochs / scenario.epochs,
        fallback_entry_count=fallback_entry_count,
        average_fallback_duration=(sum(fallback_durations) / len(fallback_durations)) if fallback_durations else 0.0,
        max_fallback_duration=max(fallback_durations) if fallback_durations else 0,
        average_recovery_time=(sum(recovery_times) / len(recovery_times)) if recovery_times else 0.0,
        average_hhi=sum(epoch.committee_hhi for epoch in committee_history) / scenario.epochs,
        average_top1_share=sum(epoch.committee_top1_share for epoch in committee_history) / scenario.epochs,
        average_top3_share=sum(epoch.committee_top3_share for epoch in committee_history) / scenario.epochs,
        max_operator_committee_share=max_operator_committee_share,
        activation_latency_epochs=activation_latency,
        average_activation_latency=(
            sum(activation_latency.values()) / len(activation_latency) if activation_latency else 0.0
        ),
        eligibility_churn_events=eligibility_churn_events,
        epochs_at_exact_threshold=epochs_at_exact_threshold,
        epochs_below_threshold=epochs_below_threshold,
        epochs_at_recovery_threshold=epochs_at_recovery_threshold,
        sticky_fallback_entry_count=sticky_fallback_entry_count,
        recovery_from_sticky_count=recovery_from_sticky_count,
        marginal_operator_committee_share=marginal_operator_committee_share_sum / scenario.epochs,
        marginal_operator_eligibility_churn=marginal_operator_eligibility_churn,
        operators_filtered_by_bond_floor=operators_filtered_by_bond_floor,
        operators_filtered_by_availability=operators_filtered_by_availability,
        bond_threshold_binding_rate=epochs_with_bond_binding / max(1, scenario.epochs),
        warmup_blocking_rate=warmup_blocked_checks / max(1, warmup_total_checks),
        cooldown_blocking_rate=cooldown_blocked_checks / max(1, cooldown_total_checks),
        per_epoch=[asdict(epoch) for epoch in committee_history],
    )


def compare_summaries(summaries: Sequence[ScenarioSummary]) -> dict[str, Any]:
    rows = []
    for summary in summaries:
        rows.append(
            {
                "scenario": summary.scenario,
                "strategy_family": summary.strategy_family,
                "committee_share_pct": percent(summary.average_coalition_committee_share),
                "proposer_share_pct": percent(summary.proposer_share),
                "bond_share_pct": percent(summary.coalition_bond_share),
                "split_amplification_ratio": round(summary.split_amplification_ratio, 6),
                "fallback_rate_pct": percent(summary.fallback_rate),
                "sticky_rate_pct": percent(summary.sticky_fallback_rate),
                "avg_hhi": round(summary.average_hhi, 6),
                "avg_top1_pct": percent(summary.average_top1_share),
                "avg_top3_pct": percent(summary.average_top3_share),
            }
        )
    baseline = summaries[0] if summaries else None
    deltas = []
    if baseline is not None:
        for summary in summaries[1:]:
            deltas.append(
                {
                    "scenario": summary.scenario,
                    "baseline": baseline.scenario,
                    "committee_share_delta_pct": percent(
                        summary.average_coalition_committee_share - baseline.average_coalition_committee_share
                    ),
                    "proposer_share_delta_pct": percent(summary.proposer_share - baseline.proposer_share),
                    "fallback_rate_delta_pct": percent(summary.fallback_rate - baseline.fallback_rate),
                    "sticky_rate_delta_pct": percent(summary.sticky_fallback_rate - baseline.sticky_fallback_rate),
                    "hhi_delta": round(summary.average_hhi - baseline.average_hhi, 6),
                }
            )
    return {"scenarios": rows, "deltas_vs_first": deltas}


def render_markdown_report(summaries: Sequence[ScenarioSummary]) -> str:
    lines = [
        "# Finalis Protocol Attack Simulation",
        "",
        "| scenario | strategy | bond share | committee share | proposer share | fallback rate | sticky rate | split amp | avg HHI |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for summary in summaries:
        lines.append(
            f"| {summary.scenario} | {summary.strategy_family} | {percent(summary.coalition_bond_share):.2f}% | "
            f"{percent(summary.average_coalition_committee_share):.2f}% | {percent(summary.proposer_share):.2f}% | "
            f"{percent(summary.fallback_rate):.2f}% | {percent(summary.sticky_fallback_rate):.2f}% | "
            f"{summary.split_amplification_ratio:.3f} | {summary.average_hhi:.4f} |"
        )
    if len(summaries) >= 2:
        baseline = summaries[0]
        lines.extend(["", "## Deltas vs Baseline", ""])
        for summary in summaries[1:]:
            lines.append(f"- `{summary.scenario}` vs `{baseline.scenario}`")
            lines.append(
                f"  committee share delta: {percent(summary.average_coalition_committee_share - baseline.average_coalition_committee_share):.2f}%"
            )
            lines.append(
                f"  proposer share delta: {percent(summary.proposer_share - baseline.proposer_share):.2f}%"
            )
            lines.append(f"  fallback rate delta: {percent(summary.fallback_rate - baseline.fallback_rate):.2f}%")
            lines.append(
                f"  sticky fallback delta: {percent(summary.sticky_fallback_rate - baseline.sticky_fallback_rate):.2f}%"
            )
    return "\n".join(lines) + "\n"


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_epoch_csv(path: Path, summaries: Sequence[ScenarioSummary]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "scenario",
                "epoch",
                "mode",
                "reason",
                "fallback_sticky",
                "eligible_operator_count",
                "coalition_committee_share",
                "coalition_proposer_share",
                "committee_hhi",
                "committee_top1_share",
                "committee_top3_share",
                "committee_operator_ids",
                "proposer_operator_id",
            ],
        )
        writer.writeheader()
        for summary in summaries:
            for epoch in summary.per_epoch:
                writer.writerow(
                    {
                        "scenario": summary.scenario,
                        "epoch": epoch["epoch"],
                        "mode": epoch["derivation_mode"],
                        "reason": epoch["fallback_reason"],
                        "fallback_sticky": int(epoch["fallback_sticky"]),
                        "eligible_operator_count": epoch["eligible_operator_count"],
                        "coalition_committee_share": f"{epoch['coalition_committee_share']:.6f}",
                        "coalition_proposer_share": f"{epoch['coalition_proposer_share']:.6f}",
                        "committee_hhi": f"{epoch['committee_hhi']:.6f}",
                        "committee_top1_share": f"{epoch['committee_top1_share']:.6f}",
                        "committee_top3_share": f"{epoch['committee_top3_share']:.6f}",
                        "committee_operator_ids": ",".join(epoch["committee_operator_ids"]),
                        "proposer_operator_id": epoch["proposer_operator_id"] or "",
                    }
                )


def scenario_from_dict(data: Mapping[str, Any]) -> SimulationScenario:
    protocol = ProtocolParameters(**data["protocol"])
    actors = tuple(ActorSpec(**item) for item in data["actors"])
    operators = tuple(OperatorSpec(**item) for item in data["operators"])
    validators = tuple(ValidatorSpec(**item) for item in data["validators"])
    return SimulationScenario(
        name=data["name"],
        description=data.get("description", ""),
        epochs=int(data["epochs"]),
        protocol=protocol,
        actors=actors,
        operators=operators,
        validators=validators,
        seed_label=data.get("seed_label", data["name"]),
        strategy_family=data.get("strategy_family", "custom"),
        baseline_scenario=data.get("baseline_scenario"),
        hypothetical_knobs=tuple(data.get("hypothetical_knobs", ())),
        threshold_controls=dict(data.get("threshold_controls", {})),
    )


def scenario_to_dict(scenario: SimulationScenario) -> dict[str, Any]:
    payload = asdict(scenario)
    payload["hypothetical_knobs"] = list(scenario.hypothetical_knobs)
    return payload


def build_honest_baseline() -> SimulationScenario:
    protocol = ProtocolParameters()
    actors = tuple(ActorSpec(actor_id=f"honest-{idx}") for idx in range(1, 9))
    operators = tuple(
        OperatorSpec(operator_id=f"op-h{idx}", actor_id=f"honest-{idx}", default_status=STATUS_ACTIVE)
        for idx in range(1, 9)
    )
    validators = tuple(
        ValidatorSpec(
            validator_id=f"val-h{idx}",
            operator_id=f"op-h{idx}",
            actor_id=f"honest-{idx}",
            bond_coins=120.0 + float(idx),
            join_source="GENESIS",
        )
        for idx in range(1, 9)
    )
    return SimulationScenario(
        name="honest_baseline",
        description="All operators honest, active, and committee-eligible.",
        epochs=8,
        protocol=protocol,
        actors=actors,
        operators=operators,
        validators=validators,
        strategy_family="honest_baseline",
    )


def build_unsplit_coalition_baseline() -> SimulationScenario:
    protocol = ProtocolParameters()
    actors = tuple([ActorSpec(actor_id="honest", adversarial=False), ActorSpec(actor_id="coalition", adversarial=True)])
    operators = tuple(
        [OperatorSpec(operator_id=f"op-h{idx}", actor_id="honest", default_status=STATUS_ACTIVE) for idx in range(1, 7)]
        + [OperatorSpec(operator_id="op-a1", actor_id="coalition", default_status=STATUS_ACTIVE)]
    )
    validators = tuple(
        [ValidatorSpec(validator_id=f"val-h{idx}", operator_id=f"op-h{idx}", actor_id="honest", bond_coins=120.0 + idx) for idx in range(1, 7)]
        + [ValidatorSpec(validator_id="val-a1", operator_id="op-a1", actor_id="coalition", bond_coins=360.0)]
    )
    return SimulationScenario(
        name="coalition_unsplit_baseline",
        description="Adversarial coalition keeps its bond under one operator.",
        epochs=8,
        protocol=protocol,
        actors=actors,
        operators=operators,
        validators=validators,
        strategy_family="unsplit_baseline",
    )


def build_split_operator_adversary(split_count: int = 3) -> SimulationScenario:
    protocol = ProtocolParameters()
    actors = tuple([ActorSpec(actor_id="honest"), ActorSpec(actor_id="coalition", adversarial=True)])
    operators = [OperatorSpec(operator_id=f"op-h{idx}", actor_id="honest", default_status=STATUS_ACTIVE) for idx in range(1, 7)]
    validators = [ValidatorSpec(validator_id=f"val-h{idx}", operator_id=f"op-h{idx}", actor_id="honest", bond_coins=120.0 + idx) for idx in range(1, 7)]
    split_bond = 360.0 / float(split_count)
    for idx in range(1, split_count + 1):
        operators.append(OperatorSpec(operator_id=f"op-a{idx}", actor_id="coalition", default_status=STATUS_ACTIVE))
        validators.append(
            ValidatorSpec(
                validator_id=f"val-a{idx}",
                operator_id=f"op-a{idx}",
                actor_id="coalition",
                bond_coins=split_bond,
                join_source="GENESIS",
            )
        )
    return SimulationScenario(
        name="split_operator_adversary",
        description="One coalition splits bond across multiple operators.",
        epochs=8,
        protocol=protocol,
        actors=actors,
        operators=tuple(operators),
        validators=tuple(validators),
        strategy_family="operator_split",
        baseline_scenario="coalition_unsplit_baseline",
    )


def build_availability_griefing_adversary() -> SimulationScenario:
    protocol = ProtocolParameters(min_eligible=4, committee_size=4)
    actors = tuple([ActorSpec(actor_id="honest"), ActorSpec(actor_id="coalition", adversarial=True)])
    operators = []
    validators = []
    for idx in range(1, 6):
        operators.append(
            OperatorSpec(
                operator_id=f"op-h{idx}",
                actor_id="honest",
                default_status=STATUS_ACTIVE,
                status_by_epoch={3: STATUS_PROBATION, 4: STATUS_WARMUP} if idx in (4, 5) else {},
                score_ok_by_epoch={3: False, 4: False} if idx in (4, 5) else {},
            )
        )
        validators.append(
            ValidatorSpec(
                validator_id=f"val-h{idx}",
                operator_id=f"op-h{idx}",
                actor_id="honest",
                bond_coins=125.0 + idx,
                join_source="GENESIS",
            )
        )
    for idx in range(1, 3):
        operators.append(OperatorSpec(operator_id=f"op-a{idx}", actor_id="coalition", default_status=STATUS_ACTIVE))
        validators.append(
            ValidatorSpec(
                validator_id=f"val-a{idx}",
                operator_id=f"op-a{idx}",
                actor_id="coalition",
                bond_coins=170.0,
                join_source="GENESIS",
            )
        )
    return SimulationScenario(
        name="availability_griefing_adversary",
        description="Coordinated availability degradation pushes honest operators below eligibility and triggers fallback.",
        epochs=8,
        protocol=protocol,
        actors=actors,
        operators=tuple(operators),
        validators=tuple(validators),
        strategy_family="availability_griefing",
        baseline_scenario="honest_baseline",
    )


def build_sticky_fallback_threshold_manipulator() -> SimulationScenario:
    protocol = ProtocolParameters(min_eligible=3, committee_size=4)
    actors = tuple([ActorSpec(actor_id="honest"), ActorSpec(actor_id="coalition", adversarial=True)])
    operators = []
    validators = []
    plans = {
        "op-h1": {},
        "op-h2": {2: STATUS_WARMUP, 3: STATUS_ACTIVE, 4: STATUS_ACTIVE},
        "op-h3": {2: STATUS_WARMUP, 3: STATUS_WARMUP, 4: STATUS_ACTIVE},
        "op-a1": {},
    }
    for operator_id, plan in plans.items():
        actor_id = "coalition" if operator_id.startswith("op-a") else "honest"
        operators.append(
            OperatorSpec(
                operator_id=operator_id,
                actor_id=actor_id,
                default_status=STATUS_ACTIVE,
                status_by_epoch=plan,
                score_ok_by_epoch={epoch: status == STATUS_ACTIVE for epoch, status in plan.items()},
            )
        )
        validators.append(
            ValidatorSpec(
                validator_id=operator_id.replace("op", "val"),
                operator_id=operator_id,
                actor_id=actor_id,
                bond_coins=150.0,
                join_source="GENESIS",
            )
        )
    return SimulationScenario(
        name="sticky_fallback_threshold_manipulator",
        description="Threshold-edge availability manipulation drives fallback entry and sticky recovery at exact minimum eligibility.",
        epochs=4,
        protocol=protocol,
        actors=actors,
        operators=tuple(operators),
        validators=tuple(validators),
        strategy_family="threshold_manipulation",
    )


def build_join_exit_boundary_adversary() -> SimulationScenario:
    protocol = ProtocolParameters(committee_size=4, min_eligible=3)
    actors = tuple([ActorSpec(actor_id="honest"), ActorSpec(actor_id="coalition", adversarial=True)])
    operators = [OperatorSpec(operator_id=f"op-h{idx}", actor_id="honest", default_status=STATUS_ACTIVE) for idx in range(1, 5)]
    validators = [
        ValidatorSpec(validator_id=f"val-h{idx}", operator_id=f"op-h{idx}", actor_id="honest", bond_coins=130.0 + idx)
        for idx in range(1, 5)
    ]
    operators.extend(
        [
            OperatorSpec(operator_id="op-a1", actor_id="coalition", default_status=STATUS_ACTIVE),
            OperatorSpec(operator_id="op-a2", actor_id="coalition", default_status=STATUS_ACTIVE),
        ]
    )
    validators.extend(
        [
            ValidatorSpec(
                validator_id="val-a1",
                operator_id="op-a1",
                actor_id="coalition",
                bond_coins=180.0,
                join_epoch=2,
                join_source="POST_GENESIS",
            ),
            ValidatorSpec(
                validator_id="val-a2",
                operator_id="op-a2",
                actor_id="coalition",
                bond_coins=180.0,
                join_epoch=3,
                exit_epoch=7,
                join_source="POST_GENESIS",
            ),
        ]
    )
    return SimulationScenario(
        name="join_exit_boundary_adversary",
        description="Coalition times joins and exits near epoch boundaries to study activation lag and removal timing.",
        epochs=12,
        protocol=protocol,
        actors=actors,
        operators=tuple(operators),
        validators=tuple(validators),
        strategy_family="join_exit_timing",
    )


CURRENT_LIKE_PROFILE = CandidateProfile(
    name="current_like_baseline",
    committee_size=16,
    min_eligible=16,
    dynamic_min_bond_coins=100.0,
    availability_min_bond_coins=100.0,
    validator_warmup_blocks=100,
    validator_cooldown_blocks=100,
)

PROFILE_A = CandidateProfile(
    name="profile_a_16_18_150",
    committee_size=16,
    min_eligible=18,
    dynamic_min_bond_coins=150.0,
    availability_min_bond_coins=150.0,
    validator_warmup_blocks=100,
    validator_cooldown_blocks=100,
)

PROFILE_B = CandidateProfile(
    name="profile_b_24_27_150",
    committee_size=24,
    min_eligible=27,
    dynamic_min_bond_coins=150.0,
    availability_min_bond_coins=150.0,
    validator_warmup_blocks=128,
    validator_cooldown_blocks=128,
)


def candidate_profiles() -> dict[str, CandidateProfile]:
    return {
        CURRENT_LIKE_PROFILE.name: CURRENT_LIKE_PROFILE,
        PROFILE_A.name: PROFILE_A,
        PROFILE_B.name: PROFILE_B,
    }


def make_scaled_protocol(
    committee_size: int,
    min_eligible: int,
    dynamic_min_bond_coins: float,
    availability_min_bond_coins: float,
    validator_warmup_blocks: int,
    validator_cooldown_blocks: int,
) -> ProtocolParameters:
    return ProtocolParameters(
        committee_size=committee_size,
        min_eligible=min_eligible,
        dynamic_min_bond_coins=dynamic_min_bond_coins,
        availability_min_bond_coins=availability_min_bond_coins,
        validator_warmup_blocks=validator_warmup_blocks,
        validator_cooldown_blocks=validator_cooldown_blocks,
    )


def build_large_split_operator_adversary(
    committee_size: int = 16,
    min_eligible: int | None = None,
    dynamic_min_bond_coins: float = 100.0,
    availability_min_bond_coins: float | None = None,
    validator_warmup_blocks: int = 100,
    validator_cooldown_blocks: int = 100,
    split_count: int = 3,
) -> SimulationScenario:
    if min_eligible is None:
        min_eligible = committee_size + 2
    if availability_min_bond_coins is None:
        availability_min_bond_coins = dynamic_min_bond_coins
    protocol = make_scaled_protocol(
        committee_size,
        min_eligible,
        dynamic_min_bond_coins,
        availability_min_bond_coins,
        validator_warmup_blocks,
        validator_cooldown_blocks,
    )
    actors = (ActorSpec(actor_id="honest"), ActorSpec(actor_id="coalition", adversarial=True))
    honest_operator_count = max(committee_size + 12, min_eligible + 8)
    operators: list[OperatorSpec] = []
    validators: list[ValidatorSpec] = []
    for idx in range(1, honest_operator_count + 1):
        operator_id = f"op-h{idx}"
        operators.append(OperatorSpec(operator_id=operator_id, actor_id="honest", default_status=STATUS_ACTIVE))
        validators.append(
            ValidatorSpec(
                validator_id=f"val-h{idx}",
                operator_id=operator_id,
                actor_id="honest",
                bond_coins=dynamic_min_bond_coins + 20.0 + float(idx % 7),
                join_source="GENESIS",
            )
        )
    coalition_total_bond = dynamic_min_bond_coins * max(split_count, 1) * 1.35
    split_bond = coalition_total_bond / float(max(1, split_count))
    for idx in range(1, split_count + 1):
        operator_id = f"op-a{idx}"
        operators.append(OperatorSpec(operator_id=operator_id, actor_id="coalition", default_status=STATUS_ACTIVE))
        validators.append(
            ValidatorSpec(
                validator_id=f"val-a{idx}",
                operator_id=operator_id,
                actor_id="coalition",
                bond_coins=split_bond,
                join_source="GENESIS",
            )
        )
    return SimulationScenario(
        name=f"split_operator_adversary_large_k{committee_size}",
        description="Large-committee coalition splitting analysis against the live checkpoint derivation path.",
        epochs=8,
        protocol=protocol,
        actors=actors,
        operators=tuple(operators),
        validators=tuple(validators),
        strategy_family="operator_split_large",
        baseline_scenario="coalition_unsplit_baseline",
    )


def build_large_availability_griefing_adversary(
    committee_size: int = 16,
    min_eligible: int | None = None,
    dynamic_min_bond_coins: float = 100.0,
    availability_min_bond_coins: float | None = None,
    validator_warmup_blocks: int = 100,
    validator_cooldown_blocks: int = 100,
) -> SimulationScenario:
    if min_eligible is None:
        min_eligible = committee_size + 2
    if availability_min_bond_coins is None:
        availability_min_bond_coins = dynamic_min_bond_coins
    protocol = make_scaled_protocol(
        committee_size,
        min_eligible,
        dynamic_min_bond_coins,
        availability_min_bond_coins,
        validator_warmup_blocks,
        validator_cooldown_blocks,
    )
    actors = (ActorSpec(actor_id="honest"), ActorSpec(actor_id="coalition", adversarial=True))
    total_operator_count = min_eligible + 1
    coalition_operator_count = max(3, committee_size // 8)
    honest_operator_count = total_operator_count - coalition_operator_count
    degraded_epochs_a = {3: STATUS_PROBATION, 4: STATUS_WARMUP, 5: STATUS_ACTIVE}
    degraded_epochs_b = {3: STATUS_PROBATION, 4: STATUS_PROBATION, 5: STATUS_WARMUP, 6: STATUS_ACTIVE}
    operators: list[OperatorSpec] = []
    validators: list[ValidatorSpec] = []
    for idx in range(1, honest_operator_count + 1):
        operator_id = f"op-h{idx}"
        if idx == honest_operator_count - 1:
            plan = degraded_epochs_a
        elif idx == honest_operator_count:
            plan = degraded_epochs_b
        else:
            plan = {}
        operators.append(
            OperatorSpec(
                operator_id=operator_id,
                actor_id="honest",
                default_status=STATUS_ACTIVE,
                status_by_epoch=plan,
                score_ok_by_epoch={epoch: status == STATUS_ACTIVE for epoch, status in plan.items()},
            )
        )
        validators.append(
            ValidatorSpec(
                validator_id=f"val-h{idx}",
                operator_id=operator_id,
                actor_id="honest",
                bond_coins=dynamic_min_bond_coins + 25.0 + float(idx % 5),
                join_source="GENESIS",
            )
        )
    for idx in range(1, coalition_operator_count + 1):
        operator_id = f"op-a{idx}"
        operators.append(OperatorSpec(operator_id=operator_id, actor_id="coalition", default_status=STATUS_ACTIVE))
        validators.append(
            ValidatorSpec(
                validator_id=f"val-a{idx}",
                operator_id=operator_id,
                actor_id="coalition",
                bond_coins=dynamic_min_bond_coins + 35.0,
                join_source="GENESIS",
            )
        )
    return SimulationScenario(
        name=f"availability_griefing_adversary_large_k{committee_size}",
        description="Large-committee availability degradation near the minimum eligible boundary.",
        epochs=8,
        protocol=protocol,
        actors=actors,
        operators=tuple(operators),
        validators=tuple(validators),
        strategy_family="availability_griefing_large",
        baseline_scenario="honest_baseline",
    )


def build_large_sticky_fallback_threshold_manipulator(
    committee_size: int = 16,
    min_eligible: int | None = None,
    dynamic_min_bond_coins: float = 100.0,
    availability_min_bond_coins: float | None = None,
    validator_warmup_blocks: int = 100,
    validator_cooldown_blocks: int = 100,
) -> SimulationScenario:
    if min_eligible is None:
        min_eligible = committee_size + 2
    if availability_min_bond_coins is None:
        availability_min_bond_coins = dynamic_min_bond_coins
    protocol = make_scaled_protocol(
        committee_size,
        min_eligible,
        dynamic_min_bond_coins,
        availability_min_bond_coins,
        validator_warmup_blocks,
        validator_cooldown_blocks,
    )
    actors = (ActorSpec(actor_id="honest"), ActorSpec(actor_id="coalition", adversarial=True))
    total_operator_count = min_eligible + 1
    coalition_operator_count = 1
    honest_operator_count = total_operator_count - coalition_operator_count
    operators: list[OperatorSpec] = []
    validators: list[ValidatorSpec] = []
    manip_a = {2: STATUS_PROBATION, 3: STATUS_ACTIVE}
    manip_b = {2: STATUS_WARMUP, 3: STATUS_WARMUP, 4: STATUS_ACTIVE}
    for idx in range(1, honest_operator_count + 1):
        operator_id = f"op-h{idx}"
        if idx == honest_operator_count - 1:
            plan = manip_a
        elif idx == honest_operator_count:
            plan = manip_b
        else:
            plan = {}
        operators.append(
            OperatorSpec(
                operator_id=operator_id,
                actor_id="honest",
                default_status=STATUS_ACTIVE,
                status_by_epoch=plan,
                score_ok_by_epoch={epoch: status == STATUS_ACTIVE for epoch, status in plan.items()},
            )
        )
        validators.append(
            ValidatorSpec(
                validator_id=f"val-h{idx}",
                operator_id=operator_id,
                actor_id="honest",
                bond_coins=dynamic_min_bond_coins + 20.0 + float(idx % 5),
                join_source="GENESIS",
            )
        )
    operators.append(OperatorSpec(operator_id="op-a1", actor_id="coalition", default_status=STATUS_ACTIVE))
    validators.append(
        ValidatorSpec(
            validator_id="val-a1",
            operator_id="op-a1",
            actor_id="coalition",
            bond_coins=dynamic_min_bond_coins + 30.0,
            join_source="GENESIS",
        )
    )
    return SimulationScenario(
        name=f"sticky_fallback_threshold_manipulator_large_k{committee_size}",
        description="Large-committee threshold-edge manipulation driving fallback and sticky recovery.",
        epochs=6,
        protocol=protocol,
        actors=actors,
        operators=tuple(operators),
        validators=tuple(validators),
        strategy_family="threshold_manipulation_large",
    )


def build_large_join_exit_boundary_adversary(
    committee_size: int = 16,
    min_eligible: int | None = None,
    dynamic_min_bond_coins: float = 100.0,
    availability_min_bond_coins: float | None = None,
    validator_warmup_blocks: int = 100,
    validator_cooldown_blocks: int = 100,
) -> SimulationScenario:
    if min_eligible is None:
        min_eligible = committee_size + 2
    if availability_min_bond_coins is None:
        availability_min_bond_coins = dynamic_min_bond_coins
    protocol = make_scaled_protocol(
        committee_size,
        min_eligible,
        dynamic_min_bond_coins,
        availability_min_bond_coins,
        validator_warmup_blocks,
        validator_cooldown_blocks,
    )
    actors = (ActorSpec(actor_id="honest"), ActorSpec(actor_id="coalition", adversarial=True))
    honest_operator_count = max(committee_size + 8, min_eligible + 2)
    operators = [OperatorSpec(operator_id=f"op-h{idx}", actor_id="honest", default_status=STATUS_ACTIVE) for idx in range(1, honest_operator_count + 1)]
    validators = [
        ValidatorSpec(
            validator_id=f"val-h{idx}",
            operator_id=f"op-h{idx}",
            actor_id="honest",
            bond_coins=dynamic_min_bond_coins + 20.0 + float(idx % 5),
            join_source="GENESIS",
        )
        for idx in range(1, honest_operator_count + 1)
    ]
    operators.extend(
        [
            OperatorSpec(operator_id="op-a1", actor_id="coalition", default_status=STATUS_ACTIVE),
            OperatorSpec(operator_id="op-a2", actor_id="coalition", default_status=STATUS_ACTIVE),
            OperatorSpec(operator_id="op-a3", actor_id="coalition", default_status=STATUS_ACTIVE),
        ]
    )
    validators.extend(
        [
            ValidatorSpec(
                validator_id="val-a1",
                operator_id="op-a1",
                actor_id="coalition",
                bond_coins=dynamic_min_bond_coins + 60.0,
                join_epoch=2,
                join_source="POST_GENESIS",
            ),
            ValidatorSpec(
                validator_id="val-a2",
                operator_id="op-a2",
                actor_id="coalition",
                bond_coins=dynamic_min_bond_coins + 60.0,
                join_epoch=3,
                exit_epoch=9,
                join_source="POST_GENESIS",
            ),
            ValidatorSpec(
                validator_id="val-a3",
                operator_id="op-a3",
                actor_id="coalition",
                bond_coins=dynamic_min_bond_coins + 60.0,
                join_epoch=5,
                exit_epoch=11,
                join_source="POST_GENESIS",
            ),
        ]
    )
    return SimulationScenario(
        name=f"join_exit_boundary_adversary_large_k{committee_size}",
        description="Large-committee join/exit timing pressure near checkpoint boundaries.",
        epochs=14,
        protocol=protocol,
        actors=actors,
        operators=tuple(operators),
        validators=tuple(validators),
        strategy_family="join_exit_timing_large",
    )


def build_marginal_eligible_pool(
    committee_size: int = 16,
    min_eligible: int = 18,
    eligible_slack_operators: int = 0,
    marginal_operator_count: int = 4,
    marginal_flip_pattern: str = "staggered",
    dynamic_min_bond_coins: float = 150.0,
    availability_min_bond_coins: float = 150.0,
) -> SimulationScenario:
    protocol = make_scaled_protocol(
        committee_size,
        min_eligible,
        dynamic_min_bond_coins,
        availability_min_bond_coins,
        100,
        100,
    )
    actors = (ActorSpec(actor_id="honest"), ActorSpec(actor_id="coalition", adversarial=True))
    stable_eligible_count = max(1, committee_size + eligible_slack_operators)
    operators: list[OperatorSpec] = []
    validators: list[ValidatorSpec] = []
    marginal_ids: list[str] = []
    for idx in range(1, stable_eligible_count + 1):
        operator_id = f"op-s{idx}"
        operators.append(OperatorSpec(operator_id=operator_id, actor_id="honest", default_status=STATUS_ACTIVE))
        validators.append(
            ValidatorSpec(
                validator_id=f"val-s{idx}",
                operator_id=operator_id,
                actor_id="honest",
                bond_coins=dynamic_min_bond_coins + 25.0,
                join_source="GENESIS",
            )
        )
    for idx in range(1, marginal_operator_count + 1):
        operator_id = f"op-m{idx}"
        marginal_ids.append(operator_id)
        if marginal_flip_pattern == "staggered":
            status_by_epoch = {
                2: STATUS_ACTIVE if idx == 1 else STATUS_WARMUP,
                3: STATUS_ACTIVE if idx <= 2 else STATUS_PROBATION,
                4: STATUS_ACTIVE if idx <= 3 else STATUS_WARMUP,
                5: STATUS_ACTIVE,
                6: STATUS_ACTIVE if idx % 2 == 0 else STATUS_PROBATION,
            }
        else:
            status_by_epoch = {
                2: STATUS_WARMUP,
                3: STATUS_ACTIVE,
                4: STATUS_PROBATION,
                5: STATUS_ACTIVE,
                6: STATUS_ACTIVE,
            }
        operators.append(
            OperatorSpec(
                operator_id=operator_id,
                actor_id="honest" if idx < marginal_operator_count else "coalition",
                default_status=STATUS_ACTIVE,
                status_by_epoch=status_by_epoch,
                score_ok_by_epoch={epoch: status == STATUS_ACTIVE for epoch, status in status_by_epoch.items()},
            )
        )
        validators.append(
            ValidatorSpec(
                validator_id=f"val-m{idx}",
                operator_id=operator_id,
                actor_id="honest" if idx < marginal_operator_count else "coalition",
                bond_coins=dynamic_min_bond_coins + 5.0,
                join_source="GENESIS",
            )
        )
    return SimulationScenario(
        name=f"marginal_eligible_pool_k{committee_size}_m{min_eligible}_slack{eligible_slack_operators}",
        description="Eligible pool hovers near min_eligible with marginal operators flipping across availability states.",
        epochs=6,
        protocol=protocol,
        actors=actors,
        operators=tuple(operators),
        validators=tuple(validators),
        strategy_family="marginal_eligible_pool",
        threshold_controls={
            "eligible_slack_operators": eligible_slack_operators,
            "marginal_operator_count": marginal_operator_count,
            "marginal_flip_pattern": marginal_flip_pattern,
            "marginal_operator_ids": marginal_ids,
        },
    )


def build_bond_threshold_edge(
    committee_size: int = 16,
    min_eligible: int = 18,
    dynamic_min_bond_coins: float = 150.0,
    availability_min_bond_coins: float | None = None,
    operator_split_count: int = 4,
    bond_margin_distribution: str = "tight",
) -> SimulationScenario:
    if availability_min_bond_coins is None:
        availability_min_bond_coins = dynamic_min_bond_coins
    protocol = make_scaled_protocol(
        committee_size,
        min_eligible,
        dynamic_min_bond_coins,
        availability_min_bond_coins,
        100,
        100,
    )
    actors = (ActorSpec(actor_id="honest"), ActorSpec(actor_id="coalition", adversarial=True))
    stable_honest = max(min_eligible - 2, committee_size)
    operators: list[OperatorSpec] = []
    validators: list[ValidatorSpec] = []
    marginal_ids: list[str] = []
    for idx in range(1, stable_honest + 1):
        operator_id = f"op-h{idx}"
        operators.append(OperatorSpec(operator_id=operator_id, actor_id="honest", default_status=STATUS_ACTIVE))
        validators.append(
            ValidatorSpec(
                validator_id=f"val-h{idx}",
                operator_id=operator_id,
                actor_id="honest",
                bond_coins=dynamic_min_bond_coins + 20.0 + float(idx % 3),
                join_source="GENESIS",
            )
        )
    bond_map = {
        "tight": (95.0, 100.0, 145.0, 150.0, 155.0, 205.0),
        "wide": (70.0, 100.0, 130.0, 150.0, 180.0, 240.0),
    }
    bonds = bond_map[bond_margin_distribution]
    for idx in range(1, operator_split_count + 1):
        operator_id = f"op-a{idx}"
        marginal_ids.append(operator_id)
        operators.append(OperatorSpec(operator_id=operator_id, actor_id="coalition", default_status=STATUS_ACTIVE))
        bond_coins = bonds[min(idx - 1, len(bonds) - 1)]
        validators.append(
            ValidatorSpec(
                validator_id=f"val-a{idx}",
                operator_id=operator_id,
                actor_id="coalition",
                bond_coins=max(1.0, bond_coins),
                join_source="POST_GENESIS",
                join_epoch=1,
            )
        )
    return SimulationScenario(
        name=f"bond_threshold_edge_k{committee_size}_bond{int(dynamic_min_bond_coins)}_split{operator_split_count}_{bond_margin_distribution}",
        description="Bond-floor edge case with adversarial split children around the qualification threshold.",
        epochs=8,
        protocol=protocol,
        actors=actors,
        operators=tuple(operators),
        validators=tuple(validators),
        strategy_family="bond_threshold_edge",
        threshold_controls={
            "bond_margin_distribution": bond_margin_distribution,
            "marginal_operator_ids": marginal_ids,
        },
    )


def build_mixed_depth_population(
    committee_size: int = 16,
    min_eligible: int = 18,
    dynamic_min_bond_coins: float = 150.0,
    availability_min_bond_coins: float = 150.0,
    adversarial_tail: bool = True,
) -> SimulationScenario:
    protocol = make_scaled_protocol(
        committee_size,
        min_eligible,
        dynamic_min_bond_coins,
        availability_min_bond_coins,
        100,
        100,
    )
    actors = (ActorSpec(actor_id="honest"), ActorSpec(actor_id="coalition", adversarial=True))
    operators: list[OperatorSpec] = []
    validators: list[ValidatorSpec] = []
    marginal_ids: list[str] = []
    large_count = 4
    medium_count = max(committee_size - 6, min_eligible - 6)
    marginal_count = max(6, min_eligible + 2 - (large_count + medium_count))
    for idx in range(1, large_count + 1):
        operator_id = f"op-l{idx}"
        operators.append(OperatorSpec(operator_id=operator_id, actor_id="honest", default_status=STATUS_ACTIVE))
        validators.append(
            ValidatorSpec(
                validator_id=f"val-l{idx}",
                operator_id=operator_id,
                actor_id="honest",
                bond_coins=dynamic_min_bond_coins * 2.5,
                join_source="GENESIS",
            )
        )
    for idx in range(1, medium_count + 1):
        operator_id = f"op-m{idx}"
        operators.append(OperatorSpec(operator_id=operator_id, actor_id="honest", default_status=STATUS_ACTIVE))
        validators.append(
            ValidatorSpec(
                validator_id=f"val-m{idx}",
                operator_id=operator_id,
                actor_id="honest",
                bond_coins=dynamic_min_bond_coins + 25.0 + float(idx % 4),
                join_source="GENESIS",
            )
        )
    for idx in range(1, marginal_count + 1):
        operator_id = f"op-t{idx}"
        marginal_ids.append(operator_id)
        actor_id = "coalition" if adversarial_tail and idx % 3 == 0 else "honest"
        status_by_epoch = {3: STATUS_PROBATION if idx % 2 else STATUS_ACTIVE, 4: STATUS_WARMUP if idx % 3 == 0 else STATUS_ACTIVE, 5: STATUS_ACTIVE}
        operators.append(
            OperatorSpec(
                operator_id=operator_id,
                actor_id=actor_id,
                default_status=STATUS_ACTIVE,
                status_by_epoch=status_by_epoch,
                score_ok_by_epoch={epoch: status == STATUS_ACTIVE for epoch, status in status_by_epoch.items()},
            )
        )
        validators.append(
            ValidatorSpec(
                validator_id=f"val-t{idx}",
                operator_id=operator_id,
                actor_id=actor_id,
                bond_coins=dynamic_min_bond_coins + (5.0 if idx % 2 else -5.0),
                join_source="GENESIS",
            )
        )
    return SimulationScenario(
        name=f"mixed_depth_population_k{committee_size}_m{min_eligible}",
        description="Large stable core with medium band and marginal tail near bond/availability thresholds.",
        epochs=8,
        protocol=protocol,
        actors=actors,
        operators=tuple(operators),
        validators=tuple(validators),
        strategy_family="mixed_depth_population",
        threshold_controls={
            "marginal_operator_ids": marginal_ids,
            "marginal_operator_count": marginal_count,
        },
    )


def build_boundary_activation_edge(
    committee_size: int = 16,
    min_eligible: int = 18,
    dynamic_min_bond_coins: float = 150.0,
    availability_min_bond_coins: float = 150.0,
    validator_warmup_blocks: int = 100,
    validator_cooldown_blocks: int = 100,
    activation_edge_density: int = 2,
) -> SimulationScenario:
    protocol = make_scaled_protocol(
        committee_size,
        min_eligible,
        dynamic_min_bond_coins,
        availability_min_bond_coins,
        validator_warmup_blocks,
        validator_cooldown_blocks,
    )
    actors = (ActorSpec(actor_id="honest"), ActorSpec(actor_id="coalition", adversarial=True))
    stable_count = min_eligible - 1
    operators: list[OperatorSpec] = []
    validators: list[ValidatorSpec] = []
    marginal_ids: list[str] = []
    for idx in range(1, stable_count + 1):
        operator_id = f"op-s{idx}"
        operators.append(OperatorSpec(operator_id=operator_id, actor_id="honest", default_status=STATUS_ACTIVE))
        validators.append(
            ValidatorSpec(
                validator_id=f"val-s{idx}",
                operator_id=operator_id,
                actor_id="honest",
                bond_coins=dynamic_min_bond_coins + 20.0,
                join_source="GENESIS",
            )
        )
    edge_join_heights = [1, 28, 29, 30]
    edge_exit_heights = [129, 157, 158, 159]
    for idx in range(1, activation_edge_density + 1):
        operator_id = f"op-e{idx}"
        marginal_ids.append(operator_id)
        actor_id = "coalition" if idx % 2 else "honest"
        operators.append(OperatorSpec(operator_id=operator_id, actor_id=actor_id, default_status=STATUS_ACTIVE))
        validators.append(
            ValidatorSpec(
                validator_id=f"val-e{idx}",
                operator_id=operator_id,
                actor_id=actor_id,
                bond_coins=dynamic_min_bond_coins + 5.0,
                join_source="POST_GENESIS",
                join_epoch=1,
                join_height=edge_join_heights[min(idx, len(edge_join_heights) - 1)],
                exit_epoch=5 if idx % 2 == 0 else None,
                exit_height=edge_exit_heights[min(idx, len(edge_exit_heights) - 1)] if idx % 2 == 0 else None,
            )
        )
    return SimulationScenario(
        name=f"boundary_activation_edge_k{committee_size}_m{min_eligible}_w{validator_warmup_blocks}_c{validator_cooldown_blocks}",
        description="Join/exit timing placed near epoch boundaries so warmup/cooldown changes can alter threshold crossings.",
        epochs=10,
        protocol=protocol,
        actors=actors,
        operators=tuple(operators),
        validators=tuple(validators),
        strategy_family="boundary_activation_edge",
        threshold_controls={
            "activation_edge_density": activation_edge_density,
            "marginal_operator_ids": marginal_ids,
        },
    )


def _checkpoint_fixture_corpus() -> list[dict[str, Any]]:
    return [load_checkpoint_fixture(path) for path in sorted(CHECKPOINT_FIXTURE_ROOT.glob("*.json"))]


def build_replay_calibrated_honest_depth(
    committee_size: int = 16,
    min_eligible: int = 18,
    eligible_slack_operators: int = 0,
    dynamic_min_bond_coins: float = 150.0,
    availability_min_bond_coins: float = 150.0,
) -> SimulationScenario:
    protocol = make_scaled_protocol(
        committee_size,
        min_eligible,
        dynamic_min_bond_coins,
        availability_min_bond_coins,
        100,
        100,
    )
    fixtures = _checkpoint_fixture_corpus()
    active_records: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    marginal_records: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    fixture_names: list[str] = []
    for fixture in fixtures:
        fixture_names.append(str(fixture["name"]))
        availability_by_operator = {item["operator_id"]: item for item in fixture["availability"]}
        effective_min_bond = int(fixture["protocol_params"]["effective_min_bond"])
        for validator in fixture["validators"]:
            availability = availability_by_operator.get(validator["operator_id"])
            if availability is None:
                continue
            pair = (validator, availability)
            if (
                bool(validator["lifecycle_active"])
                and bool(validator["has_bond"])
                and validator["join_source"] == "GENESIS"
                and int(validator["bonded_amount"]) >= effective_min_bond
                and availability["state"] == STATUS_ACTIVE
            ):
                active_records.append(pair)
            elif bool(validator["lifecycle_active"]) and bool(validator["has_bond"]):
                marginal_records.append(pair)

    if not active_records or not marginal_records:
        raise ValueError("checkpoint fixture corpus is missing replay-calibration archetypes")

    actors = (ActorSpec(actor_id="honest"), ActorSpec(actor_id="coalition", adversarial=True))
    operators: list[OperatorSpec] = []
    validators: list[ValidatorSpec] = []
    marginal_ids: list[str] = []

    stable_eligible_count = max(1, committee_size + eligible_slack_operators)
    for idx in range(stable_eligible_count):
        validator_template, _ = active_records[idx % len(active_records)]
        operator_id = f"op-rc-s{idx+1}"
        operators.append(OperatorSpec(operator_id=operator_id, actor_id="honest", default_status=STATUS_ACTIVE))
        validators.append(
            ValidatorSpec(
                validator_id=f"val-rc-s{idx+1}",
                operator_id=operator_id,
                actor_id="honest",
                bond_coins=units_to_coins(int(validator_template["bonded_amount"])),
                join_source=str(validator_template["join_source"]),
            )
        )

    marginal_count = 5 if committee_size >= 24 else 4
    for idx in range(marginal_count):
        validator_template, availability_template = marginal_records[idx % len(marginal_records)]
        operator_id = f"op-rc-m{idx+1}"
        marginal_ids.append(operator_id)
        actor_id = "coalition" if idx == marginal_count - 1 else "honest"
        status_cycle = {
            2: str(availability_template["state"]),
            3: STATUS_ACTIVE if idx % 2 == 0 else STATUS_WARMUP,
            4: STATUS_PROBATION if idx % 3 == 0 else STATUS_ACTIVE,
            5: STATUS_ACTIVE,
            6: STATUS_EJECTED if idx == 0 else STATUS_ACTIVE,
            7: STATUS_ACTIVE,
        }
        operators.append(
            OperatorSpec(
                operator_id=operator_id,
                actor_id=actor_id,
                default_status=str(availability_template["state"]),
                status_by_epoch=status_cycle,
                score_ok_by_epoch={epoch: status == STATUS_ACTIVE for epoch, status in status_cycle.items()},
            )
        )
        validators.append(
            ValidatorSpec(
                validator_id=f"val-rc-m{idx+1}",
                operator_id=operator_id,
                actor_id=actor_id,
                bond_coins=units_to_coins(int(validator_template["bonded_amount"])),
                join_source=str(validator_template["join_source"]),
                join_epoch=1 if str(validator_template["join_source"]) == "POST_GENESIS" else 0,
            )
        )

    return SimulationScenario(
        name=f"replay_calibrated_honest_depth_k{committee_size}_m{min_eligible}_slack{eligible_slack_operators}",
        description="Honest-depth threshold family calibrated from the committed C++ checkpoint fixture corpus.",
        epochs=7,
        protocol=protocol,
        actors=actors,
        operators=tuple(operators),
        validators=tuple(validators),
        strategy_family="replay_calibrated_honest_depth",
        threshold_controls={
            "eligible_slack_operators": eligible_slack_operators,
            "marginal_operator_ids": marginal_ids,
            "calibration_fixture_names": tuple(sorted(set(fixture_names))),
        },
    )


def build_replay_expanded_honest_depth(
    committee_size: int = 16,
    min_eligible: int = 18,
    eligible_slack_operators: int = 0,
    dynamic_min_bond_coins: float = 150.0,
    availability_min_bond_coins: float = 150.0,
    calibrated_depth_scale: int = 3,
) -> SimulationScenario:
    protocol = make_scaled_protocol(
        committee_size,
        min_eligible,
        dynamic_min_bond_coins,
        availability_min_bond_coins,
        100,
        100,
    )
    fixtures = _checkpoint_fixture_corpus()
    stable_archetypes: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    marginal_archetypes: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    fixture_names: list[str] = []
    for fixture in fixtures:
        fixture_names.append(str(fixture["name"]))
        by_op = {item["operator_id"]: item for item in fixture["availability"]}
        effective_min_bond = int(fixture["protocol_params"]["effective_min_bond"])
        for validator in fixture["validators"]:
            availability = by_op.get(validator["operator_id"])
            if availability is None:
                continue
            pair = (validator, availability)
            base_ok = bool(validator["lifecycle_active"]) and bool(validator["has_bond"])
            if (
                base_ok
                and validator["join_source"] == "GENESIS"
                and int(validator["bonded_amount"]) >= effective_min_bond
                and availability["state"] == STATUS_ACTIVE
            ):
                stable_archetypes.append(pair)
            elif base_ok:
                marginal_archetypes.append(pair)

    if not stable_archetypes or not marginal_archetypes:
        raise ValueError("checkpoint fixture corpus is missing expanded replay-calibration archetypes")

    actors = (ActorSpec(actor_id="honest"), ActorSpec(actor_id="coalition", adversarial=True))
    operators: list[OperatorSpec] = []
    validators: list[ValidatorSpec] = []
    marginal_ids: list[str] = []

    stable_eligible_count = max(1, min_eligible - 1 + eligible_slack_operators)
    stable_pool_target = stable_eligible_count
    marginal_pool_target = max(min_eligible + calibrated_depth_scale, committee_size // 2 + calibrated_depth_scale)

    for idx in range(stable_pool_target):
        validator_template, _ = stable_archetypes[idx % len(stable_archetypes)]
        operator_id = f"op-rx-s{idx+1}"
        operators.append(OperatorSpec(operator_id=operator_id, actor_id="honest", default_status=STATUS_ACTIVE))
        validators.append(
            ValidatorSpec(
                validator_id=f"val-rx-s{idx+1}",
                operator_id=operator_id,
                actor_id="honest",
                bond_coins=units_to_coins(int(validator_template["bonded_amount"])),
                join_source=str(validator_template["join_source"]),
            )
        )

    for idx in range(marginal_pool_target):
        validator_template, availability_template = marginal_archetypes[idx % len(marginal_archetypes)]
        operator_id = f"op-rx-m{idx+1}"
        marginal_ids.append(operator_id)
        actor_id = "coalition" if idx % 5 == 4 else "honest"
        if idx < max(0, committee_size - stable_eligible_count):
            default_status = STATUS_ACTIVE
            status_by_epoch = {2: STATUS_ACTIVE, 3: STATUS_ACTIVE, 4: STATUS_ACTIVE, 5: STATUS_ACTIVE, 6: STATUS_ACTIVE, 7: STATUS_ACTIVE}
        elif idx < 3:
            default_status = str(availability_template["state"])
            status_by_epoch = {
                2: str(availability_template["state"]),
                3: STATUS_ACTIVE if idx == 0 else STATUS_WARMUP,
                4: STATUS_ACTIVE if idx <= 1 else STATUS_PROBATION,
                5: STATUS_ACTIVE if idx != 2 else STATUS_WARMUP,
                6: STATUS_ACTIVE,
                7: STATUS_WARMUP if idx == 0 else STATUS_ACTIVE,
            }
        else:
            default_status = STATUS_WARMUP if idx % 2 == 0 else STATUS_PROBATION
            status_by_epoch = {
                2: default_status,
                3: STATUS_WARMUP,
                4: STATUS_PROBATION,
                5: STATUS_EJECTED if idx % 4 == 0 else STATUS_WARMUP,
                6: STATUS_WARMUP,
                7: STATUS_PROBATION,
            }
        operators.append(
            OperatorSpec(
                operator_id=operator_id,
                actor_id=actor_id,
                default_status=default_status,
                status_by_epoch=status_by_epoch,
                score_ok_by_epoch={epoch: status == STATUS_ACTIVE for epoch, status in status_by_epoch.items()},
            )
        )
        join_source = str(validator_template["join_source"])
        validators.append(
            ValidatorSpec(
                validator_id=f"val-rx-m{idx+1}",
                operator_id=operator_id,
                actor_id=actor_id,
                bond_coins=units_to_coins(int(validator_template["bonded_amount"])),
                join_source=join_source,
                join_epoch=1 if join_source == "POST_GENESIS" else 0,
            )
        )

    return SimulationScenario(
        name=f"replay_expanded_honest_depth_k{committee_size}_m{min_eligible}_slack{eligible_slack_operators}",
        description="Expanded replay-derived honest-depth family built from canonical checkpoint fixture archetypes.",
        epochs=7,
        protocol=protocol,
        actors=actors,
        operators=tuple(operators),
        validators=tuple(validators),
        strategy_family="replay_expanded_honest_depth",
        threshold_controls={
            "eligible_slack_operators": eligible_slack_operators,
            "marginal_operator_ids": marginal_ids,
            "calibration_fixture_names": tuple(sorted(set(fixture_names))),
            "calibrated_depth_scale": calibrated_depth_scale,
        },
    )


BUILTIN_SCENARIOS: dict[str, Callable[[], SimulationScenario]] = {
    "honest_baseline": build_honest_baseline,
    "coalition_unsplit_baseline": build_unsplit_coalition_baseline,
    "split_operator_adversary": build_split_operator_adversary,
    "availability_griefing_adversary": build_availability_griefing_adversary,
    "sticky_fallback_threshold_manipulator": build_sticky_fallback_threshold_manipulator,
    "join_exit_boundary_adversary": build_join_exit_boundary_adversary,
    "marginal_eligible_pool": build_marginal_eligible_pool,
    "bond_threshold_edge": build_bond_threshold_edge,
    "mixed_depth_population": build_mixed_depth_population,
    "boundary_activation_edge": build_boundary_activation_edge,
    "replay_calibrated_honest_depth": build_replay_calibrated_honest_depth,
    "replay_expanded_honest_depth": build_replay_expanded_honest_depth,
}


def load_scenario(path: Path) -> SimulationScenario:
    return scenario_from_dict(json.loads(path.read_text(encoding="utf-8")))


def get_builtin_scenario(name: str) -> SimulationScenario:
    try:
        return BUILTIN_SCENARIOS[name]()
    except KeyError as exc:
        raise KeyError(f"unknown scenario: {name}") from exc


def apply_override(scenario: SimulationScenario, parameter: str, value: float) -> SimulationScenario:
    if parameter == "operator_split_count":
        if scenario.strategy_family != "operator_split":
            raise ValueError("operator_split_count sweep is only supported for operator_split scenarios")
        overridden = build_split_operator_adversary(int(value))
        return replace(overridden, name=f"{overridden.name}_{parameter}_{int(value)}")

    if parameter == "adversary_bond_share":
        share = float(value)
        if share <= 0.0 or share >= 1.0:
            raise ValueError("adversary_bond_share must be in (0, 1)")
        honest_units = sum(
            coins_to_units(v.bond_coins) for v in scenario.validators if not any(
                actor.actor_id == v.actor_id and actor.adversarial for actor in scenario.actors
            )
        )
        adversarial_validators = [v for v in scenario.validators if any(actor.actor_id == v.actor_id and actor.adversarial for actor in scenario.actors)]
        if not adversarial_validators:
            raise ValueError("scenario has no adversarial validators")
        target_adv_units = int(round((share / (1.0 - share)) * honest_units))
        total_current_adv_units = max(1, sum(coins_to_units(v.bond_coins) for v in adversarial_validators))
        updated_validators: list[ValidatorSpec] = []
        remaining = target_adv_units
        for index, validator in enumerate(adversarial_validators):
            if index == len(adversarial_validators) - 1:
                new_units = remaining
            else:
                weight = coins_to_units(validator.bond_coins)
                new_units = int(round(target_adv_units * (weight / total_current_adv_units)))
                remaining -= new_units
            updated_validators.append(replace(validator, bond_coins=units_to_coins(new_units)))
        replacement = {validator.validator_id: validator for validator in updated_validators}
        validators = tuple(replacement.get(v.validator_id, v) for v in scenario.validators)
        return replace(scenario, validators=validators, name=f"{scenario.name}_{parameter}_{value}")

    protocol = scenario.protocol
    if parameter == "committee_size":
        protocol = replace(protocol, committee_size=int(value))
    elif parameter == "min_eligible":
        protocol = replace(protocol, min_eligible=int(value))
    elif parameter == "dynamic_min_bond_coins":
        protocol = replace(protocol, dynamic_min_bond_coins=float(value))
    elif parameter == "availability_min_bond_coins":
        protocol = replace(protocol, availability_min_bond_coins=float(value))
    elif parameter == "validator_warmup_blocks":
        protocol = replace(protocol, validator_warmup_blocks=int(value))
    elif parameter == "validator_cooldown_blocks":
        protocol = replace(protocol, validator_cooldown_blocks=int(value))
    else:
        raise ValueError(f"unsupported sweep parameter: {parameter}")
    return replace(scenario, protocol=protocol, name=f"{scenario.name}_{parameter}_{value}")


def run_parameter_sweep(scenario: SimulationScenario, parameter: str, values: Sequence[float]) -> dict[str, Any]:
    summaries = [run_scenario(apply_override(scenario, parameter, value)) for value in values]
    return {
        "base_scenario": scenario.name,
        "parameter": parameter,
        "values": list(values),
        "results": [asdict(summary) for summary in summaries],
        "comparison": compare_summaries(summaries),
    }


def parse_values_csv(text: str) -> list[float]:
    values = []
    for part in text.split(","):
        item = part.strip()
        if not item:
            continue
        values.append(float(item))
    if not values:
        raise ValueError("expected at least one value")
    return values


def _require_fields(payload: Mapping[str, Any], fields: Sequence[str], kind: str) -> None:
    for field in fields:
        if field not in payload:
            raise ValueError(f"{kind} missing required field: {field}")


def load_checkpoint_fixture(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    _require_fields(payload, ["fixture_version", "name", "protocol_params", "previous_checkpoint", "validators", "availability", "expected"], "checkpoint fixture")
    if payload["fixture_version"] != 1:
        raise ValueError("unsupported checkpoint fixture_version")
    validator_ids = [item["validator_pubkey"] for item in payload["validators"]]
    if len(validator_ids) != len(set(validator_ids)):
        raise ValueError("duplicate validator_pubkey in checkpoint fixture")
    operator_ids = [item["operator_id"] for item in payload["availability"]]
    if len(operator_ids) != len(set(operator_ids)):
        raise ValueError("duplicate operator_id in checkpoint fixture availability")
    return payload


def load_comparator_fixture(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    _require_fields(payload, ["fixture_version", "name", "committee_size", "seed", "candidates", "expected_sorted_order", "expected_selected_top_k"], "comparator fixture")
    if payload["fixture_version"] != 1:
        raise ValueError("unsupported comparator fixture_version")
    candidate_ids = [item["pubkey"] for item in payload["candidates"]]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValueError("duplicate comparator candidate pubkey")
    return payload


def availability_eligibility_from_fixture(record: Mapping[str, Any], protocol_params: Mapping[str, Any]) -> bool:
    score = int(record["service_score"]) + math.isqrt(max(0, int(record["retained_prefix_count"])))
    return (
        record["state"] == STATUS_ACTIVE
        and int(record["bond"]) >= int(protocol_params["availability_min_bond"])
        and score >= int(protocol_params["availability_eligibility_min_score"])
    )


def ranked_candidates_from_comparator_fixture(fixture: Mapping[str, Any]) -> list[RankedCandidate]:
    out = []
    for item in fixture["candidates"]:
        out.append(
            RankedCandidate(
                pubkey=bytes.fromhex(item["pubkey"]),
                selection_id=bytes.fromhex(item["selection_id"]),
                bonded_amount=int(item["bonded_amount"]),
                capped_bonded_amount=int(item["capped_bonded_amount"]),
                effective_weight=int(item["effective_weight"]),
                ticket_work_hash=bytes.fromhex(item["ticket_work_hash"]),
                ticket_nonce=int(item["ticket_nonce"]),
                ticket_bonus_bps=int(item["ticket_bonus_bps"]),
                ticket_bonus_cap_bps=int(item["ticket_bonus_cap_bps"]),
                actor_id="fixture",
                adversarial=False,
                validator_count=1,
            )
        )
    return out


def derive_checkpoint_from_fixture(fixture: Mapping[str, Any]) -> dict[str, Any]:
    protocol_params = fixture["protocol_params"]
    epoch_start_height = int(protocol_params["epoch_start_height"])
    epoch_seed_value = bytes.fromhex(protocol_params["epoch_seed"])
    effective_min_bond = int(protocol_params["effective_min_bond"])
    min_eligible = int(protocol_params["min_eligible"])
    committee_size = int(protocol_params["committee_size"])
    ticket_difficulty_bits = int(protocol_params["ticket_difficulty_bits"])
    ticket_bonus_cap_bps = int(protocol_params["ticket_bonus_cap_bps"])
    max_effective_bond_multiple = int(protocol_params["max_effective_bond_multiple"])

    availability_by_operator = {item["operator_id"]: item for item in fixture["availability"]}
    eligible_operator_count = sum(
        1 for item in fixture["availability"] if availability_eligibility_from_fixture(item, protocol_params)
    )
    mode, reason = derive_mode_reason(fixture["previous_checkpoint"]["derivation_mode"], eligible_operator_count, min_eligible)

    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for validator in fixture["validators"]:
        base_eligible = bool(validator["lifecycle_active"]) and bool(validator["has_bond"]) and (
            validator["join_source"] == "GENESIS" or int(validator["bonded_amount"]) >= effective_min_bond
        )
        if not base_eligible:
            continue
        if mode == MODE_NORMAL:
            availability = availability_by_operator.get(validator["operator_id"])
            if availability is None or not availability_eligibility_from_fixture(availability, protocol_params):
                continue
        grouped.setdefault(validator["operator_id"], []).append(validator)

    candidates: list[RankedCandidate] = []
    for operator_id in sorted(grouped):
        validators = grouped[operator_id]
        rep = min(validators, key=lambda item: bytes.fromhex(item["validator_pubkey"]))
        total_bonded_amount = sum(int(item["bonded_amount"]) for item in validators)
        capped_bonded_amount = min(total_bonded_amount, max_effective_bond_multiple * effective_min_bond)
        operator_bytes = bytes.fromhex(operator_id)
        best_hash: bytes | None = None
        best_nonce = 0
        for nonce in range(DEFAULT_NONCE_LIMIT):
            payload = b"SC-EPOCH-TICKET-V2" + u64le(epoch_start_height) + epoch_seed_value + operator_bytes + u64le(nonce)
            work_hash = sha256d(payload)
            if best_hash is None or work_hash < best_hash:
                best_hash = work_hash
                best_nonce = nonce
        assert best_hash is not None
        candidates.append(
            RankedCandidate(
                pubkey=bytes.fromhex(rep["validator_pubkey"]),
                selection_id=operator_bytes,
                bonded_amount=total_bonded_amount,
                capped_bonded_amount=capped_bonded_amount,
                effective_weight=sqrt_effective_weight(capped_bonded_amount),
                ticket_work_hash=best_hash,
                ticket_nonce=best_nonce,
                ticket_bonus_bps=ticket_pow_bonus_bps_from_zero_bits(
                    leading_zero_bits(best_hash), ticket_difficulty_bits, ticket_bonus_cap_bps
                ),
                ticket_bonus_cap_bps=ticket_bonus_cap_bps,
                actor_id="fixture",
                adversarial=False,
                validator_count=len(validators),
            )
        )

    committee = select_finalized_committee(candidates, epoch_seed_value, committee_size)
    schedule = proposer_schedule(committee, epoch_seed_value, epoch_start_height)
    return {
        "eligible_operator_count": eligible_operator_count,
        "derivation_mode": mode,
        "fallback_reason": reason,
        "committee": [candidate.pubkey.hex() for candidate in committee],
        "proposer_schedule": [candidate.pubkey.hex() for candidate in schedule],
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Live-protocol-faithful adversarial simulator for finalis-core.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    list_parser = sub.add_parser("list-scenarios", help="List built-in scenarios")
    list_parser.set_defaults(cmd="list-scenarios")

    run_parser = sub.add_parser("run", help="Run one or more scenarios")
    run_parser.add_argument("--scenario", action="append", dest="scenarios", help="Built-in scenario name", default=[])
    run_parser.add_argument("--scenario-file", action="append", dest="scenario_files", default=[])
    run_parser.add_argument("--json-out", type=Path)
    run_parser.add_argument("--md-out", type=Path)
    run_parser.add_argument("--csv-out", type=Path)

    sweep_parser = sub.add_parser("sweep", help="Run one-parameter sensitivity sweep")
    sweep_parser.add_argument("--scenario", required=True)
    sweep_parser.add_argument("--parameter", required=True)
    sweep_parser.add_argument("--values", required=True, help="Comma-separated values")
    sweep_parser.add_argument("--json-out", type=Path)
    sweep_parser.add_argument("--md-out", type=Path)
    sweep_parser.add_argument("--csv-out", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.cmd == "list-scenarios":
        for name in sorted(BUILTIN_SCENARIOS):
            print(name)
        return 0

    if args.cmd == "run":
        scenarios: list[SimulationScenario] = []
        for name in args.scenarios:
            scenarios.append(get_builtin_scenario(name))
        for path_text in args.scenario_files:
            scenarios.append(load_scenario(Path(path_text)))
        if not scenarios:
            raise SystemExit("at least one --scenario or --scenario-file is required")
        summaries = [run_scenario(scenario) for scenario in scenarios]
        payload = {"summaries": [asdict(summary) for summary in summaries], "comparison": compare_summaries(summaries)}
        if args.json_out:
            write_json(args.json_out, payload)
        if args.md_out:
            write_markdown(args.md_out, render_markdown_report(summaries))
        if args.csv_out:
            write_epoch_csv(args.csv_out, summaries)
        print(json.dumps(payload["comparison"], indent=2, sort_keys=True))
        return 0

    if args.cmd == "sweep":
        scenario = get_builtin_scenario(args.scenario)
        values = parse_values_csv(args.values)
        payload = run_parameter_sweep(scenario, args.parameter, values)
        if args.json_out:
            write_json(args.json_out, payload)
        if args.md_out:
            summaries = [ScenarioSummary(**item) for item in payload["results"]]
            write_markdown(args.md_out, render_markdown_report(summaries))
        if args.csv_out:
            summaries = [ScenarioSummary(**item) for item in payload["results"]]
            write_epoch_csv(args.csv_out, summaries)
        print(json.dumps(payload["comparison"], indent=2, sort_keys=True))
        return 0

    raise SystemExit(f"unsupported command: {args.cmd}")


if __name__ == "__main__":
    raise SystemExit(main())
