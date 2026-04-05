from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.sybil_model import (
    BASE_UNITS_PER_COIN,
    Candidate,
    Validator,
    adjust_ticket_difficulty_bits,
    aggregate_operator_candidates,
    effective_weight,
    make_operator_id,
    make_pubkey,
    select_finalized_committee,
    ticket_pow_bonus_bps_from_zero_bits,
)


class SybilModelTests(unittest.TestCase):
    def test_effective_weight_matches_integer_sqrt_model(self) -> None:
        self.assertEqual(effective_weight(1 * BASE_UNITS_PER_COIN), 10_000)
        self.assertEqual(effective_weight(9 * BASE_UNITS_PER_COIN), 30_000)

    def test_ticket_bonus_curve_is_capped_and_diminishing(self) -> None:
        b1 = ticket_pow_bonus_bps_from_zero_bits(16, 8)
        b2 = ticket_pow_bonus_bps_from_zero_bits(24, 8)
        b3 = ticket_pow_bonus_bps_from_zero_bits(32, 8)
        self.assertLessEqual(b1, b2)
        self.assertLessEqual(b2, b3)
        self.assertGreaterEqual(b2 - b1, b3 - b2)
        self.assertLessEqual(b3, 2500)

    def test_difficulty_adjustment_matches_live_thresholds(self) -> None:
        self.assertEqual(adjust_ticket_difficulty_bits(8, 64, 16, 0, 9500), 9)
        self.assertEqual(adjust_ticket_difficulty_bits(8, 64, 16, 1000, 10000), 8)
        self.assertEqual(adjust_ticket_difficulty_bits(8, 64, 16, 2000, 6500), 7)

    def test_operator_aggregation_collapses_same_operator_split(self) -> None:
        operator_id = make_operator_id("attacker")
        validators = [
            Validator(
                pubkey=make_pubkey(f"validator-{i}"),
                operator_id=operator_id,
                bonded_amount=4 * BASE_UNITS_PER_COIN,
                effective_weight=effective_weight(4 * BASE_UNITS_PER_COIN),
                ticket_work_hash=bytes([i]) * 32,
                ticket_hash64=i,
                ticket_zero_bits=8,
                ticket_nonce=i,
                ticket_bonus_bps=0,
                is_attacker=True,
                sample_count=4096,
            )
            for i in range(4)
        ]
        aggregated = aggregate_operator_candidates(validators)
        self.assertEqual(len(aggregated), 1)
        self.assertEqual(aggregated[0].bonded_amount, 16 * BASE_UNITS_PER_COIN)
        self.assertEqual(aggregated[0].selection_id, operator_id)
        self.assertEqual(aggregated[0].effective_weight, effective_weight(16 * BASE_UNITS_PER_COIN))

    def test_same_total_bond_same_operator_same_influence_regardless_of_split_count(self) -> None:
        seed = bytes([0x55]) * 32
        operator_a = make_operator_id("same-op-a")
        operator_b = make_operator_id("same-op-b")
        single = aggregate_operator_candidates(
            [
                Validator(
                    pubkey=make_pubkey("a-single"),
                    operator_id=operator_a,
                    bonded_amount=16 * BASE_UNITS_PER_COIN,
                    effective_weight=effective_weight(16 * BASE_UNITS_PER_COIN),
                    ticket_work_hash=b"\x11" * 32,
                    ticket_hash64=0,
                    ticket_zero_bits=8,
                    ticket_nonce=0,
                    ticket_bonus_bps=0,
                    is_attacker=True,
                    sample_count=4096,
                ),
                Validator(
                    pubkey=make_pubkey("b-single"),
                    operator_id=operator_b,
                    bonded_amount=16 * BASE_UNITS_PER_COIN,
                    effective_weight=effective_weight(16 * BASE_UNITS_PER_COIN),
                    ticket_work_hash=b"\x22" * 32,
                    ticket_hash64=0,
                    ticket_zero_bits=8,
                    ticket_nonce=0,
                    ticket_bonus_bps=0,
                    is_attacker=False,
                    sample_count=4096,
                ),
            ]
        )
        split = aggregate_operator_candidates(
            [
                Validator(
                    pubkey=make_pubkey(f"a-split-{i}"),
                    operator_id=operator_a,
                    bonded_amount=4 * BASE_UNITS_PER_COIN,
                    effective_weight=effective_weight(4 * BASE_UNITS_PER_COIN),
                    ticket_work_hash=(bytes([0x10 + i]) * 32),
                    ticket_hash64=i,
                    ticket_zero_bits=8,
                    ticket_nonce=i,
                    ticket_bonus_bps=0,
                    is_attacker=True,
                    sample_count=4096,
                )
                for i in range(4)
            ]
            + [
                Validator(
                    pubkey=make_pubkey("b-split"),
                    operator_id=operator_b,
                    bonded_amount=16 * BASE_UNITS_PER_COIN,
                    effective_weight=effective_weight(16 * BASE_UNITS_PER_COIN),
                    ticket_work_hash=b"\x22" * 32,
                    ticket_hash64=0,
                    ticket_zero_bits=8,
                    ticket_nonce=0,
                    ticket_bonus_bps=0,
                    is_attacker=False,
                    sample_count=4096,
                )
            ]
        )
        self.assertEqual(select_finalized_committee(single, seed, 1)[0].is_attacker, select_finalized_committee(split, seed, 1)[0].is_attacker)

    def test_same_total_bond_distinct_operators_behaves_differently_by_design(self) -> None:
        aggregated = aggregate_operator_candidates(
            [
                Validator(
                    pubkey=make_pubkey(f"attacker-{i}"),
                    operator_id=make_operator_id(f"attacker-op-{i}"),
                    bonded_amount=4 * BASE_UNITS_PER_COIN,
                    effective_weight=effective_weight(4 * BASE_UNITS_PER_COIN),
                    ticket_work_hash=(bytes([0x20 + i]) * 32),
                    ticket_hash64=i,
                    ticket_zero_bits=8,
                    ticket_nonce=i,
                    ticket_bonus_bps=0,
                    is_attacker=True,
                    sample_count=4096,
                )
                for i in range(4)
            ]
        )
        self.assertEqual(len(aggregated), 4)
        self.assertEqual(sum(candidate.bonded_amount for candidate in aggregated), 16 * BASE_UNITS_PER_COIN)

    def test_operator_level_committee_selection_prefers_higher_aggregated_weight(self) -> None:
        low = Candidate(
            pubkey=make_pubkey("low-rep"),
            selection_id=make_operator_id("low-op"),
            bonded_amount=1 * BASE_UNITS_PER_COIN,
            effective_weight=effective_weight(1 * BASE_UNITS_PER_COIN),
            ticket_work_hash=b"\x00" * 32,
            ticket_hash64=0,
            ticket_zero_bits=8,
            ticket_nonce=0,
            ticket_bonus_bps=0,
            is_attacker=False,
            validator_count=1,
        )
        high = Candidate(
            pubkey=make_pubkey("high-rep"),
            selection_id=make_operator_id("high-op"),
            bonded_amount=9 * BASE_UNITS_PER_COIN,
            effective_weight=effective_weight(9 * BASE_UNITS_PER_COIN),
            ticket_work_hash=b"\x00" * 32,
            ticket_hash64=0,
            ticket_zero_bits=8,
            ticket_nonce=0,
            ticket_bonus_bps=0,
            is_attacker=False,
            validator_count=1,
        )
        high_wins = 0
        low_wins = 0
        for fill in range(256):
            seed = bytes([fill]) * 32
            selected = select_finalized_committee([low, high], seed, 1)
            self.assertEqual(len(selected), 1)
            if selected[0].selection_id == high.selection_id:
                high_wins += 1
            else:
                low_wins += 1
        self.assertGreater(high_wins, low_wins)


if __name__ == "__main__":
    unittest.main()
