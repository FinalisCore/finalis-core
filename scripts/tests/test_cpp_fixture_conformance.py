from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.protocol_attack_sim import (
    derive_checkpoint_from_fixture,
    load_checkpoint_fixture,
    load_comparator_fixture,
    rank_finalized_committee_candidates,
    ranked_candidates_from_comparator_fixture,
    select_finalized_committee,
)


FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "tests" / "fixtures"


class CppFixtureConformanceTests(unittest.TestCase):
    def test_checkpoint_fixtures_match_python_checkpoint_bridge(self) -> None:
        checkpoint_dir = FIXTURE_ROOT / "checkpoint"
        fixtures = sorted(checkpoint_dir.glob("*.json"))
        self.assertTrue(fixtures, "expected checkpoint fixtures to exist")
        for path in fixtures:
            fixture = load_checkpoint_fixture(path)
            derived = derive_checkpoint_from_fixture(fixture)
            expected = fixture["expected"]
            self.assertEqual(derived["eligible_operator_count"], expected["eligible_operator_count"], path.name)
            self.assertEqual(derived["derivation_mode"], expected["derivation_mode"], path.name)
            self.assertEqual(derived["fallback_reason"], expected["fallback_reason"], path.name)
            self.assertEqual(derived["committee"], expected["committee"], path.name)
            self.assertEqual(derived["proposer_schedule"], expected["proposer_schedule"], path.name)

    def test_comparator_fixtures_match_python_ranking_bridge(self) -> None:
        comparator_dir = FIXTURE_ROOT / "comparator"
        fixtures = sorted(comparator_dir.glob("*.json"))
        self.assertTrue(fixtures, "expected comparator fixtures to exist")
        for path in fixtures:
            fixture = load_comparator_fixture(path)
            candidates = ranked_candidates_from_comparator_fixture(fixture)
            seed = bytes.fromhex(fixture["seed"])
            ranked = rank_finalized_committee_candidates(candidates, seed)
            selected = select_finalized_committee(candidates, seed, int(fixture["committee_size"]))
            self.assertEqual([candidate.pubkey.hex() for candidate in ranked], fixture["expected_sorted_order"], path.name)
            self.assertEqual([candidate.pubkey.hex() for candidate in selected], fixture["expected_selected_top_k"], path.name)

    def test_fixture_loaders_reject_unknown_versions(self) -> None:
        bad_checkpoint = {
            "fixture_version": 99,
            "name": "bad",
            "protocol_params": {},
            "previous_checkpoint": {},
            "validators": [],
            "availability": [],
            "expected": {},
        }
        bad_comparator = {
            "fixture_version": 99,
            "name": "bad",
            "committee_size": 1,
            "seed": "00" * 32,
            "candidates": [],
            "expected_sorted_order": [],
            "expected_selected_top_k": [],
        }
        checkpoint_path = FIXTURE_ROOT / "checkpoint" / "_bad_version.json"
        comparator_path = FIXTURE_ROOT / "comparator" / "_bad_version.json"
        checkpoint_path.write_text(__import__("json").dumps(bad_checkpoint), encoding="utf-8")
        comparator_path.write_text(__import__("json").dumps(bad_comparator), encoding="utf-8")
        try:
            with self.assertRaises(ValueError):
                load_checkpoint_fixture(checkpoint_path)
            with self.assertRaises(ValueError):
                load_comparator_fixture(comparator_path)
        finally:
            checkpoint_path.unlink(missing_ok=True)
            comparator_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
