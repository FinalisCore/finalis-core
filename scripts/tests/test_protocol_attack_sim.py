from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.generate_depth_boundary_report import minimum_slack_for
from scripts.generate_replay_calibrated_depth_report import main as generate_replay_calibrated_depth_report
from scripts.generate_replay_expanded_depth_report import main as generate_replay_expanded_depth_report
from scripts.protocol_attack_sim import (
    MODE_FALLBACK,
    MODE_NORMAL,
    PROFILE_A,
    PROFILE_B,
    REASON_INSUFFICIENT,
    REASON_NONE,
    REASON_STICKY,
    ActorSpec,
    OperatorSpec,
    ProtocolParameters,
    SimulationScenario,
    ValidatorSpec,
    apply_override,
    build_bond_threshold_edge,
    build_boundary_activation_edge,
    build_large_availability_griefing_adversary,
    build_large_join_exit_boundary_adversary,
    build_large_split_operator_adversary,
    build_large_sticky_fallback_threshold_manipulator,
    build_marginal_eligible_pool,
    build_mixed_depth_population,
    build_replay_calibrated_honest_depth,
    build_replay_expanded_honest_depth,
    build_split_operator_adversary,
    build_sticky_fallback_threshold_manipulator,
    candidate_profiles,
    compare_summaries,
    parse_values_csv,
    render_markdown_report,
    run_parameter_sweep,
    run_scenario,
    scenario_from_dict,
    scenario_to_dict,
    write_epoch_csv,
    write_json,
)


class ProtocolAttackSimulatorTests(unittest.TestCase):
    def test_simulator_is_deterministic_for_same_scenario(self) -> None:
        scenario = build_split_operator_adversary()
        first = run_scenario(scenario)
        second = run_scenario(scenario)
        self.assertEqual(first, second)

    def test_sticky_fallback_matches_live_hysteresis_table(self) -> None:
        summary = run_scenario(build_sticky_fallback_threshold_manipulator())
        per_epoch = summary.per_epoch
        self.assertEqual(per_epoch[0]["derivation_mode"], MODE_NORMAL)
        self.assertEqual(per_epoch[0]["fallback_reason"], REASON_NONE)
        self.assertEqual(per_epoch[1]["derivation_mode"], MODE_FALLBACK)
        self.assertEqual(per_epoch[1]["fallback_reason"], REASON_INSUFFICIENT)
        self.assertEqual(per_epoch[2]["derivation_mode"], MODE_FALLBACK)
        self.assertEqual(per_epoch[2]["fallback_reason"], REASON_STICKY)
        self.assertTrue(per_epoch[2]["fallback_sticky"])
        self.assertEqual(per_epoch[3]["derivation_mode"], MODE_NORMAL)
        self.assertEqual(per_epoch[3]["fallback_reason"], REASON_NONE)

    def test_split_operator_scenario_changes_coalition_committee_dynamics(self) -> None:
        baseline = run_scenario(apply_override(build_split_operator_adversary(), "operator_split_count", 1))
        split = run_scenario(build_split_operator_adversary())
        self.assertGreaterEqual(split.average_coalition_committee_share, 0.0)
        self.assertGreaterEqual(split.proposer_share, 0.0)
        self.assertNotEqual(split.coalition_operator_share, baseline.coalition_operator_share)

    def test_scenario_roundtrip_and_validation_rejects_malformed_input(self) -> None:
        scenario = build_split_operator_adversary()
        payload = scenario_to_dict(scenario)
        restored = scenario_from_dict(payload)
        self.assertEqual(run_scenario(scenario), run_scenario(restored))

        malformed = scenario_to_dict(scenario)
        malformed["validators"][0]["operator_id"] = "missing-operator"
        with self.assertRaises(ValueError):
            scenario_from_dict(malformed).validate()

    def test_reports_are_stable_and_parseable(self) -> None:
        summaries = [run_scenario(build_split_operator_adversary())]
        comparison = compare_summaries(summaries)
        self.assertIn("scenarios", comparison)
        markdown = render_markdown_report(summaries)
        self.assertIn("| scenario | strategy |", markdown)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            json_path = root / "summary.json"
            csv_path = root / "epochs.csv"
            write_json(json_path, comparison)
            write_epoch_csv(csv_path, summaries)
            loaded = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["scenarios"][0]["scenario"], summaries[0].scenario)
            with csv_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), summaries[0].epochs)
            self.assertEqual(rows[0]["scenario"], summaries[0].scenario)

    def test_parameter_sweep_supports_live_fallback_and_split_dimensions(self) -> None:
        scenario = build_split_operator_adversary()
        sweep = run_parameter_sweep(scenario, "operator_split_count", [1, 2, 3])
        self.assertEqual(len(sweep["results"]), 3)
        fallback_sweep = run_parameter_sweep(build_sticky_fallback_threshold_manipulator(), "min_eligible", [2, 3, 4])
        self.assertEqual(len(fallback_sweep["results"]), 3)

    def test_parse_values_csv_requires_non_empty_input(self) -> None:
        self.assertEqual(parse_values_csv("1,2,3"), [1.0, 2.0, 3.0])
        with self.assertRaises(ValueError):
            parse_values_csv(" , ")

    def test_custom_scenario_join_activation_latency_is_reported(self) -> None:
        scenario = SimulationScenario(
            name="join-latency",
            description="custom",
            epochs=6,
            protocol=ProtocolParameters(committee_size=2, min_eligible=1, validator_warmup_blocks=32),
            actors=(ActorSpec("honest"), ActorSpec("coalition", adversarial=True)),
            operators=(
                OperatorSpec("op-h1", "honest"),
                OperatorSpec("op-a1", "coalition"),
            ),
            validators=(
                ValidatorSpec("val-h1", "op-h1", "honest", 150.0),
                ValidatorSpec("val-a1", "op-a1", "coalition", 150.0, join_epoch=2, join_source="POST_GENESIS"),
            ),
        )
        summary = run_scenario(scenario)
        self.assertIn("val-a1", summary.activation_latency_epochs)
        self.assertGreaterEqual(summary.activation_latency_epochs["val-a1"], 1)

    def test_large_profile_builders_are_deterministic_and_validate(self) -> None:
        scenarios = [
            build_large_split_operator_adversary(committee_size=16, min_eligible=18, dynamic_min_bond_coins=150.0),
            build_large_availability_griefing_adversary(committee_size=16, min_eligible=18, dynamic_min_bond_coins=150.0),
            build_large_sticky_fallback_threshold_manipulator(committee_size=24, min_eligible=27, dynamic_min_bond_coins=150.0),
            build_large_join_exit_boundary_adversary(committee_size=24, min_eligible=27, dynamic_min_bond_coins=150.0),
        ]
        for scenario in scenarios:
            scenario.validate()
            self.assertEqual(run_scenario(scenario), run_scenario(scenario))

    def test_candidate_profiles_expose_expected_protocol_targets(self) -> None:
        profiles = candidate_profiles()
        self.assertIn(PROFILE_A.name, profiles)
        self.assertIn(PROFILE_B.name, profiles)
        self.assertEqual(profiles[PROFILE_A.name].committee_size, 16)
        self.assertEqual(profiles[PROFILE_A.name].min_eligible, 18)
        self.assertEqual(profiles[PROFILE_B.name].committee_size, 24)
        self.assertEqual(profiles[PROFILE_B.name].min_eligible, 27)

    def test_threshold_sensitive_scenarios_validate_and_roundtrip_controls(self) -> None:
        scenario = build_marginal_eligible_pool(committee_size=16, min_eligible=18, eligible_slack_operators=0)
        payload = scenario_to_dict(scenario)
        restored = scenario_from_dict(payload)
        self.assertEqual(restored.threshold_controls["eligible_slack_operators"], 0)
        restored.validate()

    def test_threshold_sensitive_families_are_deterministic(self) -> None:
        scenarios = [
            build_marginal_eligible_pool(),
            build_bond_threshold_edge(),
            build_mixed_depth_population(),
            build_boundary_activation_edge(),
        ]
        for scenario in scenarios:
            self.assertEqual(run_scenario(scenario), run_scenario(scenario))

    def test_marginal_eligible_pool_is_binding_on_min_eligible(self) -> None:
        low = run_scenario(build_marginal_eligible_pool(committee_size=16, min_eligible=16, eligible_slack_operators=0))
        high = run_scenario(build_marginal_eligible_pool(committee_size=16, min_eligible=19, eligible_slack_operators=0))
        self.assertNotEqual(low.epochs_at_exact_threshold, high.epochs_at_exact_threshold)
        self.assertNotEqual(low.fallback_rate, high.fallback_rate)

    def test_bond_threshold_edge_is_binding_on_dynamic_min_bond(self) -> None:
        low = run_scenario(build_bond_threshold_edge(dynamic_min_bond_coins=100.0, operator_split_count=4, bond_margin_distribution="tight"))
        high = run_scenario(build_bond_threshold_edge(dynamic_min_bond_coins=200.0, operator_split_count=4, bond_margin_distribution="tight"))
        self.assertNotEqual(low.operators_filtered_by_bond_floor, high.operators_filtered_by_bond_floor)
        self.assertNotEqual(low.split_amplification_ratio, high.split_amplification_ratio)

    def test_boundary_activation_edge_makes_warmup_difference_measurable(self) -> None:
        base = run_scenario(build_boundary_activation_edge(validator_warmup_blocks=100, validator_cooldown_blocks=100, activation_edge_density=4))
        shifted = run_scenario(build_boundary_activation_edge(validator_warmup_blocks=128, validator_cooldown_blocks=100, activation_edge_density=4))
        self.assertNotEqual(base.warmup_blocking_rate, shifted.warmup_blocking_rate)

    def test_replay_calibrated_honest_depth_uses_fixture_calibration(self) -> None:
        scenario = build_replay_calibrated_honest_depth(committee_size=16, min_eligible=18, eligible_slack_operators=0)
        self.assertGreaterEqual(len(scenario.threshold_controls["calibration_fixture_names"]), 4)
        scenario.validate()

    def test_replay_calibrated_honest_depth_is_binding_on_slack(self) -> None:
        low = run_scenario(build_replay_calibrated_honest_depth(committee_size=24, min_eligible=27, eligible_slack_operators=0))
        high = run_scenario(build_replay_calibrated_honest_depth(committee_size=24, min_eligible=27, eligible_slack_operators=3))
        self.assertNotEqual(low.fallback_rate, high.fallback_rate)
        self.assertGreater(low.epochs_below_threshold, high.epochs_below_threshold)

    def test_replay_expanded_honest_depth_uses_fixture_calibration(self) -> None:
        scenario = build_replay_expanded_honest_depth(committee_size=24, min_eligible=27, eligible_slack_operators=0)
        self.assertGreaterEqual(len(scenario.threshold_controls["calibration_fixture_names"]), 4)
        self.assertEqual(scenario.threshold_controls["calibrated_depth_scale"], 3)
        scenario.validate()

    def test_replay_expanded_honest_depth_is_binding_on_slack(self) -> None:
        low = run_scenario(build_replay_expanded_honest_depth(committee_size=24, min_eligible=27, eligible_slack_operators=0))
        high = run_scenario(build_replay_expanded_honest_depth(committee_size=24, min_eligible=27, eligible_slack_operators=5))
        self.assertNotEqual(low.fallback_rate, high.fallback_rate)
        self.assertGreater(low.epochs_below_threshold, high.epochs_below_threshold)

    def test_depth_boundary_minimum_slack_detects_profile_gap(self) -> None:
        def boundary_rows(profile):
            marginal_count = 4 if profile.committee_size == 16 else 5
            rows = []
            for slack in range(-1, 5):
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
                rows.append(
                    {
                        "eligible_slack_operators": slack,
                        "fallback_rate_pct": summary.fallback_rate * 100.0,
                        "sticky_rate_pct": summary.sticky_fallback_rate * 100.0,
                        "epochs_at_exact_threshold": summary.epochs_at_exact_threshold,
                        "epochs_below_threshold": summary.epochs_below_threshold,
                    }
                )
            return rows

        profile_a_rows = boundary_rows(PROFILE_A)
        profile_b_rows = boundary_rows(PROFILE_B)

        self.assertEqual(
            minimum_slack_for(
                profile_a_rows,
                lambda row: row["fallback_rate_pct"] == 0.0 and row["sticky_rate_pct"] == 0.0,
            ),
            1,
        )
        self.assertEqual(
            minimum_slack_for(
                profile_b_rows,
                lambda row: row["fallback_rate_pct"] == 0.0 and row["sticky_rate_pct"] == 0.0,
            ),
            2,
        )
        self.assertEqual(
            minimum_slack_for(
                profile_a_rows,
                lambda row: row["fallback_rate_pct"] == 0.0
                and row["sticky_rate_pct"] == 0.0
                and row["epochs_at_exact_threshold"] == 0
                and row["epochs_below_threshold"] == 0,
            ),
            2,
        )
        self.assertEqual(
            minimum_slack_for(
                profile_b_rows,
                lambda row: row["fallback_rate_pct"] == 0.0
                and row["sticky_rate_pct"] == 0.0
                and row["epochs_at_exact_threshold"] == 0
                and row["epochs_below_threshold"] == 0,
            ),
            3,
        )

    def test_replay_calibrated_depth_report_runs(self) -> None:
        self.assertEqual(generate_replay_calibrated_depth_report(), 0)

    def test_replay_expanded_depth_report_runs(self) -> None:
        self.assertEqual(generate_replay_expanded_depth_report(), 0)


if __name__ == "__main__":
    unittest.main()
