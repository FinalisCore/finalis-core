from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.adaptive_regime_report import load_payload_from_file, render_text


class AdaptiveRegimeReportTests(unittest.TestCase):
    def test_report_parses_result_wrapped_payload_and_renders_text(self) -> None:
        payload = {
            "result": {
                "window_epochs": 4,
                "summary": {
                    "sample_count": 2,
                    "fallback_rate_bps": 2500,
                    "sticky_fallback_rate_bps": 1250,
                    "near_threshold_operation": True,
                    "prolonged_expand_buildup": False,
                    "prolonged_contract_buildup": False,
                    "repeated_sticky_fallback": True,
                    "depth_collapse_after_bond_increase": False,
                },
                "snapshots": [
                    {
                        "epoch_start_height": 48,
                        "qualified_depth": 26,
                        "adaptive_target_committee_size": 24,
                        "adaptive_min_eligible": 27,
                        "adaptive_min_bond": 15000000000,
                        "slack": -1,
                        "checkpoint_derivation_mode": "fallback",
                        "checkpoint_fallback_reason": "hysteresis_recovery_pending",
                        "fallback_sticky": True,
                        "target_expand_streak": 3,
                        "target_contract_streak": 0,
                    }
                ],
            }
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "telemetry.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_payload_from_file(path)
        self.assertEqual(loaded["window_epochs"], 4)
        rendered = render_text(loaded)
        self.assertIn("Adaptive Regime Report", rendered)
        self.assertIn("qualified_depth: 26", rendered)
        self.assertIn("near_threshold_operation: True", rendered)


if __name__ == "__main__":
    unittest.main()
