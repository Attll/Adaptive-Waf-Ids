from __future__ import annotations

import unittest

from adaptive_waf.training.router_evaluation import evaluate_routing_thresholds, select_experts


class RouterEvaluationTests(unittest.TestCase):
    def test_confident_probability_routes_top_one(self) -> None:
        selected = select_experts([0.9, 0.1], ["EXECUTION", "INJECTION"], 0.8, 0.3)
        self.assertEqual(selected, ("EXECUTION",))

    def test_ambiguous_probability_routes_both_families(self) -> None:
        selected = select_experts([0.55, 0.45], ["EXECUTION", "INJECTION"], 0.8, 0.3)
        self.assertEqual(selected, ("EXECUTION", "INJECTION"))

    def test_threshold_evaluation_reports_coverage(self) -> None:
        results = evaluate_routing_thresholds(
            [[0.9, 0.1], [0.55, 0.45]],
            ["EXECUTION", "INJECTION"],
            ["EXECUTION", "INJECTION"],
            [0.8],
            [0.3],
        )
        self.assertEqual(results[0].top1_route_rate, 0.5)
        self.assertEqual(results[0].selected_family_coverage, 1.0)
