from __future__ import annotations

import unittest

from adaptive_waf.contracts import BehaviourContext, NetworkContext
from adaptive_waf.runtime.fusion import DeterministicRiskFusion


class DeterministicRiskFusionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fuser = DeterministicRiskFusion({"http": 1.0, "behaviour": 0.8, "network": 1.0, "rule": 1.0})

    def test_uses_largest_weighted_signal_and_retains_supporting_evidence(self) -> None:
        result = self.fuser.fuse(0.3, BehaviourContext(risk=0.8), NetworkContext(risk=0.9), {"crs": 0.7})

        self.assertEqual(result.overall_risk, 0.9)
        self.assertEqual(result.supporting_evidence["fusion_network_risk"], "0.900000")
        self.assertEqual(result.supporting_evidence["fusion_rule:crs_risk"], "0.700000")

    def test_rejects_unbounded_rule_risk(self) -> None:
        with self.assertRaisesRegex(ValueError, "rule:crs risk"):
            self.fuser.fuse(0.1, rule_evidence={"crs": 1.1})
