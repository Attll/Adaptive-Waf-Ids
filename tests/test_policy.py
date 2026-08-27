from __future__ import annotations

import unittest

from adaptive_waf.contracts import PolicyAction
from adaptive_waf.runtime.policy import OfflinePolicySimulator, PolicyThresholds


class OfflinePolicySimulatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.simulator = OfflinePolicySimulator("test-v1", PolicyThresholds(0.2, 0.5, 0.8))

    def test_thresholds_map_to_all_four_actions(self) -> None:
        self.assertEqual(self.simulator.evaluate(0.2).action, PolicyAction.ALLOW)
        self.assertEqual(self.simulator.evaluate(0.21).action, PolicyAction.MONITOR)
        self.assertEqual(self.simulator.evaluate(0.51).action, PolicyAction.RATE_LIMIT)
        self.assertEqual(self.simulator.evaluate(0.81).action, PolicyAction.BLOCK)

    def test_primary_fusion_evidence_is_recorded_as_reason(self) -> None:
        decision = self.simulator.evaluate(0.9, {"fusion_network_risk": "0.900000", "fusion_http_risk": "0.100000"})
        self.assertEqual(decision.action, PolicyAction.BLOCK)
        self.assertIn("primary_evidence=network", decision.reasons)
