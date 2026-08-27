from __future__ import annotations

import unittest

from adaptive_waf.runtime.network import OfflineNetworkDetector


class OfflineNetworkDetectorTests(unittest.TestCase):
    def test_detect_returns_risk_from_benign_probability(self) -> None:
        detector = OfflineNetworkDetector(_Model(), ("duration", "packets"), "network-v1:random_forest")

        context = detector.detect({"duration": 4.0, "packets": 12.0})

        self.assertEqual(context.network_class, "DOS_DDOS")
        self.assertEqual(context.confidence, 0.7)
        self.assertAlmostEqual(context.risk, 0.9)

    def test_detect_rejects_schema_mismatch(self) -> None:
        detector = OfflineNetworkDetector(_Model(), ("duration", "packets"), "network-v1:random_forest")

        with self.assertRaisesRegex(ValueError, "missing: packets"):
            detector.detect({"duration": 4.0})


class _Model:
    classes_ = ("BENIGN", "DOS_DDOS")

    def predict_proba(self, rows):
        return [[0.1, 0.7] for _ in rows]
