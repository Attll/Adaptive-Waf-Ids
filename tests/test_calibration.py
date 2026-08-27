from __future__ import annotations

import unittest

from adaptive_waf.training.calibration import probability_quality


class CalibrationTests(unittest.TestCase):
    def test_probability_quality_is_zero_for_perfect_confident_predictions(self) -> None:
        quality = probability_quality([[1.0, 0.0], [0.0, 1.0]], ["BENIGN", "ATTACK"], ["BENIGN", "ATTACK"])
        self.assertEqual(quality["multiclass_brier_score"], 0.0)
        self.assertEqual(quality["top_label_expected_calibration_error"], 0.0)
