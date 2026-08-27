from __future__ import annotations
import unittest
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1] / "scripts"))
from evaluate_phase10 import percentile

class Phase10EvaluationTests(unittest.TestCase):
    def test_percentiles_are_deterministic(self) -> None:
        self.assertEqual(percentile([1.0], 95), 1.0)
        self.assertAlmostEqual(percentile([1.0, 2.0, 3.0, 4.0], 50), 2.5)
