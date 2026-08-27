from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from adaptive_waf.training.network_data import load_network_dataset


class NetworkDataTests(unittest.TestCase):
    def test_loader_reservoir_samples_each_class_and_preserves_schema(self) -> None:
        records = [
            {"features": {"duration": 1.0, "packets": 2.0}, "label": "BENIGN"},
            {"features": {"duration": 2.0, "packets": 3.0}, "label": "BENIGN"},
            {"features": {"duration": 3.0, "packets": 4.0}, "label": "BOT_ANOMALY"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network.jsonl"
            path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
            features, labels, names = load_network_dataset(path, max_samples_per_class=1, seed=641)
        self.assertEqual(features.shape, (2, 2))
        self.assertEqual(labels, ["BENIGN", "BOT_ANOMALY"])
        self.assertEqual(names, ("duration", "packets"))
