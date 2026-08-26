from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from adaptive_waf.training.http_data import load_triage_dataset


class TriageDataTests(unittest.TestCase):
    def test_loader_creates_binary_labels_and_consistent_features(self) -> None:
        records = [
            {"request": {"method": "GET", "path": "/health"}, "label": "BENIGN"},
            {"request": {"method": "GET", "path": "/search", "query": "q=%27+OR+1%3D1"}, "label": "SQL_INJECTION"},
        ]
        with TemporaryDirectory() as directory:
            source = Path(directory) / "train.jsonl"
            source.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")

            dataset = load_triage_dataset(source)

            self.assertEqual(dataset.labels, ["BENIGN_LIKE", "SUSPICIOUS"])
            self.assertEqual(len(dataset.features), 2)
            self.assertEqual(len(dataset.feature_names), len(dataset.features[0]))


if __name__ == "__main__":
    unittest.main()
