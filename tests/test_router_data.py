from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from adaptive_waf.training.router_data import load_router_dataset


class RouterDataTests(unittest.TestCase):
    def test_loader_maps_only_attack_records_to_families(self) -> None:
        records = [
            _record("BENIGN", "/health"),
            _record("SQL_INJECTION", "/search", "q=' OR 1=1"),
            _record("DIRECTORY_TRAVERSAL", "/files", "path=../../etc/passwd"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "samples.jsonl"
            path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
            dataset = load_router_dataset(path)
        self.assertEqual(dataset.labels, ["INJECTION", "EXECUTION"])
        self.assertEqual(len(dataset.features), 2)


def _record(label: str, path: str, query: str = "") -> dict[str, object]:
    return {"label": label, "request": {"method": "GET", "path": path, "query": query, "headers": {}, "cookies": {}, "body": ""}}
