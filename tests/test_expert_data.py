from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from adaptive_waf.training.expert_data import load_expert_dataset


class ExpertDataTests(unittest.TestCase):
    def test_loader_keeps_only_configured_expert_classes(self) -> None:
        records = [
            _record("BENIGN", "/health"),
            _record("SQL_INJECTION", "/search", "q=' OR 1=1"),
            _record("XSS", "/comment", "text=<script>alert(1)</script>"),
            _record("DIRECTORY_TRAVERSAL", "/files", "path=../../etc/passwd"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "samples.jsonl"
            path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
            dataset = load_expert_dataset(path, ["BENIGN", "SQL_INJECTION", "XSS"])
        self.assertEqual(dataset.labels, ["BENIGN", "SQL_INJECTION", "XSS"])

    def test_loader_rejects_configuration_without_benign_class(self) -> None:
        with self.assertRaisesRegex(ValueError, "BENIGN"):
            load_expert_dataset(Path("missing.jsonl"), ["SQL_INJECTION", "XSS"])


def _record(label: str, path: str, query: str = "") -> dict[str, object]:
    return {"label": label, "request": {"method": "GET", "path": path, "query": query, "headers": {}, "cookies": {}, "body": ""}}
