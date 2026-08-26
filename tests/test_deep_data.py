from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from adaptive_waf.training.deep_data import CharacterTokenizer, load_deep_dataset


class DeepDataTests(unittest.TestCase):
    def test_loader_uses_canonical_text_and_preserves_classes(self) -> None:
        records = [_record("BENIGN", "/health"), _record("SQL_INJECTION", "/search", "q=' OR 1=1")]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "samples.jsonl"
            path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
            dataset = load_deep_dataset(path, ("BENIGN", "SQL_INJECTION"))
        self.assertEqual(dataset.labels, ["BENIGN", "SQL_INJECTION"])
        self.assertIn("[METHOD]", dataset.texts[0])
        self.assertIn("[QUERY]", dataset.texts[1])

    def test_character_tokenizer_is_fixed_length_and_deterministic(self) -> None:
        tokenizer = CharacterTokenizer()
        self.assertEqual(tokenizer.encode("Aé", 4), [tokenizer.encode("A", 1)[0], tokenizer.unknown_id, 0, 0])


def _record(label: str, path: str, query: str = "") -> dict[str, object]:
    return {"label": label, "request": {"method": "GET", "path": path, "query": query, "headers": {}, "cookies": {}, "body": ""}}
