from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import json

from adaptive_waf.contracts import AttackClass, HttpRequestRecord, NetworkClass
from adaptive_waf.data.atrdf import HttpRequestSample
from adaptive_waf.data.cicids import NetworkFlowSample
from adaptive_waf.data.preparation import (
    SplitRatios,
    near_duplicate_group_key,
    network_split_key,
    prepare_http_samples,
    prepare_network_samples,
)


class PreparationTests(unittest.TestCase):
    def test_near_duplicate_http_requests_are_assigned_to_one_split(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            samples = [
                HttpRequestSample(
                    request=HttpRequestRecord(method="GET", path="/users/101"),
                    label=AttackClass.BENIGN,
                    source_file=root / "source.json",
                    source_row=1,
                ),
                HttpRequestSample(
                    request=HttpRequestRecord(method="GET", path="/users/202"),
                    label=AttackClass.BENIGN,
                    source_file=root / "source.json",
                    source_row=2,
                ),
            ]
            source = root / "source.json"
            source.write_text("[]", encoding="utf-8")

            summary = prepare_http_samples(samples, root / "prepared", SplitRatios(0.7, 0.15, 0.15), 641, [source])

            non_empty_splits = [name for name, count in summary.split_counts.items() if count]
            self.assertEqual(len(non_empty_splits), 1)
            self.assertTrue((root / "prepared" / "manifest.json").is_file())

    def test_network_preparation_writes_numeric_feature_records(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "flows.csv"
            source.write_text("flow,label\n1.5,Bot\n", encoding="utf-8")
            sample = NetworkFlowSample(
                features={"flow": 1.5},
                label=NetworkClass.BOT_ANOMALY,
                source_file=source,
                source_row=2,
                replaced_non_finite_features=("flow",),
            )

            summary = prepare_network_samples([sample], root / "prepared", SplitRatios(0.7, 0.15, 0.15), 641, [source])

            self.assertEqual(sum(summary.split_counts.values()), 1)
            split = next(name for name, count in summary.split_counts.items() if count)
            prepared_file = root / "prepared" / f"{split}.jsonl"
            self.assertIn('"BOT_ANOMALY"', prepared_file.read_text(encoding="utf-8"))
            manifest = json.loads((root / "prepared" / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["non_finite_replacements"], {"flow": 1})

    def test_near_duplicate_group_key_masks_variable_numeric_identifiers(self) -> None:
        self.assertEqual(near_duplicate_group_key("GET /orders/1001"), near_duplicate_group_key("GET /orders/2002"))

    def test_network_split_keys_are_label_aware_and_unique_per_source_row(self) -> None:
        source = Path("flows.csv")
        first = NetworkFlowSample({"flow_duration": 1.0}, NetworkClass.BENIGN, source, 2)
        second = NetworkFlowSample({"flow_duration": 1.0}, NetworkClass.BENIGN, source, 3)
        third = NetworkFlowSample({"flow_duration": 1.0}, NetworkClass.BOT_ANOMALY, source, 2)

        self.assertNotEqual(network_split_key(first), network_split_key(second))
        self.assertNotEqual(network_split_key(first), network_split_key(third))


if __name__ == "__main__":
    unittest.main()
