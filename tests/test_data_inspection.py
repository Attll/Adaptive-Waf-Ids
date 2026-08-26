from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import json

from adaptive_waf.data.inspection import inspect_atrdf_json_file, inspect_csv_file


class DataInspectionTests(unittest.TestCase):
    def test_csv_inspection_reports_schema_quality_and_labels(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "requests.csv"
            source.write_text(
                "method,path,label\nGET,/health,BENIGN\nGET,/health,BENIGN\n,,\n",
                encoding="utf-8",
            )

            inspection = inspect_csv_file(source, label_column="label")

            self.assertEqual(inspection.columns, ("method", "path", "label"))
            self.assertEqual(inspection.row_count, 3)
            self.assertEqual(inspection.blank_row_count, 1)
            self.assertEqual(inspection.duplicate_row_count, 1)
            self.assertEqual(inspection.label_counts, {"BENIGN": 2})
            self.assertEqual(inspection.class_imbalance_ratio, 1.0)
            self.assertEqual(inspection.missing_required_columns(("label", "body")), ("body",))

    def test_atrdf_json_inspection_treats_missing_attack_tag_as_benign(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "requests.json"
            source.write_text(
                json.dumps(
                    [
                        {"request": {"method": "GET", "url": "http://waf.test/"}},
                        {"request": {"method": "GET", "url": "http://waf.test/?x=1", "Attack_Tag": "XSS"}},
                    ]
                ),
                encoding="utf-8",
            )

            inspection = inspect_atrdf_json_file(source)

            self.assertEqual(inspection.row_count, 2)
            self.assertEqual(inspection.label_counts, {"BENIGN": 1, "XSS": 1})
            self.assertIn("request.headers", inspection.null_counts)


if __name__ == "__main__":
    unittest.main()
