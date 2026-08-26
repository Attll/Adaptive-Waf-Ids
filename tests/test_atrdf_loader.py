from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import json

from adaptive_waf.contracts import AttackClass
from adaptive_waf.data.atrdf import AtrdfDatasetLoader, AtrdfSchema, normalize_atrdf_label


class AtrdfLoaderTests(unittest.TestCase):
    def test_loader_uses_explicit_schema_and_normalizes_labels(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "atrdf.csv"
            source.write_text(
                "verb,endpoint,payload,attack\nPOST,/search,id=1 OR 1=1,SQL Injection\n",
                encoding="utf-8",
            )
            loader = AtrdfDatasetLoader(
                AtrdfSchema(
                    label_column="attack",
                    method_column="verb",
                    path_column="endpoint",
                    body_column="payload",
                )
            )

            sample = loader.load_file(source)[0]

            self.assertEqual(sample.label, AttackClass.SQL_INJECTION)
            self.assertEqual(sample.request.method, "POST")
            self.assertEqual(sample.request.body, "id=1 OR 1=1")

    def test_unknown_label_requires_explicit_mapping(self) -> None:
        with self.assertRaises(ValueError):
            normalize_atrdf_label("unknown-attack")

    def test_json_loader_uses_real_atrdf_request_shape_and_skips_out_of_scope_labels(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "atrdf.json"
            source.write_text(
                json.dumps(
                    [
                        {"request": {"method": "GET", "url": "http://waf.test/search?q=a", "body": ""}},
                        {
                            "request": {
                                "method": "POST",
                                "url": "http://waf.test/forum",
                                "headers": {"Cookie": "session=abc; theme=dark"},
                                "body": "<script>alert(1)</script>",
                                "Attack_Tag": "XSS",
                            }
                        },
                        {"request": {"method": "GET", "url": "http://waf.test/", "Attack_Tag": "LOG4J"}},
                    ]
                ),
                encoding="utf-8",
            )

            samples = AtrdfDatasetLoader().load_file(source)

            self.assertEqual([sample.label for sample in samples], [AttackClass.BENIGN, AttackClass.XSS])
            self.assertEqual(samples[0].request.query, "q=a")
            self.assertEqual(samples[1].request.cookies, {"session": "abc", "theme": "dark"})


if __name__ == "__main__":
    unittest.main()
