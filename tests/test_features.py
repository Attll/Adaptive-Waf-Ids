import unittest

from adaptive_waf.contracts import HttpRequestRecord
from adaptive_waf.features.canonical import serialize_deep_request
from adaptive_waf.features.classical import ClassicalFeatureExtractor


class FeatureTests(unittest.TestCase):
    def test_equivalent_requests_have_identical_deep_representation(self) -> None:
        first = HttpRequestRecord(
            method="get",
            path="/search/%7Eitems",
            query="b=two&a=one",
            headers={"Accept": " application/json ", "Content-Type": "application/json; charset=utf-8"},
            cookies={"theme": "dark", "session": "abc"},
            body=" line one\r\nline two ",
        )
        second = HttpRequestRecord(
            method="GET",
            path="/search/~items",
            query="a=one&b=two",
            headers={"content-type": "application/json; charset=utf-8", "accept": "application/json"},
            cookies={"session": "abc", "theme": "dark"},
            body="line one line two",
        )

        self.assertEqual(serialize_deep_request(first), serialize_deep_request(second))

    def test_feature_extraction_is_deterministic_and_has_expected_structural_signals(self) -> None:
        request = HttpRequestRecord(
            method="POST",
            path="/users/../search",
            query="id=%27%20OR%201%3D1",
            headers={"Content-Type": "application/json"},
            body='{"query":"<script>alert(1)</script>"}',
        )

        extractor = ClassicalFeatureExtractor()
        first = extractor.extract(request)
        second = extractor.extract(request)
        values = first.as_dict()

        self.assertEqual(first, second)
        self.assertEqual(values["method_post"], 1.0)
        self.assertEqual(values["content_type_application_json"], 1.0)
        self.assertGreater(values["percent_encoded_count"], 0.0)
        self.assertGreater(values["special_character_density"], 0.0)
        self.assertGreater(values["shannon_entropy"], 0.0)


if __name__ == "__main__":
    unittest.main()
