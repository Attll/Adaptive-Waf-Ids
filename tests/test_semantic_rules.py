import unittest
from adaptive_waf.contracts import HttpRequestRecord, AttackClass
from adaptive_waf.runtime.rules import SemanticRules
from adaptive_waf.runtime.guarded import GuardedPipeline
from scripts.evaluate_phase10 import CASES


class SemanticRuleTests(unittest.TestCase):
    def test_development_probes_and_benign_negative(self):
        rules = SemanticRules()
        for name, payload in CASES.items():
            request = HttpRequestRecord(method="GET", **{k: v for k, v in payload.items() if k != "expected_attack"})
            self.assertEqual(bool(rules.inspect(request)), payload["expected_attack"], name)

    def test_encoded_variants_and_cookie_class(self):
        rules = SemanticRules()
        for value in ("f=..%2f..%2fprivate", "f=%252e%252e%252fprivate", "f=..\\private"):
            self.assertEqual(rules.inspect(HttpRequestRecord("GET", "/files", value))[0].attack, AttackClass.DIRECTORY_TRAVERSAL)
        self.assertEqual(rules.inspect(HttpRequestRecord("GET", "/", cookies={"x": "' or 'a'='a"}))[0].attack, AttackClass.COOKIE_INJECTION)

    def test_plain_language_and_ordinary_inputs_are_not_signatures(self):
        for value in ("q=O%27Reilly", "q=javascript+courses", "q=select+an+option", "q=rock+and+roll", "price=1.99", "path=images/photo.png"):
            self.assertFalse(SemanticRules().inspect(HttpRequestRecord("GET", "/search", value)))

    def test_mandatory_rule_cannot_be_overruled_by_benign_model(self):
        class Baseline:
            model_versions = {"triage": "fixture"}
            def detect(self, *args):
                raise AssertionError("a mandatory rule must precede optional inference")
        result = GuardedPipeline(Baseline()).detect(HttpRequestRecord("POST", "/submit", body="<script>run()</script>"))
        self.assertEqual(result.predicted_attack, AttackClass.XSS)
        self.assertGreater(result.overall_risk, .81)
        self.assertEqual(result.explanation_evidence["classification_source"], "DETERMINISTIC_RULE")
