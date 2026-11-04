import unittest
from adaptive_waf.runtime.research_baselines import DeepOnlyControl
from adaptive_waf.contracts import HttpRequestRecord,AttackClass
from test_pipeline import _pipeline,_Model


class ResearchBaselineTests(unittest.TestCase):
    def test_every_request_reaches_deep_without_semantic_or_fast_early_exit(self):
        baseline=_pipeline(_Model(["BENIGN_LIKE","SUSPICIOUS"],[.9,.1]))
        calls=[]
        baseline._deep_predictor=lambda request:calls.append(request) or {AttackClass.BENIGN:.95,AttackClass.XSS:.05}
        control=DeepOnlyControl(baseline)
        for query in ("q=ordinary","q=<script>fixture()</script>"):
            result=control.detect(HttpRequestRecord("GET","/development",query))
            self.assertTrue(result.deep_model_used)
            self.assertEqual(result.predicted_attack,AttackClass.BENIGN)
            self.assertEqual(set(result.latency_by_stage_ms),{"deep"})
            self.assertFalse(result.decision_context["semantic_guards_enabled"])
        self.assertEqual(len(calls),2)
