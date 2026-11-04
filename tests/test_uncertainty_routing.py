import unittest
from adaptive_waf.runtime.uncertainty import SplitConformal, uncertainty, higher_quantile
from adaptive_waf.runtime.routing import LinUCB, RoutingContext, empirical_gate, labeled_reward
from adaptive_waf.runtime.strategies import RoutedPipeline, DeferralBudget
from adaptive_waf.contracts import HttpRequestRecord, AttackClass
from test_pipeline import _pipeline, _Model


class UncertaintyRoutingTests(unittest.TestCase):
    def test_finite_sample_quantile_and_class_coverage(self):
        self.assertEqual(higher_quantile([.1, .2], .1), 1)
        calibration = SplitConformal.fit([[.9,.1]] * 20, ["BENIGN"] * 20, ("BENIGN","XSS"),
                                        [str(i) for i in range(20)], "v1", class_sensitive=True)
        self.assertIn("XSS", calibration.prediction_set([.99,.01], "v1"))  # absent calibration class remains conservative
        with self.assertRaises(ValueError):
            calibration.prediction_set([.9,.1], "wrong-model")
        with self.assertRaises(ValueError):
            SplitConformal.fit([[.9,.1]], ["BENIGN"], ("BENIGN","XSS"), ["leak"], "v1", forbidden_ids=["leak"])

    def test_entropy_and_invalid_vectors(self):
        self.assertAlmostEqual(uncertainty([.5,.5])["entropy"], 1)
        with self.assertRaises(ValueError):
            uncertainty([float("nan"), 1])

    def test_bandit_masks_propensities_and_label_provenance(self):
        context = RoutingContext(.9,.7,.2)
        policy = LinUCB()
        route, probabilities = policy.select(context, {"FAST_ONLY","BOTH","SYNC_DEEP"}, conservative=True)
        self.assertIn(route, {"BOTH","SYNC_DEEP"})
        self.assertAlmostEqual(sum(probabilities.values()), 1)
        self.assertGreater(probabilities[route], 0)
        with self.assertRaises(ValueError):
            policy.update(context, route, 1, "MODEL_PREDICTION")
        policy.update(context, route, labeled_reward("XSS","BENIGN",10), "VERIFIED")
        self.assertFalse(empirical_gate({}))
        invalid={"attack_recall":1.,"benign_fpr":-1.,"p95_ms":10,"queue_depth":0,"verified_attack_count":100,"verified_benign_count":100}
        self.assertFalse(empirical_gate(invalid))
        with self.assertRaises(ValueError):
            labeled_reward("BENIGN","BENIGN",-1)
        with self.assertRaises(ValueError):
            policy.select(context,{"RULES_ONLY","FAST_ONLY"},conservative=True)
        route,_ = policy.select(RoutingContext(.1,.1,.9,queue_fraction=1,deadline_fraction=0),{"BOTH","DEFERRED_DEEP","SYNC_DEEP"})
        self.assertEqual(route,"BOTH")

    def test_mandatory_rules_apply_to_every_new_strategy(self):
        for strategy in ("rules_only", "single_fast", "both", "always_deep", "confidence", "cost_threshold", "calibrated_fusion", "bandit_shadow"):
            baseline = _pipeline(_Model(["BENIGN_LIKE","SUSPICIOUS"],[.9,.1]))
            result = RoutedPipeline(baseline, strategy).detect(HttpRequestRecord("GET", "/", "q=<script>go()</script>"))
            self.assertEqual(result.predicted_attack, AttackClass.XSS)

    def test_required_deep_unavailable_is_not_a_benign_fallback(self):
        baseline = _pipeline(_Model(["BENIGN_LIKE","SUSPICIOUS"],[.9,.1]))
        result = RoutedPipeline(baseline, "always_deep").detect(HttpRequestRecord("GET", "/public"))
        self.assertTrue(result.decision_context["fallback"])
        self.assertEqual(result.decision_context["recommended_action"], "BLOCK")
        self.assertEqual(result.decision_context["inspection_status"], "DETECTION_UNAVAILABLE")

    def test_deferral_budget_is_bounded(self):
        budget = DeferralBudget(capacity=1, refill_per_second=0)
        self.assertTrue(budget.take())
        self.assertFalse(budget.take())
