from __future__ import annotations

import unittest

from adaptive_waf.contracts import AttackClass, BehaviourContext, ExpertFamily, HttpRequestRecord, TriageDecision
from adaptive_waf.runtime.pipeline import AdaptiveDetectionPipeline, PipelineThresholds


class PipelineTests(unittest.TestCase):
    def test_benign_triage_exits_before_router(self) -> None:
        pipeline = _pipeline(_Model(["BENIGN_LIKE", "SUSPICIOUS"], [0.9999, 0.0001]))
        result = pipeline.detect(HttpRequestRecord(method="GET", path="/health"))
        self.assertEqual(result.triage_decision, TriageDecision.BENIGN_LIKE)
        self.assertIsNone(result.router_output)

    def test_confident_router_uses_one_expert(self) -> None:
        pipeline = _pipeline(_Model(["BENIGN_LIKE", "SUSPICIOUS"], [0.01, 0.99]))
        result = pipeline.detect(HttpRequestRecord(method="GET", path="/search", query="q=hello"))
        self.assertEqual(result.predicted_attack, AttackClass.SQL_INJECTION)
        self.assertEqual(result.router_output.selected_experts, (ExpertFamily.INJECTION,))

    def test_behaviour_risk_elevates_overall_risk_without_changing_http_prediction(self) -> None:
        pipeline = _pipeline(_Model(["BENIGN_LIKE", "SUSPICIOUS"], [0.9999, 0.0001]))
        result = pipeline.detect(HttpRequestRecord(method="GET", path="/health"), BehaviourContext(risk=0.8, failed_auth_attempts=4))
        self.assertEqual(result.predicted_attack, AttackClass.BENIGN)
        self.assertEqual(result.overall_risk, 0.8)
        self.assertEqual(result.explanation_evidence["behaviour_failed_auth_attempts"], "4")


def _pipeline(triage):
    return AdaptiveDetectionPipeline(
        triage,
        _Model(["INJECTION", "EXECUTION"], [0.95, 0.05]),
        {ExpertFamily.INJECTION: _Model(["BENIGN", "SQL_INJECTION"], [0.01, 0.99]), ExpertFamily.EXECUTION: _Model(["BENIGN", "DIRECTORY_TRAVERSAL"], [0.8, 0.2])},
        PipelineThresholds(0.001, True, 0.9, 0.9, 0.4),
        {"triage": "triage", "router": "router", "injection": "injection", "execution": "execution", "deep": "deep"},
    )


class _Model:
    def __init__(self, classes, probabilities) -> None:
        self.classes_ = classes
        self._probabilities = probabilities

    def predict_proba(self, features):
        return [self._probabilities for _ in features]
