from __future__ import annotations

import time
import unittest
from datetime import datetime, timezone
from uuid import uuid4

from adaptive_waf.contracts import (
    AttackClass,
    BehaviourContext,
    DeepOutput,
    DetectionResult,
    ExpertFamily,
    ExpertOutput,
    HttpRequestRecord,
    RouterOutput,
    TriageDecision,
)
from adaptive_waf.runtime.fusion import DeterministicRiskFusion
from adaptive_waf.runtime.pipeline import AdaptiveDetectionPipeline, PipelineThresholds
from adaptive_waf.service.escalation import DisabledEscalationWorker, EscalationWorker


class AsynchronousEscalationTests(unittest.TestCase):
    def test_low_confidence_request_is_answered_immediately_and_deferred(self) -> None:
        scheduled: list[tuple[str, HttpRequestRecord]] = []
        pipeline = _pipeline(asynchronous=True, scheduler=lambda identifier, request, result: scheduled.append((identifier, request)))

        result = pipeline.detect(_request(), BehaviourContext(), None, {})

        self.assertTrue(result.deep_escalation_pending)
        self.assertIsNotNone(result.deep_escalation_id)
        self.assertIsNone(result.deep_output, "the deep model must not run inline when escalation is deferred")
        self.assertFalse(result.deep_model_used)
        self.assertIn("DEEP_ESCALATION_DEFERRED", result.routing_path)
        self.assertEqual(result.predicted_attack, AttackClass.SQL_INJECTION, "the fast verdict answers the caller")
        self.assertEqual(len(scheduled), 1)
        self.assertEqual(scheduled[0][0], result.deep_escalation_id)

    def test_inline_escalation_still_runs_the_deep_model_when_asynchronous_is_off(self) -> None:
        pipeline = _pipeline(asynchronous=False, scheduler=None)

        result = pipeline.detect(_request(), BehaviourContext(), None, {})

        self.assertFalse(result.deep_escalation_pending)
        self.assertTrue(result.deep_model_used)
        self.assertIsNotNone(result.deep_output)
        self.assertIn("DEEP_ESCALATION", result.routing_path)

    def test_rejected_submission_is_not_reported_pending(self) -> None:
        pipeline = _pipeline(asynchronous=True, scheduler=lambda *args: False)
        result = pipeline.detect(_request(), BehaviourContext(), None, {})
        self.assertFalse(result.deep_escalation_pending)
        self.assertIsNone(result.deep_escalation_id)
        self.assertIn("DEEP_ESCALATION_REJECTED", result.routing_path)
        self.assertEqual(result.explanation_evidence["deep_escalation"], "rejected_capacity_or_unavailable")

    def test_confident_request_is_never_escalated(self) -> None:
        scheduled: list[str] = []
        pipeline = _pipeline(asynchronous=True, scheduler=lambda identifier, request, result: scheduled.append(identifier), confidence=0.99)

        result = pipeline.detect(_request(), BehaviourContext(), None, {})

        self.assertFalse(result.deep_escalation_pending)
        self.assertFalse(result.deep_model_used)
        self.assertEqual(scheduled, [])

    def test_worker_resolves_a_deferred_escalation_and_reports_a_changed_verdict(self) -> None:
        reported: list = []
        worker = EscalationWorker(workers=1, queue_limit=8, reporter=reported.append)
        worker.bind(lambda request: (DeepOutput(AttackClass.XSS, 0.99, 0.99, "deep-v1", {AttackClass.XSS: 0.99, AttackClass.BENIGN: 0.01}), 4.2))
        worker.start()

        worker.submit("escalation-1", _request(), _result())
        outcome = _await(worker)

        self.assertEqual(outcome["revised"]["predicted_attack"], "XSS")
        self.assertEqual(outcome["provisional"]["predicted_attack"], "SQL_INJECTION")
        self.assertTrue(outcome["changed"], "a different class than the fast verdict must be flagged as revised")
        self.assertEqual(len(reported), 1)
        statistics = worker.statistics()
        self.assertEqual(statistics["resolved"], 1)
        self.assertEqual(statistics["verdict_changed"], 1)
        self.assertEqual(statistics["failed"], 0)

    def test_worker_survives_an_adjudicator_failure(self) -> None:
        worker = EscalationWorker(workers=1, queue_limit=8)

        def explode(request):
            raise RuntimeError("model unavailable")

        worker.bind(explode)
        worker.start()
        worker.submit("escalation-2", _request(), _result())
        outcome = _await(worker)

        self.assertIsNotNone(outcome["error"])
        self.assertEqual(worker.statistics()["failed"], 1)

    def test_full_queue_rejects_rather_than_blocking_the_request_path(self) -> None:
        worker = EscalationWorker(workers=1, queue_limit=1)
        # Deliberately not started, so nothing drains the queue.
        self.assertTrue(worker.submit("first", _request(), _result()))
        self.assertFalse(worker.submit("second", _request(), _result()))
        self.assertEqual(worker.statistics()["rejected"], 1)

    def test_disabled_worker_reports_itself_as_off(self) -> None:
        worker = DisabledEscalationWorker()
        self.assertFalse(worker.submit("x", _request(), _result()))
        self.assertEqual(worker.recent(), [])
        self.assertFalse(worker.statistics()["enabled"])


def _await(worker: EscalationWorker, timeout_seconds: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        recent = worker.recent(1)
        if recent:
            return recent[0]
        time.sleep(0.01)
    raise AssertionError("escalation was not resolved before the timeout")


def _request() -> HttpRequestRecord:
    return HttpRequestRecord(method="GET", path="/search", query="q=1' OR '1'='1", request_id=uuid4())


def _result() -> DetectionResult:
    expert = ExpertOutput(ExpertFamily.INJECTION, AttackClass.SQL_INJECTION, 0.72, 0.8, "injection-v1")
    return DetectionResult(
        request_id=uuid4(),
        timestamp=datetime.now(timezone.utc),
        triage_score=0.8,
        triage_decision=TriageDecision.SUSPICIOUS,
        router_output=RouterOutput({ExpertFamily.INJECTION: 0.95, ExpertFamily.EXECUTION: 0.05}, (ExpertFamily.INJECTION,), "router-v1"),
        expert_outputs=(expert,),
        predicted_attack=AttackClass.SQL_INJECTION,
        http_risk=0.8,
        behaviour_risk=0.0,
        network_risk=0.0,
        overall_risk=0.8,
        routing_path=("TRIAGE", "ROUTER_TOP1", "INJECTION_FAST", "POLICY_PENDING"),
        latency_by_stage_ms={"triage": 1.0},
        model_versions={"triage": "t", "router": "r", "injection": "i", "execution": "e", "deep": "d"},
    )


def _pipeline(asynchronous: bool, scheduler, confidence: float = 0.55) -> AdaptiveDetectionPipeline:
    return AdaptiveDetectionPipeline(
        _FakeBinary(),
        _FakeRouter(),
        {ExpertFamily.INJECTION: _FakeExpert(confidence), ExpertFamily.EXECUTION: _FakeExpert(confidence)},
        PipelineThresholds(
            triage_benign_exit_max_suspicious_probability=0.001,
            triage_early_exit_enabled=False,
            expert_minimum_confidence=0.90,
            router_minimum_top1_probability=0.5,
            router_minimum_top1_margin=0.1,
            asynchronous_deep_escalation_enabled=asynchronous,
        ),
        {"triage": "t", "router": "r", "injection": "i", "execution": "e", "deep": "d"},
        deep_predictor=lambda request: {AttackClass.XSS: 0.99, AttackClass.BENIGN: 0.01},
        risk_fuser=DeterministicRiskFusion({"http": 1.0, "behaviour": 1.0, "network": 1.0, "rule": 1.0}),
        deep_scheduler=scheduler,
    )


class _FakeBinary:
    classes_ = ("BENIGN_LIKE", "SUSPICIOUS")

    def predict_proba(self, features):
        return [[0.05, 0.95]]


class _FakeRouter:
    classes_ = ("INJECTION", "EXECUTION")

    def predict_proba(self, features):
        return [[0.97, 0.03]]


class _FakeExpert:
    classes_ = ("BENIGN", "SQL_INJECTION")

    def __init__(self, confidence: float) -> None:
        self._confidence = confidence

    def predict_proba(self, features):
        return [[1.0 - self._confidence, self._confidence]]


if __name__ == "__main__":
    unittest.main()
