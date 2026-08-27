from __future__ import annotations

import unittest

from adaptive_waf.contracts import AttackClass, ExpertFamily, ExpertOutput, HttpRequestRecord, PolicyAction, RouterOutput, TriageDecision
from adaptive_waf.runtime.benchmark import run_http_benchmark
from adaptive_waf.runtime.policy import OfflinePolicySimulator, PolicyThresholds


class BenchmarkTests(unittest.TestCase):
    def test_report_captures_routing_actions_accuracy_and_latency(self) -> None:
        samples = [
            (HttpRequestRecord("GET", "/health"), "BENIGN"),
            (HttpRequestRecord("GET", "/search", "q=test"), "SQL_INJECTION"),
        ]
        report, records = run_http_benchmark(_Pipeline(), OfflinePolicySimulator("test-v1", PolicyThresholds(0.2, 0.5, 0.8)), samples)

        self.assertEqual(report.total_requests, 2)
        self.assertEqual(report.router_accuracy, 1.0)
        self.assertEqual(report.top2_router_coverage, 1.0)
        self.assertEqual(report.attack_recall, 1.0)
        self.assertEqual(report.false_positive_rate, 0.0)
        self.assertEqual(report.action_distribution["BLOCK"], 1)
        self.assertEqual(len(records), 2)


class _Pipeline:
    def detect(self, request):
        from adaptive_waf.contracts import DetectionResult

        attack = AttackClass.BENIGN if request.path == "/health" else AttackClass.SQL_INJECTION
        risk = 0.05 if attack is AttackClass.BENIGN else 0.95
        router = None if attack is AttackClass.BENIGN else RouterOutput(
            {ExpertFamily.INJECTION: 0.98, ExpertFamily.EXECUTION: 0.02}, (ExpertFamily.INJECTION,), "router-v1"
        )
        experts = () if router is None else (ExpertOutput(ExpertFamily.INJECTION, attack, 0.98, risk, "expert-v1"),)
        return DetectionResult(
            request_id=request.request_id, timestamp=request.received_at, triage_score=risk,
            triage_decision=TriageDecision.BENIGN_LIKE if router is None else TriageDecision.SUSPICIOUS,
            router_output=router, expert_outputs=experts, predicted_attack=attack,
            http_risk=risk, behaviour_risk=0.0, network_risk=0.0, overall_risk=risk,
            routing_path=("TRIAGE", "TRIAGE_EARLY_EXIT", "POLICY_PENDING") if router is None else ("TRIAGE", "ROUTER_TOP1", "INJECTION_FAST", "POLICY_PENDING"),
            latency_by_stage_ms={"triage": 1.0}, model_versions={"triage": "triage-v1"},
        )
