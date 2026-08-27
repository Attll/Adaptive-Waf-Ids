from __future__ import annotations

import argparse
from datetime import datetime, timezone
import unittest
from uuid import uuid4

from adaptive_waf.contracts import AttackClass, DetectionResult, ExpertFamily, ExpertOutput, PolicyAction, PolicyDecision, RouterOutput, TriageDecision
from scripts.inspect_pipeline import _inspection_payload


class InspectPipelineTests(unittest.TestCase):
    def test_payload_contains_required_normalized_pipeline_sections(self) -> None:
        request_arguments = argparse.Namespace(method="GET", path="/health", query="", body="", behaviour_risk=0.0, network_risk=0.8)
        result = DetectionResult(
            request_id=uuid4(), timestamp=datetime.now(timezone.utc), triage_score=0.2,
            triage_decision=TriageDecision.SUSPICIOUS,
            router_output=RouterOutput({ExpertFamily.INJECTION: 0.9, ExpertFamily.EXECUTION: 0.1}, (ExpertFamily.INJECTION,), "router-v1"),
            expert_outputs=(ExpertOutput(ExpertFamily.INJECTION, AttackClass.BENIGN, 0.95, 0.05, "expert-v1"),),
            predicted_attack=AttackClass.BENIGN, http_risk=0.05, behaviour_risk=0.0, network_risk=0.8, overall_risk=0.8,
            routing_path=("TRIAGE", "ROUTER_TOP1", "INJECTION_FAST", "POLICY_PENDING"),
            latency_by_stage_ms={"triage": 1.0, "injection_expert": 2.0}, model_versions={"triage": "triage-v1"},
        )
        decision = PolicyDecision(PolicyAction.RATE_LIMIT, 0.8, "policy-v1", ("overall_risk=0.8",))

        payload = _inspection_payload(request_arguments, result, decision)

        self.assertEqual(payload["simulated_policy"]["action"], PolicyAction.RATE_LIMIT)
        self.assertEqual(payload["total_latency_ms"], 3.0)
        self.assertFalse(payload["ensemble"]["executed"])
        self.assertFalse(payload["deep"]["executed"])
        self.assertEqual(payload["fast_expert_results"][0]["family"], ExpertFamily.INJECTION)
