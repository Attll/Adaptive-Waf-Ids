from datetime import datetime, timezone
import unittest

from adaptive_waf.contracts import (
    AttackClass,
    BehaviourContext,
    DetectionResult,
    ExpertFamily,
    ExpertOutput,
    HttpRequestRecord,
    RouterOutput,
    TriageDecision,
)


class ContractTests(unittest.TestCase):
    def test_request_requires_absolute_path(self) -> None:
        with self.assertRaises(ValueError):
            HttpRequestRecord(method="GET", path="users")

    def test_context_rejects_invalid_risk(self) -> None:
        with self.assertRaises(ValueError):
            BehaviourContext(risk=1.01)

    def test_detection_result_preserves_normalized_evidence(self) -> None:
        request = HttpRequestRecord(method="GET", path="/health")
        router = RouterOutput(
            scores={ExpertFamily.INJECTION: 0.9, ExpertFamily.EXECUTION: 0.1},
            selected_experts=(ExpertFamily.INJECTION,),
            model_version="router-test-v1",
        )
        expert = ExpertOutput(
            family=ExpertFamily.INJECTION,
            predicted_attack=AttackClass.BENIGN,
            confidence=0.97,
            risk=0.03,
            model_version="injection-test-v1",
        )

        result = DetectionResult(
            request_id=request.request_id,
            timestamp=datetime.now(timezone.utc),
            triage_score=0.02,
            triage_decision=TriageDecision.BENIGN_LIKE,
            router_output=router,
            expert_outputs=(expert,),
            predicted_attack=AttackClass.BENIGN,
            http_risk=0.03,
            behaviour_risk=0.0,
            network_risk=0.0,
            overall_risk=0.03,
            routing_path=("TRIAGE", "INJECTION_FAST"),
            latency_by_stage_ms={"triage": 0.4},
            model_versions={"router": "router-test-v1"},
        )

        self.assertEqual(result.request_id, request.request_id)
        self.assertEqual(result.expert_outputs[0].predicted_attack, AttackClass.BENIGN)


if __name__ == "__main__":
    unittest.main()
