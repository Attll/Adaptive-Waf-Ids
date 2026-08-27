from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import time
import unittest

from fastapi.testclient import TestClient

from adaptive_waf.contracts import AttackClass, DetectionResult, ExpertFamily, ExpertOutput, NetworkContext, RouterOutput, TriageDecision
from adaptive_waf.service.app import ServiceConfig, create_app


class DetectionServiceTests(unittest.TestCase):
    def test_health_ready_models_and_detect_contract(self) -> None:
        pipeline = _FakePipeline()
        with _client(pipeline) as client:
            self.assertEqual(client.get("/health").json(), {"status": "ok"})
            self.assertEqual(client.get("/ready").json(), {"status": "ready"})
            self.assertIn("triage", client.get("/v1/models").json()["models"])

            response = client.post("/v1/detect", json={"path": "/health"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["detection"]["predicted_attack"], "BENIGN")
        self.assertIn("x-request-id", response.headers)
        self.assertIn("service_inference_ms", response.json())

    def test_known_malicious_request_and_optional_context(self) -> None:
        with _client(_FakePipeline()) as client:
            response = client.post("/v1/detect", json={
                "path": "/search", "query": "q=' OR 1=1--",
                "behaviour_context": {"risk": 0.2},
                "network_context": {"risk": 0.8, "network_class": "DOS_DDOS", "confidence": 0.9},
            })

        self.assertEqual(response.status_code, 200)
        body = response.json()["detection"]
        self.assertEqual(body["predicted_attack"], "SQL_INJECTION")
        self.assertEqual(body["risks"]["network"], 0.8)

    def test_invalid_request_has_structured_error(self) -> None:
        with _client(_FakePipeline()) as client:
            response = client.post("/v1/detect", json={"method": "GET"})
            invalid_path = client.post("/v1/detect", json={"path": "health"})

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["error"]["code"], "validation_error")
        self.assertIn("request_id", response.json())
        self.assertEqual(invalid_path.status_code, 422)
        self.assertEqual(invalid_path.json()["error"]["code"], "invalid_detection_input")

    def test_network_contract(self) -> None:
        with _client(_FakePipeline()) as client:
            response = client.post("/v1/network/detect", json={"features": {"duration": 4.0}})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["network_context"]["network_class"], "DOS_DDOS")

    def test_model_loading_failure_keeps_health_live_and_readiness_false(self) -> None:
        with TestClient(create_app(pipeline_loader=_raise_load_error, network_loader=lambda: _FakeNetworkDetector())) as client:
            self.assertEqual(client.get("/health").status_code, 200)
            ready = client.get("/ready")
            detect = client.post("/v1/detect", json={"path": "/health"})

        self.assertEqual(ready.status_code, 503)
        self.assertEqual(detect.status_code, 503)
        self.assertEqual(detect.json()["error"]["code"], "model_unavailable")

    def test_timeout_is_reported(self) -> None:
        with _client(_FakePipeline(delay_seconds=0.01), inference_timeout_ms=1) as client:
            response = client.post("/v1/detect", json={"path": "/health"})

        self.assertEqual(response.status_code, 504)
        self.assertEqual(response.json()["error"]["code"], "inference_timeout")

    def test_concurrent_requests_are_serialized_safely(self) -> None:
        pipeline = _FakePipeline(delay_seconds=0.01)
        with _client(pipeline) as client:
            with ThreadPoolExecutor(max_workers=4) as executor:
                responses = list(executor.map(lambda _: client.post("/v1/detect", json={"path": "/health"}), range(4)))

        self.assertTrue(all(response.status_code == 200 for response in responses))
        self.assertEqual(pipeline.maximum_concurrent_calls, 1)


def _client(pipeline: "_FakePipeline", inference_timeout_ms: int = 1000) -> TestClient:
    return TestClient(create_app(
        ServiceConfig(inference_timeout_ms=inference_timeout_ms, network_inference_timeout_ms=1000),
        pipeline_loader=lambda: pipeline,
        network_loader=lambda: _FakeNetworkDetector(),
    ))


def _raise_load_error():
    raise FileNotFoundError("missing model")


class _FakePipeline:
    model_versions = {"triage": "fake-triage-v1", "router": "fake-router-v1"}

    def __init__(self, delay_seconds: float = 0.0) -> None:
        self._delay_seconds = delay_seconds
        self._active_calls = 0
        self.maximum_concurrent_calls = 0

    def detect(self, request, behaviour_context, network_context, rule_evidence):
        self._active_calls += 1
        self.maximum_concurrent_calls = max(self.maximum_concurrent_calls, self._active_calls)
        try:
            if self._delay_seconds:
                time.sleep(self._delay_seconds)
            malicious = request.path == "/search"
            attack = AttackClass.SQL_INJECTION if malicious else AttackClass.BENIGN
            risk = 0.99 if malicious else 0.01
            router = RouterOutput({ExpertFamily.INJECTION: 0.98, ExpertFamily.EXECUTION: 0.02}, (ExpertFamily.INJECTION,), "fake-router-v1")
            expert = ExpertOutput(ExpertFamily.INJECTION, attack, 0.99, risk, "fake-injection-v1")
            return DetectionResult(
                request_id=request.request_id,
                timestamp=datetime.now(timezone.utc),
                triage_score=risk,
                triage_decision=TriageDecision.SUSPICIOUS,
                router_output=router,
                expert_outputs=(expert,),
                predicted_attack=attack,
                http_risk=risk,
                behaviour_risk=behaviour_context.risk if behaviour_context else 0.0,
                network_risk=network_context.risk if network_context else 0.0,
                overall_risk=max(risk, network_context.risk if network_context else 0.0),
                routing_path=("TRIAGE", "ROUTER_TOP1", "INJECTION_FAST", "POLICY_PENDING"),
                latency_by_stage_ms={"triage": 1.0, "injection_expert": 1.0},
                model_versions=self.model_versions,
            )
        finally:
            self._active_calls -= 1


class _FakeNetworkDetector:
    model_version = "fake-network-v1"

    def detect(self, features):
        return NetworkContext(risk=0.9, network_class="DOS_DDOS", confidence=0.9)
