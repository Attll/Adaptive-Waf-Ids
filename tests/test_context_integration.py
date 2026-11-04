import unittest
from unittest.mock import patch
import tempfile
from adaptive_waf.contracts import HttpRequestRecord, DeepOutput, AttackClass
from uuid import uuid4
from adaptive_waf.runtime.context import ContextPipeline
from adaptive_waf.runtime.context import ROUTING_CONTEXT
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from threading import Event,Lock
from adaptive_waf.runtime.session_risk import private_session_key
from test_detection_service import _FakePipeline, _client


class ContextIntegrationTests(unittest.TestCase):
    def test_parallel_candidate_capacity_does_not_stall_active_inference(self):
        from adaptive_waf.adaptation.lifecycle import PolicyCandidate
        ready,release=Event(),Event()
        lock=Lock()
        started=[]
        def load(**kwargs):
            with lock:
                started.append(1)
                if len(started)==20: ready.set()
            release.wait(5)
            return _FakePipeline()
        with tempfile.TemporaryDirectory() as root,patch.dict("os.environ",{"WAF_POLICY_AUDIT_ROOT":root}),patch("adaptive_waf.runtime.artifacts.load_adaptive_pipeline",side_effect=load):
            with _client(_FakePipeline()) as client,ThreadPoolExecutor(max_workers=20) as pool:
                store=client.app.state.runtime_store
                pending=[pool.submit(store.prepare_policy,PolicyCandidate(f"v{i}","both",{},"fixture")) for i in range(20)]
                try:
                    self.assertTrue(ready.wait(2))
                    with self.assertRaises(ValueError):
                        store.prepare_policy(PolicyCandidate("overflow","both",{},"fixture"))
                    self.assertEqual(client.post("/v1/detect",json={"path":"/health"}).status_code,200)
                finally:
                    release.set()
                self.assertTrue(all(item.result(3)["status"]=="SHADOW" for item in pending))

    def test_shadow_router_receives_runtime_load_queue_and_remaining_deadline(self):
        class Pipeline(_FakePipeline):
            model_versions={**_FakePipeline.model_versions,"strategy":"bandit_shadow-v1"}
            def detect(self,*arguments):
                return replace(super().detect(*arguments),decision_context={"observed":dict(ROUTING_CONTEXT.get())})
        with _client(ContextPipeline(Pipeline(),"shadow")) as client:
            response=client.post("/v1/detect",json={"path":"/health"})
            self.assertEqual(response.status_code,200,response.text)
            observed=response.json()["detection"]["decision"]["observed"]
            self.assertEqual(observed["load"],1.)
            self.assertGreater(observed["deadline_fraction"],0)
            self.assertLessEqual(observed["deadline_fraction"],1)
            self.assertIn("queue_fraction",observed)
            self.assertIn("session_risk",observed)

    def test_internal_verified_context_and_monitoring_workflows(self):
        with patch.dict("os.environ",{"WAF_INTERNAL_TOKEN":"fixture-token"}):
            pipeline=ContextPipeline(_FakePipeline(),"shadow")
            with _client(pipeline) as client:
                headers={"X-WAF-Internal-Token":"fixture-token"}
                identifier=str(uuid4())
                client.post("/v1/detect",json={"path":"/health","request_id":identifier})
                response=client.post("/internal/v1/research/feedback",headers=headers,
                    json={"request_id":identifier,"verified_label":"BENIGN","review_reference":"fixture-review"})
                self.assertEqual(response.status_code,200,response.text)
                self.assertEqual(response.json()["verified_labels"],1)
                response=client.post("/internal/v1/research/context/profiles",headers=headers,
                    json={"request":{"path":"/health"},"observation_id":str(uuid4()),"review_reference":"fixture-review"})
                self.assertEqual(response.status_code,200,response.text)
                self.assertEqual(response.json()["verified_profile_observations"],1)
                response=client.post("/internal/v1/research/context/corrections",headers=headers,
                    json={"session_key":"a"*64,"request_id":identifier,"evidence_id":str(uuid4()),"verified_risk":0,"review_reference":"fixture-review"})
                self.assertEqual(response.status_code,200,response.text)
                self.assertEqual(client.get("/v1/research/telemetry").json()["context"]["revisions_retained"],1)

    def test_simulated_future_containment_and_benign_deep_correction(self):
        class Pipeline(_FakePipeline):
            def adjudicate(self, request):
                return DeepOutput(AttackClass.BENIGN,.99,0.,"fake-deep"),1
        pipeline = ContextPipeline(Pipeline(),"simulation")
        key = private_session_key("a"*32,"separate-session")
        original_request = HttpRequestRecord("GET","/search",session_key=key)
        original = pipeline.detect(original_request)
        future = pipeline.detect(HttpRequestRecord("GET","/health",session_key=key))
        self.assertGreater(future.overall_risk,.98)
        self.assertEqual(original.predicted_attack,AttackClass.SQL_INJECTION)
        pipeline.adjudicate(original_request)
        corrected = pipeline.detect(HttpRequestRecord("GET","/health",session_key=key))
        self.assertLess(corrected.overall_risk,.1)
        self.assertEqual(original.predicted_attack,AttackClass.SQL_INJECTION)
        unrelated = pipeline.detect(HttpRequestRecord("GET","/health",session_key=private_session_key("a"*32,"other")))
        self.assertEqual(unrelated.decision_context["session_risk_before"],0)

    def test_telemetry_and_internal_authentication_are_real_api_contracts(self):
        with _client(_FakePipeline()) as client:
            self.assertEqual(client.post("/v1/detect",json={"path":"/health"}).status_code,200)
            telemetry = client.get("/v1/research/telemetry")
            self.assertEqual(telemetry.status_code,200)
            self.assertEqual(telemetry.json()["coverage_since_start"]["FULLY_INSPECTED"],1)
            self.assertEqual(client.post("/internal/v1/research/policies",json={}).status_code,401)

    def test_authenticated_shadow_preparation_never_switches_active_runtime(self):
        with tempfile.TemporaryDirectory() as root, patch.dict("os.environ",{
            "WAF_INTERNAL_TOKEN":"fixture-internal-token", "WAF_POLICY_AUDIT_ROOT":root,
            "WAF_LIVE_ACTIVATION_ENABLED":"false"}), patch("adaptive_waf.runtime.artifacts.load_adaptive_pipeline",return_value=_FakePipeline()):
            with _client(_FakePipeline()) as client:
                headers={"X-WAF-Internal-Token":"fixture-internal-token"}
                candidate={"version":"candidate-v1","strategy":"both","metrics":{},"verification_reference":"fixture-only"}
                response=client.post("/internal/v1/research/policies",headers=headers,json=candidate)
                self.assertEqual(response.status_code,200,response.text)
                self.assertEqual(response.json()["status"],"SHADOW")
                self.assertFalse(response.json()["activation_enabled"])
                self.assertEqual(client.post("/internal/v1/research/policies/candidate-v1/promote",headers=headers,
                    json={"operator_approval_reference":"fixture"}).status_code,403)
                self.assertNotIn("policy",client.get("/v1/models").json()["models"])
