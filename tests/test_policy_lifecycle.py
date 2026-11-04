from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from adaptive_waf.adaptation.lifecycle import PolicyLifecycle, PolicyCandidate
from adaptive_waf.adaptation.drift import population_stability_index


class PolicyLifecycleTests(unittest.TestCase):
    def test_audit_failure_after_ack_restores_baseline(self):
        with tempfile.TemporaryDirectory() as path:
            calls=[]
            manager=PolicyLifecycle(path,lambda candidate:calls.append(candidate) or True,"baseline",live_enabled=True)
            metrics={"attack_recall":1.,"benign_fpr":0.,"p95_ms":10,"queue_depth":0,"verified_attack_count":100,"verified_benign_count":100}
            manager.register(PolicyCandidate("v1","both",metrics,"verified-fixture",shadow_only=False))
            audit=manager._audit
            def failing_audit(action,*args,**kwargs):
                if action=="ACTIVATED": raise OSError("injected audit storage failure")
                audit(action,*args,**kwargs)
            with patch.object(manager,"_audit",side_effect=failing_audit),self.assertRaises(OSError):
                manager.promote("v1","fixture")
            self.assertEqual(manager.active,"baseline")
            self.assertEqual(calls[-1],"baseline")

    def test_failed_runtime_acknowledgement_restores_baseline_and_records_failure(self):
        with tempfile.TemporaryDirectory() as path:
            calls=[]
            manager=PolicyLifecycle(path,lambda candidate:calls.append(candidate) or candidate=="baseline","baseline",live_enabled=True)
            metrics={"attack_recall":1.,"benign_fpr":0.,"p95_ms":10,"queue_depth":0,"verified_attack_count":100,"verified_benign_count":100}
            manager.register(PolicyCandidate("v1","both",metrics,"verified-fixture",shadow_only=False))
            with self.assertRaises(RuntimeError):
                manager.promote("v1","fixture-approval")
            self.assertEqual(manager.active,"baseline")
            self.assertEqual(calls[-1],"baseline")
            self.assertEqual(manager.snapshot()["events"][-1]["action"],"ACTIVATION_FAILED")

    def test_default_shadow_cannot_promote_and_duplicate_versions_rejected(self):
        with tempfile.TemporaryDirectory() as path:
            manager = PolicyLifecycle(path,lambda candidate: True,"baseline")
            candidate = PolicyCandidate("v1","both",{},"verified-run")
            self.assertEqual(manager.register(candidate),"SHADOW")
            with self.assertRaises(PermissionError):
                manager.promote("v1","operator-ref")
            with self.assertRaises(ValueError):
                manager.register(candidate)

    def test_simulated_runtime_activation_and_operational_rollback(self):
        with tempfile.TemporaryDirectory() as path:
            activated=[]
            manager=PolicyLifecycle(path,lambda candidate: activated.append(candidate) or True,"baseline",live_enabled=True)
            metrics={"attack_recall":1.,"benign_fpr":0.,"p95_ms":10,"queue_depth":0,"verified_attack_count":200,"verified_benign_count":200}
            manager.register(PolicyCandidate("v1","both",metrics,"verified-run",shadow_only=False))
            manager.promote("v1","operator-approval")
            self.assertEqual(manager.monitor({"observations":20,"inference_error_rate":.2}),"ROLLED_BACK")
            self.assertEqual(manager.active,"baseline")
            self.assertEqual(len(list(Path(path).glob("*.json"))),3)

    def test_degenerate_drift_returns_finite_serializable_score(self):
        import math
        self.assertTrue(math.isfinite(population_stability_index([0]*10,[1]*10)))
