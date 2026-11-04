import unittest
from dataclasses import replace
from uuid import uuid4
from adaptive_waf.adaptation.monitoring import EvidenceMonitor
from adaptive_waf.contracts import HttpRequestRecord
from test_detection_service import _FakePipeline


class ResearchMonitoringTests(unittest.TestCase):
    def test_drift_requires_reviewed_reference_and_calibration_requires_verified_feedback(self):
        monitor=EvidenceMonitor()
        result=_FakePipeline().detect(HttpRequestRecord("GET","/health"),None,None,None)
        for index in range(20):
            monitor.record(replace(result,request_id=uuid4()))
        self.assertIsNone(monitor.snapshot()["risk_psi"])
        self.assertIsNone(monitor.snapshot()["verified_ece"])
        monitor.set_reference([.5]*20,"reviewed-fixture")
        self.assertIsNotNone(monitor.snapshot()["risk_psi"])
        identifier=next(iter(monitor.rows))
        with self.assertRaises(ValueError):
            monitor.feedback(identifier,"MODEL_BENIGN","")
        monitor.feedback(identifier,"BENIGN","verified-fixture")
        self.assertEqual(monitor.snapshot()["verified_labels"],1)
        self.assertIsNotNone(monitor.snapshot()["verified_ece"])
        self.assertFalse(monitor.snapshot()["automatic_policy_change"])

    def test_eviction_and_duplicate_observations_are_bounded(self):
        monitor=EvidenceMonitor(capacity=2)
        result=_FakePipeline().detect(HttpRequestRecord("GET","/health"),None,None,None)
        monitor.record(result)
        monitor.record(result)
        self.assertEqual(monitor.snapshot()["retained"],1)
        for _ in range(3):
            monitor.record(replace(result,request_id=uuid4()))
        self.assertEqual(monitor.snapshot()["retained"],2)
        with self.assertRaises(ValueError):
            monitor.feedback(str(result.request_id),"BENIGN","reviewed")

