from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from adaptive_waf.contracts import NetworkContext
from adaptive_waf.network_sensor.core import NetworkSensor
from adaptive_waf.network_sensor.flows import FlowAccumulator, PacketObservation
from adaptive_waf.network_sensor.service import SensorSettings, create_app


class NetworkSensorTests(unittest.TestCase):
    def test_sensor_classifies_and_persists_scoped_evidence(self) -> None:
        store = _Store()
        sensor = NetworkSensor(_Detector(), store, ttl_seconds=90)

        evidence = sensor.process("203.0.113.10", "198.51.100.20", {"duration": 2.0})

        self.assertEqual(evidence.network_class, "DOS_DDOS")
        self.assertEqual(store.source_ip, "203.0.113.10")
        self.assertEqual(store.ttl_seconds, 90)
        self.assertEqual(store.evidence.network_risk, 0.9)

    def test_flow_accumulator_uses_exact_deployment_feature_schema(self) -> None:
        flow = FlowAccumulator.from_packet(PacketObservation("203.0.113.10", "198.51.100.20", 50100, 443, 6, 1.0, 60, frozenset({"S"}), 8192))
        flow.add(PacketObservation("198.51.100.20", "203.0.113.10", 443, 50100, 6, 1.2, 100, frozenset({"A"}), 4096))
        features = flow.features()

        self.assertEqual(len(features), 38)
        self.assertEqual(features["Dst Port"], 443.0)
        self.assertEqual(features["Tot Fwd Pkts"], 1.0)
        self.assertEqual(features["Tot Bwd Pkts"], 1.0)
        self.assertEqual(features["SYN Flag Cnt"], 1.0)

    def test_service_exposes_recent_live_evidence(self) -> None:
        store = _Store()
        app = create_app(SensorSettings(), detector=_Detector(), store=store)
        with TestClient(app) as client:
            response = client.post("/v1/flows", json={"source_ip": "203.0.113.10", "features": {"duration": 2.0}})
            recent = client.get("/v1/network/recent")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(recent.json()["events"][0]["network_class"], "DOS_DDOS")


class _Detector:
    model_version = "network-test-v1"

    def detect(self, features):
        return NetworkContext(risk=0.9, network_class="DOS_DDOS", confidence=0.8)


class _Store:
    source_ip = None
    evidence = None
    ttl_seconds = None

    def put(self, source_ip, evidence, ttl_seconds):
        self.source_ip = source_ip
        self.evidence = evidence
        self.ttl_seconds = ttl_seconds

    def ping(self):
        return True
