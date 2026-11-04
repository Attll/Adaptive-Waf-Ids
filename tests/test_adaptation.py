from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from adaptive_waf.adaptation.drift import population_stability_index
from adaptive_waf.adaptation.service import AdaptationSettings, create_app


class AdaptationTests(unittest.TestCase):
    def test_curation_preserves_latest_correction_and_never_overwrites_exports(self):
        class Client(_Client):
            def request(self, *args):
                return {"feedback": [
                    {"eventId":"same", "verdict":"FALSE_POSITIVE", "submittedAt":"2026-10-02T00:00:00Z"},
                    {"eventId":"same", "verdict":"CONFIRMED_ATTACK", "submittedAt":"2026-10-01T00:00:00Z"}]}
        with tempfile.TemporaryDirectory() as directory:
            with TestClient(create_app(AdaptationSettings(curated_root=Path(directory)), Client())) as client:
                first = client.post("/v1/adaptation/curate").json()
                second = client.post("/v1/adaptation/curate").json()
            self.assertNotEqual(first["path"], second["path"])
            self.assertIn("FALSE_POSITIVE", Path(first["path"]).read_text())
            self.assertNotIn("CONFIRMED_ATTACK", Path(first["path"]).read_text())

    def test_psi_distinguishes_stable_and_shifted_distributions(self) -> None:
        reference = [float(value) for value in range(100)]
        self.assertAlmostEqual(population_stability_index(reference, reference), 0.0)
        self.assertGreater(population_stability_index(reference, [99.0] * 100), 0.25)

    def test_curation_exports_only_sanitized_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = create_app(AdaptationSettings(curated_root=Path(directory)), _Client())
            with TestClient(app) as client:
                response = client.post("/v1/adaptation/curate")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["records"], 1)
            contents = next(Path(directory).glob("*.jsonl")).read_text(encoding="utf-8")
            self.assertIn("CONFIRMED_ATTACK", contents)
            self.assertNotIn("password", contents.lower())

    def test_run_registration_stays_challenger_and_never_auto_promotes(self) -> None:
        client = _Client()
        app = create_app(client=client)
        with TestClient(app) as test_client:
            response = test_client.post("/v1/adaptation/runs", json={"model_name": "triage", "dataset_version": "feedback-v1", "artifact_version": "candidate-v1", "artifact_uri": "artifacts/candidate", "metrics": {"macro_f1": .91}, "baseline_metrics": {"macro_f1": .9}})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "CHALLENGER")
        self.assertFalse(response.json()["automatic_promotion"])
        self.assertFalse(any("promote" in path for _, path, _ in client.calls))


class _Client:
    def __init__(self) -> None: self.calls = []
    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if path.endswith("/feedback"):
            return {"feedback": [{"eventId": "evt-1", "verdict": "CONFIRMED_ATTACK", "correctAttackType": "SQL_INJECTION", "method": "GET", "path": "/search", "predictedAttack": "SQL_INJECTION", "submittedAt": "2026-01-01T00:00:00Z"}]}
        if path.endswith("/candidates"):
            return {"modelVersionId": "00000000-0000-0000-0000-000000000099"}
        return {}
