from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .drift import population_stability_index


class AdaptationSettings(BaseModel):
    control_service_url: str = "http://127.0.0.1:8082"
    curated_root: Path = Path("artifacts/adaptation/curated")


class RunRequest(BaseModel):
    model_name: str
    dataset_version: str
    artifact_version: str
    artifact_uri: str
    metrics: dict[str, float]
    baseline_metrics: dict[str, float] = Field(default_factory=dict)
    shadow_mode: bool = True


class DriftRequest(BaseModel):
    reference: list[float]
    observed: list[float]
    bins: int = 10


class ControlClient:
    def __init__(self, base_url: str) -> None: self.base_url = base_url.rstrip("/")
    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        data = json.dumps(body).encode() if body is not None else None
        request = Request(self.base_url + path, data=data, method=method, headers={"Content-Type": "application/json"} if data else {})
        with urlopen(request, timeout=10) as response:
            return json.loads(response.read() or b"{}")


def create_app(settings: AdaptationSettings | None = None, client: ControlClient | None = None) -> FastAPI:
    active_settings = settings or AdaptationSettings()
    active_client = client or ControlClient(active_settings.control_service_url)
    app = FastAPI(title="Adaptive WAF Training Adaptation Service", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, str]: return {"status": "ok"}

    @app.post("/v1/adaptation/curate")
    def curate_feedback() -> dict[str, Any]:
        try:
            feedback = active_client.request("GET", "/internal/v1/training/feedback").get("feedback", [])
        except OSError as error:
            raise HTTPException(status_code=503, detail="control service feedback export unavailable") from error
        run_id = f"feedback-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        target = active_settings.curated_root / f"{run_id}.jsonl"
        target.parent.mkdir(parents=True, exist_ok=True)
        rows = [{"event_id": item.get("eventId"), "verdict": item.get("verdict"), "correct_attack_type": item.get("correctAttackType"), "method": item.get("method"), "path": item.get("path"), "original_prediction": item.get("predictedAttack"), "submitted_at": item.get("submittedAt")} for item in feedback]
        target.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
        return {"curation_id": run_id, "records": len(rows), "path": str(target), "storage": "sanitized_metadata_only"}

    @app.post("/v1/adaptation/runs")
    def register_run(request: RunRequest) -> dict[str, Any]:
        run_id = f"run-{uuid4()}"
        comparison = {name: request.metrics.get(name, 0.0) - request.baseline_metrics.get(name, 0.0) for name in request.metrics}
        try:
            active_client.request("POST", "/internal/v1/training/runs", {"externalRunId": run_id, "modelName": request.model_name, "datasetVersion": request.dataset_version, "shadowMode": request.shadow_mode, "artifactUri": request.artifact_uri})
            candidate = active_client.request("POST", "/internal/v1/training/candidates", {"trainingRunId": run_id, "modelName": request.model_name, "artifactVersion": request.artifact_version, "metricsJson": json.dumps(request.metrics, sort_keys=True)})
            active_client.request("POST", f"/internal/v1/training/candidates/{candidate['modelVersionId']}/evaluate", {"metricsJson": json.dumps(request.metrics, sort_keys=True), "comparisonJson": json.dumps(comparison, sort_keys=True), "shadowMode": request.shadow_mode})
            active_client.request("PUT", f"/internal/v1/training/runs/{run_id}", {"status": "CHALLENGER", "metricsJson": json.dumps(request.metrics, sort_keys=True), "driftJson": "{}"})
        except OSError as error:
            raise HTTPException(status_code=503, detail="control service lifecycle API unavailable") from error
        return {"run_id": run_id, "candidate_model_version_id": candidate["modelVersionId"], "status": "CHALLENGER", "comparison": comparison, "shadow_mode": request.shadow_mode, "automatic_promotion": False}

    @app.post("/v1/adaptation/drift")
    def drift(request: DriftRequest) -> dict[str, Any]:
        score = population_stability_index(request.reference, request.observed, request.bins)
        return {"psi": score, "classification": "STABLE" if score < .1 else "MONITOR" if score < .25 else "SHADOW_RECOMMENDED", "automatic_policy_change": False}

    return app
