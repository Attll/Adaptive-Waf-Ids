from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request as HttpRequest
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
        headers = {"X-WAF-Internal-Token": os.environ.get("WAF_INTERNAL_TOKEN", "")}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = Request(self.base_url + path, data=data, method=method, headers=headers)
        with urlopen(request, timeout=10) as response:
            return json.loads(response.read() or b"{}")


def create_app(settings: AdaptationSettings | None = None, client: ControlClient | None = None) -> FastAPI:
    active_settings = settings or AdaptationSettings()
    active_client = client or ControlClient(active_settings.control_service_url)
    app = FastAPI(title="Adaptive WAF-IDS Training Adaptation Service", version="0.1.0")

    from threading import Lock
    rl_lock=Lock()
    @app.post("/internal/v1/tools/rl/train")
    def train_rl(body:dict,request:HttpRequest):
        import hmac
        token=os.environ.get('WAF_INTERNAL_TOKEN','')
        if not token or not hmac.compare_digest(token,request.headers.get('X-WAF-Internal-Token','')):
            raise HTTPException(status_code=401,detail='Service credentials required')
        if len(json.dumps(body))>2000000:raise HTTPException(status_code=413,detail='Offline training input too large')
        if not rl_lock.acquire(blocking=False):raise HTTPException(status_code=409,detail='Offline training already running')
        try:
            from .rl_training import train
            return train(body,active_settings.curated_root.parent/'routing')
        except (ValueError,KeyError,TypeError) as error:raise HTTPException(status_code=422,detail=str(error)) from error
        finally:rl_lock.release()

    @app.post("/internal/v1/tools/rl/validate")
    def validate_rl(request:HttpRequest):
        from .rl_training import controlled_fixture
        return train_rl(controlled_fixture(),request)

    @app.get("/internal/v1/tools/rl/runs")
    def routing_runs(request:HttpRequest):
        import hmac
        token=os.environ.get('WAF_INTERNAL_TOKEN','')
        if not token or not hmac.compare_digest(token,request.headers.get('X-WAF-Internal-Token','')):raise HTTPException(status_code=401,detail='Service credentials required')
        root=active_settings.curated_root.parent/'routing'
        paths=sorted(root.glob('*/report.json'),key=lambda path:path.stat().st_mtime,reverse=True)[:20]
        runs=[]
        for path in paths:
            if path.stat().st_size>20000000:continue
            value=json.loads(path.read_text())
            runs.append({key:value[key] for key in ('run_id','shadow_only','elapsed_seconds','data_origin','review_reference','static_baselines')})
        return {'runs':runs}

    @app.get("/internal/v1/tools/rl/runs/{run_id}")
    def routing_run(run_id:str,request:HttpRequest):
        routing_runs(request)  # enforce the same service authentication
        from uuid import UUID
        try:identifier=str(UUID(run_id))
        except ValueError as error:raise HTTPException(status_code=422,detail='Invalid run ID') from error
        path=active_settings.curated_root.parent/'routing'/identifier/'report.json'
        if not path.is_file():raise HTTPException(status_code=404,detail='Routing run unavailable')
        return json.loads(path.read_text())

    @app.get("/health")
    def health() -> dict[str, str]: return {"status": "ok"}

    @app.post("/v1/adaptation/curate")
    def curate_feedback() -> dict[str, Any]:
        try:
            feedback = active_client.request("GET", "/internal/v1/training/feedback").get("feedback", [])
        except OSError as error:
            raise HTTPException(status_code=503, detail="control service feedback export unavailable") from error
        run_id = f"feedback-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid4()}"
        target = active_settings.curated_root / f"{run_id}.jsonl"
        target.parent.mkdir(parents=True, exist_ok=True)
        valid = {}
        # Export order is not a contract. Preserve the most recent reviewed correction per event.
        for item in sorted(feedback, key=lambda row: row.get("submittedAt") or "", reverse=True):
            if item.get("eventId") and item.get("verdict") in {"CONFIRMED_ATTACK","FALSE_POSITIVE","WRONG_ATTACK_TYPE","BENIGN"}:
                valid.setdefault(item["eventId"], item)
        rows = [{"event_id": item.get("eventId"), "verdict": item.get("verdict"), "correct_attack_type": item.get("correctAttackType"), "method": item.get("method"), "path": item.get("path"), "original_prediction": item.get("predictedAttack"), "submitted_at": item.get("submittedAt")} for item in valid.values()]
        with target.open("x",encoding="utf-8") as destination:
            destination.write("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
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
        try:
            score = population_stability_index(request.reference, request.observed, request.bins)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        return {"psi": score, "classification": "STABLE" if score < .1 else "MONITOR" if score < .25 else "SHADOW_RECOMMENDED", "automatic_policy_change": False}

    return app
