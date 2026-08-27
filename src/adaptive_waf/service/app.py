from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import partial
import os
from pathlib import Path
import tomllib
from typing import Any
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from adaptive_waf.config import load_settings
from adaptive_waf.contracts import BehaviourContext, HttpRequestRecord, NetworkContext
from adaptive_waf.runtime.artifacts import load_adaptive_pipeline, load_offline_network_detector, load_pipeline_settings
from adaptive_waf.service.catalog import build_catalog
from adaptive_waf.service.corpus import CorpusLibrary
from adaptive_waf.service.escalation import ControlPlaneReporter, DisabledEscalationWorker, EscalationWorker
from adaptive_waf.service.runtime import InferenceTimeoutError, ModelUnavailableError, RuntimeStore


@dataclass(frozen=True, slots=True)
class ServiceConfig:
    inference_timeout_ms: int = 30_000
    network_inference_timeout_ms: int = 5_000

    def __post_init__(self) -> None:
        if self.inference_timeout_ms <= 0 or self.network_inference_timeout_ms <= 0:
            raise ValueError("service timeouts must be positive")


class BehaviourPayload(BaseModel):
    risk: float = 0.0
    requests_per_short_window: int = 0
    requests_per_medium_window: int = 0
    failed_auth_attempts: int = 0
    previous_attack_count: int = 0


class NetworkPayload(BaseModel):
    risk: float = 0.0
    network_class: str | None = None
    confidence: float | None = None


class DetectPayload(BaseModel):
    method: str = "GET"
    path: str
    query: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    source_ip: str | None = None
    request_id: UUID | None = None
    behaviour_context: BehaviourPayload | None = None
    network_context: NetworkPayload | None = None
    rule_evidence: dict[str, float] = Field(default_factory=dict)


class NetworkDetectPayload(BaseModel):
    features: dict[str, float]


class BatchDetectPayload(BaseModel):
    """A labelled set of probe requests evaluated against the live pipeline in one call."""

    requests: list[DetectPayload] = Field(default_factory=list, max_length=100)
    labels: list[str] = Field(default_factory=list)


def create_app(
    config: ServiceConfig | None = None,
    pipeline_loader=load_adaptive_pipeline,
    network_loader=load_offline_network_detector,
    escalation_worker=None,
) -> FastAPI:
    service_config = config or load_service_config()
    worker = escalation_worker if escalation_worker is not None else _default_escalation_worker()
    if pipeline_loader is load_adaptive_pipeline:
        pipeline_loader = partial(load_adaptive_pipeline, deep_scheduler=worker.submit)
    store = RuntimeStore(pipeline_loader, network_loader, service_config.inference_timeout_ms, service_config.network_inference_timeout_ms, worker)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        store.start()
        yield

    application = FastAPI(title="Adaptive WAF Detection Service", version="0.1.0", lifespan=lifespan)
    application.state.runtime_store = store
    application.state.corpus = CorpusLibrary()

    @application.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request.state.request_id = _request_id_from_header(request.headers.get("x-request-id"))
        response = await call_next(request)
        response.headers["x-request-id"] = str(request.state.request_id)
        return response

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, error: RequestValidationError):
        return _error_response(request, 422, "validation_error", "request validation failed", error.errors())

    @application.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/ready")
    def ready(request: Request):
        runtime: RuntimeStore = request.app.state.runtime_store
        if not runtime.ready:
            return _error_response(request, 503, "model_unavailable", runtime.load_error or "models are not ready")
        return {"status": "ready"}

    @application.get("/v1/models")
    def models(request: Request):
        try:
            return {"models": request.app.state.runtime_store.model_versions()}
        except ModelUnavailableError as error:
            return _error_response(request, 503, "model_unavailable", str(error))

    @application.post("/v1/detect")
    def detect(payload: DetectPayload, request: Request):
        try:
            record = HttpRequestRecord(
                method=payload.method,
                path=payload.path,
                query=payload.query,
                headers=payload.headers,
                cookies=payload.cookies,
                body=payload.body,
                source_ip=payload.source_ip,
                request_id=payload.request_id or request.state.request_id,
            )
            result, timing = request.app.state.runtime_store.detect(
                record,
                _behaviour_context(payload.behaviour_context),
                _network_context(payload.network_context),
                payload.rule_evidence,
            )
        except ModelUnavailableError as error:
            return _error_response(request, 503, "model_unavailable", str(error))
        except InferenceTimeoutError as error:
            return _error_response(request, 504, "inference_timeout", str(error))
        except ValueError as error:
            return _error_response(request, 422, "invalid_detection_input", str(error))
        return {"detection": _detection_payload(result), "service_inference_ms": timing.elapsed_ms}

    @application.post("/v1/detect/batch")
    def detect_batch(payload: BatchDetectPayload, request: Request):
        if not payload.requests:
            return _error_response(request, 422, "empty_batch", "at least one request is required")
        results: list[dict[str, Any]] = []
        for index, entry in enumerate(payload.requests):
            label = payload.labels[index] if index < len(payload.labels) else None
            try:
                record = HttpRequestRecord(
                    method=entry.method,
                    path=entry.path,
                    query=entry.query,
                    headers=entry.headers,
                    cookies=entry.cookies,
                    body=entry.body,
                    source_ip=entry.source_ip,
                    request_id=entry.request_id or uuid4(),
                )
                result, timing = request.app.state.runtime_store.detect(
                    record,
                    _behaviour_context(entry.behaviour_context),
                    _network_context(entry.network_context),
                    entry.rule_evidence,
                )
            except ModelUnavailableError as error:
                return _error_response(request, 503, "model_unavailable", str(error))
            except (InferenceTimeoutError, ValueError) as error:
                results.append({
                    "index": index,
                    "expected": label,
                    "request": {"method": entry.method, "path": entry.path, "query": entry.query},
                    "error": str(error),
                })
                continue
            detection = _detection_payload(result)
            results.append({
                "index": index,
                "expected": label,
                "request": {"method": entry.method, "path": entry.path, "query": entry.query, "body": entry.body},
                "detection": detection,
                "service_inference_ms": timing.elapsed_ms,
                "matched": None if label is None else label.upper() == str(detection["predicted_attack"]).upper(),
            })
        return {"results": results, "summary": _batch_summary(results)}

    @application.get("/v1/models/catalog")
    def models_catalog(request: Request):
        try:
            catalog = build_catalog()
        except (OSError, KeyError, ValueError) as error:
            return _error_response(request, 503, "catalog_unavailable", f"model catalog could not be read: {error}")
        try:
            catalog["runtime"] = request.app.state.runtime_store.model_versions()
        except ModelUnavailableError:
            catalog["runtime"] = {}
        return catalog

    @application.get("/v1/corpus")
    def corpus_summary(request: Request):
        """What labelled traffic is available to replay, and how much of each class."""
        return request.app.state.corpus.available()

    @application.get("/v1/corpus/{kind}")
    def corpus_sample(kind: str, request: Request, count: int = 20, labels: str | None = None, seed: int | None = None):
        """Randomised sample of real dataset records, optionally restricted to particular classes."""
        library = request.app.state.corpus
        if kind not in {"http", "network"}:
            return _error_response(request, 404, "unknown_corpus", f"no corpus named {kind}")
        corpus = library.http() if kind == "http" else library.network()
        if not corpus.records:
            return _error_response(request, 503, "corpus_unavailable",
                                   f"{corpus.source} is not present; run scripts/build_probe_corpus.py")
        selection = [label.strip() for label in labels.split(",") if label.strip()] if labels else None
        samples = corpus.sample(max(1, min(count, 500)), selection, seed)
        return {"kind": kind, "source": corpus.source, "requested": count, "returned": len(samples),
                "labels": corpus.labels, "samples": samples}

    @application.get("/v1/escalations")
    def escalations(request: Request, limit: int = 50):
        """Deferred deep adjudications: what the fast experts said, and what the deep model concluded afterwards."""
        worker = request.app.state.runtime_store.escalations
        return {"escalations": worker.recent(limit), "statistics": worker.statistics()}

    @application.get("/v1/escalations/statistics")
    def escalation_statistics(request: Request):
        return request.app.state.runtime_store.escalations.statistics()

    @application.post("/v1/network/detect")
    def detect_network(payload: NetworkDetectPayload, request: Request):
        try:
            context, timing = request.app.state.runtime_store.detect_network(payload.features)
        except ModelUnavailableError as error:
            return _error_response(request, 503, "model_unavailable", str(error))
        except InferenceTimeoutError as error:
            return _error_response(request, 504, "inference_timeout", str(error))
        except ValueError as error:
            return _error_response(request, 422, "invalid_network_input", str(error))
        return {
            "request_id": str(request.state.request_id),
            "network_context": {"risk": context.risk, "network_class": context.network_class, "confidence": context.confidence},
            "model_version": request.app.state.runtime_store.model_versions()["network"],
            "service_inference_ms": timing.elapsed_ms,
        }

    return application


def _default_escalation_worker():
    """Builds the background adjudicator from configuration, or a disabled stand-in when escalation stays inline."""
    try:
        settings = load_pipeline_settings()
    except (OSError, KeyError, ValueError):
        return DisabledEscalationWorker()
    if not settings["asynchronous_deep_escalation_enabled"]:
        return DisabledEscalationWorker()
    control_url = os.environ.get("CONTROL_SERVICE_URL")
    return EscalationWorker(
        workers=settings["deep_escalation_workers"],
        queue_limit=settings["deep_escalation_queue_limit"],
        reporter=ControlPlaneReporter(control_url) if control_url else None,
    )


def load_service_config(core_config: Path | None = None) -> ServiceConfig:
    settings = load_settings(core_config)
    with (settings.paths.project_root / "configs/service.toml").open("rb") as source:
        config = tomllib.load(source)
    return ServiceConfig(int(config["inference_timeout_ms"]), int(config["network_inference_timeout_ms"]))


def _request_id_from_header(value: str | None) -> UUID:
    try:
        return UUID(value) if value else uuid4()
    except ValueError:
        return uuid4()


def _behaviour_context(payload: BehaviourPayload | None) -> BehaviourContext | None:
    return BehaviourContext(**payload.model_dump()) if payload else None


def _network_context(payload: NetworkPayload | None) -> NetworkContext | None:
    return NetworkContext(**payload.model_dump()) if payload else None


def _detection_payload(result) -> dict[str, Any]:
    return {
        "request_id": str(result.request_id),
        "timestamp": result.timestamp.isoformat(),
        "triage": {"decision": result.triage_decision, "suspicious_probability": result.triage_score},
        "router": None if result.router_output is None else {"scores": result.router_output.scores, "selected_experts": result.router_output.selected_experts},
        "expert_outputs": [_expert_payload(output) for output in result.expert_outputs],
        "deep_output": None if result.deep_output is None else _expert_payload(result.deep_output),
        "ensemble_used": result.ensemble_used,
        "deep_model_used": result.deep_model_used,
        "predicted_attack": result.predicted_attack,
        "risks": {"http": result.http_risk, "behaviour": result.behaviour_risk, "network": result.network_risk, "overall": result.overall_risk},
        "routing_path": result.routing_path,
        "latency_by_stage_ms": result.latency_by_stage_ms,
        "total_latency_ms": sum(result.latency_by_stage_ms.values()),
        "model_versions": result.model_versions,
        "explanation_evidence": result.explanation_evidence,
        "deep_escalation_pending": result.deep_escalation_pending,
        "deep_escalation_id": result.deep_escalation_id,
    }


def _batch_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    evaluated = [entry for entry in results if "detection" in entry]
    scored = [entry for entry in evaluated if entry.get("matched") is not None]
    latencies = sorted(entry["detection"]["total_latency_ms"] for entry in evaluated)
    risks = [entry["detection"]["risks"]["overall"] for entry in evaluated]
    routes: dict[str, int] = {}
    attacks: dict[str, int] = {}
    for entry in evaluated:
        route = " > ".join(entry["detection"]["routing_path"])
        routes[route] = routes.get(route, 0) + 1
        attack = str(entry["detection"]["predicted_attack"])
        attacks[attack] = attacks.get(attack, 0) + 1
    return {
        "submitted": len(results),
        "evaluated": len(evaluated),
        "failed": len(results) - len(evaluated),
        "matched": sum(1 for entry in scored if entry["matched"]),
        "scored": len(scored),
        "accuracy": (sum(1 for entry in scored if entry["matched"]) / len(scored)) if scored else None,
        "deep_escalations": sum(1 for entry in evaluated if entry["detection"]["deep_model_used"]),
        "mean_risk": (sum(risks) / len(risks)) if risks else 0.0,
        "latency_p50_ms": _percentile(latencies, 0.50),
        "latency_p95_ms": _percentile(latencies, 0.95),
        "total_latency_ms": sum(latencies),
        "routes": routes,
        "attacks": attacks,
    }


def _percentile(sorted_values: list[float], quantile: float) -> float:
    if not sorted_values:
        return 0.0
    from math import ceil

    index = min(len(sorted_values) - 1, max(0, ceil(quantile * len(sorted_values)) - 1))
    return float(sorted_values[index])


def _expert_payload(output) -> dict[str, Any]:
    return {"predicted_attack": output.predicted_attack, "confidence": output.confidence, "risk": output.risk, "model_version": output.model_version, "class_scores": output.class_scores}


def _error_response(request: Request, status_code: int, code: str, message: str, details: object | None = None) -> JSONResponse:
    payload: dict[str, object] = {"error": {"code": code, "message": message}, "request_id": str(request.state.request_id)}
    if details is not None:
        payload["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=payload)


app = create_app()
