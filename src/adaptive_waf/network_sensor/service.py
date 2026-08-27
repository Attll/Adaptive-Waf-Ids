from __future__ import annotations

from collections import deque
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from adaptive_waf.network_sensor.core import NetworkEvidence, NetworkSensor
from adaptive_waf.network_sensor.redis_store import RedisNetworkContextStore
from adaptive_waf.runtime.artifacts import load_offline_network_detector


class FlowPayload(BaseModel):
    source_ip: str
    destination_ip: str | None = None
    features: dict[str, float]


class SensorSettings(BaseModel):
    redis_host: str = "127.0.0.1"
    redis_port: int = 6379
    redis_timeout_seconds: float = Field(default=0.25, gt=0)
    context_ttl_seconds: int = Field(default=300, ge=1)
    recent_limit: int = Field(default=100, ge=1, le=1000)


def create_app(
    settings: SensorSettings | None = None,
    detector=None,
    store=None,
) -> FastAPI:
    active_settings = settings or SensorSettings()
    active_detector = detector or load_offline_network_detector()
    active_store = store or RedisNetworkContextStore(active_settings.redis_host, active_settings.redis_port, active_settings.redis_timeout_seconds)
    sensor = NetworkSensor(active_detector, active_store, active_settings.context_ttl_seconds)
    recent: deque[NetworkEvidence] = deque(maxlen=active_settings.recent_limit)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.sensor = sensor
        yield

    application = FastAPI(title="Adaptive WAF Network Sensor", version="0.1.0", lifespan=lifespan)

    @application.get("/health")
    def health() -> dict[str, object]:
        redis_available = active_store.ping()
        return {"status": "ok" if redis_available else "degraded", "redis": "up" if redis_available else "down", "model_version": sensor.model_version}

    @application.get("/ready")
    def ready() -> dict[str, object]:
        if not active_store.ping():
            raise HTTPException(status_code=503, detail="Redis network context store is unavailable")
        return {"status": "ready", "model_version": sensor.model_version}

    @application.post("/v1/flows")
    def process_flow(payload: FlowPayload) -> dict[str, object]:
        try:
            evidence = sensor.process(payload.source_ip, payload.destination_ip, payload.features)
        except (ConnectionError, OSError) as error:
            raise HTTPException(status_code=503, detail="Redis network context store is unavailable") from error
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        recent.appendleft(evidence)
        return {"network_context": asdict(evidence)}

    @application.get("/v1/network/recent")
    def recent_evidence() -> dict[str, object]:
        return {"events": [asdict(evidence) for evidence in recent], "model_version": sensor.model_version}

    return application


def load_sensor_settings(path: Path) -> SensorSettings:
    import tomllib
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    return SensorSettings(**raw)
