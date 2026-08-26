from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Mapping
from uuid import UUID, uuid4


class AttackClass(StrEnum):
    BENIGN = "BENIGN"
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    COOKIE_INJECTION = "COOKIE_INJECTION"
    DIRECTORY_TRAVERSAL = "DIRECTORY_TRAVERSAL"
    REMOTE_CODE_EXECUTION = "REMOTE_CODE_EXECUTION"


class ExpertFamily(StrEnum):
    INJECTION = "INJECTION"
    EXECUTION = "EXECUTION"


class NetworkClass(StrEnum):
    BENIGN = "BENIGN"
    BRUTE_FORCE = "BRUTE_FORCE"
    DOS_DDOS = "DOS_DDOS"
    BOT_ANOMALY = "BOT_ANOMALY"


class TriageDecision(StrEnum):
    BENIGN_LIKE = "BENIGN_LIKE"
    SUSPICIOUS = "SUSPICIOUS"


@dataclass(frozen=True, slots=True)
class HttpRequestRecord:
    method: str
    path: str
    query: str = ""
    headers: Mapping[str, str] = field(default_factory=dict)
    cookies: Mapping[str, str] = field(default_factory=dict)
    body: str = ""
    source_ip: str | None = None
    request_id: UUID = field(default_factory=uuid4)
    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.method.strip():
            raise ValueError("method must not be blank")
        if not self.path.startswith("/"):
            raise ValueError("path must start with '/'")
        if self.received_at.tzinfo is None:
            raise ValueError("received_at must be timezone-aware")


@dataclass(frozen=True, slots=True)
class BehaviourContext:
    risk: float = 0.0
    requests_per_short_window: int = 0
    requests_per_medium_window: int = 0
    failed_auth_attempts: int = 0
    previous_attack_count: int = 0

    def __post_init__(self) -> None:
        _validate_risk("behaviour risk", self.risk)
        _validate_non_negative(
            self.requests_per_short_window,
            self.requests_per_medium_window,
            self.failed_auth_attempts,
            self.previous_attack_count,
        )


@dataclass(frozen=True, slots=True)
class NetworkContext:
    risk: float = 0.0
    network_class: str | None = None
    confidence: float | None = None

    def __post_init__(self) -> None:
        _validate_risk("network risk", self.risk)
        if self.confidence is not None:
            _validate_risk("network confidence", self.confidence)


@dataclass(frozen=True, slots=True)
class RouterOutput:
    scores: Mapping[ExpertFamily, float]
    selected_experts: tuple[ExpertFamily, ...]
    model_version: str

    def __post_init__(self) -> None:
        if not self.scores:
            raise ValueError("router scores must not be empty")
        for score in self.scores.values():
            _validate_risk("router score", score)
        if not self.selected_experts:
            raise ValueError("at least one expert must be selected")
        if any(expert not in self.scores for expert in self.selected_experts):
            raise ValueError("selected experts must have router scores")


@dataclass(frozen=True, slots=True)
class ExpertOutput:
    family: ExpertFamily
    predicted_attack: AttackClass
    confidence: float
    risk: float
    model_version: str
    class_scores: Mapping[AttackClass, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_risk("expert confidence", self.confidence)
        _validate_risk("expert risk", self.risk)
        for score in self.class_scores.values():
            _validate_risk("expert class score", score)


@dataclass(frozen=True, slots=True)
class DetectionResult:
    request_id: UUID
    timestamp: datetime
    triage_score: float
    triage_decision: TriageDecision
    router_output: RouterOutput | None
    expert_outputs: tuple[ExpertOutput, ...]
    predicted_attack: AttackClass
    http_risk: float
    behaviour_risk: float
    network_risk: float
    overall_risk: float
    routing_path: tuple[str, ...]
    latency_by_stage_ms: Mapping[str, float]
    model_versions: Mapping[str, str]
    explanation_evidence: Mapping[str, str] = field(default_factory=dict)
    ensemble_used: bool = False
    deep_model_used: bool = False

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        for name, value in (
            ("triage score", self.triage_score),
            ("http risk", self.http_risk),
            ("behaviour risk", self.behaviour_risk),
            ("network risk", self.network_risk),
            ("overall risk", self.overall_risk),
        ):
            _validate_risk(name, value)
        if not self.routing_path:
            raise ValueError("routing path must not be empty")
        if any(latency < 0 for latency in self.latency_by_stage_ms.values()):
            raise ValueError("stage latencies must not be negative")


def _validate_risk(name: str, value: float) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")


def _validate_non_negative(*values: int) -> None:
    if any(value < 0 for value in values):
        raise ValueError("context counters must not be negative")
