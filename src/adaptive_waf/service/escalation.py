"""Background adjudication of requests the fast experts were not confident about.

A request that lands below the expert confidence threshold is answered immediately from the fast verdict, so the
caller is never made to wait for the transformer. The deep model then runs on a worker thread and the revised
verdict is retained here — and optionally reported to the control plane — so an operator can see that a request
was allowed provisionally and what the deep model eventually concluded.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from queue import Empty, Full, Queue
from threading import Lock, Thread
from typing import Any, Callable
import urllib.error
import urllib.request


@dataclass(frozen=True, slots=True)
class EscalationOutcome:
    escalation_id: str
    request_id: str
    method: str
    path: str
    query: str
    source_ip: str | None
    submitted_at: str
    resolved_at: str
    queued_ms: float
    deep_latency_ms: float
    provisional_attack: str
    provisional_risk: float
    provisional_confidence: float
    revised_attack: str
    revised_risk: float
    revised_confidence: float
    changed: bool
    model_version: str
    class_scores: dict[str, float] = field(default_factory=dict)
    error: str | None = None

    def as_payload(self) -> dict[str, Any]:
        return {
            "escalation_id": self.escalation_id,
            "request_id": self.request_id,
            "method": self.method,
            "path": self.path,
            "query": self.query,
            "source_ip": self.source_ip,
            "submitted_at": self.submitted_at,
            "resolved_at": self.resolved_at,
            "queued_ms": round(self.queued_ms, 4),
            "deep_latency_ms": round(self.deep_latency_ms, 4),
            "provisional": {
                "predicted_attack": self.provisional_attack,
                "risk": self.provisional_risk,
                "confidence": self.provisional_confidence,
            },
            "revised": {
                "predicted_attack": self.revised_attack,
                "risk": self.revised_risk,
                "confidence": self.revised_confidence,
                "model_version": self.model_version,
                "class_scores": self.class_scores,
            },
            "changed": self.changed,
            "error": self.error,
        }


class EscalationWorker:
    """A bounded queue drained by daemon threads that run the deep model out of the request path."""

    def __init__(
        self,
        workers: int = 2,
        queue_limit: int = 256,
        retain: int = 200,
        reporter: Callable[[EscalationOutcome], None] | None = None,
    ) -> None:
        self._queue: Queue = Queue(maxsize=max(1, queue_limit))
        self._workers = max(1, workers)
        self._outcomes: deque[EscalationOutcome] = deque(maxlen=retain)
        self._lock = Lock()
        self._reporter = reporter
        self._adjudicator: Callable[[Any], tuple[Any, float]] | None = None
        self._started = False
        self._submitted = 0
        self._resolved = 0
        self._rejected = 0
        self._failed = 0
        self._running = 0

    def bind(self, adjudicator: Callable[[Any], tuple[Any, float]]) -> None:
        """Supply the callable that runs the deep model, once the pipeline has finished loading."""
        self._adjudicator = adjudicator

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        for index in range(self._workers):
            Thread(target=self._drain, name=f"deep-escalation-{index}", daemon=True).start()

    def submit(self, escalation_id: str, request, result) -> bool:
        item = (escalation_id, request, _provisional(result), _now())
        try:
            self._queue.put_nowait(item)
        except Full:
            with self._lock:
                self._rejected += 1
            return False
        with self._lock:
            self._submitted += 1
        return True

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return [outcome.as_payload() for outcome in list(self._outcomes)[: max(1, limit)]]

    def statistics(self) -> dict[str, Any]:
        with self._lock:
            outcomes = list(self._outcomes)
            changed = sum(1 for outcome in outcomes if outcome.changed)
            latencies = sorted(outcome.deep_latency_ms for outcome in outcomes if outcome.error is None)
            queued = [outcome.queued_ms for outcome in outcomes if outcome.error is None]
            return {
                "enabled": True,
                "workers": self._workers,
                "queue_depth": self._queue.qsize(),
                "queue_limit": self._queue.maxsize,
                "submitted": self._submitted,
                "resolved": self._resolved,
                "failed": self._failed,
                "pending": max(0, self._submitted - self._resolved - self._failed),
                "running": self._running,
                "rejected": self._rejected,
                "retained": len(outcomes),
                "verdict_changed": changed,
                "mean_queued_ms": round(sum(queued) / len(queued), 4) if queued else 0.0,
                "median_deep_latency_ms": round(latencies[len(latencies) // 2], 4) if latencies else 0.0,
            }

    def _drain(self) -> None:
        while True:
            try:
                escalation_id, request, provisional, submitted_at = self._queue.get(timeout=1.0)
            except Empty:
                continue
            try:
                with self._lock:
                    self._running += 1
                self._resolve(escalation_id, request, provisional, submitted_at)
            except Exception as error:  # a worker thread must never die on one bad request
                self._record(_failure(escalation_id, request, provisional, submitted_at, error))
            finally:
                with self._lock:
                    self._running -= 1
                self._queue.task_done()

    def _resolve(self, escalation_id: str, request, provisional, submitted_at) -> None:
        if self._adjudicator is None:
            raise RuntimeError("no deep adjudicator is bound")
        started = datetime.now(timezone.utc)
        deep_output, elapsed_ms = self._adjudicator(request)
        revised_attack = str(deep_output.predicted_attack)
        outcome = EscalationOutcome(
            escalation_id=escalation_id,
            request_id=str(request.request_id),
            method=request.method,
            path=request.path,
            query=request.query,
            source_ip=request.source_ip,
            submitted_at=submitted_at.isoformat(),
            resolved_at=datetime.now(timezone.utc).isoformat(),
            queued_ms=(started - submitted_at).total_seconds() * 1000.0,
            deep_latency_ms=elapsed_ms,
            provisional_attack=provisional["attack"],
            provisional_risk=provisional["risk"],
            provisional_confidence=provisional["confidence"],
            revised_attack=revised_attack,
            revised_risk=float(deep_output.risk),
            revised_confidence=float(deep_output.confidence),
            changed=revised_attack != provisional["attack"],
            model_version=deep_output.model_version,
            class_scores={str(name): float(score) for name, score in (deep_output.class_scores or {}).items()},
        )
        with self._lock:
            self._resolved += 1
        self._record(outcome)

    def _record(self, outcome: EscalationOutcome) -> None:
        with self._lock:
            self._outcomes.appendleft(outcome)
            if outcome.error is not None:
                self._failed += 1
        if self._reporter is not None:
            try:
                self._reporter(outcome)
            except Exception:
                pass  # reporting is best effort; the outcome is still retained locally


class ControlPlaneReporter:
    """Posts a resolved escalation to the control plane so it lands in the journal an operator watches."""

    def __init__(self, base_url: str, timeout_seconds: float = 5.0) -> None:
        self._url = base_url.rstrip("/") + "/internal/v1/security/escalations"
        self._timeout = timeout_seconds

    def __call__(self, outcome: EscalationOutcome) -> bool:
        body = json.dumps(outcome.as_payload()).encode("utf-8")
        request = urllib.request.Request(self._url, data=body, method="POST", headers={
            "Content-Type": "application/json", "X-WAF-Internal-Token": os.environ.get("WAF_INTERNAL_TOKEN", "")})
        try:
            with urllib.request.urlopen(request, timeout=self._timeout):
                return True
        except (urllib.error.URLError, OSError, TimeoutError):
            return False


class DisabledEscalationWorker:
    """Stand-in used when escalation stays inline, so callers need no conditional branches."""

    def bind(self, adjudicator) -> None: ...
    def start(self) -> None: ...
    def submit(self, escalation_id, request, result) -> bool: return False
    def recent(self, limit: int = 50) -> list[dict[str, Any]]: return []
    def statistics(self) -> dict[str, Any]:
        return {"enabled": False, "workers": 0, "queue_depth": 0, "queue_limit": 0, "submitted": 0,
                "resolved": 0, "failed": 0, "rejected": 0, "retained": 0, "verdict_changed": 0,
                "mean_queued_ms": 0.0, "median_deep_latency_ms": 0.0}


def _provisional(result) -> dict[str, Any]:
    best = max(result.expert_outputs, key=lambda output: output.risk) if result.expert_outputs else None
    return {
        "attack": str(result.predicted_attack),
        "risk": float(result.overall_risk),
        "confidence": float(best.confidence) if best is not None else 0.0,
    }


def _failure(escalation_id, request, provisional, submitted_at, error) -> EscalationOutcome:
    return EscalationOutcome(
        escalation_id=escalation_id,
        request_id=str(request.request_id),
        method=request.method,
        path=request.path,
        query=request.query,
        source_ip=request.source_ip,
        submitted_at=submitted_at.isoformat(),
        resolved_at=datetime.now(timezone.utc).isoformat(),
        queued_ms=0.0,
        deep_latency_ms=0.0,
        provisional_attack=provisional["attack"],
        provisional_risk=provisional["risk"],
        provisional_confidence=provisional["confidence"],
        revised_attack=provisional["attack"],
        revised_risk=provisional["risk"],
        revised_confidence=provisional["confidence"],
        changed=False,
        model_version="unavailable",
        error=type(error).__name__,
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)
