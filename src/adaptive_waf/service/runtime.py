from __future__ import annotations

from dataclasses import dataclass
from threading import RLock, Thread
from time import perf_counter_ns


class ModelUnavailableError(RuntimeError):
    pass


class InferenceTimeoutError(TimeoutError):
    pass


@dataclass(frozen=True, slots=True)
class ServiceTimings:
    elapsed_ms: float


class RuntimeStore:
    """Caches loaded artifacts and serializes model calls for thread-safe inference."""

    def __init__(self, pipeline_loader, network_loader, inference_timeout_ms: int, network_timeout_ms: int, escalation_worker=None) -> None:
        self._pipeline_loader = pipeline_loader
        self._network_loader = network_loader
        self._inference_timeout_ms = inference_timeout_ms
        self._network_timeout_ms = network_timeout_ms
        self._escalation_worker = escalation_worker
        self._lock = RLock()
        self._pipeline = None
        self._network_detector = None
        self._load_error: str | None = None

    @property
    def escalations(self):
        return self._escalation_worker

    @property
    def ready(self) -> bool:
        return self._pipeline is not None and self._network_detector is not None and self._load_error is None

    @property
    def load_error(self) -> str | None:
        return self._load_error

    def start(self) -> None:
        with self._lock:
            if self.ready or self._load_error is not None:
                return
            try:
                self._pipeline = self._pipeline_loader()
                self._network_detector = self._network_loader()
                if self._escalation_worker is not None and hasattr(self._pipeline, "adjudicate"):
                    # Deep adjudication runs outside the inference lock: it never contends with a live request.
                    self._escalation_worker.bind(self._pipeline.adjudicate)
                    self._escalation_worker.start()
                    self._warm_deep_model()
            except Exception as error:
                self._pipeline = None
                self._network_detector = None
                self._load_error = f"artifact loading failed: {type(error).__name__}"

    def detect(self, request, behaviour_context, network_context, rule_evidence):
        with self._lock:
            pipeline = self._require_pipeline()
            result, timing = self._timed(
                self._inference_timeout_ms,
                pipeline.detect,
                request,
                behaviour_context,
                network_context,
                rule_evidence,
            )
        return result, timing

    def detect_network(self, features):
        with self._lock:
            detector = self._require_network_detector()
            result, timing = self._timed(self._network_timeout_ms, detector.detect, features)
        return result, timing

    def model_versions(self) -> dict[str, str]:
        with self._lock:
            pipeline = self._require_pipeline()
            detector = self._require_network_detector()
            return {**pipeline.model_versions, "network": detector.model_version}

    def _warm_deep_model(self) -> None:
        """Loads the transformer off the request path, so the first deferred escalation is not stuck behind it."""
        warm = getattr(self._pipeline, "warm_deep_model", None)
        if warm is None:
            return
        Thread(target=self._safe_warm, args=(warm,), name="deep-model-warmup", daemon=True).start()

    @staticmethod
    def _safe_warm(warm) -> None:
        try:
            warm()
        except Exception:
            pass  # a failed warm-up only costs a slower first adjudication

    def _require_pipeline(self):
        if self._pipeline is None:
            raise ModelUnavailableError(self._load_error or "pipeline is not loaded")
        return self._pipeline

    def _require_network_detector(self):
        if self._network_detector is None:
            raise ModelUnavailableError(self._load_error or "network detector is not loaded")
        return self._network_detector

    @staticmethod
    def _timed(timeout_ms: int, callable_object, *arguments):
        start = perf_counter_ns()
        result = callable_object(*arguments)
        elapsed_ms = (perf_counter_ns() - start) / 1_000_000
        if elapsed_ms > timeout_ms:
            raise InferenceTimeoutError(f"inference exceeded {timeout_ms} ms")
        return result, ServiceTimings(elapsed_ms)
