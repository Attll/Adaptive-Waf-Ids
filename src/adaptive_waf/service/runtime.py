from __future__ import annotations

from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from threading import BoundedSemaphore
from threading import RLock, Thread
from time import perf_counter_ns
from collections import deque


class ModelUnavailableError(RuntimeError):
    pass


class InferenceTimeoutError(TimeoutError):
    pass


class InferenceBusyError(RuntimeError):
    pass


class _BoundedRunner:
    """Timed-out native calls keep their slots until they stop. Submissions are bounded."""

    def __init__(self, workers: int, queue_limit: int, name: str) -> None:
        self._slots = BoundedSemaphore(workers + queue_limit)
        self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix=name)

    def call(self, timeout_ms, function, *arguments):
        start = perf_counter_ns()
        if not self._slots.acquire(blocking=False):
            raise InferenceBusyError("inference capacity exhausted")
        try:
            future = self._executor.submit(function, *arguments)
        except BaseException:
            self._slots.release()
            raise
        future.add_done_callback(lambda _: self._slots.release())
        try:
            result = future.result(timeout=max(0.0, timeout_ms / 1000 - (perf_counter_ns() - start) / 1e9))
        except FutureTimeout:
            future.cancel()  # queued work can be cancelled; native running calls cannot be killed safely
            raise InferenceTimeoutError(f"inference exceeded {timeout_ms} ms") from None
        elapsed = (perf_counter_ns() - start) / 1_000_000
        if elapsed > timeout_ms:
            raise InferenceTimeoutError(f"inference exceeded {timeout_ms} ms")
        return result, ServiceTimings(elapsed)

    def close(self):
        self._executor.shutdown(wait=False, cancel_futures=True)


@dataclass(frozen=True, slots=True)
class ServiceTimings:
    elapsed_ms: float


class RuntimeStore:
    """Caches artifacts with independent bounded HTTP and network execution pools."""

    def __init__(self, pipeline_loader, network_loader, inference_timeout_ms: int, network_timeout_ms: int, escalation_worker=None,
                 http_workers: int = 1, network_workers: int = 1, queue_limit: int = 16) -> None:
        self._pipeline_loader = pipeline_loader
        self._network_loader = network_loader
        self._inference_timeout_ms = inference_timeout_ms
        self._network_timeout_ms = network_timeout_ms
        self._escalation_worker = escalation_worker
        self._lock = RLock()
        self._pipeline = None
        self._owned_pipelines = []
        self._network_detector = None
        self._load_error: str | None = None
        self._http_runner = _BoundedRunner(http_workers, queue_limit, "http-inference")
        self._network_runner = _BoundedRunner(network_workers, queue_limit, "network-inference")
        self._policy_lifecycle = None
        self._policy_candidates = {}
        self._recent_errors = deque(maxlen=20)
        self._http_workers = http_workers
        self._active_shadow_calls = 0

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
                self._owned_pipelines.append(self._pipeline)
                self._network_detector = self._network_loader()
                if self._escalation_worker is not None and hasattr(self._pipeline, "adjudicate"):
                    # Deep work has its own queue, but can still contend for CPU/GPU resources.
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
        function=pipeline.detect
        if getattr(pipeline,"model_versions",{}).get("strategy") == "bandit_shadow-v1":
            submitted=perf_counter_ns()
            def with_runtime_context(*arguments):
                from adaptive_waf.runtime.context import ROUTING_CONTEXT
                with self._lock:
                    self._active_shadow_calls+=1
                    load=min(1.,self._active_shadow_calls/self._http_workers)
                try:
                    cached=getattr(self._escalation_worker,"cached_statistics",None)
                    # In-process statistics are local. Durable statistics must use maintenance's cached snapshot.
                    if cached:
                        stats=cached()
                    elif self._escalation_worker and self._escalation_worker.__class__.__name__ in {"EscalationWorker","DisabledEscalationWorker"}:
                        stats=self._escalation_worker.statistics()
                    else:
                        stats=None
                    queue_fraction=min(1.,stats.get("queue_depth",0)/max(1,stats.get("queue_limit",1))) if stats else 1.
                    batch_statistics=getattr(pipeline,"batch_statistics",None)
                    batch=batch_statistics() if batch_statistics else {}
                    if batch.get("enabled"):
                        queue_fraction=max(queue_fraction,min(1.,batch["queue_depth"]/max(1,batch["queue_limit"])))
                    remaining=max(0.,1-(perf_counter_ns()-submitted)/1e6/self._inference_timeout_ms)
                    token=ROUTING_CONTEXT.set({"load":load,"queue_fraction":queue_fraction,"deadline_fraction":remaining})
                    try:
                        return pipeline.detect(*arguments)
                    finally:
                        ROUTING_CONTEXT.reset(token)
                finally:
                    with self._lock:
                        self._active_shadow_calls-=1
            function=with_runtime_context
        try:
            value = self._http_runner.call(self._inference_timeout_ms, function, request, behaviour_context, network_context, rule_evidence)
        except Exception:
            self._record_inference_outcome(True)
            raise
        self._record_inference_outcome(False)
        return value

    def policy_lifecycle(self):
        import os
        from adaptive_waf.adaptation.lifecycle import PolicyLifecycle, PolicyCandidate
        with self._lock:
            if self._policy_lifecycle is None:
                baseline = self._require_pipeline()
                def activate(candidate):
                    with self._lock:
                        self._pipeline = self._policy_candidates[candidate.version] if isinstance(candidate, PolicyCandidate) else candidate
                    return True
                self._policy_lifecycle = PolicyLifecycle(os.environ.get("WAF_POLICY_AUDIT_ROOT", "artifacts/adaptation/policy-audit"),
                    activate, baseline, live_enabled=os.environ.get("WAF_LIVE_ACTIVATION_ENABLED") == "true")
            return self._policy_lifecycle

    def prepare_policy(self, candidate):
        with self._lock:
            if len(self._policy_candidates) >= 20:
                raise ValueError("prepared policy capacity exhausted")
            if candidate.version in self._policy_candidates:
                raise ValueError("policy version already prepared or preparing")
            self._policy_candidates[candidate.version]=None  # atomic capacity reservation, no inference lock during loading
        try:
            return self._prepare_reserved_policy(candidate)
        except BaseException:
            with self._lock:
                self._policy_candidates.pop(candidate.version,None)
            raise

    def _prepare_reserved_policy(self,candidate):
        from adaptive_waf.runtime.artifacts import load_adaptive_pipeline
        pipeline = load_adaptive_pipeline(strategy=candidate.strategy, deep_scheduler=self._escalation_worker.submit if self._escalation_worker else None)
        class VersionedPipeline:
            @property
            def model_versions(self):
                return {**pipeline.model_versions, "policy":candidate.version}
            def detect(self, *arguments):
                from dataclasses import replace
                result = pipeline.detect(*arguments)
                return replace(result, model_versions={**result.model_versions,"policy":candidate.version},
                               decision_context={**result.decision_context,"policy_version":candidate.version})
            def adjudicate(self, request):
                return pipeline.adjudicate(request)
            def warm_deep_model(self):
                return pipeline.warm_deep_model()
            def close(self):
                close = getattr(pipeline,"close",None)
                if close:close()
            def batch_statistics(self):
                statistics = getattr(pipeline,"batch_statistics",None)
                return statistics() if statistics else {"enabled":False}
        versioned = VersionedPipeline()
        manager = self.policy_lifecycle()
        with self._lock:
            self._policy_candidates[candidate.version] = versioned
        try:
            manager.register(candidate)
        except Exception:
            versioned.close()
            raise
        with self._lock:
            self._owned_pipelines.append(versioned)
        return {"status":"SHADOW", "policy_version":candidate.version, "runtime_versions":pipeline.model_versions,
                "activation_enabled":manager.live_enabled}

    def _record_inference_outcome(self, failed):
        with self._lock:
            self._recent_errors.append(failed)
            manager = self._policy_lifecycle
            metrics = {"observations":len(self._recent_errors), "inference_error_rate":sum(self._recent_errors)/len(self._recent_errors)}
        if manager:
            manager.monitor(metrics)

    def detect_network(self, features):
        with self._lock:
            detector = self._require_network_detector()
        return self._network_runner.call(self._network_timeout_ms, detector.detect, features)

    def close(self):
        self._http_runner.close()
        self._network_runner.close()
        close = getattr(self._escalation_worker, "close", None)
        if close:
            close()
        with self._lock:
            pipelines, self._owned_pipelines = self._owned_pipelines, []
        for pipeline in pipelines:
            close = getattr(pipeline,"close",None)
            if close:close()

    def batch_statistics(self):
        with self._lock:
            statistics = getattr(self._pipeline,"batch_statistics",None)
        return statistics() if statistics else {"enabled":False}

    def model_versions(self) -> dict[str, str]:
        with self._lock:
            pipeline = self._require_pipeline()
            detector = self._require_network_detector()
            return {**pipeline.model_versions, "network": detector.model_version}

    def research_context(self):
        pipeline = self._require_pipeline()
        if not hasattr(pipeline,"sessions") or not hasattr(pipeline,"profiles"):
            raise ValueError("Research context is disabled; select WAF_CONTEXT_MODE=shadow or simulation")
        return pipeline

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
