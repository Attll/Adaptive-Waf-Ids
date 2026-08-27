from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter_ns
from typing import Callable, Mapping
from uuid import uuid4

from adaptive_waf.contracts import AttackClass, BehaviourContext, DeepOutput, DetectionResult, ExpertFamily, ExpertOutput, HttpRequestRecord, NetworkContext, RouterOutput, TriageDecision
from adaptive_waf.features.classical import ClassicalFeatureExtractor
from adaptive_waf.runtime.behaviour import behaviour_evidence
from adaptive_waf.runtime.fusion import DeterministicRiskFusion
from adaptive_waf.training.router_evaluation import select_experts


@dataclass(frozen=True, slots=True)
class PipelineThresholds:
    triage_benign_exit_max_suspicious_probability: float
    triage_early_exit_enabled: bool
    expert_minimum_confidence: float
    router_minimum_top1_probability: float
    router_minimum_top1_margin: float
    asynchronous_deep_escalation_enabled: bool = False


class AdaptiveDetectionPipeline:
    def __init__(
        self,
        triage_model,
        router_model,
        expert_models: Mapping[ExpertFamily, object],
        thresholds: PipelineThresholds,
        model_versions: Mapping[str, str],
        deep_predictor: Callable[[HttpRequestRecord], Mapping[AttackClass, float]] | None = None,
        risk_fuser: DeterministicRiskFusion | None = None,
        deep_scheduler: Callable[[str, HttpRequestRecord, "DetectionResult"], None] | None = None,
    ) -> None:
        self._triage_model = triage_model
        self._router_model = router_model
        self._expert_models = dict(expert_models)
        self._thresholds = thresholds
        self._model_versions = dict(model_versions)
        self._deep_predictor = deep_predictor
        self._deep_scheduler = deep_scheduler
        self._risk_fuser = risk_fuser or DeterministicRiskFusion({"http": 1.0, "behaviour": 1.0, "network": 1.0, "rule": 1.0})
        self._extractor = ClassicalFeatureExtractor()

    @property
    def model_versions(self) -> dict[str, str]:
        return dict(self._model_versions)

    def detect(
        self,
        request: HttpRequestRecord,
        behaviour_context: BehaviourContext | None = None,
        network_context: NetworkContext | None = None,
        rule_evidence: Mapping[str, float] | None = None,
    ) -> DetectionResult:
        feature_start = perf_counter_ns()
        features = [list(self._extractor.extract(request).values)]
        latencies = {"feature_extraction": _elapsed_ms(feature_start)}
        triage_start = perf_counter_ns()
        triage_scores = _scores(self._triage_model, features)
        triage_score = triage_scores["SUSPICIOUS"]
        latencies["triage"] = _elapsed_ms(triage_start)
        if self._thresholds.triage_early_exit_enabled and triage_score <= self._thresholds.triage_benign_exit_max_suspicious_probability:
            return _early_result(request, triage_score, behaviour_context, network_context, rule_evidence, latencies, self._model_versions, self._risk_fuser)
        router_start = perf_counter_ns()
        router_scores = {ExpertFamily(label): score for label, score in _scores(self._router_model, features).items()}
        selected = tuple(
            ExpertFamily(label)
            for label in select_experts(
                [router_scores[ExpertFamily(label)] for label in self._router_model.classes_],
                [str(label) for label in self._router_model.classes_],
                self._thresholds.router_minimum_top1_probability,
                self._thresholds.router_minimum_top1_margin,
            )
        )
        latencies["router"] = _elapsed_ms(router_start)
        outputs = tuple(self._expert_output(family, features, latencies) for family in selected)
        best = max(outputs, key=lambda output: output.risk)
        unsure = best.confidence < self._thresholds.expert_minimum_confidence and self._deep_predictor is not None
        deferred = unsure and self._thresholds.asynchronous_deep_escalation_enabled and self._deep_scheduler is not None
        deep_used = unsure and not deferred
        deep_output = None
        if deep_used:
            deep_start = perf_counter_ns()
            deep_scores = self._deep_predictor(request)
            latencies["deep"] = _elapsed_ms(deep_start)
            attack, confidence = max(deep_scores.items(), key=lambda item: item[1])
            deep_output = DeepOutput(attack, confidence, 1.0 - deep_scores[AttackClass.BENIGN], self._model_versions["deep"], deep_scores)
        escalation_id = str(uuid4()) if deferred else None
        behaviour = behaviour_context or BehaviourContext()
        network = network_context or NetworkContext()
        http_risk = deep_output.risk if deep_output is not None else best.risk
        predicted_attack = deep_output.predicted_attack if deep_output is not None else best.predicted_attack
        fusion = self._risk_fuser.fuse(http_risk, behaviour, network, rule_evidence)
        result = DetectionResult(
            request_id=request.request_id,
            timestamp=request.received_at,
            triage_score=triage_score,
            triage_decision=TriageDecision.SUSPICIOUS,
            router_output=RouterOutput(router_scores, selected, self._model_versions["router"]),
            expert_outputs=outputs,
            predicted_attack=predicted_attack,
            http_risk=http_risk,
            behaviour_risk=behaviour.risk,
            network_risk=network.risk,
            overall_risk=fusion.overall_risk,
            routing_path=(
                "TRIAGE",
                "ROUTER_TOP1" if len(selected) == 1 else "ROUTER_TOP2",
                *(f"{output.family}_FAST" for output in outputs),
                *(("DEEP_ESCALATION",) if deep_used else ()),
                *(("DEEP_ESCALATION_DEFERRED",) if deferred else ()),
                "POLICY_PENDING",
            ),
            latency_by_stage_ms=latencies,
            model_versions=self._model_versions,
            explanation_evidence={
                "triage_suspicious_probability": f"{triage_score:.6f}",
                "expert_confidence": f"{best.confidence:.6f}",
                **({"deep_escalation": "deferred_to_background_worker"} if deferred else {}),
                **behaviour_evidence(behaviour),
                **fusion.supporting_evidence,
            },
            deep_model_used=deep_used,
            deep_output=deep_output,
            deep_escalation_pending=deferred,
            deep_escalation_id=escalation_id,
        )
        if deferred:
            # The caller is answered from the fast experts and the deep model adjudicates out of band; the revised
            # verdict is reported afterwards so an operator can act on a request that was allowed provisionally.
            self._deep_scheduler(escalation_id, request, result)
        return result

    def warm_deep_model(self) -> None:
        """Loads the deep artifact ahead of first use. Safe to call when no deep predictor is configured."""
        warm = getattr(self._deep_predictor, "warm", None)
        if warm is not None:
            warm()

    def adjudicate(self, request: HttpRequestRecord) -> tuple[DeepOutput, float]:
        """Run the deep model alone. Used by the background worker that resolves a deferred escalation."""
        if self._deep_predictor is None:
            raise RuntimeError("no deep predictor is configured")
        start = perf_counter_ns()
        scores = self._deep_predictor(request)
        elapsed = _elapsed_ms(start)
        attack, confidence = max(scores.items(), key=lambda item: item[1])
        return DeepOutput(attack, confidence, 1.0 - scores[AttackClass.BENIGN], self._model_versions["deep"], scores), elapsed

    def _expert_output(self, family: ExpertFamily, features, latencies) -> ExpertOutput:
        start = perf_counter_ns()
        scores = {AttackClass(label): score for label, score in _scores(self._expert_models[family], features).items()}
        latencies[f"{family.value.lower()}_expert"] = _elapsed_ms(start)
        attack, confidence = max(scores.items(), key=lambda item: item[1])
        return ExpertOutput(family, attack, confidence, 1.0 - scores[AttackClass.BENIGN], self._model_versions[family.value.lower()], scores)


def _scores(model, features) -> dict[str, float]:
    return {str(label): float(score) for label, score in zip(model.classes_, model.predict_proba(features)[0], strict=True)}


def _elapsed_ms(start: int) -> float:
    return (perf_counter_ns() - start) / 1_000_000


def _early_result(request, triage_score, behaviour, network, rule_evidence, latencies, versions, risk_fuser) -> DetectionResult:
    behaviour_context = behaviour or BehaviourContext()
    network_context = network or NetworkContext()
    fusion = risk_fuser.fuse(triage_score, behaviour_context, network_context, rule_evidence)
    return DetectionResult(
        request_id=request.request_id,
        timestamp=request.received_at,
        triage_score=triage_score,
        triage_decision=TriageDecision.BENIGN_LIKE,
        router_output=None,
        expert_outputs=(),
        predicted_attack=AttackClass.BENIGN,
        http_risk=triage_score,
        behaviour_risk=behaviour_context.risk,
        network_risk=network_context.risk,
        overall_risk=fusion.overall_risk,
        routing_path=("TRIAGE", "TRIAGE_EARLY_EXIT", "POLICY_PENDING"),
        latency_by_stage_ms=latencies,
        model_versions=versions,
        explanation_evidence={"triage_suspicious_probability": f"{triage_score:.6f}", **behaviour_evidence(behaviour_context), **fusion.supporting_evidence},
    )
