from dataclasses import replace
import json
from threading import Lock
from time import monotonic, perf_counter_ns
from uuid import uuid4
from adaptive_waf.contracts import AttackClass, BehaviourContext, NetworkContext, DetectionResult, TriageDecision, RouterOutput, ExpertFamily
from adaptive_waf.runtime.guarded import GuardedPipeline
from adaptive_waf.runtime.pipeline import _scores
from adaptive_waf.runtime.routing import LinUCB, RoutingContext
from adaptive_waf.runtime.uncertainty import uncertainty

STRATEGIES = {"rules_only", "single_fast", "both", "always_deep", "confidence", "cost_threshold", "calibrated_fusion", "conformal", "bandit_shadow"}


class DeferralBudget:
    def __init__(self, capacity=10, refill_per_second=1):
        if capacity <= 0 or refill_per_second < 0:
            raise ValueError("invalid deferral budget")
        self.capacity, self.refill = capacity, refill_per_second
        self.tokens, self.at = float(capacity), monotonic()
        self.lock = Lock()

    def take(self):
        with self.lock:
            now = monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.at) * self.refill)
            self.at = now
            if self.tokens < 1:
                return False
            self.tokens -= 1
            return True


class RoutedPipeline(GuardedPipeline):
    def __init__(self, baseline, strategy, conformal=None, bandit=None, budget=None):
        super().__init__(baseline)
        if strategy not in STRATEGIES:
            raise ValueError("unknown routing strategy")
        if strategy == "conformal" and conformal is None:
            raise ValueError("conformal strategy requires a fitted disjoint calibration artifact")
        self.strategy, self.conformal = strategy, conformal
        self.bandit, self.budget = bandit or LinUCB(), budget or DeferralBudget()

    def unmatched(self, request, behaviour_context, network_context, rule_evidence):
        before = perf_counter_ns()
        baseline = self.baseline
        behaviour, network = behaviour_context or BehaviourContext(), network_context or NetworkContext()
        timings, outputs, router, deep = {}, (), None, None
        route, reason, pending, identifier = "RULES_ONLY", "configured_strategy", False, None
        risk, attack, info, propensities = 0., AttackClass.BENIGN, {}, {}
        available = ["RULES_ONLY", "FAST_ONLY", "BOTH"]
        if baseline._deep_predictor is not None:
            available.append("SYNC_DEEP")
            if baseline._deep_scheduler is not None:
                available.append("DEFERRED_DEEP")
        if self.strategy != "rules_only":
            started = perf_counter_ns()
            features = [list(baseline._extractor.extract(request).values)]
            timings["feature_extraction"] = (perf_counter_ns() - started) / 1e6
            started = perf_counter_ns()
            router_scores = {ExpertFamily(label): score for label, score in _scores(baseline._router_model, features).items()}
            family = max(router_scores, key=router_scores.get)
            timings["router"] = (perf_counter_ns() - started) / 1e6
            fast = baseline._expert_output(family, features, timings)
            outputs, attack, risk = (fast,), fast.predicted_attack, fast.risk
            info = uncertainty(list(fast.class_scores.values()))
            router = RouterOutput(router_scores, (family,), baseline.model_versions["router"])
            route = "FAST_ONLY"
            if self.strategy in {"both", "calibrated_fusion"}:
                route = "BOTH"
            elif self.strategy == "always_deep":
                route = "SYNC_DEEP"
            elif self.strategy in {"confidence", "cost_threshold", "bandit_shadow"}:
                # The cost gate is an explicit experimental parameter, not advertised as tuned.
                threshold = .90 if self.strategy != "cost_threshold" else .80
                route = "SYNC_DEEP" if info["confidence"] < threshold else "FAST_ONLY"
            elif self.strategy == "conformal":
                values = [fast.class_scores.get(AttackClass(label), 0.) for label in self.conformal.classes]
                try:
                    prediction_set = self.conformal.prediction_set(values, fast.model_version)
                    info["calibration_available"] = True
                except ValueError:
                    prediction_set = ()
                    info["calibration_available"] = False
                info["prediction_set"] = prediction_set
                route = "FAST_ONLY" if len(prediction_set) == 1 else "SYNC_DEEP"
            if self.strategy == "bandit_shadow":
                from adaptive_waf.runtime.context import ROUTING_CONTEXT
                context = RoutingContext(risk, info["entropy"], info["margin"], min(1, behaviour.requests_per_short_window / 100), network_risk=network.risk, **ROUTING_CONTEXT.get())
                info["pre_action_context"] = context.__dict__
                proposed, propensities = self.bandit.select(context, available, conservative=True)
                info["shadow_route"] = proposed
                reason = "bandit_recommendation_shadow_only"
            if route == "BOTH":
                outputs = tuple(fast if candidate == family else baseline._expert_output(candidate, features, timings) for candidate in ExpertFamily)
                best = max(outputs, key=lambda item: item.risk)
                attack, risk = best.predicted_attack, best.risk
                router = RouterOutput(router_scores, tuple(ExpertFamily), baseline.model_versions["router"])
                if self.strategy == "calibrated_fusion":
                    scores = {label: sum(item.class_scores.get(label, 0.) for item in outputs) / len(outputs) for label in AttackClass}
                    attack, risk = max(scores, key=scores.get), 1 - scores[AttackClass.BENIGN]
            if route == "SYNC_DEEP":
                if route not in available or not self.budget.take():
                    reason = "required_deep_unavailable_or_budget_exhausted"
                else:
                    try:
                        deep, duration = baseline.adjudicate(request)
                        timings["deep"] = duration
                        attack, risk = deep.predicted_attack, deep.risk
                    except Exception as error:
                        reason = "required_deep_failed_" + type(error).__name__
        fallback = reason.startswith("required_deep")
        fusion = baseline._risk_fuser.fuse(risk, behaviour, network, rule_evidence)
        overall = fusion.overall_risk
        action = "BLOCK" if fallback or overall > .81 else "RATE_LIMIT" if overall > .5 else "MONITOR" if overall > .2 else "ALLOW"
        status = "DETECTION_UNAVAILABLE" if fallback else "RULES_ONLY" if self.strategy == "rules_only" else "FULLY_INSPECTED"
        decision = {"policy_version": self.strategy + "-v1", "route": route, "available_routes": available,
                    "uncertainty": info, "reason": reason, "fallback": fallback, "inspection_status": status,
                    "recommended_action": action, "shadow_action_probabilities": propensities,
                    "action_probabilities": {route: 1.0},
                    "decision_overhead_ms": max(0., (perf_counter_ns() - before) / 1e6 - sum(timings.values()))}
        return DetectionResult(request.request_id, request.received_at, risk, TriageDecision.SUSPICIOUS, router, outputs,
                               attack, risk, behaviour.risk, network.risk, overall,
                               (route, "POLICY_PENDING"), timings, self.model_versions,
                               {"policy_version": self.strategy + "-v1", "decision_reason": reason,
                                "fallback_block": str(fallback).lower(), "recommended_action": action},
                               ensemble_used=len(outputs) > 1, deep_model_used=deep is not None, deep_output=deep,
                               decision_context=decision)
