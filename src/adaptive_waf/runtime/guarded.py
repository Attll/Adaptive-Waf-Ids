from time import perf_counter_ns
from adaptive_waf.contracts import BehaviourContext, NetworkContext, DetectionResult, TriageDecision
from adaptive_waf.runtime.rules import SemanticRules


class GuardedPipeline:
    """Mandatory semantic evidence precedes an unchanged executable fixed baseline."""
    def __init__(self, baseline):
        self.baseline = baseline
        self.rules = SemanticRules()
        self.strategy = "guarded_fixed"

    @property
    def model_versions(self):
        return {**self.baseline.model_versions, "rules": self.rules.version, "strategy": self.strategy + "-v1"}

    def detect(self, request, behaviour_context=None, network_context=None, rule_evidence=None):
        start = perf_counter_ns()
        matches = self.rules.inspect(request)
        elapsed = (perf_counter_ns() - start) / 1e6
        if not matches:
            from dataclasses import replace
            result = self.unmatched(request, behaviour_context, network_context, rule_evidence)
            return replace(result, routing_path=("SEMANTIC_RULES", *result.routing_path), model_versions=self.model_versions,
                           latency_by_stage_ms={"semantic_rules": elapsed, **result.latency_by_stage_ms})
        strongest = max(matches, key=lambda match: match.risk)
        behaviour, network = behaviour_context or BehaviourContext(), network_context or NetworkContext()
        return DetectionResult(request.request_id, request.received_at, strongest.risk, TriageDecision.SUSPICIOUS,
                               None, (), strongest.attack, strongest.risk, behaviour.risk, network.risk,
                               max(strongest.risk, behaviour.risk, network.risk),
                               ("SEMANTIC_RULES", "MANDATORY_RULE", "POLICY_PENDING"), {"semantic_rules": elapsed}, self.model_versions,
                               {"classification_source": "DETERMINISTIC_RULE", "rule_ids": ",".join(sorted({m.rule_id for m in matches})),
                                "rule_fields": ",".join(sorted({m.field for m in matches})), "policy_version": self.strategy + "-v1"},
                               decision_context={"inspection_status": "RULES_ONLY", "policy_version": self.strategy + "-v1",
                                                 "reason": "mandatory_semantic_rule", "recommended_action": "BLOCK"})

    def unmatched(self, request, behaviour_context, network_context, rule_evidence):
        return self.baseline.detect(request, behaviour_context, network_context, rule_evidence)

    def adjudicate(self, request):
        return self.baseline.adjudicate(request)

    def warm_deep_model(self):
        return self.baseline.warm_deep_model()

    def close(self):
        close = getattr(self.baseline,"close",None)
        if close:close()

    def batch_statistics(self):
        statistics = getattr(self.baseline,"batch_statistics",None)
        return statistics() if statistics else {"enabled":False}
