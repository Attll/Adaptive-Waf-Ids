from dataclasses import replace
from contextvars import ContextVar
from adaptive_waf.contracts import BehaviourContext
from adaptive_waf.runtime.session_risk import SessionRiskStore, RiskRevision
from adaptive_waf.runtime.profiles import EndpointProfiles

ROUTING_CONTEXT = ContextVar("research_routing_context", default={})


class ContextPipeline:
    """Shadow by default; simulation mode supports containment tests without enabling deployment mitigation."""
    def __init__(self, pipeline, mode="shadow", sessions=None, profiles=None):
        if mode not in {"shadow", "simulation"}:
            raise ValueError("live session mitigation requires a separately approved deployment policy")
        self.pipeline, self.mode = pipeline, mode
        self.sessions, self.profiles = sessions or SessionRiskStore(), profiles or EndpointProfiles("empty-v1")

    @property
    def model_versions(self):
        return {**self.pipeline.model_versions, "context_mode": self.mode}

    def detect(self, request, behaviour_context=None, network_context=None, rule_evidence=None):
        previous = self.sessions.risk(request.session_key) if request.session_key else 0.
        behaviour = behaviour_context or BehaviourContext()
        profile = self.profiles.score(request)
        if self.mode == "simulation":
            behaviour = replace(behaviour, risk=max(behaviour.risk, previous))
        token = ROUTING_CONTEXT.set({**ROUTING_CONTEXT.get(),"session_risk":previous,"endpoint_anomaly":profile["score"]})
        try:
            result = self.pipeline.detect(request, behaviour, network_context, rule_evidence)
        finally:
            ROUTING_CONTEXT.reset(token)
        if self.mode == "simulation":
            result = replace(result, overall_risk=max(result.overall_risk,previous), behaviour_risk=max(result.behaviour_risk,previous))
        if request.session_key:
            self.sessions.revise(request.session_key, RiskRevision(str(request.request_id), "immediate:" + str(request.request_id),
                str(result.model_versions), self.mode, result.http_risk, False, self.sessions.clock()))
        return replace(result, decision_context={**result.decision_context, "context_mode": self.mode,
            "session_risk_before": previous, "endpoint_profile": profile, "context_applied_to_enforcement": self.mode == "simulation"})

    def adjudicate(self, request):
        output, timing = self.pipeline.adjudicate(request)
        if request.session_key:
            self.sessions.revise(request.session_key, RiskRevision(str(request.request_id), "deep:" + str(request.request_id),
                output.model_version, self.mode, output.risk, False, self.sessions.clock()))
        return output, timing

    def warm_deep_model(self):
        return self.pipeline.warm_deep_model()

    def close(self):
        close = getattr(self.pipeline,"close",None)
        if close:close()

    def batch_statistics(self):
        statistics = getattr(self.pipeline,"batch_statistics",None)
        return statistics() if statistics else {"enabled":False}

    def research_snapshot(self):
        with self.sessions.lock, self.profiles.lock:
            self.sessions._purge()
            return {"available":True,"mode":self.mode,"sessions_retained":len(self.sessions.sessions),
                "revisions_retained":sum(len(value[1]) for value in self.sessions.sessions.values()),
                "profile_version":self.profiles.version,"endpoints":len(self.profiles.profiles),
                "verified_profile_observations":len(self.profiles.seen),"persistence":"process-local; restart clears context"}
