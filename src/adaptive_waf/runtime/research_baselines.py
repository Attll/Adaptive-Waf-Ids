"""Explicit experimental comparators; these are not selectable deployment policies."""
from adaptive_waf.contracts import BehaviourContext,NetworkContext,DetectionResult,TriageDecision


class DeepOnlyControl:
    """Execute the saved deep model on every request, without fast/semantic early exits."""
    def __init__(self, baseline):
        self.baseline=baseline

    @property
    def model_versions(self):
        return {"deep":self.baseline.model_versions["deep"],"strategy":"deep-only-research-control-v1"}

    def detect(self,request,behaviour_context=None,network_context=None,rule_evidence=None):
        behaviour,network=behaviour_context or BehaviourContext(),network_context or NetworkContext()
        deep,duration=self.baseline.adjudicate(request)
        fusion=self.baseline._risk_fuser.fuse(deep.risk,behaviour,network,rule_evidence)
        return DetectionResult(request.request_id,request.received_at,0.,TriageDecision.SUSPICIOUS,None,(),
            deep.predicted_attack,deep.risk,behaviour.risk,network.risk,fusion.overall_risk,
            ("DEEP_ONLY_RESEARCH_CONTROL","DEEP_ESCALATION","POLICY_PENDING"),{"deep":duration},self.model_versions,
            {"classification_source":"DEEP_ONLY_RESEARCH_CONTROL","triage":"not_executed"},deep_model_used=True,deep_output=deep,
            decision_context={"route":"DEEP_ONLY_RESEARCH_CONTROL","inspection_status":"FULLY_INSPECTED",
                "reason":"research_comparator_all_requests_deep","semantic_guards_enabled":False})
