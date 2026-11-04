"""Bounded shadow monitoring. Unlabeled observations never become supervised labels."""
from collections import OrderedDict
from threading import RLock
import math
from adaptive_waf.adaptation.drift import population_stability_index


class EvidenceMonitor:
    def __init__(self, capacity=1000):
        if capacity<=0:
            raise ValueError("positive monitoring capacity required")
        self.capacity,self.rows,self.lock=capacity,OrderedDict(),RLock()
        self.reference=None

    def record(self, result):
        confidence=result.deep_output.confidence if result.deep_output else max((output.confidence for output in result.expert_outputs),default=None)
        decision=result.decision_context
        row={"request_id":str(result.request_id),"prediction":str(result.predicted_attack),"risk":result.overall_risk,
            "confidence":confidence,"verified_label":None,"review_reference":None,
            "uncertainty":decision.get("uncertainty",{}),"model_versions":dict(result.model_versions)}
        with self.lock:
            if row["request_id"] in self.rows:
                return
            self.rows[row["request_id"]]=row
            while len(self.rows)>self.capacity:
                self.rows.popitem(last=False)

    def feedback(self, identifier, label, review_reference):
        from adaptive_waf.contracts import AttackClass
        if label not in {str(item) for item in AttackClass} or not review_reference:
            raise ValueError("recognized verified class and review reference required")
        with self.lock:
            if identifier not in self.rows:
                raise ValueError("observation no longer retained; cannot join feedback")
            self.rows[identifier].update(verified_label=label,review_reference=review_reference)

    def set_reference(self, values, review_reference):
        if len(values)<20 or len(values)>self.capacity or not review_reference or any(not math.isfinite(value) or not 0<=value<=1 for value in values):
            raise ValueError("reviewed reference requires 20..capacity finite risk observations in [0,1]")
        with self.lock:
            self.reference=tuple(values)

    def candidates(self, limit=20):
        with self.lock:
            rows=[row for row in self.rows.values() if row["verified_label"] is None and row["confidence"] is not None]
            return [{"request_id":r["request_id"],"prediction":r["prediction"],"confidence":r["confidence"],"model_versions":r["model_versions"]}
                for r in sorted(rows,key=lambda row:row["confidence"])[:max(1,min(limit,100))]]

    def snapshot(self):
        with self.lock:
            rows=list(self.rows.values())
            verified=[row for row in rows if row["verified_label"] is not None and row["confidence"] is not None]
            ece=0.
            for index in range(10):
                group=[row for row in verified if index/10<=row["confidence"] and (row["confidence"]<(index+1)/10 or index==9)]
                if group:
                    accuracy=sum(r["prediction"]==r["verified_label"] for r in group)/len(group)
                    confidence=sum(r["confidence"] for r in group)/len(group)
                    ece+=len(group)/len(verified)*abs(accuracy-confidence)
            sets=[row["uncertainty"]["prediction_set"] for row in rows if "prediction_set" in row["uncertainty"]]
            return {"retained":len(rows),"verified_labels":len(verified),"verified_ece":ece if verified else None,
                "risk_psi":population_stability_index(self.reference,[row["risk"] for row in rows]) if self.reference and len(rows)>=20 else None,
                "conformal_set_count":len(sets),"conformal_mean_set_size":sum(map(len,sets))/len(sets) if sets else None,
                "bandit_reward":None,"reason":"No verified bandit rewards ingested; monitoring never trains or promotes policies",
                "reference_available":self.reference is not None,"automatic_policy_change":False}
