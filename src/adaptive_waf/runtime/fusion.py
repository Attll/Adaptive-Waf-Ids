from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from adaptive_waf.contracts import BehaviourContext, NetworkContext


@dataclass(frozen=True, slots=True)
class FusionResult:
    overall_risk: float
    supporting_evidence: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class DeterministicRiskFusion:
    """Replaceable, normalized weighted-max evidence fusion for Phase 1."""

    source_weights: Mapping[str, float]
    supporting_evidence_minimum_risk: float = 0.20

    def __post_init__(self) -> None:
        expected = {"http", "behaviour", "network", "rule"}
        if set(self.source_weights) != expected:
            raise ValueError("fusion source_weights must define http, behaviour, network, and rule")
        if not 0.0 <= self.supporting_evidence_minimum_risk <= 1.0:
            raise ValueError("supporting evidence minimum risk must be between 0 and 1")
        for name, weight in self.source_weights.items():
            if not 0.0 <= weight <= 1.0:
                raise ValueError(f"fusion weight for {name} must be between 0 and 1")

    def fuse(
        self,
        http_risk: float,
        behaviour_context: BehaviourContext | None = None,
        network_context: NetworkContext | None = None,
        rule_evidence: Mapping[str, float] | None = None,
    ) -> FusionResult:
        raw_risks = {
            "http": http_risk,
            "behaviour": (behaviour_context or BehaviourContext()).risk,
            "network": (network_context or NetworkContext()).risk,
        }
        rules = rule_evidence or {}
        for name, value in {**raw_risks, **{f"rule:{name}": value for name, value in rules.items()}}.items():
            _validate_normalized_risk(name, value)

        weighted_risks = {
            name: value * self.source_weights[name]
            for name, value in raw_risks.items()
        }
        weighted_risks.update({f"rule:{name}": value * self.source_weights["rule"] for name, value in rules.items()})
        overall_risk = max(weighted_risks.values(), default=0.0)
        supporting = {
            f"fusion_{name}_risk": f"{risk:.6f}"
            for name, risk in weighted_risks.items()
            if risk >= self.supporting_evidence_minimum_risk
        }
        if not supporting:
            source, risk = max(weighted_risks.items())
            supporting[f"fusion_{source}_risk"] = f"{risk:.6f}"
        supporting["fusion_strategy"] = "weighted_max_v1"
        supporting["fusion_overall_risk"] = f"{overall_risk:.6f}"
        return FusionResult(overall_risk=overall_risk, supporting_evidence=supporting)


def _validate_normalized_risk(name: str, value: float) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} risk must be between 0 and 1")
