from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from adaptive_waf.contracts import PolicyAction, PolicyDecision


@dataclass(frozen=True, slots=True)
class PolicyThresholds:
    allow_max_risk: float
    monitor_max_risk: float
    rate_limit_max_risk: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.allow_max_risk < self.monitor_max_risk < self.rate_limit_max_risk <= 1.0:
            raise ValueError("policy thresholds must be strictly increasing values between 0 and 1")


class OfflinePolicySimulator:
    """Temporary Phase 1 policy evaluator; it has no enforcement side effects."""

    def __init__(self, policy_version: str, thresholds: PolicyThresholds) -> None:
        if not policy_version.strip():
            raise ValueError("policy version must not be blank")
        self.policy_version = policy_version
        self._thresholds = thresholds

    def evaluate(self, overall_risk: float, evidence: Mapping[str, str] | None = None) -> PolicyDecision:
        if not 0.0 <= overall_risk <= 1.0:
            raise ValueError("overall risk must be between 0 and 1")
        action = self._action_for(overall_risk)
        primary_source = _primary_source(evidence or {})
        return PolicyDecision(
            action=action,
            overall_risk=overall_risk,
            policy_version=self.policy_version,
            reasons=(f"overall_risk={overall_risk:.6f}", f"primary_evidence={primary_source}"),
        )

    def _action_for(self, risk: float) -> PolicyAction:
        if risk <= self._thresholds.allow_max_risk:
            return PolicyAction.ALLOW
        if risk <= self._thresholds.monitor_max_risk:
            return PolicyAction.MONITOR
        if risk <= self._thresholds.rate_limit_max_risk:
            return PolicyAction.RATE_LIMIT
        return PolicyAction.BLOCK


def _primary_source(evidence: Mapping[str, str]) -> str:
    candidates: list[tuple[float, str]] = []
    for name, raw_value in evidence.items():
        if not name.startswith("fusion_") or not name.endswith("_risk") or name == "fusion_overall_risk":
            continue
        try:
            candidates.append((float(raw_value), name.removeprefix("fusion_").removesuffix("_risk")))
        except ValueError:
            continue
    return max(candidates, default=(0.0, "none"))[1]
