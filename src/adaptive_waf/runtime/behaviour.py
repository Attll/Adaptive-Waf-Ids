from __future__ import annotations

from adaptive_waf.contracts import BehaviourContext


def combine_http_and_behaviour_risk(http_risk: float, context: BehaviourContext) -> float:
    return max(http_risk, context.risk)


def behaviour_evidence(context: BehaviourContext) -> dict[str, str]:
    return {
        "behaviour_risk": f"{context.risk:.6f}",
        "behaviour_requests_short_window": str(context.requests_per_short_window),
        "behaviour_failed_auth_attempts": str(context.failed_auth_attempts),
        "behaviour_previous_attack_count": str(context.previous_attack_count),
    }
