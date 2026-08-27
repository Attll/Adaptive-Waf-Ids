from __future__ import annotations

import argparse
import json

from adaptive_waf.contracts import BehaviourContext, HttpRequestRecord, NetworkContext
from adaptive_waf.runtime.artifacts import load_adaptive_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one HTTP request through the offline adaptive pipeline.")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--path", default="/")
    parser.add_argument("--query", default="")
    parser.add_argument("--body", default="")
    parser.add_argument("--behaviour-risk", type=float, default=0.0)
    parser.add_argument("--network-risk", type=float, default=0.0)
    parser.add_argument("--rule-risk", action="append", default=[], metavar="NAME=RISK")
    arguments = parser.parse_args()
    result = load_adaptive_pipeline().detect(
        HttpRequestRecord(arguments.method, arguments.path, arguments.query, body=arguments.body),
        behaviour_context=BehaviourContext(risk=arguments.behaviour_risk),
        network_context=NetworkContext(risk=arguments.network_risk),
        rule_evidence=_rule_evidence(arguments.rule_risk),
    )
    print(json.dumps({
        "triage": result.triage_decision,
        "attack": result.predicted_attack,
        "route": result.routing_path,
        "http_risk": result.http_risk,
        "behaviour_risk": result.behaviour_risk,
        "network_risk": result.network_risk,
        "overall_risk": result.overall_risk,
        "evidence": result.explanation_evidence,
        "latencies_ms": result.latency_by_stage_ms,
    }, default=str, indent=2))


def _rule_evidence(values: list[str]) -> dict[str, float]:
    evidence: dict[str, float] = {}
    for value in values:
        name, separator, risk = value.partition("=")
        if not separator or not name:
            raise ValueError("rule-risk must use NAME=RISK")
        evidence[name] = float(risk)
    return evidence


if __name__ == "__main__":
    main()
