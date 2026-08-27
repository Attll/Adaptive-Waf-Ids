from __future__ import annotations

import argparse
import json

from adaptive_waf.contracts import BehaviourContext, DetectionResult, HttpRequestRecord, NetworkContext, PolicyDecision
from adaptive_waf.runtime.artifacts import load_adaptive_pipeline, load_offline_policy_simulator


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
    policy = load_offline_policy_simulator().evaluate(result.overall_risk, result.explanation_evidence)
    print(json.dumps(_inspection_payload(arguments, result, policy), default=str, indent=2))


def _inspection_payload(arguments: argparse.Namespace, result: DetectionResult, policy: PolicyDecision) -> dict[str, object]:
    return {
        "input": {
            "method": arguments.method,
            "path": arguments.path,
            "query": arguments.query,
            "body_length": len(arguments.body),
            "behaviour_risk": arguments.behaviour_risk,
            "network_risk": arguments.network_risk,
        },
        "triage": {"decision": result.triage_decision, "suspicious_probability": result.triage_score},
        "router": None if result.router_output is None else {
            "probabilities": result.router_output.scores,
            "selected_experts": result.router_output.selected_experts,
        },
        "fast_expert_results": [_expert_payload(output) for output in result.expert_outputs],
        "ensemble": {"executed": result.ensemble_used, "result": None},
        "deep": {"executed": result.deep_model_used, "result": None if result.deep_output is None else _deep_payload(result.deep_output)},
        "predicted_attack": result.predicted_attack,
        "risks": {"http": result.http_risk, "behaviour": result.behaviour_risk, "network": result.network_risk, "overall": result.overall_risk},
        "simulated_policy": {"action": policy.action, "version": policy.policy_version, "reasons": policy.reasons},
        "models_used": result.model_versions,
        "routing_path": result.routing_path,
        "latency_by_stage_ms": result.latency_by_stage_ms,
        "total_latency_ms": sum(result.latency_by_stage_ms.values()),
        "evidence": result.explanation_evidence,
    }


def _expert_payload(output) -> dict[str, object]:
    return {
        "family": output.family,
        "predicted_attack": output.predicted_attack,
        "confidence": output.confidence,
        "risk": output.risk,
        "class_scores": output.class_scores,
        "model_version": output.model_version,
    }


def _deep_payload(output) -> dict[str, object]:
    return {
        "predicted_attack": output.predicted_attack,
        "confidence": output.confidence,
        "risk": output.risk,
        "class_scores": output.class_scores,
        "model_version": output.model_version,
    }


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
