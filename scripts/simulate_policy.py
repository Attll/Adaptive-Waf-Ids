from __future__ import annotations

import argparse
import json
from pathlib import Path

from adaptive_waf.runtime.artifacts import load_offline_policy_simulator


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a normalized risk with the Phase 1 offline policy simulator.")
    parser.add_argument("--overall-risk", required=True, type=float)
    parser.add_argument("--evidence", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--core-config", type=Path, default=None)
    arguments = parser.parse_args()
    evidence = _evidence(arguments.evidence)
    decision = load_offline_policy_simulator(arguments.core_config).evaluate(arguments.overall_risk, evidence)
    print(json.dumps({
        "action": decision.action,
        "overall_risk": decision.overall_risk,
        "policy_version": decision.policy_version,
        "reasons": decision.reasons,
    }, default=str, indent=2))


def _evidence(values: list[str]) -> dict[str, str]:
    evidence: dict[str, str] = {}
    for value in values:
        name, separator, risk = value.partition("=")
        if not separator or not name:
            raise ValueError("evidence must use NAME=VALUE")
        evidence[name] = risk
    return evidence


if __name__ == "__main__":
    main()
