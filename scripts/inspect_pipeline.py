from __future__ import annotations

import argparse
import json

from adaptive_waf.contracts import HttpRequestRecord
from adaptive_waf.runtime.artifacts import load_adaptive_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one HTTP request through the offline adaptive pipeline.")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--path", default="/")
    parser.add_argument("--query", default="")
    parser.add_argument("--body", default="")
    arguments = parser.parse_args()
    result = load_adaptive_pipeline().detect(HttpRequestRecord(arguments.method, arguments.path, arguments.query, body=arguments.body))
    print(json.dumps({"triage": result.triage_decision, "attack": result.predicted_attack, "route": result.routing_path, "http_risk": result.http_risk, "latencies_ms": result.latency_by_stage_ms}, default=str, indent=2))


if __name__ == "__main__":
    main()
