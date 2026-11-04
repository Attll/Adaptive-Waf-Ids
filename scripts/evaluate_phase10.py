from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from statistics import quantiles
from time import perf_counter
from urllib.error import HTTPError
from urllib.request import Request, urlopen


CASES = {
    "benign": {"path": "/health", "expected_attack": False},
    "sqli": {"path": "/search", "query": "q=' OR 1=1--", "expected_attack": True},
    "xss": {"path": "/comment", "query": "text=<script>alert(1)</script>", "expected_attack": True},
    "traversal": {"path": "/download", "query": "file=../../etc/passwd", "expected_attack": True},
    "rce": {"path": "/run", "query": "cmd=;cat /etc/passwd", "expected_attack": True},
    "cookie": {"path": "/account", "cookies": {"session": "' OR 1=1--"}, "expected_attack": True},
}


def invoke(url: str, payload: dict[str, object]) -> tuple[float, bool, bool]:
    started = perf_counter()
    request_payload = {"path": payload["path"], "query": payload.get("query", ""), "cookies": payload.get("cookies", {})}
    request = Request(url, data=json.dumps(request_payload).encode(), method="POST", headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=20) as response:
            body = json.loads(response.read())
            attack = body["detection"]["predicted_attack"] != "BENIGN"
            return (perf_counter() - started) * 1000, attack, True
    except HTTPError:
        return (perf_counter() - started) * 1000, False, False
    except OSError:
        return (perf_counter() - started) * 1000, False, False


def percentile(values: list[float], value: float) -> float:
    return quantiles(values, n=100, method="inclusive")[int(value) - 1] if len(values) > 1 else values[0]


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Phase 10 traffic scenarios against the detection API.")
    parser.add_argument("--url", default="http://127.0.0.1:8000/v1/detect")
    parser.add_argument("--requests-per-case", type=int, default=10)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--output", type=Path, default=Path("research/results") / ("phase10-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json"))
    args = parser.parse_args()
    from scripts.research_probe import local_url
    local_url(args.url)
    if args.output.exists():
        parser.error("output exists; select a new run identifier")
    if not 1 <= args.requests_per_case <= 100 or not 1 <= args.workers <= 16:
        parser.error("requests-per-case must be 1..100 and workers 1..16")
    jobs = [(name, payload) for name, payload in CASES.items() for _ in range(args.requests_per_case)]
    # One concurrent batch of six repeated development probes; this does not establish multiple workloads.
    results = []
    started = perf_counter()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(invoke, args.url, payload): (name, payload) for name, payload in jobs}
        for future in as_completed(futures):
            name, payload = futures[future]
            latency, predicted_attack, available = future.result()
            results.append((name, bool(payload["expected_attack"]), predicted_attack, available, latency))
    duration = perf_counter() - started
    latencies = [row[4] for row in results]
    true_positive = sum(expected and actual for _, expected, actual, _, _ in results)
    false_positive = sum(not expected and actual for _, expected, actual, _, _ in results)
    false_negative = sum(expected and not actual for _, expected, actual, _, _ in results)
    true_negative = sum(not expected and not actual for _, expected, actual, _, _ in results)
    precision = true_positive / max(1, true_positive + false_positive)
    recall = true_positive / max(1, true_positive + false_negative)
    summary = {"total_requests": len(results), "available_requests": sum(row[3] for row in results), "scenarios": ["benign", "attack-heavy", "burst", "sustained", "mixed"], "latency_p50_ms": percentile(latencies, 50), "latency_p95_ms": percentile(latencies, 95), "latency_p99_ms": percentile(latencies, 99), "throughput_requests_per_second": len(results) / max(duration, .001), "precision": precision, "recall": recall, "f1": 2 * precision * recall / max(.000001, precision + recall), "false_positive_rate": false_positive / max(1, false_positive + true_negative), "false_negative_rate": false_negative / max(1, false_negative + true_positive), "architecture_variants": ["rules_only", "single_ml", "always_ensemble", "always_deep", "adaptive_hierarchy"], "adaptive_variants": ["hard_top1", "always_top2", "confidence_gated"], "ablations": ["without_behaviour", "without_network", "without_deep", "without_ensemble"]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    summary.update(measurement_schema_version=2, boundary="detection_api_client_round_trip",
                   scenarios=list(CASES), architecture_variants=["configured_runtime_only"], adaptive_variants=[], ablations=[],
                   limitations=["Six repeated development probes; not independent held-out samples.",
                                "Classification only; no gateway enforcement or inspection coverage measurement.",
                                "Unavailable responses count as missed attacks in the submitted-request recall."])
    args.output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__": main()
