"""Small matched-input diagnostic; never reads the reserved final dataset or trains a model."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import platform
import random
from time import perf_counter
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen
import uuid

from scripts.evaluate_phase10 import CASES

LABELS = {"benign": "BENIGN", "sqli": "SQL_INJECTION", "xss": "XSS", "traversal": "DIRECTORY_TRAVERSAL",
          "rce": "REMOTE_CODE_EXECUTION", "cookie": "COOKIE_INJECTION"}


def local_url(url):
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("use a local HTTP base URL without credentials, query or fragment")
    if parsed.hostname != "localhost":
        if not ipaddress.ip_address(parsed.hostname or "").is_loopback:
            raise ValueError("only locally controlled loopback endpoints are permitted")
    return url.rstrip("/")


def percentile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    lower = int(position)
    upper = min(len(ordered) - 1, lower + 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def summarize(rows, elapsed):
    completed = [r for r in rows if r["completed"]]
    inspected = [r for r in rows if r.get("inspection_status") == "FULLY_INSPECTED"]
    classified = [r for r in completed if r.get("predicted_attack") is not None]
    attacks = [r for r in rows if r["expected"] != "BENIGN"]
    benign = [r for r in rows if r["expected"] == "BENIGN"]
    def detected(row):
        return row.get("predicted_attack") not in (None, "BENIGN", "UNAVAILABLE", "SKIPPED", "UNKNOWN")
    tp = sum(detected(r) for r in attacks)
    fp = sum(detected(r) for r in benign)
    # Unavailable outcomes are explicitly counted as unresolved, never benign true negatives.
    unresolved = sum(not r["completed"] or r.get("inspection_status") in ("DETECTION_UNAVAILABLE", "PARTIALLY_INSPECTED", "UNKNOWN") for r in rows)
    per_class = {label: {"count": sum(r["expected"] == label for r in rows),
                         "exact_matches": sum(r["expected"] == label and r.get("predicted_attack") == label for r in rows)}
                 for label in sorted({r["expected"] for r in rows})}
    enforcement = {truth: {action: sum((r["expected"] != "BENIGN") == (truth == "attack") and r.get("action") == action for r in rows)
                           for action in ("ALLOW", "MONITOR", "RATE_LIMIT", "BLOCK", "UNKNOWN")}
                   for truth in ("attack", "benign")}
    result = {"request_count": len(rows), "completed_http_responses": len(completed),
            "http_success_2xx": sum(200 <= r["http_status"] < 300 for r in completed),
            "fully_inspected": len(inspected), "unresolved": unresolved,
            "completed_rps": len(completed) / elapsed, "fully_inspected_rps": len(inspected) / elapsed,
            "classified_count": len(classified),
            "exact_class_accuracy_all_submitted": sum(r.get("predicted_attack")==r["expected"] for r in rows)/len(rows) if rows and classified else None,
            "attack_detection_recall_all_submitted": tp / len(attacks) if attacks and classified else None,
            "benign_false_positive_rate_all_submitted": fp / len(benign) if benign and classified else None,
            "enforcement_confusion": enforcement, "classification_by_class": per_class,
            "partial_inspections": sum(r.get("inspection_status") == "PARTIALLY_INSPECTED" for r in rows),
            "fallback_or_bypass": sum(r.get("inspection_status") == "DETECTION_UNAVAILABLE" for r in rows),
            "latency_p50_ms": percentile([r["round_trip_ms"] for r in rows], .50),
            "latency_p95_ms": percentile([r["round_trip_ms"] for r in rows], .95),
            "latency_p99_ms": percentile([r["round_trip_ms"] for r in rows], .99),
            "elapsed_seconds": elapsed}
    if classified:
        from sklearn.metrics import precision_recall_fscore_support
        classes = sorted({row["expected"] for row in rows})
        precision, recall, f1, support = precision_recall_fscore_support(
            [row["expected"] for row in rows], [row.get("predicted_attack") or "UNAVAILABLE" for row in rows], labels=classes, zero_division=0)
        result["macro_f1"] = float(sum(f1) / len(f1))
        result["per_class"] = {label: {"precision": float(p), "recall": float(r), "f1": float(f), "support": int(n)}
                               for label,p,r,f,n in zip(classes,precision,recall,f1,support,strict=True)}
    result["enforcement_attack_containment_rate"] = sum(row.get("action") in {"BLOCK","RATE_LIMIT"} for row in attacks) / len(attacks) if attacks else None
    result["enforcement_benign_interruption_rate"] = sum(row.get("action") in {"BLOCK","RATE_LIMIT"} for row in benign) / len(benign) if benign else None
    return result


def invoke(mode, base, job):
    name, case = job
    request_id = str(uuid.uuid4())
    row = {"case_id": name, "request_id": request_id, "expected": LABELS.get(name,case.get("expected_attack")), "completed": False,
           "http_status": 0, "action": "UNKNOWN", "inspection_status": "UNKNOWN", "predicted_attack": None}
    if mode == "api":
        payload = {k: v for k, v in case.items() if k != "expected_attack"}
        payload["request_id"] = request_id
        request = Request(base + "/v1/detect", json.dumps(payload).encode(), method="POST",
                          headers={"Content-Type": "application/json", "X-Request-ID": request_id})
    else:
        query = case.get("query", "")
        # Preserve probe syntax and percent-encode only at the HTTP transport boundary.
        from urllib.parse import quote
        target = base + ("/backend" if mode == "gateway" else "") + str(case["path"])
        target += "?" + quote(query, safe="=&%") if query else ""
        headers = {**case.get("headers",{}),"X-Request-ID": request_id}
        if "cookies" in case:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in case["cookies"].items())
        request = Request(target, data=case["body"].encode("utf-8") if case.get("body") else None,
                          method=case.get("method","GET"), headers=headers)
    started = perf_counter()
    try:
        try:
            response = urlopen(request, timeout=35)
        except HTTPError as error:
            response = error  # HTTP errors are completed responses, not successful security inspections.
        with response:
            content = response.read(2_000_000)
            row.update(completed=True, http_status=response.code)
            if mode == "api" and response.code == 200:
                detection = json.loads(content)["detection"]
                rejected = str(detection.get("explanation_evidence", {}).get("deep_escalation", "")).startswith("rejected_")
                row.update(predicted_attack=detection["predicted_attack"],
                           inspection_status=detection.get("inspection_status") or ("PARTIALLY_INSPECTED" if detection.get("deep_escalation_pending") or rejected else "FULLY_INSPECTED"),
                           inference_ms=detection.get("total_latency_ms"), service_inference_ms=json.loads(content).get("service_inference_ms"),
                           routing_path=detection.get("routing_path"), model_versions=detection.get("model_versions"))
            elif mode == "api":
                row["inspection_status"] = "DETECTION_UNAVAILABLE"
            elif mode == "gateway":
                row.update(inspection_status=response.headers.get("X-WAF-Inspection-Status", "UNKNOWN"),
                           action=response.headers.get("X-WAF-Action", "UNKNOWN"))
                # Classification is unavailable for allowed gateway responses; never infer it from HTTP status.
    except (OSError, URLError, ValueError, KeyError) as error:
        row["error_type"] = type(error).__name__
    row["round_trip_ms"] = (perf_counter() - started) * 1000
    return row


def direct_jobs(jobs):
    from adaptive_waf.runtime.artifacts import load_adaptive_pipeline
    from adaptive_waf.contracts import HttpRequestRecord
    pipeline = load_adaptive_pipeline()
    rows = []
    started = perf_counter()
    for name, case in jobs:
        before = perf_counter()
        record = HttpRequestRecord(method="GET", path=case["path"], query=case.get("query", ""), cookies=case.get("cookies", {}))
        result = pipeline.detect(record)
        rows.append({"case_id": name, "expected": LABELS[name], "completed": True, "http_status": 0,
                     "action": "UNKNOWN", "inspection_status": "FULLY_INSPECTED", "predicted_attack": str(result.predicted_attack),
                     "risk": result.overall_risk, "routing_path": result.routing_path, "model_versions": result.model_versions,
                     "inference_ms": sum(result.latency_by_stage_ms.values()), "round_trip_ms": (perf_counter() - before) * 1000})
    return rows, perf_counter() - started


def local_api_jobs(jobs, workers):
    """Own one loopback-only HTTP server for the duration of a bounded diagnostic."""
    import socket
    from threading import Thread
    from time import sleep
    import uvicorn
    from adaptive_waf.service.app import create_app
    application = create_app()
    server = uvicorn.Server(uvicorn.Config(application, access_log=False, log_level="error"))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        base = "http://127.0.0.1:" + str(listener.getsockname()[1])
        thread = Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
        thread.start()
        try:
            deadline = perf_counter() + 30
            while not server.started:
                if not thread.is_alive() or perf_counter() > deadline:
                    raise RuntimeError("local detection fixture did not start within 30 seconds")
                sleep(.02)
            started = perf_counter()
            with ThreadPoolExecutor(max_workers=workers) as pool:
                rows = list(pool.map(lambda job: invoke("api", base, job), jobs))
            return rows, perf_counter() - started
        finally:
            server.should_exit = True
            thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("direct", "local-api", "api", "gateway", "backend"), required=True)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--seed", type=int, default=641)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 20 or not 1 <= args.workers <= 16:
        parser.error("repeats must be 1..20 and workers 1..16")
    if args.mode == "direct" and args.workers != 1:
        parser.error("direct diagnostic currently supports one worker")
    if args.output.exists():
        parser.error("output exists; select a new run identifier")
    base = local_url(args.url)
    jobs = list(CASES.items()) * args.repeats
    random.Random(args.seed).shuffle(jobs)
    if args.mode == "direct":
        rows, elapsed = direct_jobs(jobs)
    elif args.mode == "local-api":
        rows, elapsed = local_api_jobs(jobs, args.workers)
    else:
        started = perf_counter()
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            rows = list(pool.map(lambda job: invoke(args.mode, base, job), jobs))
        elapsed = perf_counter() - started
    root = Path(__file__).resolve().parents[1]
    hashes = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in sorted((root / "configs").rglob("*.toml"))}
    report = {"schema_version": 1, "created_at": datetime.now(timezone.utc).isoformat(), "mode": args.mode,
              "boundary": "pipeline call (first call may include lazy loading)" if args.mode == "direct" else "client HTTP round trip",
              "input_set": "phase10-six-development-probes-v1", "input_sha256": hashlib.sha256(json.dumps(CASES, sort_keys=True).encode()).hexdigest(),
              "seed": args.seed, "workers": args.workers, "config_sha256": hashes,
              "environment": {"python": platform.python_version(), "platform": platform.platform()},
              "limitations": ["Development diagnostics only; not held-out generalization evidence.",
                              "No hardware utilization sampling, uncertainty intervals, or final-test evaluation.",
                              "Gateway classification requires joining the persisted decision journal by request ID.",
                              "Direct mode has no HTTP responses; completed_http_responses counts completed pipeline calls there."],
              "metrics": summarize(rows, elapsed), "records": rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["metrics"], indent=2))


if __name__ == "__main__":
    main()
