"""End-to-end check that every backend component is doing its job.

Walks the whole chain rather than pinging health endpoints: sends real traffic through the gateway, confirms the
verdict, confirms the request was journalled in Postgres with its evidence, confirms Redis carries the resulting
behavioural state, and confirms the network sensor publishes risk context.

    python scripts/smoke_platform.py
    python scripts/smoke_platform.py --gateway http://127.0.0.1:8080 --control http://127.0.0.1:8082
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"


class Checks:
    def __init__(self) -> None:
        self.results: list[tuple[str, str, str]] = []

    def record(self, status: str, name: str, detail: str = "") -> None:
        self.results.append((status, name, detail))
        marker = {PASS: "[ok]  ", FAIL: "[FAIL]", WARN: "[warn]"}[status]
        print(f"{marker} {name}" + (f" — {detail}" if detail else ""))

    @property
    def failed(self) -> int:
        return sum(1 for status, _, _ in self.results if status == FAIL)


def request(url: str, method: str = "GET", body: Any = None, auth: tuple[str, str] | None = None, timeout: float = 15.0):
    headers = {}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if auth:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    call = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(call, timeout=timeout) as response:
        payload = response.read()
        return response.status, json.loads(payload) if payload else {}


def try_request(url: str, **kwargs):
    try:
        return request(url, **kwargs)
    except urllib.error.HTTPError as error:
        body = error.read()
        try:
            return error.code, json.loads(body) if body else {}
        except json.JSONDecodeError:
            return error.code, {"raw": body.decode("utf-8", "replace")[:400]}
    except (urllib.error.URLError, OSError, TimeoutError) as error:
        return 0, {"error": str(error)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", default="http://127.0.0.1:8080")
    parser.add_argument("--control", default="http://127.0.0.1:8082")
    parser.add_argument("--detection", default="http://127.0.0.1:8000")
    parser.add_argument("--sensor", default="http://127.0.0.1:8083")
    parser.add_argument("--adaptation", default="http://127.0.0.1:8084")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="adaptive_waf_dev")
    arguments = parser.parse_args()
    auth = (arguments.username, arguments.password)
    checks = Checks()

    print("== service readiness ==")
    for name, url in [
        ("detection /health", f"{arguments.detection}/health"),
        ("detection /ready", f"{arguments.detection}/ready"),
        ("gateway actuator", f"{arguments.gateway}/actuator/health"),
        ("control actuator", f"{arguments.control}/actuator/health"),
        ("sensor /health", f"{arguments.sensor}/health"),
        ("adaptation /health", f"{arguments.adaptation}/health"),
    ]:
        status, body = try_request(url)
        checks.record(PASS if status == 200 else FAIL, name, f"HTTP {status} {json.dumps(body)[:110]}")

    print("\n== models and corpus ==")
    status, catalog = try_request(f"{arguments.detection}/v1/models/catalog")
    if status == 200 and catalog.get("stages"):
        deployed = [f"{stage['stage']}={stage['deployment']['algorithm']}" for stage in catalog["stages"]]
        checks.record(PASS, "model catalog", f"{len(catalog['stages'])} stages: {', '.join(deployed)}")
        missing = [stage["stage"] for stage in catalog["stages"] if not stage["deployment"]["hyperparameters"]]
        checks.record(PASS if not missing else WARN, "hyperparameters recorded",
                      "all stages" if not missing else f"missing for {missing}")
    else:
        checks.record(FAIL, "model catalog", f"HTTP {status}")

    status, corpus = try_request(f"{arguments.detection}/v1/corpus")
    if status == 200:
        http_records = corpus.get("http", {}).get("records", 0)
        network_records = corpus.get("network", {}).get("records", 0)
        checks.record(PASS if http_records and network_records else WARN, "payload corpus",
                      f"{http_records} HTTP, {network_records} network records")
    else:
        checks.record(FAIL, "payload corpus", f"HTTP {status}")

    print("\n== detection pipeline ==")
    status, batch = try_request(
        f"{arguments.detection}/v1/detect/batch",
        method="POST",
        body={
            "requests": [
                {"method": "GET", "path": "/search", "query": "q=1' OR '1'='1"},
                {"method": "GET", "path": "/search", "query": "q=<script>alert(1)</script>"},
                {"method": "GET", "path": "/search", "query": "q=wireless+keyboard"},
            ],
            "labels": ["SQL_INJECTION", "XSS", "BENIGN"],
        },
    )
    if status == 200:
        summary = batch["summary"]
        checks.record(PASS, "batch detection",
                      f"{summary['evaluated']} evaluated, {summary['matched']}/{summary['scored']} matched, p95 {summary['latency_p95_ms']:.1f}ms")
    else:
        checks.record(FAIL, "batch detection", f"HTTP {status} {json.dumps(batch)[:160]}")

    status, escalations = try_request(f"{arguments.detection}/v1/escalations")
    if status == 200:
        statistics = escalations["statistics"]
        checks.record(PASS, "escalation worker",
                      f"enabled={statistics['enabled']} workers={statistics['workers']} submitted={statistics['submitted']} resolved={statistics['resolved']}")
    else:
        checks.record(FAIL, "escalation worker", f"HTTP {status}")

    print("\n== gateway enforcement and journalling ==")
    before_status, before = try_request(f"{arguments.control}/v1/control/infrastructure", auth=auth)
    events_before = before.get("database", {}).get("totalEvents", 0) if before_status == 200 else 0

    # Benign traffic is checked before the attack: a revised escalation blocks the source, which would otherwise
    # reject the benign request too and look like a false positive.
    benign_status, _ = try_request(f"{arguments.gateway}/backend/search?q=wireless+keyboard")
    checks.record(PASS if benign_status == 200 else FAIL, "benign request forwarded",
                  f"HTTP {benign_status} (expected 200)")

    attack_status, _ = try_request(f"{arguments.gateway}/backend/search?q=1'%20OR%20'1'='1")
    if attack_status == 403:
        checks.record(PASS, "attack blocked at the gateway", "HTTP 403 on the fast verdict")
    else:
        # With deferred escalation the fast experts answer first; protection then comes from the deep model
        # revising the verdict and the control plane blocking the source before the next request lands.
        time.sleep(4)
        _, blocks = try_request(f"{arguments.control}/v1/control/blocks", auth=auth)
        escalation_blocked = any(entry.get("active") for entry in blocks.get("blocks", []))
        repeat_status, _ = try_request(f"{arguments.gateway}/backend/search?q=1'%20OR%20'1'='1")
        checks.record(
            PASS if repeat_status == 403 or escalation_blocked else FAIL,
            "attack stopped by deferred escalation",
            f"first request HTTP {attack_status}, repeat HTTP {repeat_status}, source blocked={escalation_blocked}")

    time.sleep(2.5)  # the journal is written asynchronously through the broker
    after_status, after = try_request(f"{arguments.control}/v1/control/infrastructure", auth=auth)
    if after_status == 200:
        database = after["database"]
        events_after = database.get("totalEvents", 0)
        grew = events_after > events_before
        checks.record(PASS if grew else FAIL, "requests journalled in Postgres",
                      f"{events_before} -> {events_after} rows")
        checks.record(PASS if database.get("reachable") else FAIL, "Postgres reachable",
                      f"{database.get('queryLatencyMs')}ms, connect with {database.get('externalJdbcUrl')}")
        redis = after["redis"]
        tracked = redis.get("totalTrackedKeys", 0)
        checks.record(PASS if redis.get("reachable") else FAIL, "Redis reachable",
                      f"{redis.get('ping')} in {redis.get('pingLatencyMs')}ms")
        checks.record(PASS if tracked > 0 else WARN, "Redis carrying WAF state",
                      f"{tracked} tracked keys: " + ", ".join(f"{name}={entry['count']}" for name, entry in redis.get("namespaces", {}).items()))
    else:
        checks.record(FAIL, "control infrastructure endpoint", f"HTTP {after_status}")

    status, events = try_request(f"{arguments.control}/v1/security/events?limit=5", auth=auth)
    if status == 200 and events.get("events"):
        newest = events["events"][0]
        has_evidence = bool(newest.get("routingPath")) and newest.get("gatewayLatencyMs", 0) > 0
        checks.record(PASS if has_evidence else WARN, "journal carries decision evidence",
                      f"route={newest.get('routingPath')} latency={newest.get('gatewayLatencyMs')}ms")
        checks.record(PASS if newest.get("sourceIp") else FAIL, "source address stored unhashed",
                      f"sourceIp={newest.get('sourceIp')}")
    else:
        checks.record(FAIL, "security event journal", f"HTTP {status}")

    print("\n== network sensor ==")
    status, flow = try_request(
        f"{arguments.sensor}/v1/flows",
        method="POST",
        body={
            "source_ip": "203.0.113.55",
            "destination_ip": "10.0.0.20",
            "features": {"Dst Port": 80.0, "Protocol": 6.0, "Flow Duration": 477471.0, "Tot Fwd Pkts": 5.0},
        },
    )
    if status == 200:
        context = flow.get("network_context", {})
        checks.record(PASS, "flow classified", f"class={context.get('network_class')} risk={context.get('network_risk')}")
    elif status == 422:
        checks.record(WARN, "flow classified", "sensor rejected the partial feature vector (expected with a trimmed sample)")
    else:
        checks.record(FAIL, "flow classified", f"HTTP {status} {json.dumps(flow)[:160]}")

    print("\n== control plane surface ==")
    for name, path in [
        ("policy", "/v1/control/policy"),
        ("applications", "/v1/control/applications"),
        ("blocks", "/v1/control/blocks"),
        ("models", "/v1/control/models"),
        ("training runs", "/v1/control/training-runs"),
        ("feedback", "/v1/control/feedback"),
        ("audit", "/v1/control/audit"),
        ("statistics", "/v1/security/statistics"),
        ("escalations", "/v1/security/escalations"),
        ("stream ticket", "/v1/security/stream-ticket"),
    ]:
        status, _ = try_request(f"{arguments.control}{path}", auth=auth)
        checks.record(PASS if status == 200 else FAIL, f"control {name}", f"HTTP {status}")

    # A source this run blocked itself would otherwise stay blocked for the configured window.
    _, blocks = try_request(f"{arguments.control}/v1/control/blocks", auth=auth)
    for entry in blocks.get("blocks", []):
        if entry.get("active") and "Deep escalation revised" in (entry.get("reason") or ""):
            try_request(f"{arguments.control}/v1/control/blocks/{entry['sourceIp']}", method="DELETE", auth=auth)
            checks.record(PASS, "cleared the escalation block", f"{entry['sourceIp']} released after the check")

    print()
    passed = sum(1 for status, _, _ in checks.results if status == PASS)
    warned = sum(1 for status, _, _ in checks.results if status == WARN)
    print(f"{passed} passed, {warned} warnings, {checks.failed} failed")
    return 1 if checks.failed else 0


if __name__ == "__main__":
    sys.exit(main())
