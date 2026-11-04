# Connected operator tools — 30 October 2026

Open http://127.0.0.1:13000 and refresh the page to load dashboard 1.1.0. The existing administrator and requested dev account are preserved.

## Shared request information

Generator now sends HTTP templates through an authenticated, fixed-destination replay endpoint. It preserves cookies, content type, raw query evidence and supported bodies, returns a request ID, and waits for the asynchronous journal before its final refresh. Progress and completed runs are shared with Overview. Network runs are recorded separately from HTTP traffic.

Streamed requests update the retained request list immediately and refresh statistics in a bounded lightweight call. Older refresh responses cannot replace newer counts/events. Delayed escalation revisions are excluded from HTTP request counts. Overview has an all-time persisted request counter; its detection/latency charts are explicitly recent-window views. Retained request/run lists are bounded, not the entire database history.

## New pages

| Page | Operation |
|---|---|
| Redis Cache | Read-only `waf:*` keys, Redis types, TTL and actual values. Refresh and scan-offset pagination; collection values are limited samples and strings are capped at 2,048 characters. Expiring/changing keys can move during scanning. |
| Model Lab | Select any deployed HTTP/network model or existing trained classical candidate. Query editable request arrays or load attack/benign suites and network samples. See per-role expected/predicted labels, matches, probability vectors, measured inference time and artifact identity. Deployed queries use runtime calibration; explicitly selected raw candidates are labeled accordingly. |
| RL Training | Run controlled validation immediately, or upload separate reviewed development/evaluation outcome matrices. Fits constrained/unconstrained LinUCB for seeds 641/642/643. Compare rewards with common static routes, load saved reports, and retain individually loadable policy artifacts. |
| Timing | Send up to 10,000 requests with concurrency 1–32 and a 120-second dispatch budget. Stop prevents new dispatch; in-flight work completes or times out. Browser-to-gateway latency, p50/p95/p99, response/success/error/block counts and matched inspection coverage are reported. Export contains full-run aggregates plus up to 200 retained response samples. |
| Escalations | Page through persistent jobs, including pending/running/completed/failed/expired. Expand completed outcomes to see original/revised verdicts, class probabilities, queue/deep latency, request IDs and model versions. Raw payloads remain redacted according to existing retention rules. |
| Training / Overview | Show shared console activity and offline routing runs. Training also loads persisted routing history after a reload. |

Direct model probes are not gateway traffic and do not inflate HTTP charts. Timing uses the actual gateway with enforcement enabled. A blocked or unavailable response is not a fully inspected decision. Inspection totals are lower bounds when only a recent journal window can be matched. There is no claim that the default timing run measures fully inspected model capacity.

## Offline RL input and safeguards

The input object has `review_reference`, `model_versions`, `development` and `evaluation`. Each role has 1–1,000 rows, with IDs and application/template/session groups disjoint across roles. Rows require:

```json
{
  "request_id": "reviewed-request-id",
  "group_id": "application/template/session-group",
  "population": "development",
  "label_source": "VERIFIED",
  "expected": "XSS",
  "pre_action_context": {"fast_risk": 0.8, "entropy": 0.8, "margin": 0.1},
  "outcomes": {
    "BOTH": {"predicted": "XSS", "latency_ms": 12.5, "compute_cost": 0.02}
  }
}
```

This is a schema illustration, not measured data. Supply actual reviewed labels and measured route outcomes; do not convert predictions into VERIFIED truth. Context values must be normalized to 0–1. Supported actions are FAST_ONLY, BOTH, SYNC_DEEP, DEFERRED_DEEP and RULES_ONLY. Comparisons can only cover actions with measured outcomes; constrained training rejects populations without a safe available route. Uploads are capped at 2 MB. One fit runs at a time with a 20-second replay deadline and a 200-run artifact capacity. No policy is deployed automatically.

Controlled validation explicitly uses a deterministic simulated environment with prescribed costs. It validates fitting, serialization, disjoint roles, safety masks and UI integration; it does **not** establish real-world detection accuracy, hardware latency or an adaptive-policy advantage. Existing representative calibration/policy-data blockers remain.

Routing reports and six version-pinned policy files are saved under the adaptation volume's `routing/<run-id>/` directory. The model-version mapping is retained for later reviewed loading; simulation policies are incompatible with actual detector versions and must not be promoted. Live activation remains disabled.

## Verification

- Full `operator-tools-final-v5`: 141 Python, Java 33 gateway / 13 control / 2 demo, zero failures; dashboard type check and production build pass.
- Real HTTP `operator-tools-http-v6` and `operator-tools-http-final`: authenticated Redis values, cookie-bearing replay, journal joins, all 21 model selections (16 distinct trained artifacts, including deployed/raw choices), controlled RL fitting and saved report retrieval pass.
- Browser `operator-tools-browser-v2`: Generator → Overview, cache values, all HTTP models, RL → Training, a 120-request timing run, persistent job rows and expanded deep probabilities pass with no JavaScript errors.
- Browser `operator-tools-browser-final`: same workflow with 1,000 requests. Actual observations: 1,000 responses in 14.522 seconds; 68.86 responses/s; p50/p95/p99 20.40/253.10/666.00 ms. Outcomes: 32 successful 2xx, 961 HTTP 403, one 429 and six errors. The recent journal window matched 500 requests; the last 200 all matched. Zero fully inspected requests were observed in that retained window. These are policy-enforced workload diagnostics, not independent accuracy or model-throughput findings.
- Final smaller browser handoff checks follow the lighter streamed-statistics refresh and sample-retention clarification. Earlier failed checks remain retained, including the Redis response-shape mismatch, service-proxy transport issue, deep config key/error-handler defect and premature browser row assertion. They were fixed; assertions were not weakened.
- A runtime download initially failed pip's hash verification. Hash checking remained enabled; retry succeeded. Python dependency layers no longer depend on application source changes, avoiding repeated runtime downloads on ordinary updates.
- Gateway service-client DNS caching is bounded to five seconds, allowing recovery after replacing internal service containers without retrying protected requests.

The existing 18 baseline artifacts were verified unchanged when staging the additional already-trained candidate models. No new supervised model training or live learned-policy promotion occurred. All UI additions reuse existing panels, metrics, tables, badges and styling.

## Reproduction

```powershell
docker compose -p adaptive-waf-research -f research/compose.integration.yml up -d --pull never
.\scripts\verify_research.ps1 -RunId operator-tools-new-check -Integration
.\.venv\Scripts\python.exe -m scripts.verify_operator_tools --output research/runs/operator-tools-new-http
# Optional browser dependency, installed only in ignored build tooling:
npm.cmd install --prefix release-build/browser playwright-core --no-audit --no-fund
$env:WAF_BROWSER_REPORT_ROOT='research/runs/operator-tools-new-browser'
$env:WAF_TIMING_REQUESTS='120'
node scripts/browser_operator_tools.cjs
```

Select new output IDs; historical results are preserved. Browser checks use installed Edge and the existing dev account. Updated running images are gateway/control/detection/adaptation/dashboard 1.1.0; previous images and older portable archives remain untouched. To export the updated stack, use `scripts/release.ps1 Export -Bundle releases/adaptive-waf-ids-1.1.0` with a new directory. Database accounts and routing artifacts live in persistent volumes, not in image archives.

Final handoff browser checks passed after the lighter statistics refresh and recent-event merge. Persistence checks in `operator-tools-persistence-final.json` confirm saved policy files survive adaptation restart, two deep-job pages have disjoint IDs, and a 1.1 MB upload reaches the application validator through the dashboard proxy (422 for invalid schema, rather than a proxy-size rejection).
