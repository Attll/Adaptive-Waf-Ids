# Adaptive WAF-IDS Docker release verification — 30 October 2026

The local Dockerized engineering stack is operational under the executed acceptance scope. All seven application images and four infrastructure images build/start; an exported bundle was loaded and started in a second isolated project without build/pull. This is not production certification or completion of the independent research evaluation.

## Services and images

| Service | Release image | Internal port | Acceptance host port | Size MiB | Result |
|---|---|---:|---:|---:|---|
| redis | `adaptive-waf-ids/vendor-redis:1.0.0` | 6379 | internal | 15.5 | Healthy / integrated |
| rabbitmq | `adaptive-waf-ids/vendor-rabbitmq:1.0.0` | 5672 | internal | 82.0 | Healthy / integrated |
| postgres | `adaptive-waf-ids/vendor-postgres:1.0.0` | 5432 | internal | 110.7 | Healthy / integrated |
| gateway | `adaptive-waf-ids/gateway:1.0.0` | 8080 | 18080 | 149.9 | Healthy / integrated |
| control | `adaptive-waf-ids/control:1.0.0` | 8082 | 18082 | 170.5 | Healthy / integrated |
| demo | `adaptive-waf-ids/demo:1.0.0` | 8081 | internal | 128.0 | Healthy / integrated |
| dashboard | `adaptive-waf-ids/dashboard:1.0.0` | 80 | 13000 | 20.1 | Healthy / integrated |
| detection | `adaptive-waf-ids/detection:1.0.0` | 8000 | 18000 | 918.2 | Healthy / integrated |
| sensor | `adaptive-waf-ids/sensor:1.0.0` | 8083 | 18083 | 154.5 | Healthy / integrated |
| adaptation | `adaptive-waf-ids/adaptation:1.0.0` | 8084 | 18084 | 151.4 | Healthy / integrated |
| crs | `adaptive-waf-ids/vendor-crs:1.0.0` | 8080 | 18090 | 90.1 | Healthy / integrated |

Exact IDs/digests and sizes: `releases/adaptive-waf-ids-1.0.0-final/image-manifest.json`. Published ports are loopback; the source example defaults to 8080/8000/8082/3000/8083/8084/8090. Acceptance uses alternate ports to avoid collisions. No source or model bind mounts are required.

## Executed evidence

- V32: Python 135, Java gateway/control/demo 33/10/2, dashboard TypeScript + production build pass. V31 found stopped research fixtures; V32 started only the owned fixtures and passed with no assertions weakened.
- V47: 29 platform smoke passes, one expected warning for the intentionally partial flow. V48 and V50 pass all eight additional end-to-end checks using a full sampled flow.
- Five diagnostic attacks return 403 under explicit `guarded_fixed`; benign returns 200; every request correlates with the PostgreSQL journal. These attacks are rule-assisted, not model-only accuracy.
- Durable RabbitMQ/PostgreSQL jobs complete with model versions; workers are inside detection. V38 retains original job IDs through volume-preserving shutdown/start, tests real detection/Redis/RabbitMQ outage and recovery. Detection outage returns 503; Redis outage permits forwarding without Redis behavioral enforcement; broker outage returns 503 for a deferred path. No durable gateway event disk spool is claimed.
- V51: policy propagation, burst HTTP 429, restored policy, temporary block HTTP 403 and expiry back to HTTP 200 all pass.
- V52: an ephemeral container refuses startup after its own model copy is removed; all host/model image artifacts remain intact. Curated packaging verifies 18 original baseline hashes and includes selected catalog metadata; detection and sensor validate packaged manifests before serving.
- V43: actual CPU deep inference inside detection. V39: Docker NVIDIA access verified using the existing CUDA image; the separate GPU release override is prepared but not built or accepted.
- V55: installed Edge headless browser authenticates and navigates 17 actual dashboard pages; screenshots and page/error/stream evidence are retained. The initial browser selector used the heading instead of the Continue button; it was corrected without changing the application.
- V44/V45/V50: all bundle checksums and 11 imported image IDs verified; independent deployment starts with `--no-build --pull never` and passes gateway, journal, network, auth proxy and completed-job checks.

## Final diagnostic performance

| Client concurrency | Requests | p50 / p95 / p99 ms | HTTP completions/s | Fully inspected/s | Rule-only |
|---|---:|---|---:|---:|---:|
| 1 | 6 | 12.83 / 74.69 / 87.15 | 35.30 | 0.00 | 5 |
| 4 | 6 | 78.70 / 90.95 / 91.72 | 55.52 | 0.00 | 5 |

One six-probe pass per setting, not sustained capacity or independent accuracy. Each setting has five rule-only decisions and one provisional/partially inspected benign request awaiting deep evidence. Rule-assisted attack recall is 5/5 and observed FP is 0/1 per setting; these tiny counts cannot establish generalization/FPR. No inline fully inspected throughput is claimed. CPU/RAM snapshot: `docker-resources-v49.jsonl`; it is not a time-integrated resource experiment. Stage latency/queue state are exposed in runtime telemetry. Microbatching stays disabled because previous actual gateway trials worsened p95.

## Training and research

New dataset training time: **0 minutes**. Additional training was skipped as optional: very few independent attack templates cannot support meaningful release validation, and packaging takes priority. The 60-minute cumulative cap was respected. Existing artifacts are retained, no candidate or RL policy is activated. The older 90-minute plan is superseded. Conformal calibration, learned-policy evaluation, generalization and corresponding ablations remain blocked by appropriate disjoint verified populations; endpoint/session features remain experimental. Full stage 0–14 classification is in `implementation_status.md`.

## Portable package and commands

Final archive: `releases/adaptive-waf-ids-1.0.0-final/images.tar` (1,548,018,176 bytes); checksums and exact image manifest sit alongside it. The earlier first export is preserved separately. No `.env`, real credentials, raw datasets, host virtualenv or Git history are exported. GPU wheels/images are not included in this CPU bundle.

```powershell
.\scripts\release.ps1 Build
.\scripts\release.ps1 Start -Project adaptive-waf-release-acceptance
.\scripts\release.ps1 Health -Project adaptive-waf-release-acceptance
.\scripts\release.ps1 Smoke
.\.venv\Scripts\python.exe -m scripts.accept_release --output research/runs/new-release-check.json
.\scripts\verify_research.ps1 -RunId new-release-suite -Integration
.\scripts\release.ps1 Export -Bundle releases/new-release-export
docker load -i releases/adaptive-waf-ids-1.0.0-final/images.tar
# Inside the exported directory, create a private .env from .env.example first:
docker compose --env-file .env up -d --no-build --pull never --wait
docker compose down
```

Source build requires network/cache for pinned base images and dependencies. Bundle import is the tested offline runtime path. Full-suite integration requires owned research fixtures running (`docker compose -p adaptive-waf-research -f research/compose.integration.yml up -d --pull never`). Select new run/output IDs; existing evidence is never overwritten.

## Remaining limits

No claim of exhaustive dependency partitions, exact-once publication, production TLS/role/exposure certification, cross-dataset model accuracy, live learned routing, native CICFlowMeter parity or fully tested GPU release. Browser navigation is covered; exhaustive per-control destructive/security workflows and every role/disconnection combination remain outside acceptance. Model catalog promotion is administrative metadata; runtime replacement uses a reviewed versioned image/manifest with rollback to the retained previous image ID. Persistent database/broker backups remain an operator responsibility.

## Handoff state

Primary project `adaptive-waf-release-acceptance` remains running with all 11 services healthy. Dashboard http://127.0.0.1:13000; gateway http://127.0.0.1:18080/backend/. Private credentials are in the ignored `infra/docker/release/.env`. The extra imported project was stopped without volume deletion; owned research fixtures were stopped. Run `Start/Health/Logs/Stop` with `-Project adaptive-waf-release-acceptance` to manage this already-running demonstration. Source verification fixtures must be started again before `-Integration`. Release implementation commit: `3a85915`.

## Login correction — 30 October 2026

The release login screen offered a hardcoded `Use local credentials` autofill for an obsolete demo password, while the release uses a private generated administrator password. Actual proxy checks returned 200 for the configured account and 401 for the autofill. Removed the misleading button and added configured-account guidance. Dashboard image `adaptive-waf-ids/dashboard:1.0.1` is deployed; TypeScript/production build and real Edge login/Overview checks pass with zero JavaScript errors (`runs/login-browser-v1.json`). No account/password/data was reset. The previously exported 1.0.0 bundle is preserved and retains the old UI; use its configured credentials, or rebuild/export from the updated source for the corrected screen.

Copy the local release password without printing it:

```powershell
(Get-Content infra/docker/release/.env | Where-Object { $_ -like 'ADMIN_PASSWORD=*' }) -replace '^ADMIN_PASSWORD=', '' | Set-Clipboard
```

Username is the ADMIN_USERNAME value (currently admin). Current dashboard URL: http://127.0.0.1:13000.

## Requested dev administrator and login cleanup — 30 October 2026

Removed the configured-credentials guidance from the login page and deployed dashboard image `adaptive-waf-ids/dashboard:1.0.2`. Created the explicitly requested `dev` administrator in the persistent release PostgreSQL `admin_users` table with a BCrypt password hash and existing ADMIN role. The original administrator remains intact. Account creation is recorded in `audit_log`; the account is database state, not an automatically seeded image credential. It persists with the release database volume.

TypeScript/production build passed. Actual dev login succeeds in Edge, guidance is absent, and zero JavaScript errors were observed (`runs/login-dev-browser-v1.json`). Administrator-only policy/model/audit/block/event API reads through the dashboard proxy all returned 200 (`runs/login-dev-admin-api-v1.json`). Previously exported image archives remain unchanged; their login-page versions are historical.

## Connected operator tools — 30 October 2026

Implemented and deployed v1.1.0 operator workflows: correlated HTTP Generator replay with headers/cookies/body preservation; shared console runs; monotonic all-time Overview counts and lightweight streamed statistics; authenticated read-only Redis key/value sampling; calibrated deployed-model and raw-candidate queries with template suites; persistent paginated deep jobs/results; bounded offline three-seed constrained/unconstrained RL training with saved policies; and a direct-gateway Timing page. See `operator_tools.md` for limits, exact evidence and reproduction.

Full `operator-tools-final-v5`: 141 Python tests, Java 33 gateway / 13 control / 2 demo, zero failures and dashboard build pass with real dependency integration. Final UI changes also pass TypeScript/build and the complete browser handoff. HTTP checks cover all 21 model selections, request/event joins, Redis values, cookie evidence, RL fitting and saved-report retrieval. Browser checks cover all requested cross-page flows, deep class probabilities and both 120- and 1,000-request timing runs; actual overload/enforcement results are retained, not hidden. Saved RL reports survived an adaptation restart and paginated jobs had disjoint IDs.

RL validation is controlled simulation with prescribed outcomes/costs; representative learned-routing effectiveness remains unproven. No live learned policy was activated. All original baseline artifacts remain intact. Previous failed checks, download hash rejection and fixes are preserved. The primary stack retains existing accounts and data; earlier portable archives are historical and have not been overwritten.
