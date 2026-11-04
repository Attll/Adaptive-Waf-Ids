# Baseline audit — 28 October 2026

This is a staged implementation checkpoint, not evidence that the complete research system is finished. The original executable baseline is Git revision `12a6a4a` (`rf1`). Work is isolated on `codex/research-backend-stabilization`. The initially untracked `README.md` and `adaptive-waf-codebase.zip` belong to the user and are excluded from implementation commits. Existing datasets, training runs, deployment configurations and historical metrics are preserved.

## Architecture and feature inventory before changes

| Component | Existing implementation | Verified limitation before changes |
|---|---|---|
| Gateway | Spring Boot 3.4.5 / Spring Cloud Gateway 2024.0.1; `/backend/**` strips one prefix | Redis timeout enclosed detection and upstream execution; broad recovery handlers could forward again |
| HTTP inspection | Bounded-by-header body caching; canonical Python features; six HTTP classes | Unknown Content-Length skipped body inspection; actual bytes had no join limit; cookie objects violated string schema; decoded query reconstructed ambiguously |
| Behavior | Reactive Redis sliding sorted sets, failed-login counters, temporary blocks, load modes | Window operations were separate commands; policy rate limit was cached but not consumed; UNAVAILABLE/SKIPPED counted as attacks |
| Identity | Peer address for behavior/network, unconditional X-Forwarded-For for detection/events | Spoofable and inconsistent keys; Java IPv6 representation differed from Python; manual IPv6 block keys lacked the underscore mapping |
| Detection service | FastAPI, loaded joblib models, lazy DistilBERT, calibrated weighted-max fusion | One global lock serialized HTTP and network; timeout checked only after execution; gateway accepted invalid risk/schema values |
| HTTP models | RF triage, LR router, calibrated RF injection, calibrated Extra Trees execution, Character CNN and DistilBERT artifacts | Current deployed models generalize poorly to the six simple development probes; aggregate historical scores do not explain this |
| Network | CICIDS model + strict ordered 38-feature manifest, sensor REST API, Redis TTL context | Capture retained flows and packets until capture ended; length/std/activity definitions require CICFlowMeter equivalence validation |
| Events | Bounded gateway executor → RabbitMQ topic exchange → transactional JPA consumer → PostgreSQL → WebSocket/dashboard | DiscardPolicy silently dropped overflow; no publisher confirmation; poison events requeued indefinitely; broadcast occurred before commit |
| Deep escalation | In-process bounded Python queue, daemon workers, HTTP result reporter, control-plane follow-up IP block | Not durable; rejected submissions still marked pending; result reporting was best effort; control endpoint claimed successful persistence even on failure |
| Control/security | Basic-auth admin APIs, unauthenticated internal policy/training/escalation APIs, stream tickets | Internal mutation routes were public; tickets reusable for ten minutes; reverse proxy exposed internal routes; Compose published all interfaces |
| Registry/adaptation | DB model registration/assignment/promotion; metadata feedback curation; PSI and shadow candidate comparison | Registry promotion changes DB state, not the running artifact configuration; no automatic retraining, verified-label gate, runtime activation, or automatic rollback |
| Dashboard | React 19 / TypeScript / Vite; 16 existing screens | Retained-window metrics are not lifetime counts; rate limiting conflated with attack classification; no inspection coverage; queue depth omitted running work |
| Evaluation | Direct prepared-sample benchmark; repeated API probes; historical PowerShell checks | Different input populations and boundaries; API report listed variants and ablations it did not execute; no measured complete research comparison |

Existing screens retained: Overview, LiveAttacks, Requests, Visualizer, Network, Escalations, Policy, Models, Applications, AccessControl, Review, Training, Services, Audit, Settings, Generator.

Source review covered the gateway/filter/client/Redis/policy/event paths, inference/pipeline/artifact/calibration paths, flow accumulator/sensor, control/security/event/registry/adaptation paths, migrations, Compose, dashboard integrations and test/evaluation entry points. `source_inventory.json` records tracked source/configuration hashes; it is an inventory, not a claim that every training algorithm and every UI interaction has been validated.

## Four traced workflows

**A — Enforcement:** client → Gateway route → AdaptiveDetectionFilter body cache → Redis load/behavior → Redis network lookup → `/v1/detect` → triage/router/experts/optional deep → GatewayPolicy threshold → 403/429 or a single upstream call. The original Redis timeout applied to this entire chain. Fail-open is the historical default; bypasses had no explicit inspection status.

**B — Journal:** filter → SecurityEventPublisher executor → `adaptive.waf.events` / `security.#` → durable `security.events.persist` → SecurityEventConsumer → unique `event_id` in PostgreSQL → SecurityEventBroadcaster → ticketed WebSocket and dashboard polling. A unique index supports duplicate rejection; it does not make transport exactly-once. Existing query/details persistence was insufficiently redacted.

**C — Deep follow-up:** low expert confidence → EscalationWorker.submit → provisional result → Python daemon adjudication → HTTP `/internal/v1/security/escalations` → a separate journal event → optional temporary source block. This does not revise the completed backend operation. Worker restart loses in-memory pending jobs. No session reconciliation or durable job state machine exists yet.

**D — Feedback:** authenticated admin feedback → admin_feedback → adaptation `/curate` exports sanitized metadata → candidate/run/evaluation APIs → registry CHALLENGER/approval/promotion rows. There is no connection from registry ACTIVE status to artifact reload in RuntimeStore. The service does not train from feedback or safely activate an online learned policy.

## Baseline checks actually run before behavioral changes

| Check | Current baseline result | Evidence |
|---|---|---|
| Python `unittest discover` | 68 passed | `results/python-baseline-retry.txt` |
| Gateway Maven tests | 4 passed | `results/gateway-baseline.txt` |
| Control Maven tests | 2 passed | `results/control-baseline-retry.txt` |
| Demo backend Maven tests | 2 passed | `results/backend-baseline-retry.txt` |
| Dashboard `npm run build` | TypeScript and Vite passed | `results/dashboard-baseline.txt` |

Initial sandbox runs stalled in Windows asyncio wakeup sockets and JVM Mockito attachment; those are unsuccessful attempts, not passing tests. Scoped reruns outside the sandbox completed. Python emits a Starlette/httpx deprecation warning; Java emits Mockito attachment warnings. No dependencies were installed.

## Historical discrepancy and new diagnostic

`artifacts/benchmarks/phase1-benchmark-v1/metrics.json` reports 600 prepared ATRDF test samples, 100 per class, exact-class attack recall 1.0 and p95 **summed detector stages** 81.3309 ms. The benchmark times feature/model stages and offline policy separately from an actual gateway. Its `attack_recall` is exact-class matching, not simply attack-versus-benign recall. No deep invocations were reported. These are historical results, not a newly repeated final-set evaluation.

`artifacts/evaluations/phase10-summary.json` reports 30 repeated requests over six manually specified probes, binary attack recall 0.2 and p95 **client API round trip** 746.8332 ms. Its script issued POSTs only to the detection API. Listed scenarios, architecture variants, adaptive variants and ablations were not separately executed. They cannot be interpreted as measured comparisons. Original artifacts remain unchanged; the evaluator now labels only what it runs and defaults to a fresh output path.

New `scripts/research_probe.py` runs the same six development inputs without opening any final evaluation inputs. `results/direct-six-probes-v2.json` reproduces 1/5 binary attack detection directly with saved models. `results/api-six-probes-v2.json` also reports 1/5 from a real temporary loopback FastAPI server. V2 recomputes provisional/unknown unresolved counters from the original observations; the original reports are retained. The direct path has no scheduler and invokes deep inline; the configured service defers four of six requests, so these are **different routing conditions** even though input hashes match. Inline detects SQL injection; the provisional API detects cookie injection. XSS and traversal exit through confident fast BENIGN predictions, and the RCE probe is routed to the injection expert. This establishes model/routing weakness independently of gateway forwarding; it does not establish dataset leakage or identify a unique root cause. Selected deployment artifact checksums are recorded in `results/artifact_manifest.json`.

The diagnostic has six samples, cold loading, no repetitions or confidence intervals, and no representative benign application workload. Its latency is not a performance comparison with either historical run. Deferred verdicts are provisional and must be distinguished from completed deep outcomes.

## Highest priorities and remaining acceptance work

1. Stabilize single forwarding, bounded body handling, consistent identities and actual inference deadlines. Regression tests now cover these; see implementation status.
2. Make publishing overflow and delivery failure visible; verify atomic Redis windows and event persistence against isolated dependencies. Tests now cover these. Gateway publishing still has no durable outbox/replay.
3. Migrate deep escalation behind an adapter to a separate durable RabbitMQ queue, add terminal job states/expiry/retries, and test restart/saturation/reconciliation. In-process repairs do not satisfy durable acceptance.
4. Validate parser equivalence and network feature semantics, then add bounded capture accumulation. Do not claim CICFlowMeter equivalence from matching feature names alone.
5. Build matched gateway/backend/rules/fixed-mode evaluations before changing model-routing algorithms. Freeze disjoint development, calibration and new untouched evaluation populations. Existing test splits have already been inspected by historical tooling and are not newly untouched final sets.
6. Only then evaluate GPU training changes, conformal deferral, bandits, bounded session reconciliation and guarded promotion. No training or costly experiment was launched during this checkpoint.

Known residual risks include process-local deep job loss, broker-outage event loss, recovery republish failure, missing runtime model activation, public local-demo sensor/adaptation helper endpoints, path identifiers that may require application-specific redaction, unverified capture statistics, incomplete parser coverage, and absent browser-level end-to-end acceptance. No production readiness, novelty, formal security guarantees or improved performance is claimed.
