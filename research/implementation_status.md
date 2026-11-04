# Research modernization status â€” 28 October 2026

Branch: `codex/research-backend-stabilization`. Baseline rollback: `12a6a4a`. The original fixed decision engine and deployment files remain available and are still the default. No production policy or model was promoted. Existing artifacts and old benchmark reports were not overwritten.

**The complete master plan is not accepted as finished.** Safe implementation and development verification have advanced across all stages. Expensive training is ON HOLD by the user's explicit instruction. Representative verified calibration/evaluation/session populations, network reference fixtures and live-promotion approval are still required. Experimental components are not security guarantees.

Status vocabulary follows the latest continuation request. BLOCKED means the listed acceptance needs a named external input or approval; it does not mean the component's code is absent.

| Stage | Status | Implemented and measured evidence | Remaining acceptance / blocker |
|---|---|---|---|
| 0 Audit and baseline | COMPLETE_AND_VERIFIED | Baseline audit, inventories, four workflow traces, original plan, hardware/artifact manifests and actual baseline failures retained | Exhaustive literature review remains part of paper work, not a completed novelty claim |
| 1 Backend stabilization | IMPLEMENTED_BUT_INCOMPLETE | Single forwarding, body/read bounds, dependency timeout isolation, source identity/IPv6, atomic Redis, internal API security, raw cookies and parser transport fixtures; 33 gateway tests | Network name/order contract is tested, but 38-feature units/CICFlowMeter equivalence needs reference PCAP and matching expected features; deployment proxy/NAT matrix not established |
| 2 Messaging and durable deep jobs | IMPLEMENTED_BUT_INCOMPLETE | Publisher confirmations, overflow, consumer retries, idempotent PostgreSQL writes; opt-in distinct RabbitMQ/Postgres deep state machine; actual child-process crash, duplicate delivery, expiry, saturation, retries and reporting outbox tests | Exhaustive broker/DB/network-partition combinations and long-run durability require a dedicated fault campaign. Native hung calls retain slots; no forceful process isolation. Security-event publisher has no durable disk spool |
| 3 Evaluation framework | IMPLEMENTED_BUT_INCOMPLETE | Matched direct/API/full gateway/backend/rules/fixed/static strategy runner; real journal joins; c=1/4; CPU/RAM, GPU allocator and device samples; hashes and measured-source archive; preserved V1â€“V5 | Broad benign/application-separated/temporal/held-out attack populations and independent repeated trials are unavailable. Six repeated probes are diagnostics only |
| 4 GPU and model portfolio | BLOCKED | Seeded CUDA AMP/pinning/clipping/checkpoint/early-stop controls, CPU fallback and injected CUDA OOM recovery; existing-model CPU/CUDA timing and inference-thread equivalence profiles; optional candidate adapters/configs | User holds expensive training. XGBoost/LightGBM packages/build capability are unavailable; pristine cached DistilBERT weights are available for a new compact candidate, but no candidate comparison has run |
| 5 Modular decision engine | EXPERIMENTAL | Fixed baseline retained; mandatory semantic evidence; rules-only, single-fast, both, always-deep, confidence, cost-threshold, averaging, conformal and bandit-shadow strategies; explicit routes/actions/coverage/reasons/versions | Security/resource acceptance on representative verified data. Averaging is not learned fusion; cost/confidence parameters are configured, not tuned |
| 6 Conformal uncertainty | BLOCKED | Probability validation, entropy/margin, finite-sample/class-sensitive quantiles, absent-class conservatism, artifact/version/overlap checks and calibration CLI tested | New dedicated calibration IDs/groups disjoint from training and untouched evaluation; empirical coverage under supported shifts. No fitted real artifact or conformal guarantee claimed |
| 7 Constrained bandit | EXPERIMENTAL | LinUCB, availability/suspicion/queue/deadline masks, actual tie propensities, verified-only rewards, empirical promotion gates, full-information replay, serialization and model-version pinning; shadow only | Verified route-outcome matrices and separated evaluation groups for training/comparison. Existing deterministic logs cannot support valid IPS/DR; no learned live policy or formal safety claim |
| 8 Delayed reconciliation | EXPERIMENTAL | Bounded HMAC session keys/history/expiry/decay, immutable revisions, deduplication and reviewed corrections; deep evidence updates future session risk; shadow/simulation API integration | Representative multi-step containment/correction study and approval for deployment mitigation. Context is process-local and cleared on restart; distributed correlation is not accepted |
| 9 Endpoint/parser robustness | EXPERIMENTAL | Reviewed-benign-only bounded profiles, immutable exports/load, shadow anomaly evidence; actual gateway/backend duplicate/empty/encoding/Unicode/nested JSON/form/body-boundary fixtures; unsupported multipart rejected | Trustworthy benign application profile and held-out family/legitimate-shift populations. Transport fidelity is not universal parser or Unicode equivalence |
| 10 Drift/feedback/lifecycle | EXPERIMENTAL | Finite PSI, bounded confidence/review selection, verified-label ECE, reviewed drift reference, validated event feedback/latest correction curation; shadow candidate preparation, runtime ACK, empirical gates, operational rollback and append-only audit tested | Adequate reviewed labels, trusted evaluation references, sustained monitored shadow evaluation and explicit live approval. No autonomous classifier retraining or live promotion ran |
| 11 Dashboard | IMPLEMENTED_BUT_INCOMPLETE | Existing screens retained; real runtime/research views, source versions, routes, stage latency, coverage/RPS, device allocator, queue, uncertainty/context/policy events, measured comparisons; counts exclude synthetic nonrequests; build passes | Final local browser fixture workflows are recorded separately in `browser_qa.md`; broad production-role/disconnection matrix remains incomplete |
| 12 Research evaluation/ablations | BLOCKED | V7 local static comparisons, separate digest-pinned CRS 3.3.10 fixture, CPU/CUDA/thread profiles, tables and measured plots | Fresh frozen evaluation data; verified calibration/route/session populations; approved candidate training; independent trials and intervals. H1â€“H4 remain unestablished |
| 13 Reliability/security acceptance | IMPLEMENTED_BUT_INCOMPLETE | Actual HTTP single-forwarding/errors/body limits, Redis concurrency/expiry, Rabbit/Postgres duplication/retry, worker crash/saturation/outbox, deadlines/capacity, corrupt load, CPU fallback/injected OOM, bad candidate/failed ACK/rollback, correction/expiry and internal auth | Full fault matrix, sustained load/partition tests, actual GPU allocation-pressure behavior and deployment security matrix are not certified |
| 14 Paper/reproducibility | IMPLEMENTED_BUT_INCOMPLETE | Architecture, threat model/formulation, literature/novelty boundaries, inventories, methods, results/ablation status, configs, figures, failure matrix and paper draft | Full paper claims, learning/adaptation/containment curves and uncertainty intervals are BLOCKED by the missing experiments above |

## Detection failure and actual measurements

The saved structural fast features have no lexical request content and can produce confident false benign results. Adding semantic guards is a candidate repair, not successful model retraining. The original raw-query diagnostic detected 1/5 attacks. Percent encoding changes structural features: the matched wire-input V7 fixed pipeline detects 2/5; guarded gateway detects 5/5. A strict cookie parser had dropped invalid raw cookie evidence; that gap is repaired and tested over actual HTTP. Only one distinct benign diagnostic was used, so 0 observed FPs cannot support a low operational FPR claim.

See `experimental_results.md` and raw `runs/gateway-comparison-v7/metrics.json` for exact class metrics, latency, throughput and costs. Guarded attack decisions are RULES_ONLY; only fully executed learned paths count as FULLY_INSPECTED. Direct backend throughput is not inspection throughput. CRS-only interventions and host-JVM timing have different measurement boundaries.

Latest existing deep-model read-only profile: CPU p95 128.04 ms, CUDA p95 12.72 ms, 18 calls/device, one CPU thread; predictions agree, max probability difference 1.38e-7. It uses the inference-mode/OOM implementation and is not a trained-candidate comparison. The older V1 timing is preserved separately; uncontrolled ambient conditions prevent attributing timing differences to code changes. The saved model only matches 12/18 expected exact classes in that diagnostic. Inference-thread profile p95: original 177.59 ms, one thread 27.40 ms, two threads 67.65 ms, with equal predictions/risks.

## Verification checkpoints

- `stage2-durable-v1`: Python 82; Java gateway/control/backend 28/9/2; dashboard build, all pass.
- `stages4-7-controls-v1`: Python 93; Java 28/9/2; dashboard build, all pass.
- `parser-and-routing-v2`: Python 93; Java 30/9/2; dashboard build, all pass.
- `stages8-11-integration-v1`: one Python simulation assertion failed; retained as failed evidence and repaired.
- `stages8-11-integration-v2`: Python 101; Java 30/9/2; dashboard build, all pass.
- `reliability-controls-v3`: Python 104; Java 32/9/2; dashboard build, all pass.
- `context-monitoring-v4`: two new monitoring test fixtures omitted required fake-pipeline arguments; retained failure and corrected.
- `research-acceptance-v5`: Python 110; Java 33/10/2; dashboard build, all pass.
- `final-runtime-v6`: Python 112; Java 33/10/2; dashboard build, all pass, isolated dependency integration enabled. Unit training uses only tiny synthetic temporary fixtures; it is not the held expensive experiment.

## Rollback and migration

Select `WAF_DETECTION_STRATEGY=fixed`; leave context/conformal/bandit flags unset and omit `WAF_MODEL_THREADS` for original inference settings. Original deployment artifacts/configurations are intact. Durable deep jobs are opt-in and Flyway V6 is additive. Queue topology v2 adds 60-second dead-letter raw-message retention; pre-existing v1 queues are not redeclared or deleted. Drain/inspect old queues under operator control before migration; changing queue names is not a claim of automatic transfer. In-process escalation remains available.

A model registry status is administrative metadata, not a runtime reload. Prepared runtime policies remain shadow-only by default; live promotion needs both a disabled-by-default flag, a reviewed operator reference and empirical gates. Audit files persist but startup restores the configured baseline; candidate/context process state is not automatically revived. Deferred analysis cannot undo an already executed backend operation. No user data volumes were deleted and no expensive training or deployment activation occurred.

Checkpoint `3968665` records raw parser evidence, pseudonymous gateway session identity, corrected HTTP request counts and validated feedback. Subsequent verified Python runtime and dashboard changes are being committed independently.

Checkpoint `5f73fef` records reviewed context/profile/monitoring integration, policy ACK/rollback, replay fitting/state validation and CPU OOM recovery. A subsequent shadow context integration supplies measured worker occupancy, cached queue saturation and remaining deadline; its acceptance output is recorded separately.

Final shadow-context acceptance `final-routing-context-v10`: 114 Python, 33 gateway, 10 control and 2 backend tests, zero failures and dashboard build passed. V9 exposed a compatibility regression for metadata-free pipeline fixtures; the guarded metadata lookup was repaired, deadline regressions were rerun, and the complete V10 suite passed. All 18 selected baseline artifact hashes still match (`results/artifact_integrity_final.json`).

Final V7 development comparison and derived exact-class accuracy are in `experimental_results.md`; independent trials, calibrated/learned populations and training remain blocked. Browser QA and display corrections are recorded; latest full final evidence acceptance is `final-evidence-v12`. All earlier raw reports and failed runs remain retained.

Final policy safety acceptance `final-policy-safety-v14`: 117 Python tests; Java 33 gateway / 10 control / 2 backend; dashboard build all pass. Added concurrent preparation reservations without blocking active inference, rollback after injected audit-write failure, and a true deep-only research comparator. No live candidate activation occurred.

True deep-only gateway comparator V8 detected 3/5 distinct development attacks; macro-F1 0.583, exact-class accuracy 0.667, deep executed 12/12 per concurrency level. It is distinct from the guarded always_deep route. The combined development view retains source hashes and labels the separate-trial timing boundary. Final policy safety commit: `2d85347`.

Benchmark checkpoint `98a0ca4` preserves actual V1–V8 data, measured source archives, exact accuracy derivation, independent CRS enforcement results and plotted development operating points. Final dashboard acceptance `final-dashboard-v15`: 117 Python, 33 gateway, 10 control, 2 backend tests and dashboard build all pass. Final browser v4 verifies actual CPU/RSS, active enforcement policy and inline queue state; screenshots and review flow evidence are in `browser_qa.md`.

Dashboard checkpoint `dd04d95` and full `final-dashboard-v15` verification retain 117 Python and 45 Java passes, zero failures/skips in dependency-enabled runs, plus dashboard build. Final browser v4 verified process CPU/RSS, enforcement policy revision, inline state and corrected DB URL. Only owned fixture projects were stopped; no project JAR process remains. Remaining completion needs the resources/approval recorded in `methods_and_blockers.md`; the whole 0–14 plan is not marked complete.

## Continuation: dataset validity and startup readiness

`representation-readiness-v21` passes 122 Python tests, Java 33/10/2, and dashboard build with real Redis/RabbitMQ/PostgreSQL integration. `continuation-baseline-v16` retains a RabbitMQ handshake startup failure. The verifier now waits for successful protocol operations before starting tests; assertions were not weakened.

The new learned-input representation excludes transport metadata that the gateway filters, retains raw and once-decoded URL evidence, and allocates bounded field windows. Existing deployed model representations are preserved. This is an untrained candidate input, not measured ML improvement. Current user-facing titles use Adaptive WAF-IDS; the paper uses the full requested title.

The audit of existing **train and validation only** finds 6,564 overlapping normalized template groups; class totals and hashes are in `runs/http-population-v22/audit.json`. Under this conservative grouping, there are 48,187 benign, 3,144 SQL, 30 traversal, 5 cookie, 4 RCE and 3 XSS groups. This does not establish universal semantic equivalence, but invalidates treating those repeated rows as independent samples for this protocol. No conflicting-label group was observed.

A frozen new-candidate protocol uses one representative per group, with disjoint train/tune/evaluation roles. Counts are 2,028 / 407 / 407; evaluation has only one XSS, RCE and cookie example each. The legacy test file was not opened. Legacy fitted models have seen source training rows and cannot serve as uncontaminated final baselines for this new holdout. Independent calibration/policy/final populations for all six classes remain unavailable. Expensive training remains ON HOLD. No evaluation predictions or model promotion occurred.

## Candidate controls checkpoint

`candidate-controls-v24`: 128 Python tests; Java 33/10/2; dashboard build; all pass with real dependency fixtures. Added executable prospective model-only structural/lexical/CNN/compact/full-transformer candidates, field-token budgets, local-only pristine base initialization, bounded sequential process supervision, source/population/artifact hashes, model-only scoring and completed-epoch resumption. Tiny CPU fixtures verify exact resumed-vs-uninterrupted weights and a real subprocess experiment; their accuracy is not research evidence. Three-seed real-data training/evaluation remains unexecuted pending the consolidated approval described in `candidate_training_approval.md`. Stage 4 remains BLOCKED.

## Batching/network checkpoint and release priority (30 October)

V29 passes 135 Python, Java 33/10/2 and dashboard build. Bounded microbatching remains disabled by default: V27/V28 gateway trials show worse p95 with batching at c=1/4/8 despite in-process CUDA gains. All 12 requests per setting were fully inspected, development attack recall 0.6. Versioned network payload/sample-statistic corrections pass controlled PCAP arithmetic tests; native CICFlowMeter parity remains blocked. V26–V28 preserve raw measurements/source.

Latest instruction supersedes the expensive-training hold with at most 60 cumulative minutes; the old 90-minute plan is not authorized unchanged. Docker delivery takes priority; no real candidate training has run yet.

## Docker engineering release — 30 October 2026

See `docker_release_status.md` for tagged images, 11-service health, actual source/container/browser/fault/import acceptance and exact commands. V32 passes 135 Python and Java 33/10/2 plus dashboard build. The engineering local release is operational within tested scope. Stage 1/2/11/13 engineering evidence is extended; full research and production-certification acceptance remains incomplete. No training ran (0 minutes of the authorized 60-minute cap); no new model or learned policy was deployed.

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
