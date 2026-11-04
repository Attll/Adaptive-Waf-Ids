# Methods, input contracts and blocked acceptance

## Implemented decision formulation

For request x, mandatory semantic evidence is evaluated before optional routing. The fixed executable baseline remains available. A candidate route combines existing fast/deep evidence with behavioral/network risk; actions are ALLOW, MONITOR, RATE_LIMIT and BLOCK. Required deep failure returns explicit unavailable inspection and a conservative recommendation. Deferred results never undo completed backend operations.

Candidate strategies: rules_only, single_fast, both, always_deep, confidence (0.90), cost_threshold (0.80), calibrated_fusion (arithmetic averaging of calibrated expert scores), conformal, and bandit_shadow. These parameter values were not tuned on the development probes. Mandatory rules dominate five of the six default probes; the measured experiment cannot isolate routing gains.

Conformal nonconformity is 1-p(y|x). The finite-sample rank is ceil((n+1)(1-alpha)); a rank beyond n uses threshold 1. Class-sensitive absent classes remain conservative. Probability vectors, classes, thresholds, alpha, calibration IDs, overlap and executed model version are checked. Coverage requires appropriate exchangeability and does not hold against arbitrary adversarial shift by assertion.

LinUCB uses an intercept plus fast risk, normalized entropy, margin, source rate, session risk, network risk, endpoint anomaly, load, queue fraction and deadline fraction. Inputs must be available before selecting extra work; fast-model cost has already been incurred. High suspicion masks fast-only, deferred and rules-only recommendations; full queue masks deferral, exhausted deadline masks synchronous deep. Live shadow integration supplies fast/source/network/session/endpoint signals, current HTTP worker occupancy, a local deep-queue snapshot and remaining request deadline after queue wait. Durable queue counts are refreshed by maintenance, with no DB/broker call on the routing path; unknown queue state is conservatively treated as full. The load feature is worker occupancy, not whole-machine CPU utilization. A validated learned load-aware policy still requires verified route data. Recommendations run in shadow and do not replace enforcement.

The labeled reward is exact-class correctness minus 10 for a false negative, 2 for a false positive, 0.001*latency_ms, compute_cost and 0.001*queue_ms. Costs must be finite and nonnegative. Only VERIFIED labels update the policy. Ties are randomized with their actual probabilities; deterministic journal entries do not acquire stochastic support retroactively. Replay is full-information simulation, not IPS/DR. State serialization validates matrix dimensions, finiteness, symmetry and positive definiteness, preserves RNG state, and pins the model versions.

Empirical promotion gates currently require >=100 verified attack and >=100 verified benign observations, attack recall >=0.99, benign FPR <=0.01, p95 <=250 ms and queue depth <=256. These aggregate point-estimate gates are not confidence bounds, per-family security guarantees or a formally conservative bandit algorithm. Adequate per-class/application/shift evidence and operator review remain necessary before deployment approval.

## Delayed evidence and profiles

Session revisions contain immutable request/evidence/model/policy IDs, risk, verified flag and time. The latest detector revision per request is superseded by reviewed correction, never relabeled as ground truth automatically. Risk decays with a 60-second half-life by default, expires after 300 seconds, and retains at most 16 revisions/session and 4096 sessions. HMAC requires an explicit session token and secret; shared-IP users are not merged. Runtime state is local to the process. A deep prediction and an operator correction are distinct evidence.

Endpoint profiles accept only explicitly reviewed benign observations, have capacity limits for endpoints/observation IDs/structure, and use method/content type/parameter names/length statistics. Unknown/underpopulated endpoints are unavailable rather than automatically malicious. Structural anomalies are supporting evidence. Exports use exclusive writes, freeze updates and require provenance; artifact loading validates bounds and finite statistics. No real trusted application profile has been fitted in this checkpoint.

Transport parser fixtures compare raw gateway inspection with backend path/query/body bytes for duplicates, encoded/Unicode/empty fields, nested JSON/form data and exact body limits. A malformed cookie is inspected even if a strict parser rejects it. Multipart is rejected explicitly. These fixtures do not prove universal application parser agreement or CICFlowMeter feature equivalence.

## Input formats and prepared commands

No unavailable data file is represented as present. The following commands are prepared, not executed on real research populations.

**Gateway development envelope:** JSON object with population=`development`, nonempty review_reference and id, and cases mapping unique IDs to request objects. Each request supplies expected_attack (one of the six HTTP classes), path, and optional method/query/headers/cookies/body. At most 1000 submitted requests and 2 MB input. Input authority/representativeness must be reviewed separately.

```powershell
.\.venv\Scripts\python.exe -m scripts.benchmark_gateway_research --input research/private-inputs/reviewed-development.json --output research/runs/reviewed-development-001
```

**Conformal input:** JSON with population=`calibration`, review_reference, model_version, classes, alpha, class_sensitive, explicit training_ids/evaluation_ids/training_groups/evaluation_groups manifests and records. Each record has request_id, group_id, label_source=`VERIFIED`, label and probabilities in exactly the declared class order. Record IDs and groups must not overlap forbidden manifests. A manifest alone cannot prove provenance; review it against actual dataset construction and prior training/calibration usage.

```powershell
.\.venv\Scripts\python.exe -m scripts.calibrate_research --kind conformal --input research/private-inputs/reviewed-calibration.json --output artifacts/research/conformal-reviewed-001.json
```

**Profile input:** JSON with population=`development`, version, review_reference and records. Each record supplies request_id, label_source=`VERIFIED`, label=`BENIGN` and request arguments for HttpRequestRecord. The output parent must exist, and existing artifacts are never replaced.

```powershell
.\.venv\Scripts\python.exe -m scripts.calibrate_research --kind profiles --input research/private-inputs/reviewed-benign-profile.json --output artifacts/research/endpoint-reviewed-001.json
```

**Routing matrices:** JSONL records with population=`development` or `evaluation`, request_id, group_id (application/template/session grouping), label_source=`VERIFIED`, expected, pre_action_context and outcomes. Outcomes maps route names to actually measured predicted/latency_ms/compute_cost values. Do not populate unexecuted outcomes with guessed values. Populations must have disjoint IDs AND groups. model-versions.json is the exact model-version mapping used to collect the matrix.

```powershell
.\.venv\Scripts\python.exe -m scripts.train_routing_replay --development research/private-inputs/routes-development.jsonl --evaluation research/private-inputs/routes-evaluation.jsonl --model-versions research/private-inputs/model-versions.json --output artifacts/research/constrained-routing-001
.\.venv\Scripts\python.exe -m scripts.train_routing_replay --development research/private-inputs/routes-development.jsonl --evaluation research/private-inputs/routes-evaluation.jsonl --model-versions research/private-inputs/model-versions.json --unconstrained --output artifacts/research/unconstrained-routing-001
```

These bounded CPU replay commands are not a substitute for the held expensive GPU experiment. No verified real routing matrix exists yet, so no real learned-policy artifact or learning curve is claimed.

## Explicit blockers and acceptance boundary

| Requirement | Exact blocker | Safe preparation completed |
|---|---|---|
| Candidate GPU training | User explicitly holds expensive training | Seeded config, CPU smoke, CUDA capability, AMP/clipping/checkpoints/early stop, exclusive artifact paths; exact command in training_approval.md |
| Optional tree/compact candidates | XGBoost/LightGBM dependencies and GPU build capabilities unavailable; compact weights not cached or download-approved | Lazy adapters and candidate configurations; no trained results |
| Conformal acceptance | Existing validation data was used previously for calibration/selection; new disjoint reviewed calibration and untouched evaluation population not assigned | Validated artifact fitter and tests; no final-test reads |
| Learned routing/fusion and ablations | No representative verified full-information route matrix or frozen application/session-separated evaluation set; learned load/queue response not empirically validated | Replay/state loader, shadow masks, explicit reward/gates; no OPE or formal safety claim |
| Network IDS semantics | No reference PCAP plus authoritative matching 38-feature units/expected output | Bounded flow table/periodic capture/name-order/API tests; no live capture performed |
| Endpoint/session/shift study | No trustworthy application profile and labeled multi-step/legitimate-shift population | Reviewed frozen profile, bounded corrections/expiry and shadow/simulation tests |
| Live adaptation | Adequate verified evaluation, monitored shadow evidence and explicit live security approval absent | Runtime candidate preparation, gates, ACK, rollback tests/audit; live flag stays disabled |
| Long-run fault/security certification | Dedicated sustained fault/load campaign and exclusive GPU-pressure environment not available in this controlled checkpoint | Local real HTTP/Redis/Rabbit/Postgres/crash/saturation tests and injected OOM; no actual device exhaustion or production outage caused |
| Full paper findings | Above experiments/independent repetitions/uncertainty intervals are incomplete | Honest results, plots, citation matrix, protocol and draft; hypotheses remain hypotheses |

Incomplete acceptance is not evidence that a component is production-ready. Outstanding implementation integration and unexecuted experiments remain explicitly experimental. Do not promote the candidate semantic guards based on a single benign probe or describe all stages as complete.

The always_deep experimental strategy still runs mandatory semantic guards and pre-action fast evidence; it means deep inference on unmatched requests, not a claim that every guard hit invoked deep. The separate deep-device profile does execute the saved deep model on every diagnostic input. `DeepOnlyControl` is separately measured in V8 on every input, without semantic/fast early exits; it is a research comparator that cannot be selected as a deployment policy. Learned-fusion comparisons still require appropriate verified populations.

Resource interpretation: common model weights remain resident across the static benchmark modes. GPU allocator peak is a shared-process lifetime peak, not per-trial peak memory; sparse whole-device samples can include unrelated workloads. CPU/RSS include the detection/client and three JVMs, including background housekeeping. FULLY_INSPECTED describes execution of the selected inspection contract, not a guarantee against semantic evasions or model input truncation. Broker TTL limits logical delivery retention while operating; it is not a secure-erasure guarantee.
