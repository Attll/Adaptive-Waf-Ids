# Adaptive WAF IDS — Complete Research-Grade Architecture and Implementation

## ROLE

You are a principal Java backend engineer, distributed-systems architect, machine-learning researcher, reinforcement-learning engineer, GPU optimization specialist, and research software engineer.

Your task is to upgrade an existing Adaptive Web Application Firewall and Intrusion Detection System (Adaptive WAF IDS) into a research-grade system.

Repository:

`C:\Projects\Adaptive Waf Ids`

This is an existing project, not a greenfield application.

Read the entire relevant repository before making changes. Preserve its functionality, reuse existing code where appropriate, and implement improvements incrementally.

The user wants a functioning system, measurable research results, and a defensible research-paper contribution.

Do not finish with only an architecture proposal.

## 1. PRIMARY RESEARCH OBJECTIVE

Investigate whether safety-constrained, uncertainty-aware adaptive model routing can reduce the computational cost and latency of a multi-stage WAF while maintaining attack-detection effectiveness and limiting false positives.

Investigate whether delayed deep-learning evidence and session-level reconciliation improve containment of repeated or multi-step suspicious behavior.

The research contribution should combine:

1. Safety-constrained adaptive detection-path selection.
2. Cost-aware and conformal-assisted deep-model deferral.
3. Delayed evidence reconciliation and time-limited session risk.
4. Endpoint-specific anomaly evidence and parser consistency as supporting improvements.
5. Evaluation on an actual HTTP gateway under realistic workload, distribution shift, and dependency failures.

Do not assume the combination is novel. Establish its relationship to existing work and determine its contribution through experiments.

Keep the engineering solution simpler than the full set of available research ideas.

## 2. NON-NEGOTIABLE REQUIREMENTS

- Preserve Java Spring Boot and Spring Cloud Gateway as the main backend and enforcement platform.
- Preserve the existing Python ML infrastructure.
- Preserve Redis, RabbitMQ, PostgreSQL, and the existing dashboard.
- Preserve all existing HTTP and network detection classes.
- Preserve all operational API and data contracts unless a versioned migration is necessary.
- Preserve the existing ALLOW, MONITOR, RATE_LIMIT and BLOCK actions.
- Do not introduce CAPTCHA or CHALLENGE actions.
- Preserve the old decision engine as an executable baseline.
- Do not delete existing training data, model artifacts, benchmark results or configuration without explicit authorization.
- Do not claim production readiness, guaranteed security, novelty or improved performance without evidence.
- Do not replace substantial modules merely because rewriting is easier.
- Do not launch expensive training, large downloads, destructive Docker commands or uncontrolled network tests without approval.
- Perform security testing only against locally controlled applications or authorized fixtures.
- Maintain CPU fallback for GPU-dependent features.
- Do not train on the final untouched test set.
- Keep passwords, credentials and sensitive request content out of logs and research artifacts.

Use Git branches or small checkpoints to isolate substantial changes.

At every phase, maintain a working rollback path.

---

# STAGE 0 — FULL REPOSITORY AUDIT AND ACCEPTANCE BASELINE

Inspect:

- Spring Cloud Gateway and reactive filters
- Redis behavioral controls
- HTTP inspection and canonicalization
- ML inference API
- Classical and deep-learning models
- Network flow sensor
- RabbitMQ topology and consumers
- PostgreSQL migrations and repositories
- Control-plane services
- Model registry and deployment logic
- Adaptation service
- Dashboard and its backend integrations
- Docker Compose configuration
- Tests, datasets, training scripts and saved metrics

Trace four complete workflows:

A. HTTP request → gateway → detection → enforcement → backend.

B. HTTP request → security event → RabbitMQ → PostgreSQL → dashboard.

C. Uncertain request → deep escalation → revised verdict → source/session policy.

D. Operator feedback → adaptation service → candidate model or policy → runtime activation.

Identify broken paths, nonfunctional controls, data inconsistencies and missing verification.

Record the existing architecture before changing it.

### Important baseline evidence

A historical offline benchmark reported 600/600 exact-class predictions and approximately 81.33 ms p95 summed detection-stage latency.

A separate detection API evaluation reported 20% attack recall and approximately 747 ms p95 client round-trip latency.

These are different workloads and measurement boundaries.

Investigate the discrepancy directly.

Run the current practical tests, including Java, Python, API and dashboard builds.

Produce:

`research/00_baseline_audit.md`

Include a feature inventory, verified results, failed tests, known issues and implementation priorities.

Do not describe historical test results as current passing tests.

---

# STAGE 1 — STABILIZE THE CURRENT BACKEND

## 1.1 Gateway correctness

Fix verified issues involving:

- Redis timeout scope
- Inference timeout scope
- Upstream response handling
- Duplicate request forwarding
- Request-body buffering
- Content-Length assumptions
- Oversized or streaming request bodies
- Duplicate parameters
- Headers and cookies
- Encoding and canonicalization
- Error handling
- Source-IP and trusted-proxy identity
- IPv4/IPv6 consistency
- Request correlation
- Fail-open/fail-closed behavior

Specifically test that a delayed upstream POST is never executed twice.

Create explicit inspection statuses:

- FULLY_INSPECTED
- PARTIALLY_INSPECTED
- RULES_ONLY
- DETECTION_UNAVAILABLE
- INSPECTION_REJECTED

Do not count bypassed requests as successfully inspected.

## 1.2 Redis

Make sliding-window enforcement atomic where needed.

Test concurrent requests, expiry, temporary blocking and rate-limit consistency.

Ensure dashboard policy changes actually modify the active enforcement settings.

Avoid per-request blocking Redis operations that stall the reactive event loop.

## 1.3 Internal security

Review and secure internal APIs.

Check authentication, authorization, service identity, exposed control endpoints, secrets, dashboard proxy routes and WebSocket tickets.

Maintain a convenient but explicitly isolated local-demo configuration.

## 1.4 ML runtime correctness

Investigate unnecessary global inference serialization.

Use separate locks only where model implementations require them.

Apply actual deadlines and bounded concurrency.

Test CPU fallback and model-loading failures.

Ensure model outputs and gateway decisions use consistent schemas.

## 1.5 Network sensor

Verify the existing 38-feature network model contract.

Ensure feature names, order, units and inference semantics match training.

Implement bounded flow accumulation, periodic emission, expiry and memory limits.

Verify the correlation between network evidence and gateway source identity.

### Acceptance

All existing representative allowed, blocked and rate-limited requests must continue functioning.

Tests must verify request-body integrity, single forwarding, consistent source keys and correct failure handling.

---

# STAGE 2 — FIX MESSAGING, DEEP ESCALATION AND PERSISTENCE

## 2.1 Security-event pipeline

Retain:

Gateway → RabbitMQ → Spring control plane → PostgreSQL → dashboard.

Implement reliable bounded publishing and processing.

Where necessary, introduce:

- Publisher confirmations
- Retry and dead-letter policies
- Consumer acknowledgments
- Idempotent writes
- Explicit overflow handling
- Correlation IDs
- Event processing timestamps
- Delivery metrics

Consider a transactional outbox where it solves a demonstrated event-loss problem.

Do not falsely claim exactly-once delivery.

## 2.2 Durable deep escalation

Evaluate migrating the current in-process deep queue to a separate RabbitMQ queue.

The deep-analysis queue must be independent of the security-event queue.

Implement explicit states:

PENDING, RUNNING, COMPLETED, FAILED, EXPIRED.

Requirements:

- Job IDs
- Retry limits
- Dead-letter behavior
- Idempotent processing
- Queue capacity and backpressure
- Per-request model version
- Result correlation
- Deep-inference timing
- Accurate pending-job counts

Support both:

A. Bounded synchronous deep inference when a decision requires it before forwarding.

B. Deferred analysis when permitted by the safety policy.

Never imply deferred analysis can undo an already completed backend operation.

### Acceptance

Test worker crashes, duplicate deliveries, expired jobs, queue saturation and result reconciliation.

Every pending job must eventually have a recorded terminal outcome or a clearly documented unresolved/failure state.

---

# STAGE 3 — REPRODUCIBLE EVALUATION FRAMEWORK

Build the benchmark infrastructure before changing the decision algorithm.

Use identical inputs for comparisons.

Required execution modes:

1. Direct inference
2. Detection API
3. Complete gateway
4. Direct backend without WAF
5. Rules-only gateway
6. Existing fixed decision engine

Record:

- Request count
- Successful requests
- Actually inspected requests
- Attack-specific recall
- Benign false-positive rate
- Enforcement confusion matrix
- p50/p95/p99 latency
- Inference latency
- Queue waiting
- Added gateway overhead
- Throughput
- CPU/RAM
- GPU/VRAM
- Fallback and bypass counts

Create controlled benchmarks at multiple concurrency levels.

Distinguish completed request throughput, inspected request throughput and model throughput.

Save benchmark environment, model/configuration hashes, random seeds and input-set identifiers.

Build a representative benign traffic test set.

Keep development, calibration and final evaluation data separate.

Investigate application/template/session leakage.

Include application-separated, temporal and held-out attack-variant testing where data supports it.

Do not claim external generalization from only synthetic or prepared samples.

Deliver machine-readable metrics and reproducible commands.

---

# STAGE 4 — GPU MODERNIZATION AND MODEL PORTFOLIO

## 4.1 Hardware support

Detect the actual GPU, CUDA runtime, driver compatibility, available VRAM and library capabilities.

Implement configurable modes:

auto, cpu, cuda.

Do not hardcode assumptions about GPU support.

## 4.2 Existing models

Preserve existing trained baselines:

- Random Forest
- Extra Trees
- Logistic Regression
- Character CNN
- DistilBERT
- Existing HTTP and network models

Correct training/evaluation issues and reproducibility problems.

## 4.3 Additional models

Evaluate:

- CUDA-enabled XGBoost
- GPU-capable LightGBM
- One compact transformer alternative
- Existing Character CNN as a fast deep model
- An optional simple anomaly detector for endpoint deviations

Do not indiscriminately add many redundant models.

Select additions according to accuracy, calibration, latency, resource cost and complementary error patterns.

## 4.4 Training improvements

Implement suitable:

- CUDA training
- Mixed precision
- Pinned-memory loading
- Efficient batching
- Early stopping
- Gradient clipping
- Checkpointing
- Reproducible splits
- GPU monitoring
- Training manifests
- Artifact validation

Schedule GPU experiments according to available VRAM.

Do not launch unrestricted parallel jobs on a single GPU.

Use CPU training where it is faster or GPU implementations are unavailable.

## 4.5 Inference optimization

Profile:

- Feature extraction
- Tokenization
- Model prediction
- Runtime locking
- GPU transfer
- Queue delays
- Serialization
- Network calls

Experiment with bounded deep-inference microbatching and an optimized inference runtime if profiling warrants it.

Measure the accuracy-versus-latency tradeoff.

Do not sacrifice request tail latency merely to maximize batch throughput.

### Acceptance

Every proposed new model must have a reproducible training configuration and valid held-out evaluation.

Preserve CPU fallback and prior deployment artifacts.

---

# STAGE 5 — NEW MODULAR DECISION ENGINE

Refactor the existing decision logic into testable components.

Suggested conceptual interfaces:

- RequestContextExtractor
- EvidenceProvider
- DetectorAdapter
- CalibrationProvider
- UncertaintyEstimator
- DetectionRouteSelector
- RiskFusionStrategy
- SafetyPolicy
- EnforcementResolver
- DecisionJournal
- PolicyRegistry

Adapt these names to existing conventions instead of introducing unnecessary abstractions.

Separate:

**Detection classification**

from

**Enforcement decisions**.

Every decision should record:

- Request ID
- Timestamp
- Model and policy versions
- Available context
- Executed detection stages
- Predicted attack class
- Risk estimate
- Uncertainty estimate
- Selected detection route
- Final enforcement action
- Decision reason
- Timing components
- Fallback status

Implement switchable strategies:

- Existing fixed policy
- Fixed confidence thresholds
- Cost-tuned thresholds
- Rules-only
- Single fast model
- Always-both experts
- Always-deep when feasible
- Calibrated fusion
- Conformal-based deferral
- Learned adaptive routing

Ensure all strategies respect mandatory deterministic security rules.

---

# STAGE 6 — CONFORMAL UNCERTAINTY AND LEARNING TO DEFER

Build a reusable uncertainty-calibration module.

Evaluate:

- Prediction confidence
- Prediction margin
- Entropy
- Model disagreement
- Split-conformal prediction sets

Investigate class-sensitive calibration and calibration under distribution shift.

Use disjoint calibration data.

Report:

- Marginal coverage
- Per-attack coverage
- Prediction-set size
- Escalation frequency
- Missed attacks
- Deep-inference cost
- Latency

Do not claim universal conditional coverage.

Do not claim ordinary split conformal guarantees remain valid under arbitrary adversarial distribution shift.

Define which uncertainty states should trigger another detection stage.

Introduce a resource-aware deferral budget.

When an expensive model is unavailable, produce a clearly defined safe fallback rather than silently treating uncertainty as benign.

Compare conformal deferral with tuned static confidence gates and other simple uncertainty criteria.

---

# STAGE 7 — SAFETY-CONSTRAINED ADAPTIVE ROUTING

This is the primary research implementation.

## 7.1 Contextual bandit

Build a contextual-bandit routing policy using only pre-action information.

Initial candidates:

- LinUCB
- Cost-sensitive contextual-bandit baseline
- Safety-constrained contextual-bandit variant

Optional alternatives may be included if they have a clear experimental justification.

## 7.2 State

Include suitable features from:

- Fast-model risk
- Prediction uncertainty
- Expert disagreement, if already available
- Traffic rate and source behavior
- Session suspicion
- Network evidence
- Endpoint anomaly score
- CPU/GPU load
- Queue depth
- Inference deadline
- Previously measured model costs

Never include outputs from a model that has not yet executed.

Implement action availability masks.

## 7.3 Detection-path actions

Support choices among available detection routes:

- Fast-only when allowed
- Relevant specialist
- Both specialists
- Synchronous deep model
- Deferred deep analysis where appropriate
- Rules-only fallback when ML is unavailable

Mandatory rules take priority.

Do not allow RL to disable core protection.

## 7.4 Reward and constraints

Implement a configurable reward incorporating:

- Correct labeled decision
- False-negative cost
- False-positive cost
- Detection latency
- CPU/GPU cost
- Queue cost
- Safety violations

Clearly separate verified labels from detector-generated predictions.

Add explicit empirical constraints for attack recall, benign false positives, queue budgets and request latency.

Do not assert these constraints are formally guaranteed unless the method and evaluation establish such guarantees.

## 7.5 Offline learning

Build a reproducible replay environment using labeled requests and realistic resource-cost observations.

For controlled full-information benchmarks, precompute all eligible detector outcomes on the same samples.

For genuine partial-feedback logs, store policy action probabilities and required metadata.

Use IPS or doubly robust estimators only when the logged data supports valid off-policy evaluation.

Do not treat past deterministic decisions as randomized logged bandit feedback.

## 7.6 Enforcement

Keep the initial RL contribution focused on model routing.

Use deterministic guardrails and calibrated evidence for final enforcement.

Only after validating adaptive routing, add an optional experimental policy that recommends ALLOW, MONITOR, RATE_LIMIT or BLOCK.

Run potentially unsafe policy variants only in simulation or shadow mode.

---

# STAGE 8 — DELAYED EVIDENCE RECONCILIATION

Implement a time-bounded session/source risk subsystem.

Maintain references between:

- Original requests
- Immediate decisions
- Deferred deep results
- Recent session events
- Updated suspicion scores
- Manual review feedback
- Subsequent mitigation decisions

When a delayed result disagrees with an earlier result:

1. Record the new evidence.
2. Update the relevant suspicion score.
3. Re-evaluate a bounded history where useful.
4. Record the revisions and policy version.
5. Apply updated policy only to future or still-pending requests.
6. Preserve the original immutable decision history.
7. Allow scores to decay or be corrected.

Do not rewrite history as though the revised prediction had been known earlier.

Do not automatically treat deep-model predictions as verified training labels.

Do not propagate suspicion indefinitely to unrelated users sharing an IP address.

Use privacy-aware, short-lived session identity and explicit expiry rules.

Compare:

- No session reconciliation
- Existing forward-only follow-up blocking
- Proposed bounded delayed reconciliation

Measure containment time, subsequent malicious requests, benign disruption and correction behavior.

---

# STAGE 9 — ENDPOINT PROFILING AND PARSER CONSISTENCY

## 9.1 Positive-security profiles

Create a lightweight endpoint profile from trustworthy benign samples.

Candidate attributes:

- HTTP method
- Expected content type
- Known parameter names
- Input length distribution
- Missing or unexpected fields
- Encoding patterns
- Value-type patterns
- Structural anomaly scores

Profiles should have versioning and update safeguards.

Do not let suspicious or attacker-controlled samples automatically redefine normal behavior.

Use endpoint risk as an additional evidence source, not a universal block condition.

Evaluate held-out attack families and altered legitimate traffic.

## 9.2 Parser-differential testing

Create isolated fixtures that compare gateway interpretation with protected-backend interpretation.

Cover:

- Duplicate keys
- Cookie serialization
- Encoded characters
- Unicode normalization
- Empty and missing values
- Multipart/form input
- Nested JSON
- Body-size boundaries
- Streaming bodies
- Path normalization

Use local fixtures and metamorphic testing.

Measure disagreement frequency.

Repair verified mismatches or reject unsupported request forms explicitly.

Do not create an unrestricted external attack tool.

---

# STAGE 10 — DRIFT, FEEDBACK AND AUTOMATIC POLICY LIFECYCLE

Extend the existing adaptation service rather than rebuilding it.

Implement:

- Input drift monitoring
- Confidence/calibration monitoring
- Validated feedback storage
- Operator review queue
- Active-learning candidate selection
- Offline candidate training
- Shadow policy evaluation
- Safety-gated activation
- Monitoring after activation
- Automatic rollback
- Versioned audit history

Separate classifier retraining from RL policy training.

Unlabeled traffic can support drift analysis but must not be treated as true attack labels.

Require adequate verified feedback before supervised model retraining.

Protect against malicious or repeated poisoned feedback.

Default to shadow-only automated candidates.

Support live promotion only after predefined measurable gates, approval policy, rollback testing and reliable monitoring exist.

---

# STAGE 11 — COMPLETE DASHBOARD REPAIR AND RESEARCH UI

Audit every existing screen and backend endpoint.

Do not remove current dashboard features.

Fix:

- Incorrect request counts
- Broken filters and pagination
- Stale event data
- Policy changes that do not reach enforcement
- Model states that do not reflect active inference
- Incorrect block statistics
- Missing error states
- Broken feedback workflows
- Incorrect infrastructure health
- Delayed-analysis status mismatches

Add research-relevant views:

1. Active model and policy versions
2. Detection-path distribution
3. Per-model inference latency
4. Successful and fully inspected requests per second
5. CPU/GPU usage
6. Deep queue status
7. Conformal uncertainty statistics
8. Adaptive policy reward and safety metrics
9. Delayed session-risk revisions
10. Policy promotion and rollback history
11. Evaluation and benchmark comparisons

Keep experimental results clearly separated from live operational metrics.

Use the existing frontend framework.

Verify through type checking, builds, integration tests and browser-level workflows where available.

Do not present a decorative working-looking UI that is disconnected from backend actions.

---

# STAGE 12 — FULL RESEARCH EVALUATION

## Experimental baselines

Include:

- Rules-only
- OWASP CRS-only under a documented version and configuration
- Existing weighted-max fusion
- Tuned static thresholds
- Existing hierarchical routing
- Always-deep where feasible
- Conformal-only deferral
- Learned unconstrained routing
- Learned constrained routing
- Full proposed system

## Hypotheses

H1: Adaptive routing reduces expected detection cost at comparable security effectiveness.

H2: Conformal-assisted deferral reduces unnecessary deep inference compared with tuned confidence thresholds.

H3: Delayed evidence reconciliation reduces subsequent harmful activity in multi-step scenarios.

H4: Endpoint profiles and parser-consistency improvements increase robustness without unacceptable benign false positives.

Do not write the hypotheses as established results.

## Datasets and evaluation

Use existing ATRDF and CICIDS data according to their actual supported tasks.

Investigate additional HTTP datasets such as CSIC 2010, verifying availability, labeling, compatibility and usage rights.

Use application/template-separated and held-out attack variants where possible.

Keep all final test inputs untouched until the experiment design is frozen.

Evaluate distribution shifts and safe synthetic workload scenarios.

Use controlled, local adversarial-variation fixtures rather than sending traffic to external targets.

## Metrics

Required:

- Macro-F1
- Per-class precision/recall
- Benign false-positive rate
- Attack false-negative rate
- Recall at fixed FPR
- Gateway p50/p95/p99 latency
- Detection latency
- Fully inspected throughput
- End-to-end throughput
- Deep-inference invocation rate
- GPU memory/compute consumption
- Decision overhead
- Queue delay
- Expected policy cost
- Policy safety violations
- Drift adaptation
- Delayed-reconciliation containment performance

Run repeated experiments and record uncertainty intervals.

## Ablations

Compare the proposed system with:

- No adaptive routing
- No conformal module
- No delayed reconciliation
- No endpoint profile
- No network context
- No learned fusion
- No load-aware features
- No cost constraints

Keep datasets, hardware and timing boundaries comparable.

If an ablation cannot be implemented or executed, mark it incomplete rather than inventing a result.

---

# STAGE 13 — RELIABILITY AND SECURITY ACCEPTANCE

Test:

- Redis unavailable
- RabbitMQ unavailable
- PostgreSQL unavailable
- Detection API unavailable
- Slow model inference
- Full deep queue
- GPU unavailable or out of memory
- Corrupted model artifact
- Invalid policy candidate
- Failed policy activation
- Duplicate events
- Worker restarts
- Delayed or incorrect labels
- Session expiry
- Dashboard disconnection
- Long or unsupported request bodies
- Concurrent rate-limit updates

Verify that the protected backend behaves correctly and is not accidentally invoked multiple times.

Do not silently report uninspected traffic as successful security enforcement.

Preserve and test all existing functional routes.

---

# STAGE 14 — PAPER AND REPRODUCIBILITY ARTIFACTS

Create a `research/` directory containing:

- System architecture
- Research problem formulation
- Threat model
- Literature matrix
- Novelty-gap analysis
- Model inventory
- Dataset inventory
- Baseline audit
- Decision-policy mathematical formulation
- Reinforcement-learning design
- Conformal calibration protocol
- Delayed-reconciliation method
- Training configurations
- Benchmark configurations
- Experimental results
- Ablation tables
- Model comparisons
- GPU performance comparisons
- Failure testing
- Limitations and threats to validity
- Paper draft outline

Provide plots for:

- Accuracy and cost tradeoffs
- Recall versus false-positive rate
- Latency and throughput
- Model invocation distribution
- Deep queue utilization
- RL policy learning curves
- Adaptation under traffic shift
- Delayed containment comparison

Only generate plots from actual measured data.

Use real citations to published research.

Do not create fictional experimental results or unsupported novelty claims.

---

# IMPLEMENTATION ORDER AND WORK RULES

Follow this order:

**Phase A:** Full audit and baseline.

**Phase B:** Backend correctness and reliable messaging.

**Phase C:** End-to-end testing, benchmark infrastructure and dashboard repair.

**Phase D:** GPU modernization and selected model experiments.

**Phase E:** Modular decision engine, calibrated risk and conformal deferral.

**Phase F:** Contextual-bandit routing and safety constraints.

**Phase G:** Delayed evidence reconciliation.

**Phase H:** Endpoint profiling, parser consistency and drift adaptation.

**Phase I:** Guarded automated policy lifecycle.

**Phase J:** Research comparisons, ablations and paper evidence.

After each phase:

- List files changed.
- Explain architectural changes.
- Run relevant tests.
- Provide the actual test results.
- Record regressions and limitations.
- Preserve an executable baseline.
- Update an implementation-status document.
- Record the commands for reproducing results.
- Leave a concise handoff for the next phase.

Keep the repository usable at the end of every phase.

Do not attempt a complete untested rewrite in one enormous commit.

Do not install new dependencies unless they are required and compatible.

For expensive GPU training, build and validate the training scripts and then provide exact commands before running long experiments.

If an independent phase can continue despite a blocker, proceed without making false claims about the blocked work.

## REQUIRED COMPLETION CRITERIA

The project should ultimately demonstrate:

- A functional Java Spring Cloud Gateway.
- Correct request forwarding and enforcement.
- Existing HTTP and network detection.
- Working rate limiting and Redis context.
- Reliable event and deep-analysis pipelines.
- Working control APIs and dashboard.
- Measured end-to-end gateway performance.
- Reproducible GPU/CPU model comparisons.
- Calibrated uncertainty-based model selection.
- Constrained adaptive routing.
- Bounded delayed evidence reconciliation.
- Safe and reversible policy updates.
- Reproducible research experiments.
- Honest, evidence-backed paper documentation.

Every major capability must be marked as one of:

IMPLEMENTED_AND_TESTED / IMPLEMENTED_NOT_FULLY_TESTED / EXPERIMENTAL / BLOCKED / NOT_IMPLEMENTED.

Never claim that all features work without corresponding evidence.

## FIRST ACTION

Begin immediately by inspecting the repository and constructing the baseline feature and test inventory.

Verify the previously reported correctness issues against the current source.

Then implement the highest-priority backend and inference-consistency fixes before proceeding to GPU training or reinforcement learning.

Treat the entire project as a staged research implementation with measurable acceptance criteria, not as a collection of disconnected feature additions.