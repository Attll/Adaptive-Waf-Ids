# Adaptive Web Application Firewall and Intrusion Detection System

Guarded routing and delayed evidence: implementation and research validation

**Research draft and protocol; findings are not established. 28 October 2026.**

## Abstract

We investigate whether uncertainty-aware model routing can reduce a multi-stage WAF's computational cost while maintaining detection effectiveness, and whether delayed session evidence improves future containment. The implementation preserves a Java Spring Cloud Gateway, Python inference, Redis context, RabbitMQ messaging, PostgreSQL journaling and the existing dashboard. It adds explicit inspection coverage, bounded execution, durable optional deep jobs, switchable routing strategies, split-conformal artifact validation, a shadow LinUCB router, reviewed bounded session/profile evidence, drift monitoring and guarded policy activation/rollback. Local development diagnostics expose a structural-feature detection failure and a cookie parsing gap; opt-in semantic guards detect the five diagnostic attacks. These probes are not a held-out evaluation. Full learned-policy, conformal, shift and containment findings remain blocked by separate verified populations and approved candidate training. We make no novelty, production-readiness or formal security claim.

## 1. Problem and scope

The operational objective is correct backend execution under explicit inspection and availability constraints. Optimize expected measured routing cost subject to predefined recall/FPR/resource gates. Report classification separately from enforcement: a behavior block does not prove attack recognition, an HTTP 200 does not prove inspection, and delayed detection cannot reverse a completed transaction. The original fixed hierarchy is an executable baseline.

The threat model includes request syntax variation, repeated/multi-step activity, shared-IP benign users, load/dependency failures, delayed or incorrect detector evidence and poisoned/repeated feedback. Host or administrator compromise and full volumetric denial of service are outside the demonstrated protection. Experiments target only owned local fixtures. See `threat_model_and_protocol.md`.

## 2. Related work and unresolved contribution

Contextual selection and offline evaluation are established in [Li et al. (2010)](https://arxiv.org/abs/1003.0146). Deferral to an expert is established in [Mozannar and Sontag (2020)](https://proceedings.mlr.press/v119/mozannar20b.html). Split conformal prediction and its assumptions are explained by [Angelopoulos and Bates](https://arxiv.org/abs/2107.07511). Conservative contextual-bandit constraints precede this proposal; an engineering mask is not a proof of the guarantees in those papers. Delayed feedback is also established, and a deep-model prediction is not verified feedback. [Arp et al. (2022)](https://www.usenix.net/system/files/sec22-arp.pdf) motivates caution about security ML evaluation and leakage.

The potential contribution is a measured integration at a real reactive HTTP enforcement boundary, rather than the invention of these components. A broader systematic literature review and comparable experiments are required to determine whether any defensible research gap remains. `literature_matrix.md` records the checked primary sources and limits.

## 3. System and methods

The gateway preserves raw supported request bytes for the backend while passing bounded inspection representations. It correlates UUIDs through inference, policy and journal records. Separate dependency deadlines cannot retry backend operations. Atomic Redis windows and explicit source identity support existing behavioral/network context. Inspection status exposes FULLY_INSPECTED, PARTIALLY_INSPECTED, RULES_ONLY, DETECTION_UNAVAILABLE and INSPECTION_REJECTED.

Mandatory semantic evidence precedes candidate optional routes. Learned evidence uses existing artifacts; simple candidate strategies provide interpretable baselines. A conformal artifact is fitted only from a separate reviewed calibration population and pinned to the executed model. LinUCB sees pre-action evidence, worker occupancy, a cached queue state and remaining deadline; no future unexecuted model output enters context. Recommendations remain shadow-only. Empirical gates are aggregate point estimates and do not establish formal safety under attack or drift.

Durable deep jobs have a separate RabbitMQ topology, PostgreSQL leases, bounded attempts, model pinning, terminal state and a retained reporting outbox. Delayed evidence appends bounded revisions to pseudonymous sessions and can be corrected or decay. Original decisions remain immutable. Profile updates require reviewed benign observations; exports freeze their structure. Drift analysis can use unlabeled observations, while supervised labels require explicit review. Runtime activation requires a real prepared pipeline, measured gates, a separate enabling flag, operator reference and runtime acknowledgement. Failed activation/operational regressions support rollback.

Full equations, parameters, input schemas, implementation limits and prepared fitting commands are in `methods_and_blockers.md` and `architecture.md`.

## 4. Evaluation design

H1: Routing may reduce expected cost at comparable effectiveness. H2: Conformal deferral may reduce deep invocation relative to tuned simple uncertainty gates. H3: Delayed reconciliation may reduce subsequent harmful activity. H4: Endpoint/profile/parser consistency may improve robustness under supported variations without unacceptable benign disruption. These are hypotheses, not results.

Freeze development, calibration and a new untouched final population before model selection. Separate applications/templates/sessions and temporal groups where available; retain task-appropriate network data. Audit leakage and label quality. Existing validation/calibration use prevents calling it fresh conformal evidence. Never train on the final set. Additional datasets/downloads require availability/rights/label compatibility review and resource approval.

Required comparisons: fixed hierarchy/fusion, rules-only, pinned CRS-only, static thresholds, always-deep, conformal deferral, unconstrained and constrained learned routing, then the integrated system. Ablate reconciliation/profile/network/fusion/load/cost constraints. Measure per-class precision/recall, macro-F1, FPR/FNR, recall at fixed FPR, p50/p95/p99 wall time, stage/queue delay, completed and fully inspected throughput, invocation distributions, CPU/RAM/GPU/VRAM and computational cost. Run independent repeated trials and uncertainty intervals. Delayed studies must count only future containment, benign disruption and correction behavior.

## 5. Current measured observations

`experimental_results.md` contains the actual gateway/static/CRS/device/thread measurements and raw report locations. The default repeated six-probe workload has one distinct benign example, so zero observed FPs is insufficient to estimate a low deployment FPR. Fixed raw-query and percent-encoded inputs produce different structural features; the matched wire representation is explicitly shared across modes. Semantic guard hits are RULES_ONLY, not full learned inspections. Static candidate results are dominated by mandatory signatures and cannot establish an adaptive-routing benefit.

The pinned CRS-only fixture is a separate container baseline and reports enforcement rather than exact-class ML predictions. Its timing boundary/cold order differs from the host-JVM experiment. CPU/GPU profiles use existing weights, not newly trained candidates. Whole-device GPU samples may include unrelated work. CPU core-ms/request is a cost proxy, not a monetary or energy result.

## 6. Reliability and threats to validity

`failure_acceptance.md` distinguishes actual sockets/broker/DB/crash evidence from injected unit failures. The final complete runtime suite and dashboard build pass, and browser workflows verify actual journal/stream/filter/visualizer/review paths. These results do not certify deployment or long-run reliability. Timed-out native calls retain slots; session/monitor state is process-local; gateway event publication has no durable disk spool. Full fault campaigns, real GPU memory pressure, reference network feature equivalence, production role/TLS/exposure and sustained monitored activation remain open.

Principal validity threats are tiny prepared samples, repeated non-independent observations, label/template leakage, unknown benign diversity, signature selection on development examples, reused validation/calibration data, workload/order/thermal/background-resource effects, different container timing boundaries, missing shifts/containment trials and unexecuted learned-policy/ablation experiments. A learning curve or security interval cannot be fabricated to fill those gaps.

## 7. Reproducibility and next evidence

Source/config/model hashes and measured source snapshots accompany gateway reports. Existing training artifacts and prior runs remain intact; all 18 selected artifact hashes still match the baseline. Commands in `reproduction.md` reproduce local diagnostics with fresh output paths and stop only owned fixtures. Training remains explicitly on hold, and no production model/policy was promoted. The next research evidence requires approved candidate training, trustworthy disjoint calibration/route/application/session populations and independent frozen-protocol trials. Only then should the hypotheses, ablations and contribution be assessed.

## Engineering release addendum — 30 October 2026

A portable CPU Docker release now passes local 11-service startup, actual gateway/journal/network/deferred-job acceptance, selected dependency outages, persistence restart and independent image import/start tests. Headless browser evidence covers the dashboard navigation and authentication surface. Source suites pass 135 Python and 45 Java tests plus dashboard build. These engineering observations do not validate the proposed adaptive-learning hypotheses. No new training ran. Model-only generalization, disjoint conformal calibration and learned routing remain unestablished; see `docker_release_status.md` for exact raw evidence and diagnostic timing boundaries.
