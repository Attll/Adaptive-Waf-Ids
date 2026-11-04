# Measured development results — 28 October 2026

These are controlled development diagnostics, not held-out security results. Each row submits the same six wire representations twice (10 attack and 2 benign requests), seed 641. Repeats are not independent samples. Latency includes client HTTP round trip except direct inference. Rules-only decisions do not count as FULLY_INSPECTED.

| Mode | Concurrency | Exact-class accuracy | Attack detection recall | Benign FPR | Macro F1 | p95 ms | Completed/s | Fully inspected/s | CPU ms/request |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| direct_inference | 1 | 0.500 | 0.400 | 0.000 | 0.400 | 495.284 | 5.505 | 5.505 | 143.229 |
| detection_api | 1 | 0.500 | 0.400 | 0.000 | 0.400 | 164.898 | 7.689 | 7.689 | 140.625 |
| detection_api | 4 | 0.500 | 0.400 | 0.000 | 0.400 | 457.965 | 8.923 | 8.923 | 115.885 |
| fixed_gateway | 1 | 0.500 | 0.400 | 0.000 | 0.400 | 219.535 | 6.586 | 6.586 | 236.979 |
| fixed_gateway | 4 | 0.500 | 0.400 | 0.000 | 0.400 | 509.813 | 8.257 | 8.257 | 184.896 |
| guarded_gateway | 1 | 1.000 | 1.000 | 0.000 | 1.000 | 138.169 | 23.138 | 3.856 | 82.031 |
| guarded_gateway | 4 | 1.000 | 1.000 | 0.000 | 1.000 | 183.069 | 38.492 | 6.415 | 67.708 |
| rules_only_gateway | 1 | 1.000 | 1.000 | 0.000 | 1.000 | 44.052 | 32.799 | 0.000 | 45.573 |
| rules_only_gateway | 4 | 1.000 | 1.000 | 0.000 | 1.000 | 39.767 | 105.509 | 0.000 | 46.875 |
| both_gateway | 1 | 1.000 | 1.000 | 0.000 | 1.000 | 119.243 | 22.462 | 3.744 | 49.479 |
| both_gateway | 4 | 1.000 | 1.000 | 0.000 | 1.000 | 181.870 | 39.086 | 6.514 | 53.385 |
| single_fast_gateway | 1 | 1.000 | 1.000 | 0.000 | 1.000 | 74.669 | 28.854 | 4.809 | 35.156 |
| single_fast_gateway | 4 | 1.000 | 1.000 | 0.000 | 1.000 | 156.719 | 58.929 | 9.822 | 22.135 |
| always_deep_gateway | 1 | 1.000 | 1.000 | 0.000 | 1.000 | 88.526 | 25.406 | 4.234 | 54.688 |
| always_deep_gateway | 4 | 1.000 | 1.000 | 0.000 | 1.000 | 131.609 | 54.817 | 9.136 | 39.062 |
| confidence_gateway | 1 | 1.000 | 1.000 | 0.000 | 1.000 | 80.827 | 26.226 | 4.371 | 35.156 |
| confidence_gateway | 4 | 1.000 | 1.000 | 0.000 | 1.000 | 133.863 | 57.031 | 9.505 | 52.083 |
| cost_threshold_gateway | 1 | 1.000 | 1.000 | 0.000 | 1.000 | 106.112 | 18.758 | 3.126 | 58.594 |
| cost_threshold_gateway | 4 | 1.000 | 1.000 | 0.000 | 1.000 | 147.848 | 58.947 | 9.824 | 62.500 |
| calibrated_fusion_gateway | 1 | 1.000 | 1.000 | 0.000 | 1.000 | 141.159 | 16.851 | 2.809 | 54.688 |
| calibrated_fusion_gateway | 4 | 1.000 | 1.000 | 0.000 | 1.000 | 243.800 | 39.908 | 6.651 | 69.010 |
| direct_backend | 1 | unavailable | unavailable | unavailable | unavailable | 20.895 | 94.478 | 0.000 | 28.646 |
| direct_backend | 4 | unavailable | unavailable | unavailable | unavailable | 26.020 | 385.040 | 0.000 | 7.812 |

Raw data, source snapshot, exact configuration/artifact hashes, Python/Torch/CUDA versions and device observations: `runs/gateway-comparison-v7/`. CPU covers the client/detection process and three JVMs; core-ms is a computational cost proxy, not monetary cost. RSS is end-of-trial. GPU allocator metrics are process observations; nvidia-smi utilization/power/memory samples cover the whole device and can include unrelated work. No GPU energy or dollar cost is inferred.

## Separate CRS-only fixture

CRS image pinned by digest in `compose.crs.yml`; the installed rule header reports 3.3.10. The same current backend JAR is mounted read-only in its own container. The CRS fixture does not forward to the WAF gateway. This has a different container/host timing boundary and cold/warm ordering, so latency is not a matched routing ablation. Exact-class classification and macro-F1 are unavailable; these are enforcement interventions against a backend returning 200 for these probes.

| Concurrency | Attack containment | Benign interruption | p95 ms | Completed/s |
|---:|---:|---:|---:|---:|
| 1 | 1.000 | 0.000 | 154.137 | 27.035 |
| 4 | 1.000 | 0.000 | 12.884 | 362.597 |

## Read-only inference profiles

With identical warmed development inputs, the original all-core sklearn settings measured p95 177.59 ms, one thread 27.40 ms, and two threads 67.65 ms. Predictions and risk values were checked equal. This supports an opt-in setting for this workload (`WAF_MODEL_THREADS=1`); it does not establish multicore throughput capacity. Raw: `runs/model-thread-profile-v1.json`.

The latest saved deep model profile measured CPU p95 128.04 ms and CUDA p95 12.72 ms, 18 calls per device, one CPU thread, warmed tokenization/transfer/inference/probability boundary. CPU and CUDA predictions agreed; maximum probability difference was 1.38e-7. Raw: `runs/deep-device-profile-v2.json`. This profile includes the tested inference-mode/OOM fallback implementation; no actual GPU exhaustion was induced. Earlier profile V1 remains preserved (CPU 41.93 / CUDA 3.33 ms); ambient load/order/thermal conditions are uncontrolled, so no speed change is attributed to implementation between profiles. No new candidate training ran.

## Evidence boundaries and ablations

| Requested comparison / ablation | Executed evidence | Remaining acceptance |
|---|---|---|
| Existing hierarchy vs guarded hierarchy | Matched V7 development requests | More than one representative benign case; held-out variants and repeated trials |
| Rules-only, single-fast, both, always-deep, confidence, cost threshold, score averaging | Switchable strategies and V7 local gateway execution | Thresholds are configured, not tuned; mandatory rules dominate 5/6 probes |
| CRS-only | Separate pinned container fixture | Matched hardware/process boundary, broad benign traffic and representative repeated trials |
| Conformal deferral | Quantile/schema/overlap tests, fitting CLI | Dedicated disjoint calibration and new untouched evaluation data |
| Constrained/unconstrained learned routing | Verified-only replay and policy serialization tests, shadow runtime loader | Verified full-information route matrix, policy training/evaluation, overlap for any OPE |
| No session reconciliation / source follow-up / bounded revisions | Expiry, deduplication, correction and future-risk API tests | Representative multi-step sessions and operational containment comparison |
| No endpoint profile | Reviewed frozen artifacts, bounded updates and raw parser differential fixtures | Trustworthy benign application profiles and shifted legitimate/held-out attack traffic |
| No network context | Existing network API, 38-name/order contract and bounded flow tests | Reference PCAP/CICFlowMeter features with matching units and source attribution |
| No learned fusion / no load features / no cost constraints | Static averaging and masked shadow-policy components | Fitted fusion and separated verified route populations; no results claimed |

Latest figures in `figures/development-v5/` use V7 gateway/V2 device measurements and preserve source hashes. Earlier figure versions remain intact. Accuracy, cost, recall/FPR operating points, latency/throughput, actual journal-derived stage invocations and CPU/CUDA/thread profiles are plotted. No RL learning, adaptation-shift or containment curves are generated because the required measured experiments do not exist. Figures are diagnostic operating points, not paper evidence of novelty.

## Superseded runs

V1 Java CPU/RSS measurements sampled launcher PIDs and are invalid (see its `run_validation.json`); HTTP observations remain recorded. V2 compared raw vs percent-encoded query representations and is confounded. V3/V4 share wire representations. V5 adds candidate static strategies and a measured source archive. V6 repeats the inference-mode/OOM implementation; V7 records the final committed runtime and source archive. Aggregate exact-class accuracy and stage counts are recomputed in the additional V7 `derived_summary.json` without modifying the measured report. All old reports are retained unchanged.

## Recorded resource observations (V7, concurrency 1)

Whole-device samples are sparse and include unrelated processes. RSS is the end-of-trial sum for the client/detection and three Java processes. Zero sampled CPU core-ms means below the clock resolution for that short boundary, not zero computational cost. No power integration or monetary cost is inferred.

| Mode | CPU ms/request | RSS MiB | Device GPU mean % | Device GPU peak % | Process CUDA allocated MiB |
|---|---:|---:|---:|---:|---:|
| direct_inference | 143.23 | 2064.39 | 37.29 | 39.00 | 264.63 |
| detection_api | 140.62 | 2021.37 | 38.60 | 39.00 | 272.76 |
| fixed_gateway | 236.98 | 2119.15 | 37.33 | 41.00 | 272.76 |
| guarded_gateway | 82.03 | 2196.87 | 39.00 | 39.00 | 272.76 |
| rules_only_gateway | 45.57 | 2211.77 | 38.00 | 39.00 | 272.76 |
| both_gateway | 49.48 | 2188.48 | 38.00 | 38.00 | 272.76 |
| single_fast_gateway | 35.16 | 2208.92 | 31.00 | 31.00 | 272.76 |
| always_deep_gateway | 54.69 | 2222.80 | 29.00 | 29.00 | 272.76 |
| confidence_gateway | 35.16 | 2219.98 | 33.50 | 35.00 | 272.76 |
| cost_threshold_gateway | 58.59 | 2235.13 | 34.50 | 36.00 | 272.76 |
| calibrated_fusion_gateway | 54.69 | 2211.19 | 34.67 | 38.00 | 272.76 |
| direct_backend | 28.65 | 2256.84 | 34.00 | 34.00 | 272.76 |

## True deep-only gateway control (separate V8 trial)

This research-only comparator executes the saved deep model on every request, without semantic or fast early exits; it is not a selectable deployment policy. It shares the V7 input hash but is a separate cold/warm ordered trial. It does not establish a causal latency comparison.

| Concurrency | Exact-class accuracy | Attack detection recall | Macro F1 | Benign FPR | p95 ms | Fully inspected/s | Deep invocations |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0.667 | 0.600 | 0.583 | 0.000 | 467.005 | 8.124 | 12 / 12 |
| 4 | 0.667 | 0.600 | 0.583 | 0.000 | 89.419 | 58.337 | 12 / 12 |

`runs/combined-development-v1/` combines immutable V7 and V8 tables with matching input hashes and retained source hashes. It is explicitly a derived view, not a new experiment. Latest plots are `figures/development-v7/`; legends were visually checked so they do not cover invocation bars or latency peaks. Earlier measured files and figure versions remain preserved.

## Dataset-validity audit, continuation V22

No candidate accuracy was measured. Audit metadata and source hashes are retained in `runs/http-population-v22`. Existing train/validation share 6,564 candidate template groups; XSS/RCE/cookie have only 3/4/5 groups under the documented normalization. A prospective new-candidate split contains 2,028 train and 407 examples in each of tune/evaluation. Only one representative per group is selected, and each held-out rare attack has one example. Neither statistical generalization nor disjoint six-class calibration/policy/final acceptance is supported. Existing fixed and guarded development results remain diagnostic.
