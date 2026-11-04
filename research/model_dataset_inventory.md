# Model and dataset inventory

All existing artifacts and configurations are preserved. `configs/models/*_deployment.toml` remain the active artifact selectors. The registry database does not override these files or reload runtime objects.

| Role | Selected artifact/config | Contract |
|---|---|---|
| Triage | triage-full-v1 RF + calibration-full-v1 isotonic | BENIGN_LIKE / SUSPICIOUS |
| Router | router-full-v1 logistic regression | INJECTION / EXECUTION, top1 threshold 0.90 and margin 0.40 |
| Injection | injection-expert-full-v1 RF + isotonic | BENIGN / SQL_INJECTION / XSS / COOKIE_INJECTION |
| Execution | execution-expert-full-v1 Extra Trees + isotonic | BENIGN / DIRECTORY_TRAVERSAL / REMOTE_CODE_EXECUTION |
| Deep | distilbert-full-gpu-v1 + temperature | All six HTTP classes; lazy load; configured CUDA falls back to CPU if unavailable |
| Network | network-full-v1 RF | BENIGN / BRUTE_FORCE / DOS_DDOS / BOT_ANOMALY; ordered 38-feature manifest |

RF, Extra Trees, logistic regression, Character CNN and DistilBERT training artifacts remain available as baselines. The CPU fallback device selector exists; corrupted-artifact and CUDA OOM recovery acceptance are not established. Auto device mode, additional compact transformers, XGBoost and LightGBM are not implemented. `results/hardware.json` records the actual RTX 4070 Laptop (8188 MiB), driver 617.14, CUDA 12.6 and successful tiny CUDA execution. Hardware capability is not evidence of a trained model's accuracy, speedup, memory envelope or CPU fallback quality.

| Dataset/source | Supported use | Split/provenance limitation |
|---|---|---|
| Existing ATRDF dataset3/dataset4 processed version | HTTP classifier training/evaluation, six labels | Existing HTTP splitting groups normalized near duplicates; application/session/temporal separation is not established; source rights still need recorded provenance |
| Existing CICIDS2018 flow subset v3 | Network contextual classification | Row-based split key is not session/host/time separation; packet-derived lengths, population/sample std and activity thresholds need parity verification |
| datasets/samples | Existing replay development corpus | Do not assume disjointness from prior train/test samples; do not use as untouched final evidence |
| Six Phase 10 hand probes | Small development diagnosis | Repeated payload templates; no representative benign workload and no external generalization claim |
| CSIC 2010 | Potential additional HTTP validation | Availability, original distribution and license/provenance not established in this checkpoint; not downloaded, trained on or evaluated |

The [official CSE-CIC-IDS2018 page](https://www.unb.ca/cic/datasets/ids-2018.html) describes its flow data and requires dataset citation and a source link for use/redistribution. Its network labels are not a substitute for HTTP attack class labels.

Existing calibration scripts fit on validation and report quality on test. Model/threshold selection may therefore already have used historical test results. A new final evaluation population must be reserved before future tuning. This checkpoint neither trains models nor opens the existing final test inputs. It reads saved metrics and uses the six already-public development probes.


## CSIC 2010 acquisition and compatibility review (28 October 2026)

The [preserved author dataset description](https://petescully.co.uk/wp-content/uploads/2018/04/http_dataset_csic_2010.pdf) describes generated Spanish e-commerce HTTP traffic, binary normal/anomalous labels, normal-only training and separate normal/anomalous test subsets. Anomalies include invalid non-malicious inputs, so anomalous must not automatically mean a verified attack or one of this project's six classes. This is a task-compatibility limitation, not grounds for inventing multiclass labels.

The original CSIC dataset URL was inaccessible through the research browser. The [IMPACT catalog record](https://impactcybertrust.org/dataset_view?idDataset=940) still identifies it as externally hosted, labels restrictions Unrestricted, and lists commercial permission as unknown. I could not verify a complete explicit redistribution/commercial license from those sources. A mirrored author page is useful provenance, not a substitute for permission terms. No dataset download occurred. Acquisition, hashes, rights review, parser validation and a frozen binary/application-separated evaluation design remain required before use. No CSIC results are claimed.
