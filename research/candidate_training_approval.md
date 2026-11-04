# Bounded candidate experiment awaiting consolidated approval

Expensive training remains ON HOLD. Successful read-only preflight is recorded in `runs/candidate-plan-v23/preflight.json`. No real candidate has been trained or scored. Tiny CPU regression fixtures exercise implementation only.

The frozen population contains 2,028 training requests and 407 tuning requests. Final candidate evaluation contains 407 requests, with just one XSS, RCE and cookie template each. These are prospective group holdouts for newly initialized models, derived only from old train/validation. They cannot establish broad generalization, support independent six-class conformal/policy populations, or provide an uncontaminated final comparison to old fitted artifacts. Legacy test data remain unopened. No trial/parameter selection will use evaluation results.

| Candidate | Initialization and input | Maximum per seed | Trials |
|---|---|---|---|
| Structural logistic | Fresh; existing structural extractor with transport-neutral headers; balanced loss | 300 optimizer iterations, CPU | 3 |
| Lexical logistic | Fresh; field-budgeted character TF-IDF 3–5 grams, <=50,000 features; balanced loss | 300 optimizer iterations, CPU | 3 |
| Byte CNN | Fresh; UTF-8 byte IDs, 1,024 field-budgeted tokens; embedding 32, 48 filters | 8 epochs, batch 32, patience 2 | 3 |
| Compact DistilBERT | First two layers and embeddings from pristine cached base, fresh six-class head; 256 field-budgeted tokens | 4 epochs, batch 8, patience 2 | 3 |
| Full DistilBERT | Six pristine cached base layers, fresh six-class head; 256 field-budgeted tokens | 3 epochs, batch 8, patience 2 | 3 |

Seeds are 641/642/643. There is no parameter search. The task-fitted deployed transformer is never used for initialization. GPU fits use AMP, gradient clipping and bounded inverse-frequency class weighting. DataLoaders use a per-epoch seeded generator, zero Windows subprocess workers and pinned/nonblocking CUDA transfers. Completed-epoch checkpoints include optimizer/scaler, Python/NumPy/PyTorch/CUDA RNG, best weights, early-stopping state and immutable source/population/configuration signatures.

The batch contains six CPU fits and nine GPU fits, at most **45 GPU epochs in total**, all sequential. The supervisor stops on the first failure, an aggregate **90-minute wall-clock limit**, or sampled process-tree RSS above **8 GiB**. Each GPU worker limits the PyTorch allocator to 50% of device memory (approximately 4 GiB on an 8 GiB GPU; CUDA context/driver/other processes are additional). Allow approximately 6–10 GiB of new artifact space; this is a planning estimate, not measured use. Runtime and fit quality are unknown. CUDA unavailability selects CPU within the same wall-clock budget; training OOM aborts rather than retrying partly updated batches. A watchdog can overshoot its time/RSS sampling boundary; it is not an operating-system hard memory quota.

The approved batch would run this **single command**:

```powershell
.\.venv\Scripts\python.exe -m scripts.candidate_experiments --config configs/models/candidate_experiment_v2.toml --execute --output artifacts/research/experiments/model-only-v2-20261028-01
```

Without `--execute`, the command performs read-only preflight and prints the complete frozen plan. Execution refuses existing output directories. All fits finish before any final evaluation prediction. Model-only reports contain per-class precision/recall/F1, confusion matrices, rare-class Wilson recall intervals, FPR/FNR, descriptive ECE/entropy/log loss, serial p50/p95/p99 and batched in-process throughput. These are not end-to-end gateway measurements. Epoch histories, candidate manifests, hashes, checkpoints and resource samples are retained. GPU utilization/power samples describe the whole shared device; they cannot establish process energy or dollar cost. No model or policy is deployed. No downloads, package installation, cloud resources or live policy changes are included.

XGBoost/LightGBM are excluded from this batch because compatible packages/build capability are not installed/verified. Existing optional adapters remain available; installing them requires a separately justified environment change.

An interrupted deep fit can resume from its last complete epoch into a **new** directory using the same config/source/seed:

```powershell
.\.venv\Scripts\python.exe -m scripts.candidate_experiments --config configs/models/candidate_experiment_v2.toml --fit byte_cnn --seed 641 --resume artifacts/research/experiments/model-only-v2-20261028-01/byte_cnn-641/last_checkpoint.pt --output artifacts/research/experiments/byte-cnn-641-resume-01
```

This resume command is an operator recovery command, outside the original batch wall-clock budget; execution requires applicable training approval. Existing checkpoints remain read-only. Resume rejects changed sources, populations, options or device type. Corrupted artifacts fail loading. Active baseline rollback paths are unchanged.
