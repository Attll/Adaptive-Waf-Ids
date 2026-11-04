# Training run prepared — ON HOLD

On 28 October 2026 the user explicitly instructed: “Hold expensive training; continue safe work.” Do not execute the proposed training or substitute another expensive run without new authorization.

The revised Character CNN training controls passed a two-record CPU smoke test. It checks checkpointing and a training manifest, not predictive utility. CUDA hardware capability was verified separately. No expensive dataset training has been launched.

Proposed first bounded GPU experiment (run sequentially; output must not already exist):

```powershell
.\.venv\Scripts\python.exe -m scripts.train_deep --config configs/models/deep_research.toml --candidate char_cnn --max-samples-per-class 1000 --run-id research-char-cnn-cuda-20261028-v1
```

Maximum 1000 examples per class from each of train and validation, six classes, ten epochs with patience two; clipping, CUDA mixed precision, pinned transfers, seeded ordering and best-checkpoint selection are enabled. Only train/validation are read. The model is not deployed and existing artifacts are not overwritten. Runtime and held-out utility remain unmeasured until the experiment is approved and run. A comparable CPU run and repeated GPU trials require separate resource budgeting after the first manifest is inspected.

XGBoost and LightGBM are not installed; GPU-capable LightGBM cannot be inferred from CUDA availability. Compact transformer weights are not cached/approved. These candidate configurations are prepared but their model comparisons are BLOCKED by dependencies/download approval and measured training. They are not reported as evaluated models.
