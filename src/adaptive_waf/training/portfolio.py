"""Optional candidates are loaded lazily; unavailable GPU backends are explicit, never mislabeled."""
from importlib.util import find_spec


def available_candidates():
    return {"xgboost": find_spec("xgboost") is not None, "lightgbm": find_spec("lightgbm") is not None,
            "char_cnn": find_spec("torch") is not None, "compact_transformer": find_spec("transformers") is not None}


def build_tabular_candidate(name, device="auto", seed=641):
    if device not in {"auto", "cpu", "cuda"}:
        raise ValueError("device must be auto, cpu or cuda")
    use_cuda = False
    if device != "cpu" and find_spec("torch"):
        import torch
        use_cuda = torch.cuda.is_available()
    if name == "xgboost":
        from xgboost import XGBClassifier
        return XGBClassifier(n_estimators=200, max_depth=6, tree_method="hist", device="cuda" if use_cuda else "cpu",
                             random_state=seed, n_jobs=2, eval_metric="mlogloss")
    if name == "lightgbm":
        from lightgbm import LGBMClassifier
        # OpenCL availability cannot be inferred from CUDA presence. Use CPU unless explicitly requested.
        return LGBMClassifier(n_estimators=200, max_depth=6, device_type="gpu" if device == "cuda" else "cpu",
                              random_state=seed, n_jobs=2, verbosity=-1)
    raise ValueError("unknown tabular portfolio candidate")
