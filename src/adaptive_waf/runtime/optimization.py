def configure_inference_threads(model, threads):
    """Bound estimator parallelism for single-record inference without retraining or changing artifacts."""
    if not isinstance(threads, int) or not 1 <= threads <= 32:
        raise ValueError("inference threads must be in 1..32")
    visited = set()
    def apply(value):
        if id(value) in visited:
            return
        visited.add(id(value))
        if hasattr(value, "n_jobs"):
            value.n_jobs = threads
        for name in ("estimator", "base_estimator", "calibrated_classifiers_"):
            child = getattr(value, name, None)
            if child is not None:
                for member in child if isinstance(child, list) else [child]:
                    apply(member)
        for _, child in getattr(value, "steps", []):
            apply(child)
    apply(model)
    return model
