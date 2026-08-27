from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import tomllib

from adaptive_waf.config import load_settings
from adaptive_waf.training.models import CandidateAlgorithm
from adaptive_waf.training.network_data import load_network_dataset
from adaptive_waf.training.runner import train_candidates


def main() -> None:
    arguments = _parse_arguments()
    settings = load_settings(arguments.core_config)
    config = _toml(arguments.config)
    sample_limit = arguments.max_samples_per_class or int(config["max_samples_per_class"])
    dataset_directory = settings.paths.processed_data / "cicids2018" / str(config["dataset_version"])
    output_directory = settings.paths.artifacts / "training" / "network" / (arguments.run_id or _default_run_id())
    algorithms = tuple(CandidateAlgorithm(value) for value in (arguments.algorithms or config["algorithms"]))
    parameters = {CandidateAlgorithm(name): values for name, values in config.get("parameters", {}).items() if CandidateAlgorithm(name) in algorithms}
    print(f"Loading CICIDS network data with up to {sample_limit} samples per class")
    train_features, train_labels, feature_names = load_network_dataset(dataset_directory / "train.jsonl", sample_limit, settings.random_seed)
    validation_features, validation_labels, validation_names = load_network_dataset(dataset_directory / "validation.jsonl", sample_limit, settings.random_seed + 1)
    if feature_names != validation_names:
        raise ValueError("network training and validation feature schemas differ")
    print(f"Training network candidates: {', '.join(algorithm.value for algorithm in algorithms)}; train={len(train_labels)}; validation={len(validation_labels)}")
    runs = train_candidates(
        train_features,
        train_labels,
        validation_features,
        validation_labels,
        feature_names,
        output_directory,
        settings.random_seed,
        algorithms,
        parameters,
        {"model_role": "network_context", "dataset_version": config["dataset_version"], "feature_version": config["feature_version"], "max_samples_per_class": sample_limit},
    )
    _write(output_directory / "config.json", {"config": config, "run_id": output_directory.name, "dataset_directory": str(dataset_directory)})
    _write(output_directory / "feature_manifest.json", {"feature_names": feature_names, "feature_version": config["feature_version"]})
    _write(output_directory / "metrics.json", {"runs": [{"algorithm": run.algorithm.value, "artifact_directory": str(run.artifact_directory), "model_size_bytes": run.model_size_bytes, "evaluation": run.evaluation.as_dict()} for run in runs]})
    (output_directory / "train.log").write_text("\n".join(f"{run.algorithm.value}: macro_f1={run.evaluation.f1_macro:.4f}" for run in runs) + "\n", encoding="utf-8")
    print(f"Network training completed: {output_directory}")


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train offline CICIDS network-context candidates.")
    parser.add_argument("--config", type=Path, default=Path("configs/models/network.toml"))
    parser.add_argument("--core-config", type=Path, default=None)
    parser.add_argument("--run-id")
    parser.add_argument("--algorithms", nargs="+")
    parser.add_argument("--max-samples-per-class", type=int, default=None)
    return parser.parse_args()


def _toml(path: Path) -> dict[str, object]:
    with path.open("rb") as source:
        return tomllib.load(source)


def _write(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _default_run_id() -> str:
    return datetime.now(timezone.utc).strftime("network-%Y%m%dT%H%M%SZ")


if __name__ == "__main__":
    main()
