from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import tomllib

from adaptive_waf.config import load_settings
from adaptive_waf.training.expert_data import load_expert_dataset
from adaptive_waf.training.models import CandidateAlgorithm
from adaptive_waf.training.runner import train_candidates


def main() -> None:
    arguments = _parse_arguments()
    settings = load_settings(arguments.core_config)
    config = _load_toml(arguments.config)
    family = str(config["expert_family"]).lower()
    classes = tuple(str(label) for label in config["classes"])
    dataset_directory = settings.paths.processed_data / "atrdf" / str(config["dataset_version"])
    run_id = arguments.run_id or _default_run_id(family)
    output_directory = settings.paths.artifacts / "training" / "experts" / family / run_id
    algorithms = tuple(CandidateAlgorithm(value) for value in (arguments.algorithms or config["algorithms"]))
    parameters = {CandidateAlgorithm(name): values for name, values in config.get("parameters", {}).items() if CandidateAlgorithm(name) in algorithms}
    print(f"Training {family} expert candidates: {', '.join(algorithm.value for algorithm in algorithms)}")
    train = load_expert_dataset(dataset_directory / "train.jsonl", classes, arguments.max_samples_per_class)
    validation = load_expert_dataset(dataset_directory / "validation.jsonl", classes, arguments.max_samples_per_class)
    print(f"Train samples: {len(train.labels)}; validation samples: {len(validation.labels)}; classes: {', '.join(classes)}")
    runs = train_candidates(
        train.features,
        train.labels,
        validation.features,
        validation.labels,
        train.feature_names,
        output_directory,
        settings.random_seed,
        algorithms,
        parameters,
        {
            "model_role": "expert",
            "expert_family": str(config["expert_family"]),
            "classes": list(classes),
            "dataset_version": config["dataset_version"],
            "feature_version": config["feature_version"],
            "train_samples": len(train.labels),
            "validation_samples": len(validation.labels),
        },
    )
    _write_json(output_directory / "config.json", {"config": config, "run_id": run_id, "dataset_directory": str(dataset_directory)})
    _write_json(output_directory / "feature_manifest.json", {"feature_names": train.feature_names, "feature_version": config["feature_version"]})
    _write_json(output_directory / "metrics.json", {"runs": [_run_summary(run) for run in runs]})
    (output_directory / "train.log").write_text(
        "\n".join(f"{run.algorithm.value}: macro_f1={run.evaluation.f1_macro:.4f}" for run in runs) + "\n",
        encoding="utf-8",
    )
    print(f"{family.title()} expert training completed: {output_directory}")


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train a configured ATRDF HTTP attack-family expert.")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--core-config", type=Path, default=None)
    parser.add_argument("--run-id")
    parser.add_argument("--algorithms", nargs="+")
    parser.add_argument("--max-samples-per-class", type=int, default=None)
    return parser.parse_args()


def _load_toml(path: Path) -> dict[str, object]:
    with path.open("rb") as source:
        return tomllib.load(source)


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _run_summary(run) -> dict[str, object]:
    return {
        "algorithm": run.algorithm.value,
        "artifact_directory": str(run.artifact_directory),
        "model_size_bytes": run.model_size_bytes,
        "evaluation": run.evaluation.as_dict(),
    }


def _default_run_id(family: str) -> str:
    return datetime.now(timezone.utc).strftime(f"{family}-expert-%Y%m%dT%H%M%SZ")


if __name__ == "__main__":
    main()
