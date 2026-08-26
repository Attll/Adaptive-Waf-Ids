from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import tomllib

from adaptive_waf.config import load_settings
from adaptive_waf.training.http_data import load_triage_dataset
from adaptive_waf.training.models import CandidateAlgorithm
from adaptive_waf.training.runner import train_candidates


def main() -> None:
    arguments = _parse_arguments()
    settings = load_settings(arguments.core_config)
    config = _load_toml(arguments.config)
    dataset_directory = settings.paths.processed_data / "atrdf" / config["dataset_version"]
    run_id = arguments.run_id or _default_run_id()
    output_directory = settings.paths.artifacts / "training" / "triage" / run_id
    algorithms = tuple(CandidateAlgorithm(value) for value in (arguments.algorithms or config["algorithms"]))
    parameters = {
        CandidateAlgorithm(name): values for name, values in config.get("parameters", {}).items() if CandidateAlgorithm(name) in algorithms
    }
    print(f"Training triage candidates: {', '.join(algorithm.value for algorithm in algorithms)}")
    train = load_triage_dataset(dataset_directory / "train.jsonl", arguments.max_samples_per_class)
    validation = load_triage_dataset(dataset_directory / "validation.jsonl", arguments.max_samples_per_class)
    print(f"Train samples: {len(train.labels)}; validation samples: {len(validation.labels)}")
    runs = train_candidates(
        train.features,
        train.labels,
        validation.features,
        validation.labels,
        feature_names=train.feature_names,
        output_directory=output_directory,
        random_seed=settings.random_seed,
        algorithms=algorithms,
        parameters=parameters,
        run_metadata={
            "model_role": "triage",
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
    print(f"Training completed: {output_directory}")


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train ATRDF binary triage candidates.")
    parser.add_argument("--config", type=Path, default=Path("configs/models/triage.toml"))
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


def _default_run_id() -> str:
    return datetime.now(timezone.utc).strftime("triage-%Y%m%dT%H%M%SZ")


if __name__ == "__main__":
    main()
