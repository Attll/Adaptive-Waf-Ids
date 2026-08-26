from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import tomllib

from adaptive_waf.config import load_settings
from adaptive_waf.training.ensemble_evaluation import evaluate_expert_ensembles
from adaptive_waf.training.expert_data import load_expert_dataset


def main() -> None:
    arguments = _parse_arguments()
    settings = load_settings(arguments.core_config)
    config = _load_toml(arguments.config)
    output_directory = settings.paths.artifacts / "training" / "ensembles" / (arguments.run_id or _default_run_id())
    output_directory.mkdir(parents=True, exist_ok=False)
    dataset_directory = settings.paths.processed_data / "atrdf" / str(config["dataset_version"])
    summaries: dict[str, object] = {}
    for family in ("injection", "execution"):
        family_config = config[family]
        validation = load_expert_dataset(
            dataset_directory / "validation.jsonl",
            family_config["classes"],
            arguments.max_samples_per_class,
        )
        artifact_directory = settings.paths.artifacts / "training" / "experts" / family / str(family_config["run_id"])
        print(f"Evaluating {family} ensembles with {len(validation.labels)} validation samples")
        results = evaluate_expert_ensembles(
            artifact_directory,
            family_config["algorithms"],
            validation.features,
            validation.labels,
            float(config["minimum_macro_f1_gain"]),
        )
        summaries[family] = {"results": [result.as_dict() for result in results]}
        for result in results:
            print(f"{family} ensemble {'+'.join(result.members)}: macro_f1={result.evaluation.f1_macro:.4f}; retained={result.retained}")
    _write_json(output_directory / "config.json", config)
    _write_json(output_directory / "metrics.json", summaries)
    print(f"Ensemble evaluation completed: {output_directory}")


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate optional soft-voting HTTP expert ensembles.")
    parser.add_argument("--config", type=Path, default=Path("configs/models/expert_ensemble.toml"))
    parser.add_argument("--core-config", type=Path, default=None)
    parser.add_argument("--run-id")
    parser.add_argument("--max-samples-per-class", type=int, default=None)
    return parser.parse_args()


def _load_toml(path: Path) -> dict[str, object]:
    with path.open("rb") as source:
        return tomllib.load(source)


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _default_run_id() -> str:
    return datetime.now(timezone.utc).strftime("expert-ensembles-%Y%m%dT%H%M%SZ")


if __name__ == "__main__":
    main()
