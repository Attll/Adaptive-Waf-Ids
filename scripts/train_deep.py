from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import tomllib

from adaptive_waf.config import load_settings
from adaptive_waf.training.deep_data import load_deep_dataset
from adaptive_waf.training.deep_training import ensure_deep_dependencies, train_char_cnn, train_distilbert


def main() -> None:
    arguments = _parse_arguments()
    settings = load_settings(arguments.core_config)
    config = _load_toml(arguments.config)
    candidate = arguments.candidate
    ensure_deep_dependencies(candidate)
    options = config["candidates"][candidate]
    classes = tuple(str(label) for label in config["classes"])
    dataset_directory = settings.paths.processed_data / "atrdf" / str(config["dataset_version"])
    run_id = arguments.run_id or _default_run_id(candidate)
    output_directory = settings.paths.artifacts / "training" / "deep" / run_id
    output_directory.mkdir(parents=True, exist_ok=False)
    train = load_deep_dataset(dataset_directory / "train.jsonl", classes, arguments.max_samples_per_class)
    validation = load_deep_dataset(dataset_directory / "validation.jsonl", classes, arguments.max_samples_per_class)
    print(f"Training deep candidate: {candidate}; train samples: {len(train.labels)}; validation samples: {len(validation.labels)}")
    trainer = {"char_cnn": train_char_cnn, "distilbert": train_distilbert}[candidate]
    evaluation = trainer(train, validation, classes, options, output_directory, settings.random_seed, str(config["device"]))
    _write_json(output_directory / "config.json", {"config": config, "candidate": candidate, "run_id": run_id, "dataset_directory": str(dataset_directory)})
    _write_json(output_directory / "class_mapping.json", {"classes": classes})
    _write_json(output_directory / "metrics.json", {"candidate": candidate, "evaluation": evaluation.as_dict()})
    (output_directory / "train.log").write_text(f"{candidate}: macro_f1={evaluation.f1_macro:.4f}\n", encoding="utf-8")
    print(f"Deep candidate complete: {candidate}; macro_f1={evaluation.f1_macro:.4f}; p95_ms={evaluation.inference_p95_ms:.4f}; artifact={output_directory}")


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train a deep HTTP escalation candidate.")
    parser.add_argument("--config", type=Path, default=Path("configs/models/deep.toml"))
    parser.add_argument("--core-config", type=Path, default=None)
    parser.add_argument("--candidate", choices=("char_cnn", "distilbert"), required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--max-samples-per-class", type=int, default=None)
    return parser.parse_args()


def _load_toml(path: Path) -> dict[str, object]:
    with path.open("rb") as source:
        return tomllib.load(source)


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _default_run_id(candidate: str) -> str:
    return datetime.now(timezone.utc).strftime(f"{candidate}-%Y%m%dT%H%M%SZ")


if __name__ == "__main__":
    main()
