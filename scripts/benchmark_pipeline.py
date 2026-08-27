from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import tomllib

from adaptive_waf.config import load_settings
from adaptive_waf.runtime.artifacts import load_adaptive_pipeline, load_offline_policy_simulator
from adaptive_waf.runtime.benchmark import run_http_benchmark
from adaptive_waf.training.http_data import iter_prepared_http_samples


def main() -> None:
    arguments = _parse_arguments()
    settings = load_settings(arguments.core_config)
    config = _toml(arguments.config)
    sample_limit = arguments.max_samples_per_class or int(config["max_samples_per_class"])
    split = arguments.split or str(config["split"])
    dataset_directory = settings.paths.processed_data / "atrdf" / str(config["dataset_version"])
    output_directory = settings.paths.artifacts / "benchmarks" / (arguments.run_id or _default_run_id())
    output_directory.mkdir(parents=True, exist_ok=False)
    print(f"Benchmarking {split} samples with up to {sample_limit} samples per class")
    report, records = run_http_benchmark(
        load_adaptive_pipeline(arguments.core_config),
        load_offline_policy_simulator(arguments.core_config),
        iter_prepared_http_samples(dataset_directory / f"{split}.jsonl", sample_limit),
    )
    (output_directory / "metrics.json").write_text(json.dumps(report.as_dict(), indent=2) + "\n", encoding="utf-8")
    with (output_directory / "records.jsonl").open("w", encoding="utf-8", newline="\n") as destination:
        for record in records:
            destination.write(json.dumps(record, default=str) + "\n")
    print(json.dumps(report.as_dict(), indent=2))
    print(f"Benchmark artifacts: {output_directory}")


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark the deployed Adaptive WAF pipeline on a balanced prepared ATRDF split.")
    parser.add_argument("--config", type=Path, default=Path("configs/models/benchmark.toml"))
    parser.add_argument("--core-config", type=Path, default=None)
    parser.add_argument("--split", choices=("train", "validation", "test"), default=None)
    parser.add_argument("--max-samples-per-class", type=int, default=None)
    parser.add_argument("--run-id")
    return parser.parse_args()


def _toml(path: Path) -> dict[str, object]:
    with path.open("rb") as source:
        return tomllib.load(source)


def _default_run_id() -> str:
    return datetime.now(timezone.utc).strftime("phase1-%Y%m%dT%H%M%SZ")


if __name__ == "__main__":
    main()
