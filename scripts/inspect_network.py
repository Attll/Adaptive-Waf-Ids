from __future__ import annotations

import argparse
import json
from pathlib import Path

from adaptive_waf.config import load_settings
from adaptive_waf.runtime.artifacts import load_offline_network_detector


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect one prepared CICIDS flow with the deployed network detector.")
    parser.add_argument("--sample-split", choices=("train", "validation", "test"), default="test")
    parser.add_argument("--sample-index", type=int, default=0)
    parser.add_argument("--core-config", type=Path, default=None)
    arguments = parser.parse_args()
    if arguments.sample_index < 0:
        raise ValueError("sample-index must not be negative")

    settings = load_settings(arguments.core_config)
    deployment = _toml(settings.paths.project_root / "configs/models/network_deployment.toml")
    record = _read_record(
        settings.paths.processed_data / "cicids2018" / str(deployment["dataset_version"]) / f"{arguments.sample_split}.jsonl",
        arguments.sample_index,
    )
    detector = load_offline_network_detector(arguments.core_config)
    context = detector.detect(record["features"])
    print(json.dumps({
        "expected_class": record["label"],
        "network_class": context.network_class,
        "network_risk": context.risk,
        "confidence": context.confidence,
        "model_version": detector.model_version,
    }, indent=2))


def _read_record(path: Path, index: int) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as source:
        for current_index, line in enumerate(source):
            if current_index == index:
                record = json.loads(line)
                if not isinstance(record.get("features"), dict) or not isinstance(record.get("label"), str):
                    raise ValueError(f"invalid prepared network record at {path}:{index}")
                return record
    raise IndexError(f"sample-index {index} is outside {path}")


def _toml(path: Path) -> dict[str, object]:
    import tomllib

    with path.open("rb") as source:
        return tomllib.load(source)


if __name__ == "__main__":
    main()
