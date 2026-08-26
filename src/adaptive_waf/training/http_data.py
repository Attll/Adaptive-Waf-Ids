from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Iterator

from adaptive_waf.contracts import HttpRequestRecord
from adaptive_waf.features.classical import ClassicalFeatureExtractor


@dataclass(frozen=True, slots=True)
class HttpFeatureDataset:
    features: list[list[float]]
    labels: list[str]
    feature_names: tuple[str, ...]


def load_triage_dataset(path: Path, max_samples_per_class: int | None = None) -> HttpFeatureDataset:
    extractor = ClassicalFeatureExtractor()
    features: list[list[float]] = []
    labels: list[str] = []
    feature_names: tuple[str, ...] | None = None
    class_counts: Counter[str] = Counter()
    for record in _read_jsonl(path):
        label = "BENIGN_LIKE" if record["label"] == "BENIGN" else "SUSPICIOUS"
        if max_samples_per_class is not None and class_counts[label] >= max_samples_per_class:
            continue
        vector = extractor.extract(_request_from_record(record["request"]))
        if feature_names is None:
            feature_names = vector.names
        elif feature_names != vector.names:
            raise ValueError("classical feature schema changed within one dataset split")
        features.append(list(vector.values))
        labels.append(label)
        class_counts[label] += 1
        if max_samples_per_class is not None and len(class_counts) == 2 and all(
            class_counts[name] >= max_samples_per_class for name in ("BENIGN_LIKE", "SUSPICIOUS")
        ):
            break
    if not features:
        raise ValueError(f"no HTTP records found in {path}")
    return HttpFeatureDataset(features=features, labels=labels, feature_names=feature_names or ())


def _read_jsonl(path: Path) -> Iterator[dict[str, object]]:
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if line.strip():
                record = json.loads(line)
                if not isinstance(record.get("request"), dict) or not isinstance(record.get("label"), str):
                    raise ValueError(f"invalid prepared HTTP record at {path}:{line_number}")
                yield record


def _request_from_record(record: dict[str, object]) -> HttpRequestRecord:
    return HttpRequestRecord(
        method=str(record["method"]),
        path=str(record["path"]),
        query=str(record.get("query", "")),
        headers={str(name): str(value) for name, value in dict(record.get("headers", {})).items()},
        cookies={str(name): str(value) for name, value in dict(record.get("cookies", {})).items()},
        body=str(record.get("body", "")),
    )
