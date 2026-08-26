from __future__ import annotations

from pathlib import Path
from typing import Collection

from adaptive_waf.features.classical import ClassicalFeatureExtractor
from adaptive_waf.training.http_data import HttpFeatureDataset, _read_jsonl, _request_from_record


def load_expert_dataset(
    path: Path,
    classes: Collection[str],
    max_samples_per_class: int | None = None,
) -> HttpFeatureDataset:
    allowed_classes = tuple(classes)
    if "BENIGN" not in allowed_classes or len(allowed_classes) < 3:
        raise ValueError("an expert must include BENIGN and at least two attack classes")
    extractor = ClassicalFeatureExtractor()
    features: list[list[float]] = []
    labels: list[str] = []
    feature_names: tuple[str, ...] | None = None
    class_counts: dict[str, int] = {}
    for record in _read_jsonl(path):
        label = str(record["label"])
        if label not in allowed_classes:
            continue
        if max_samples_per_class is not None and class_counts.get(label, 0) >= max_samples_per_class:
            continue
        vector = extractor.extract(_request_from_record(record["request"]))
        if feature_names is None:
            feature_names = vector.names
        elif feature_names != vector.names:
            raise ValueError("classical feature schema changed within one dataset split")
        features.append(list(vector.values))
        labels.append(label)
        class_counts[label] = class_counts.get(label, 0) + 1
    if not features:
        raise ValueError(f"no expert records found in {path}")
    missing = sorted(set(allowed_classes) - set(labels))
    if missing:
        raise ValueError(f"expert dataset is missing required classes: {missing}")
    return HttpFeatureDataset(features=features, labels=labels, feature_names=feature_names or ())
