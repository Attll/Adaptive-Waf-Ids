from __future__ import annotations

import json
from pathlib import Path
import random

import numpy


def load_network_dataset(path: Path, max_samples_per_class: int, seed: int) -> tuple[numpy.ndarray, list[str], tuple[str, ...]]:
    if max_samples_per_class <= 0:
        raise ValueError("max_samples_per_class must be positive")
    reservoirs: dict[str, list[list[float]]] = {}
    seen: dict[str, int] = {}
    feature_names: tuple[str, ...] | None = None
    randomizer = random.Random(seed)
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            features = record.get("features")
            label = record.get("label")
            if not isinstance(features, dict) or not isinstance(label, str):
                raise ValueError(f"invalid network record at {path}:{line_number}")
            names = tuple(features)
            if feature_names is None:
                feature_names = names
            elif names != feature_names:
                raise ValueError("network feature schema changed within one split")
            values = [float(features[name]) for name in names]
            seen[label] = seen.get(label, 0) + 1
            reservoir = reservoirs.setdefault(label, [])
            if len(reservoir) < max_samples_per_class:
                reservoir.append(values)
            else:
                replacement = randomizer.randrange(seen[label])
                if replacement < max_samples_per_class:
                    reservoir[replacement] = values
    if not reservoirs:
        raise ValueError(f"no network records found in {path}")
    labels = [label for label in sorted(reservoirs) for _ in reservoirs[label]]
    rows = [row for label in sorted(reservoirs) for row in reservoirs[label]]
    return numpy.asarray(rows, dtype=numpy.float32), labels, feature_names or ()
