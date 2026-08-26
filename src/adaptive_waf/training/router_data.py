from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from adaptive_waf.contracts import AttackClass, ExpertFamily
from adaptive_waf.training.http_data import HttpFeatureDataset, _read_jsonl, _request_from_record
from adaptive_waf.features.classical import ClassicalFeatureExtractor


_FAMILY_BY_ATTACK = {
    AttackClass.SQL_INJECTION.value: ExpertFamily.INJECTION.value,
    AttackClass.XSS.value: ExpertFamily.INJECTION.value,
    AttackClass.COOKIE_INJECTION.value: ExpertFamily.INJECTION.value,
    AttackClass.DIRECTORY_TRAVERSAL.value: ExpertFamily.EXECUTION.value,
    AttackClass.REMOTE_CODE_EXECUTION.value: ExpertFamily.EXECUTION.value,
}


def load_router_dataset(path: Path, max_samples_per_family: int | None = None) -> HttpFeatureDataset:
    extractor = ClassicalFeatureExtractor()
    features: list[list[float]] = []
    labels: list[str] = []
    feature_names: tuple[str, ...] | None = None
    family_counts: dict[str, int] = {}
    for record in _read_jsonl(path):
        family = _FAMILY_BY_ATTACK.get(str(record["label"]))
        if family is None:
            continue
        if max_samples_per_family is not None and family_counts.get(family, 0) >= max_samples_per_family:
            continue
        vector = extractor.extract(_request_from_record(record["request"]))
        if feature_names is None:
            feature_names = vector.names
        elif feature_names != vector.names:
            raise ValueError("classical feature schema changed within one dataset split")
        features.append(list(vector.values))
        labels.append(family)
        family_counts[family] = family_counts.get(family, 0) + 1
    if not features:
        raise ValueError(f"no labeled attack records found in {path}")
    if len(set(labels)) != len(ExpertFamily):
        raise ValueError(f"router dataset must contain every family: found {sorted(set(labels))}")
    return HttpFeatureDataset(features=features, labels=labels, feature_names=feature_names or ())
