from __future__ import annotations

import math
from typing import Sequence


def probability_quality(
    probabilities: Sequence[Sequence[float]], labels: Sequence[str], class_order: Sequence[str], bins: int = 10
) -> dict[str, float]:
    class_indexes = {label: index for index, label in enumerate(class_order)}
    brier = sum(
        sum((score - float(index == class_indexes[label])) ** 2 for index, score in enumerate(row))
        for row, label in zip(probabilities, labels)
    ) / len(labels)
    confidence_and_correctness = [
        (max(row), class_order[max(range(len(row)), key=row.__getitem__)] == label) for row, label in zip(probabilities, labels)
    ]
    ece = 0.0
    for index in range(bins):
        lower, upper = index / bins, (index + 1) / bins
        members = [item for item in confidence_and_correctness if lower <= item[0] < upper or (index == bins - 1 and item[0] == 1.0)]
        if members:
            ece += len(members) / len(labels) * abs(sum(item[1] for item in members) / len(members) - sum(item[0] for item in members) / len(members))
    return {"multiclass_brier_score": brier, "top_label_expected_calibration_error": ece}


def calibrate_sklearn_model(model, features, labels, method: str):
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.frozen import FrozenEstimator

    calibrated = CalibratedClassifierCV(FrozenEstimator(model), method=method)
    calibrated.fit(features, labels)
    return calibrated
