from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from typing import Sequence

from sklearn.metrics import accuracy_score, average_precision_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.preprocessing import label_binarize


@dataclass(frozen=True, slots=True)
class DeepEvaluationResult:
    accuracy: float
    precision_macro: float
    recall_macro: float
    f1_macro: float
    f1_weighted: float
    pr_auc: float | None
    roc_auc: float | None
    confusion_matrix: list[list[int]]
    labels: list[str]
    inference_p50_ms: float
    inference_p95_ms: float

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def evaluate_deep_predictions(
    labels: Sequence[str],
    probabilities: Sequence[Sequence[float]],
    class_order: Sequence[str],
    durations_ms: Sequence[float],
) -> DeepEvaluationResult:
    predictions = [class_order[max(range(len(row)), key=row.__getitem__)] for row in probabilities]
    return DeepEvaluationResult(
        accuracy=float(accuracy_score(labels, predictions)),
        precision_macro=float(precision_score(labels, predictions, average="macro", zero_division=0)),
        recall_macro=float(recall_score(labels, predictions, average="macro", zero_division=0)),
        f1_macro=float(f1_score(labels, predictions, average="macro", zero_division=0)),
        f1_weighted=float(f1_score(labels, predictions, average="weighted", zero_division=0)),
        pr_auc=_multiclass_auc(labels, probabilities, class_order, average_precision_score),
        roc_auc=_multiclass_auc(labels, probabilities, class_order, roc_auc_score),
        confusion_matrix=confusion_matrix(labels, predictions, labels=class_order).tolist(),
        labels=list(class_order),
        inference_p50_ms=_percentile(durations_ms, 50),
        inference_p95_ms=_percentile(durations_ms, 95),
    )


def _multiclass_auc(labels, probabilities, classes, metric) -> float | None:
    try:
        encoded = label_binarize(labels, classes=classes)
        return float(metric(encoded, probabilities, average="macro"))
    except ValueError:
        return None


def _percentile(values: Sequence[float], percentile: int) -> float:
    ordered = sorted(values) or [0.0]
    position = (len(ordered) - 1) * percentile / 100
    lower, upper = math.floor(position), math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)
