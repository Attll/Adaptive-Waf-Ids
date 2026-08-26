from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from time import perf_counter_ns
from typing import Sequence

from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import label_binarize


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    accuracy: float
    precision_macro: float
    recall_macro: float
    f1_macro: float
    f1_weighted: float
    pr_auc: float | None
    roc_auc: float | None
    false_positive_rate: float | None
    false_negative_rate: float | None
    confusion_matrix: list[list[int]]
    labels: list[str]
    inference_p50_ms: float
    inference_p95_ms: float

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def evaluate_classifier(model, features: Sequence[Sequence[float]], labels: Sequence[str]) -> EvaluationResult:
    predictions = model.predict(features)
    probabilities = model.predict_proba(features)
    label_order = [str(label) for label in model.classes_]
    durations = _inference_durations_ms(model, features)
    binary_rates = _binary_error_rates(labels, predictions, label_order)
    return EvaluationResult(
        accuracy=float(accuracy_score(labels, predictions)),
        precision_macro=float(precision_score(labels, predictions, average="macro", zero_division=0)),
        recall_macro=float(recall_score(labels, predictions, average="macro", zero_division=0)),
        f1_macro=float(f1_score(labels, predictions, average="macro", zero_division=0)),
        f1_weighted=float(f1_score(labels, predictions, average="weighted", zero_division=0)),
        pr_auc=_multiclass_auc(labels, probabilities, label_order, average_precision_score),
        roc_auc=_multiclass_auc(labels, probabilities, label_order, roc_auc_score),
        false_positive_rate=binary_rates[0],
        false_negative_rate=binary_rates[1],
        confusion_matrix=confusion_matrix(labels, predictions, labels=label_order).tolist(),
        labels=label_order,
        inference_p50_ms=_percentile(durations, 50),
        inference_p95_ms=_percentile(durations, 95),
    )


def _multiclass_auc(labels, probabilities, classes: Sequence[str], metric) -> float | None:
    try:
        if len(classes) == 2:
            positive = classes[1]
            encoded = [int(label == positive) for label in labels]
            return float(metric(encoded, [row[1] for row in probabilities]))
        encoded = label_binarize(labels, classes=classes)
        return float(metric(encoded, probabilities, average="macro"))
    except ValueError:
        return None


def _binary_error_rates(labels, predictions, classes: Sequence[str]) -> tuple[float | None, float | None]:
    if len(classes) != 2:
        return None, None
    matrix = confusion_matrix(labels, predictions, labels=classes)
    true_negative, false_positive, false_negative, true_positive = matrix.ravel()
    fpr = false_positive / (false_positive + true_negative) if false_positive + true_negative else 0.0
    fnr = false_negative / (false_negative + true_positive) if false_negative + true_positive else 0.0
    return fpr, fnr


def _inference_durations_ms(model, features: Sequence[Sequence[float]]) -> list[float]:
    samples = features[: min(len(features), 128)]
    durations: list[float] = []
    for sample in samples:
        start = perf_counter_ns()
        model.predict_proba([sample])
        durations.append((perf_counter_ns() - start) / 1_000_000)
    return durations or [0.0]


def _percentile(values: Sequence[float], percentile: int) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile / 100
    lower = math.floor(position)
    upper = math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)
