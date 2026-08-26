from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from time import perf_counter_ns
from typing import Sequence

from sklearn.metrics import accuracy_score, confusion_matrix

from adaptive_waf.contracts import ExpertFamily


@dataclass(frozen=True, slots=True)
class RouterEvaluationResult:
    top1_accuracy: float
    top2_coverage: float
    confusion_matrix: list[list[int]]
    labels: list[str]
    multiclass_brier_score: float
    top_label_expected_calibration_error: float
    inference_p50_ms: float
    inference_p95_ms: float

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RoutingThresholdResult:
    minimum_top1_probability: float
    minimum_top1_margin: float
    top1_route_rate: float
    selected_family_coverage: float

    def as_dict(self) -> dict[str, float]:
        return asdict(self)


def evaluate_router(model, features: Sequence[Sequence[float]], labels: Sequence[str]) -> RouterEvaluationResult:
    probabilities = model.predict_proba(features)
    class_order = [str(label) for label in model.classes_]
    predictions = [class_order[max(range(len(row)), key=row.__getitem__)] for row in probabilities]
    durations = _inference_durations_ms(model, features)
    return RouterEvaluationResult(
        top1_accuracy=float(accuracy_score(labels, predictions)),
        top2_coverage=_top2_coverage(probabilities, labels, class_order),
        confusion_matrix=confusion_matrix(labels, predictions, labels=class_order).tolist(),
        labels=class_order,
        multiclass_brier_score=_multiclass_brier_score(probabilities, labels, class_order),
        top_label_expected_calibration_error=_top_label_ece(probabilities, labels, class_order),
        inference_p50_ms=_percentile(durations, 50),
        inference_p95_ms=_percentile(durations, 95),
    )


def evaluate_routing_thresholds(
    probabilities: Sequence[Sequence[float]],
    labels: Sequence[str],
    class_order: Sequence[str],
    top1_probabilities: Sequence[float],
    margins: Sequence[float],
) -> list[RoutingThresholdResult]:
    results: list[RoutingThresholdResult] = []
    for minimum_probability in top1_probabilities:
        for minimum_margin in margins:
            selected = [
                select_experts(row, class_order, minimum_probability, minimum_margin)
                for row in probabilities
            ]
            results.append(
                RoutingThresholdResult(
                    minimum_top1_probability=minimum_probability,
                    minimum_top1_margin=minimum_margin,
                    top1_route_rate=sum(len(families) == 1 for families in selected) / len(selected),
                    selected_family_coverage=sum(label in families for label, families in zip(labels, selected)) / len(selected),
                )
            )
    return results


def select_experts(
    probabilities: Sequence[float],
    class_order: Sequence[str],
    minimum_top1_probability: float,
    minimum_top1_margin: float,
) -> tuple[str, ...]:
    if len(probabilities) != len(class_order) or len(probabilities) != len(ExpertFamily):
        raise ValueError("router probabilities must contain exactly the configured expert families")
    if not 0.0 <= minimum_top1_probability <= 1.0 or not 0.0 <= minimum_top1_margin <= 1.0:
        raise ValueError("routing thresholds must be between 0 and 1")
    ranked = sorted(range(len(probabilities)), key=probabilities.__getitem__, reverse=True)
    top, runner_up = ranked
    if probabilities[top] >= minimum_top1_probability and probabilities[top] - probabilities[runner_up] >= minimum_top1_margin:
        return (str(class_order[top]),)
    return tuple(str(class_order[index]) for index in ranked)


def router_probability_outputs(model, features: Sequence[Sequence[float]]) -> tuple[list[list[float]], list[str]]:
    return model.predict_proba(features).tolist(), [str(label) for label in model.classes_]


def _top2_coverage(probabilities: Sequence[Sequence[float]], labels: Sequence[str], classes: Sequence[str]) -> float:
    return sum(
        label in {classes[index] for index in sorted(range(len(row)), key=row.__getitem__, reverse=True)[:2]}
        for row, label in zip(probabilities, labels)
    ) / len(labels)


def _multiclass_brier_score(probabilities: Sequence[Sequence[float]], labels: Sequence[str], classes: Sequence[str]) -> float:
    index_by_class = {label: index for index, label in enumerate(classes)}
    return sum(
        sum((score - float(index == index_by_class[label])) ** 2 for index, score in enumerate(row))
        for row, label in zip(probabilities, labels)
    ) / len(labels)


def _top_label_ece(probabilities: Sequence[Sequence[float]], labels: Sequence[str], classes: Sequence[str], bins: int = 10) -> float:
    confidence_and_correctness = [
        (max(row), classes[max(range(len(row)), key=row.__getitem__)] == label) for row, label in zip(probabilities, labels)
    ]
    total = len(confidence_and_correctness)
    error = 0.0
    for bin_index in range(bins):
        lower, upper = bin_index / bins, (bin_index + 1) / bins
        members = [item for item in confidence_and_correctness if lower <= item[0] < upper or (bin_index == bins - 1 and item[0] == 1.0)]
        if members:
            average_confidence = sum(item[0] for item in members) / len(members)
            accuracy = sum(item[1] for item in members) / len(members)
            error += len(members) / total * abs(accuracy - average_confidence)
    return error


def _inference_durations_ms(model, features: Sequence[Sequence[float]]) -> list[float]:
    durations: list[float] = []
    for sample in features[: min(len(features), 128)]:
        start = perf_counter_ns()
        model.predict_proba([sample])
        durations.append((perf_counter_ns() - start) / 1_000_000)
    return durations or [0.0]


def _percentile(values: Sequence[float], percentile: int) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile / 100
    lower, upper = math.floor(position), math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)
