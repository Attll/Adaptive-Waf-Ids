"""Finite-sample split conformal calibration; guarantees require exchangeable calibration/evaluation data."""
from dataclasses import dataclass
import math
import numpy as np


def probabilities(values):
    row = np.asarray(values, dtype=float)
    if row.ndim != 1 or len(row) < 2 or not np.isfinite(row).all() or (row < 0).any() or not np.isclose(row.sum(), 1):
        raise ValueError("invalid probability vector")
    return row


def uncertainty(values):
    row = probabilities(values)
    ordered = np.sort(row)
    return {"confidence": float(ordered[-1]), "margin": float(ordered[-1] - ordered[-2]),
            "entropy": float(-np.sum(row[row > 0] * np.log(row[row > 0])) / math.log(len(row)))}


def higher_quantile(scores, alpha):
    if not 0 < alpha < 1 or not scores:
        raise ValueError("nonempty calibration scores and alpha in (0,1) required")
    rank = math.ceil((len(scores) + 1) * (1 - alpha))
    return 1.0 if rank > len(scores) else float(sorted(scores)[rank - 1])


@dataclass(frozen=True)
class SplitConformal:
    classes: tuple[str, ...]
    thresholds: dict[str, float]
    alpha: float
    model_version: str
    calibration_ids: tuple[str, ...]

    def __post_init__(self):
        if (len(self.classes)<2 or len(set(self.classes))!=len(self.classes) or set(self.thresholds)!=set(self.classes)
                or not 0<self.alpha<1 or not self.model_version or not self.calibration_ids
                or len(set(self.calibration_ids))!=len(self.calibration_ids)
                or any(not math.isfinite(value) or not 0<=value<=1 for value in self.thresholds.values())):
            raise ValueError("invalid conformal artifact")
        object.__setattr__(self,"classes",tuple(self.classes))
        object.__setattr__(self,"calibration_ids",tuple(self.calibration_ids))

    @classmethod
    def fit(cls, rows, labels, classes, identifiers, model_version, alpha=.1, class_sensitive=False, forbidden_ids=()):
        classes, identifiers = tuple(classes), tuple(identifiers)
        if len(set(classes)) != len(classes) or len(rows) != len(labels) or len(rows) != len(identifiers) or len(set(identifiers)) != len(identifiers):
            raise ValueError("calibration rows, classes or identifiers are invalid")
        if set(identifiers).intersection(forbidden_ids):
            raise ValueError("calibration overlaps training or reserved evaluation population")
        scores = {label: [] for label in classes}
        all_scores = []
        for row, label in zip(rows, labels, strict=True):
            row = probabilities(row)
            if len(row) != len(classes) or label not in scores:
                raise ValueError("calibration class schema mismatch")
            score = 1 - float(row[classes.index(label)])
            scores[label].append(score)
            all_scores.append(score)
        global_q = higher_quantile(all_scores, alpha)
        thresholds = {label: (higher_quantile(scores[label], alpha) if scores[label] else 1.) if class_sensitive else global_q for label in classes}
        return cls(classes, thresholds, alpha, model_version, identifiers)

    def prediction_set(self, values, model_version):
        if model_version != self.model_version:
            raise ValueError("conformal artifact does not match model version")
        row = probabilities(values)
        if len(row) != len(self.classes):
            raise ValueError("conformal class schema mismatch")
        return tuple(label for label, probability in zip(self.classes, row, strict=True) if 1 - probability <= self.thresholds[label])

    def evaluate(self, rows, labels, model_version):
        sets = [self.prediction_set(row, model_version) for row in rows]
        if not labels or len(sets) != len(labels):
            raise ValueError("nonempty matched evaluation rows required")
        return {"coverage": sum(label in group for label, group in zip(labels, sets)) / len(labels),
                "mean_set_size": sum(map(len, sets)) / len(sets),
                "per_class_coverage": {label: sum(y == label and label in group for y, group in zip(labels, sets)) / labels.count(label)
                                       for label in self.classes if label in labels}}
