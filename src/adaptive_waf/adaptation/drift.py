from __future__ import annotations

import math
from collections.abc import Sequence


def population_stability_index(reference: Sequence[float], observed: Sequence[float], bins: int = 10) -> float:
    """Deterministic PSI for numeric features; returns 0 for identical distributions."""
    if not reference or not observed or bins < 2:
        raise ValueError("reference, observed, and at least two bins are required")
    minimum, maximum = min(reference), max(reference)
    if minimum == maximum:
        return 0.0 if all(value == minimum for value in observed) else float("inf")
    width = (maximum - minimum) / bins
    expected = _histogram(reference, minimum, maximum, width, bins)
    actual = _histogram(observed, minimum, maximum, width, bins)
    total = 0.0
    for base, current in zip(expected, actual):
        base_share = max(base / len(reference), 1e-6)
        current_share = max(current / len(observed), 1e-6)
        total += (current_share - base_share) * math.log(current_share / base_share)
    return total


def _histogram(values: Sequence[float], minimum: float, maximum: float, width: float, bins: int) -> list[int]:
    counts = [0] * bins
    for value in values:
        index = int((value - minimum) / width)
        counts[max(0, min(bins - 1, index))] += 1
    return counts
