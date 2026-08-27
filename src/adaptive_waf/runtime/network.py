from __future__ import annotations

from collections.abc import Mapping, Sequence
import math

import numpy

from adaptive_waf.contracts import NetworkContext


class OfflineNetworkDetector:
    """Applies a trained CICIDS flow classifier to one schema-validated flow."""

    def __init__(self, model: object, feature_names: Sequence[str], model_version: str) -> None:
        if not feature_names:
            raise ValueError("network feature names must not be empty")
        self._model = model
        self._feature_names = tuple(feature_names)
        self.model_version = model_version

    def detect(self, features: Mapping[str, float]) -> NetworkContext:
        missing = [name for name in self._feature_names if name not in features]
        unexpected = [name for name in features if name not in self._feature_names]
        if missing or unexpected:
            details = []
            if missing:
                details.append(f"missing: {', '.join(missing)}")
            if unexpected:
                details.append(f"unexpected: {', '.join(unexpected)}")
            raise ValueError("network feature schema mismatch (" + "; ".join(details) + ")")
        row = [float(features[name]) for name in self._feature_names]
        if not all(math.isfinite(value) for value in row):
            raise ValueError("network features must be finite numbers")

        probabilities = numpy.asarray(self._model.predict_proba([row])[0], dtype=float)
        classes = tuple(str(label) for label in self._model.classes_)
        if len(classes) != len(probabilities) or not classes:
            raise ValueError("network model returned invalid class probabilities")
        index = int(numpy.argmax(probabilities))
        confidence = float(probabilities[index])
        benign_index = classes.index("BENIGN") if "BENIGN" in classes else None
        risk = 1.0 - float(probabilities[benign_index]) if benign_index is not None else 1.0
        return NetworkContext(risk=risk, network_class=classes[index], confidence=confidence)
