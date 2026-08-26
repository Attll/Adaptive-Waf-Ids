from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Mapping, Sequence

import joblib
from sklearn.calibration import CalibratedClassifierCV

from adaptive_waf.training.models import CandidateAlgorithm, build_classifier
from adaptive_waf.training.router_evaluation import (
    RouterEvaluationResult,
    evaluate_router,
    evaluate_routing_thresholds,
    router_probability_outputs,
)


@dataclass(frozen=True, slots=True)
class RouterCandidateRun:
    algorithm: CandidateAlgorithm
    artifact_directory: Path
    evaluation: RouterEvaluationResult
    model_size_bytes: int


def train_router_candidates(
    train_features: Sequence[Sequence[float]],
    train_labels: Sequence[str],
    validation_features: Sequence[Sequence[float]],
    validation_labels: Sequence[str],
    feature_names: Sequence[str],
    output_directory: Path,
    random_seed: int,
    algorithms: Sequence[CandidateAlgorithm],
    calibration_method: str,
    calibration_folds: int,
    threshold_grid: Mapping[str, Sequence[float]],
    parameters: Mapping[CandidateAlgorithm, Mapping[str, object]] | None = None,
    run_metadata: Mapping[str, object] | None = None,
) -> list[RouterCandidateRun]:
    output_directory.mkdir(parents=True, exist_ok=False)
    runs: list[RouterCandidateRun] = []
    for algorithm in algorithms:
        candidate_directory = output_directory / algorithm.value
        candidate_directory.mkdir()
        base_model = build_classifier(algorithm, random_seed, (parameters or {}).get(algorithm))
        model = CalibratedClassifierCV(base_model, method=calibration_method, cv=calibration_folds, n_jobs=-1)
        print(f"Training and calibrating router candidate: {algorithm.value}")
        model.fit(train_features, train_labels)
        model_path = candidate_directory / "model.joblib"
        joblib.dump(model, model_path)
        evaluation = evaluate_router(model, validation_features, validation_labels)
        probabilities, class_order = router_probability_outputs(model, validation_features)
        threshold_results = evaluate_routing_thresholds(
            probabilities,
            validation_labels,
            class_order,
            threshold_grid["top1_probabilities"],
            threshold_grid["margins"],
        )
        metadata = {
            "algorithm": algorithm.value,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "random_seed": random_seed,
            "feature_names": list(feature_names),
            "calibration_method": calibration_method,
            "calibration_folds": calibration_folds,
            "evaluation": evaluation.as_dict(),
            "model_path": str(model_path),
            "model_size_bytes": model_path.stat().st_size,
            **dict(run_metadata or {}),
        }
        (candidate_directory / "metrics.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        (candidate_directory / "threshold_evaluation.json").write_text(
            json.dumps({"results": [result.as_dict() for result in threshold_results]}, indent=2) + "\n",
            encoding="utf-8",
        )
        print(
            f"Router candidate complete: {algorithm.value}; top1_accuracy={evaluation.top1_accuracy:.4f}; "
            f"top2_coverage={evaluation.top2_coverage:.4f}; ece={evaluation.top_label_expected_calibration_error:.4f}; "
            f"p95_ms={evaluation.inference_p95_ms:.4f}; artifact={model_path}"
        )
        runs.append(RouterCandidateRun(algorithm, candidate_directory, evaluation, model_path.stat().st_size))
    return runs
