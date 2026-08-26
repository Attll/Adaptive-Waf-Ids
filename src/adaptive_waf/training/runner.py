from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Mapping, Sequence

import joblib

from adaptive_waf.training.evaluation import EvaluationResult, evaluate_classifier
from adaptive_waf.training.models import CandidateAlgorithm, build_classifier


@dataclass(frozen=True, slots=True)
class CandidateRun:
    algorithm: CandidateAlgorithm
    artifact_directory: Path
    evaluation: EvaluationResult
    model_size_bytes: int


def train_candidates(
    train_features: Sequence[Sequence[float]],
    train_labels: Sequence[str],
    validation_features: Sequence[Sequence[float]],
    validation_labels: Sequence[str],
    feature_names: Sequence[str],
    output_directory: Path,
    random_seed: int,
    algorithms: Sequence[CandidateAlgorithm],
    parameters: Mapping[CandidateAlgorithm, Mapping[str, object]] | None = None,
    run_metadata: Mapping[str, object] | None = None,
) -> list[CandidateRun]:
    output_directory.mkdir(parents=True, exist_ok=False)
    runs: list[CandidateRun] = []
    for algorithm in algorithms:
        candidate_directory = output_directory / algorithm.value
        candidate_directory.mkdir()
        model = build_classifier(algorithm, random_seed, (parameters or {}).get(algorithm))
        print(f"Training candidate: {algorithm.value}")
        model.fit(train_features, train_labels)
        model_path = candidate_directory / "model.joblib"
        joblib.dump(model, model_path)
        evaluation = evaluate_classifier(model, validation_features, validation_labels)
        metadata = {
            "algorithm": algorithm.value,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "random_seed": random_seed,
            "feature_names": list(feature_names),
            "evaluation": evaluation.as_dict(),
            "model_path": str(model_path),
            "model_size_bytes": model_path.stat().st_size,
            **dict(run_metadata or {}),
        }
        (candidate_directory / "metrics.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        print(
            f"Candidate complete: {algorithm.value}; macro_f1={evaluation.f1_macro:.4f}; "
            f"recall={evaluation.recall_macro:.4f}; artifact={model_path}"
        )
        runs.append(
            CandidateRun(
                algorithm=algorithm,
                artifact_directory=candidate_directory,
                evaluation=evaluation,
                model_size_bytes=model_path.stat().st_size,
            )
        )
    return runs
