from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence

import joblib

from adaptive_waf.training.ensemble import SoftVotingClassifier, ensemble_member_sets
from adaptive_waf.training.evaluation import EvaluationResult, evaluate_classifier


@dataclass(frozen=True, slots=True)
class EnsembleEvaluation:
    members: tuple[str, ...]
    evaluation: EvaluationResult
    retained: bool

    def as_dict(self) -> dict[str, object]:
        return {"members": list(self.members), "evaluation": asdict(self.evaluation), "retained": self.retained}


def evaluate_expert_ensembles(
    artifact_directory: Path,
    algorithms: Sequence[str],
    validation_features: Sequence[Sequence[float]],
    validation_labels: Sequence[str],
    minimum_macro_f1_gain: float,
) -> list[EnsembleEvaluation]:
    models = {algorithm: joblib.load(artifact_directory / algorithm / "model.joblib") for algorithm in algorithms}
    individual_scores = {
        algorithm: evaluate_classifier(model, validation_features, validation_labels).f1_macro for algorithm, model in models.items()
    }
    best_individual_f1 = max(individual_scores.values())
    results: list[EnsembleEvaluation] = []
    for members in ensemble_member_sets(algorithms):
        evaluation = evaluate_classifier(SoftVotingClassifier([models[name] for name in members]), validation_features, validation_labels)
        results.append(
            EnsembleEvaluation(
                members=members,
                evaluation=evaluation,
                retained=evaluation.f1_macro >= best_individual_f1 + minimum_macro_f1_gain,
            )
        )
    return results
