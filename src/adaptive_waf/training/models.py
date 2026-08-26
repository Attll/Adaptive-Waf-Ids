from __future__ import annotations

from enum import StrEnum
from typing import Mapping

from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression


class CandidateAlgorithm(StrEnum):
    LOGISTIC_REGRESSION = "logistic_regression"
    RANDOM_FOREST = "random_forest"
    EXTRA_TREES = "extra_trees"
    XGBOOST = "xgboost"
    LIGHTGBM = "lightgbm"


def build_classifier(
    algorithm: CandidateAlgorithm,
    random_seed: int,
    parameters: Mapping[str, object] | None = None,
):
    options = dict(parameters or {})
    if algorithm is CandidateAlgorithm.LOGISTIC_REGRESSION:
        return LogisticRegression(random_state=random_seed, max_iter=1000, **options)
    if algorithm is CandidateAlgorithm.RANDOM_FOREST:
        return RandomForestClassifier(random_state=random_seed, n_jobs=-1, **options)
    if algorithm is CandidateAlgorithm.EXTRA_TREES:
        return ExtraTreesClassifier(random_state=random_seed, n_jobs=-1, **options)
    if algorithm is CandidateAlgorithm.XGBOOST:
        return _build_xgboost(random_seed, options)
    if algorithm is CandidateAlgorithm.LIGHTGBM:
        return _build_lightgbm(random_seed, options)
    raise ValueError(f"unsupported candidate algorithm: {algorithm}")


def _build_xgboost(random_seed: int, options: Mapping[str, object]):
    try:
        from xgboost import XGBClassifier
    except ModuleNotFoundError as error:
        raise RuntimeError("xgboost candidate requested but xgboost is not installed") from error
    return XGBClassifier(random_state=random_seed, n_jobs=-1, **options)


def _build_lightgbm(random_seed: int, options: Mapping[str, object]):
    try:
        from lightgbm import LGBMClassifier
    except ModuleNotFoundError as error:
        raise RuntimeError("lightgbm candidate requested but lightgbm is not installed") from error
    return LGBMClassifier(random_state=random_seed, n_jobs=-1, **options)
