from __future__ import annotations

import unittest

from adaptive_waf.training.ensemble import SoftVotingClassifier, ensemble_member_sets


class EnsembleTests(unittest.TestCase):
    def test_soft_voting_averages_member_probabilities(self) -> None:
        ensemble = SoftVotingClassifier([_StaticModel([[0.8, 0.2]]), _StaticModel([[0.4, 0.6]])])
        self.assertEqual(ensemble.predict_proba([[1.0]]), [[0.6000000000000001, 0.4]])
        self.assertEqual(ensemble.predict([[1.0]]), ["BENIGN"])

    def test_member_sets_include_pairs_and_full_set(self) -> None:
        self.assertEqual(
            ensemble_member_sets(["logistic_regression", "random_forest", "extra_trees"]),
            [("logistic_regression", "random_forest"), ("logistic_regression", "extra_trees"), ("random_forest", "extra_trees"), ("logistic_regression", "random_forest", "extra_trees")],
        )


class _StaticModel:
    classes_ = ["BENIGN", "SQL_INJECTION"]

    def __init__(self, probabilities: list[list[float]]) -> None:
        self._probabilities = probabilities

    def predict_proba(self, features):
        return self._probabilities
