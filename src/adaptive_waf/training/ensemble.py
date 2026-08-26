from __future__ import annotations

from itertools import combinations
from typing import Sequence


class SoftVotingClassifier:
    def __init__(self, members: Sequence[object]) -> None:
        if len(members) < 2:
            raise ValueError("a soft-voting ensemble requires at least two members")
        self._members = tuple(members)
        self.classes_ = [str(label) for label in self._members[0].classes_]
        if any([str(label) for label in member.classes_] != self.classes_ for member in self._members[1:]):
            raise ValueError("ensemble members must use the same class order")

    def predict_proba(self, features: Sequence[Sequence[float]]) -> list[list[float]]:
        member_probabilities = [member.predict_proba(features) for member in self._members]
        return [
            [sum(float(probabilities[row][column]) for probabilities in member_probabilities) / len(member_probabilities) for column in range(len(self.classes_))]
            for row in range(len(features))
        ]

    def predict(self, features: Sequence[Sequence[float]]) -> list[str]:
        return [self.classes_[max(range(len(row)), key=row.__getitem__)] for row in self.predict_proba(features)]


def ensemble_member_sets(algorithms: Sequence[str]) -> list[tuple[str, ...]]:
    return [members for size in range(2, len(algorithms) + 1) for members in combinations(algorithms, size)]
