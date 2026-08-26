from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from adaptive_waf.features.canonical import serialize_deep_request
from adaptive_waf.training.http_data import _read_jsonl, _request_from_record


@dataclass(frozen=True, slots=True)
class DeepTextDataset:
    texts: list[str]
    labels: list[str]


def load_deep_dataset(
    path: Path,
    classes: tuple[str, ...],
    max_samples_per_class: int | None = None,
) -> DeepTextDataset:
    allowed = set(classes)
    texts: list[str] = []
    labels: list[str] = []
    counts: dict[str, int] = {}
    for record in _read_jsonl(path):
        label = str(record["label"])
        if label not in allowed or (max_samples_per_class is not None and counts.get(label, 0) >= max_samples_per_class):
            continue
        texts.append(serialize_deep_request(_request_from_record(record["request"])))
        labels.append(label)
        counts[label] = counts.get(label, 0) + 1
    if not texts:
        raise ValueError(f"no deep-learning records found in {path}")
    missing = sorted(allowed - set(labels))
    if missing:
        raise ValueError(f"deep dataset is missing required classes: {missing}")
    return DeepTextDataset(texts=texts, labels=labels)


class CharacterTokenizer:
    pad_id = 0
    unknown_id = 1

    def __init__(self) -> None:
        self.characters = tuple(chr(codepoint) for codepoint in range(32, 127)) + ("\n", "\t")
        self._ids = {character: index + 2 for index, character in enumerate(self.characters)}

    @property
    def vocabulary_size(self) -> int:
        return len(self.characters) + 2

    def encode(self, text: str, max_length: int) -> list[int]:
        values = [self._ids.get(character, self.unknown_id) for character in text[:max_length]]
        return values + [self.pad_id] * (max_length - len(values))

    def as_dict(self) -> dict[str, object]:
        return {"pad_id": self.pad_id, "unknown_id": self.unknown_id, "characters": list(self.characters)}
