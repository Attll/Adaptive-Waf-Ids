from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
import re
from types import MappingProxyType
from typing import Mapping

from adaptive_waf.contracts import NetworkClass


@dataclass(frozen=True, slots=True)
class CicidsSchema:
    label_column: str
    feature_columns: tuple[str, ...]

    def required_columns(self) -> tuple[str, ...]:
        return (self.label_column, *self.feature_columns)


@dataclass(frozen=True, slots=True)
class NetworkFlowSample:
    features: Mapping[str, float]
    label: NetworkClass
    source_file: Path
    source_row: int


class CicidsDatasetLoader:
    def __init__(self, schema: CicidsSchema, label_aliases: Mapping[str, NetworkClass]) -> None:
        self._schema = schema
        self._label_aliases = MappingProxyType(
            {_normalize_label(label): network_class for label, network_class in label_aliases.items()}
        )

    def load_file(self, path: Path) -> list[NetworkFlowSample]:
        with path.open("r", encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            if reader.fieldnames is None:
                raise ValueError(f"CSV file has no header: {path}")
            missing = set(self._schema.required_columns()) - set(reader.fieldnames)
            if missing:
                raise ValueError(f"CICIDS schema mismatch in {path}: missing {sorted(missing)}")

            samples: list[NetworkFlowSample] = []
            for row_number, row in enumerate(reader, start=2):
                samples.append(
                    NetworkFlowSample(
                        features={column: float(row[column]) for column in self._schema.feature_columns},
                        label=self._normalize_label(row[self._schema.label_column]),
                        source_file=path,
                        source_row=row_number,
                    )
                )
        return samples

    def _normalize_label(self, raw_label: str) -> NetworkClass:
        try:
            return self._label_aliases[_normalize_label(raw_label)]
        except KeyError as error:
            raise ValueError(f"unrecognized CICIDS label: {raw_label!r}") from error


def _normalize_label(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")
