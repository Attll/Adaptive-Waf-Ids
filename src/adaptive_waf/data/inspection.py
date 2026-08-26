from __future__ import annotations

import csv
from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import ijson
import json
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True, slots=True)
class DatasetInspection:
    path: Path
    columns: tuple[str, ...]
    row_count: int
    blank_row_count: int
    malformed_row_count: int
    duplicate_row_count: int
    null_counts: dict[str, int]
    label_counts: dict[str, int]
    class_imbalance_ratio: float | None

    def missing_required_columns(self, required_columns: Iterable[str]) -> tuple[str, ...]:
        available = set(self.columns)
        return tuple(column for column in required_columns if column not in available)

    def as_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["path"] = str(self.path)
        return result


def inspect_csv_tree(directory: Path, label_column: str | None = None) -> list[DatasetInspection]:
    if not directory.is_dir():
        raise FileNotFoundError(f"dataset directory does not exist: {directory}")
    return [inspect_csv_file(path, label_column) for path in sorted(directory.rglob("*.csv"))]


def inspect_csv_file(path: Path, label_column: str | None = None) -> DatasetInspection:
    if path.suffix.lower() != ".csv":
        raise ValueError(f"only CSV files are supported: {path}")

    with path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source, restkey="__extra_columns__", restval=None)
        if reader.fieldnames is None:
            raise ValueError(f"CSV file has no header: {path}")

        columns = tuple(reader.fieldnames)
        null_counts: Counter[str] = Counter()
        label_counts: Counter[str] = Counter()
        fingerprints: set[str] = set()
        row_count = blank_rows = malformed_rows = duplicate_rows = 0

        for row in reader:
            row_count += 1
            if _is_blank_row(row, columns):
                blank_rows += 1
                continue
            if row.get("__extra_columns__") or any(row[column] is None for column in columns):
                malformed_rows += 1
                continue

            for column in columns:
                if not row[column].strip():
                    null_counts[column] += 1

            if label_column is not None and label_column in row and row[label_column].strip():
                label_counts[row[label_column].strip()] += 1

            fingerprint = _row_fingerprint(row, columns)
            if fingerprint in fingerprints:
                duplicate_rows += 1
            else:
                fingerprints.add(fingerprint)

    class_imbalance_ratio = _class_imbalance_ratio(label_counts)
    return DatasetInspection(
        path=path,
        columns=columns,
        row_count=row_count,
        blank_row_count=blank_rows,
        malformed_row_count=malformed_rows,
        duplicate_row_count=duplicate_rows,
        null_counts=dict(sorted(null_counts.items())),
        label_counts=dict(sorted(label_counts.items())),
        class_imbalance_ratio=class_imbalance_ratio,
    )


def inspect_atrdf_json_tree(directory: Path) -> list[DatasetInspection]:
    if not directory.is_dir():
        raise FileNotFoundError(f"dataset directory does not exist: {directory}")
    return [inspect_atrdf_json_file(path) for path in sorted(directory.rglob("*.json"))]


def inspect_atrdf_json_file(path: Path) -> DatasetInspection:
    columns = ("request.headers", "request.method", "request.url", "request.body", "request.Attack_Tag")
    null_counts: Counter[str] = Counter()
    label_counts: Counter[str] = Counter()
    fingerprints: set[str] = set()
    row_count = blank_rows = malformed_rows = duplicate_rows = 0

    with path.open("rb") as source:
        for record in ijson.items(source, "item"):
            row_count += 1
            request = record.get("request") if isinstance(record, dict) else None
            if not isinstance(request, dict):
                malformed_rows += 1
                continue
            if not any(request.get(key) for key in ("method", "url", "body", "headers")):
                blank_rows += 1
                continue
            for key in ("headers", "method", "url", "body"):
                if not request.get(key):
                    null_counts[f"request.{key}"] += 1
            label_counts[str(request.get("Attack_Tag") or "BENIGN").strip()] += 1
            fingerprint = hashlib.sha256(json.dumps(request, sort_keys=True).encode("utf-8")).hexdigest()
            if fingerprint in fingerprints:
                duplicate_rows += 1
            else:
                fingerprints.add(fingerprint)

    return DatasetInspection(
        path=path,
        columns=columns,
        row_count=row_count,
        blank_row_count=blank_rows,
        malformed_row_count=malformed_rows,
        duplicate_row_count=duplicate_rows,
        null_counts=dict(sorted(null_counts.items())),
        label_counts=dict(sorted(label_counts.items())),
        class_imbalance_ratio=_class_imbalance_ratio(label_counts),
    )


def _is_blank_row(row: dict[str | None, str | list[str] | None], columns: tuple[str, ...]) -> bool:
    return not any(isinstance(row[column], str) and row[column].strip() for column in columns)


def _row_fingerprint(row: dict[str | None, str | list[str] | None], columns: tuple[str, ...]) -> str:
    canonical_row = "\x1f".join((row[column] or "").strip() for column in columns)
    return hashlib.sha256(canonical_row.encode("utf-8")).hexdigest()


def _class_imbalance_ratio(label_counts: Counter[str]) -> float | None:
    if not label_counts:
        return None
    return max(label_counts.values()) / min(label_counts.values())
