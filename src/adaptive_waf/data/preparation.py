from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Iterable, Mapping

from adaptive_waf.data.atrdf import HttpRequestSample
from adaptive_waf.data.cicids import NetworkFlowSample
from adaptive_waf.features.canonical import serialize_deep_request


PREPROCESSING_VERSION = "v1"
_NUMBER_PATTERN = re.compile(r"\b\d+\b")
_LONG_TOKEN_PATTERN = re.compile(r"\b[A-Za-z0-9_-]{16,}\b")


@dataclass(frozen=True, slots=True)
class SplitRatios:
    train: float
    validation: float
    test: float

    def __post_init__(self) -> None:
        if min(self.train, self.validation, self.test) <= 0:
            raise ValueError("all split ratios must be positive")
        if not abs(self.train + self.validation + self.test - 1.0) < 1e-9:
            raise ValueError("split ratios must sum to 1")


@dataclass(frozen=True, slots=True)
class PreparationSummary:
    output_directory: Path
    split_counts: Mapping[str, int]
    class_counts: Mapping[str, Mapping[str, int]]


def prepare_http_samples(
    samples: Iterable[HttpRequestSample],
    output_directory: Path,
    ratios: SplitRatios,
    seed: int,
    source_paths: Iterable[Path],
) -> PreparationSummary:
    return _prepare_samples(
        samples=samples,
        output_directory=output_directory,
        ratios=ratios,
        seed=seed,
        source_paths=source_paths,
        record_builder=_http_record,
        group_key_builder=lambda sample: near_duplicate_group_key(serialize_deep_request(sample.request)),
    )


def prepare_network_samples(
    samples: Iterable[NetworkFlowSample],
    output_directory: Path,
    ratios: SplitRatios,
    seed: int,
    source_paths: Iterable[Path],
) -> PreparationSummary:
    return _prepare_samples(
        samples=samples,
        output_directory=output_directory,
        ratios=ratios,
        seed=seed,
        source_paths=source_paths,
        record_builder=_network_record,
        group_key_builder=lambda sample: network_flow_group_key(sample.features),
    )


def near_duplicate_group_key(value: str) -> str:
    normalized = _LONG_TOKEN_PATTERN.sub("<TOKEN>", _NUMBER_PATTERN.sub("<NUMBER>", value.lower()))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def network_flow_group_key(features: Mapping[str, float]) -> str:
    serialized = json.dumps(features, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _prepare_samples(
    samples: Iterable[object],
    output_directory: Path,
    ratios: SplitRatios,
    seed: int,
    source_paths: Iterable[Path],
    record_builder,
    group_key_builder,
) -> PreparationSummary:
    output_directory.mkdir(parents=True, exist_ok=False)
    split_counts: Counter[str] = Counter()
    non_finite_replacements: Counter[str] = Counter()
    class_counts: dict[str, Counter[str]] = {name: Counter() for name in ("train", "validation", "test")}
    destinations = {
        name: (output_directory / f"{name}.jsonl").open("w", encoding="utf-8", newline="\n")
        for name in class_counts
    }
    try:
        for sample in samples:
            split = _split_for_group(group_key_builder(sample), ratios, seed)
            record = record_builder(sample)
            destinations[split].write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")
            split_counts[split] += 1
            class_counts[split][record["label"]] += 1
            non_finite_replacements.update(getattr(sample, "replaced_non_finite_features", ()))
    finally:
        for destination in destinations.values():
            destination.close()

    manifest = {
        "preprocessing_version": PREPROCESSING_VERSION,
        "split_ratios": asdict(ratios),
        "random_seed": seed,
        "sources": [_source_metadata(path) for path in source_paths],
        "split_counts": dict(sorted(split_counts.items())),
        "class_counts": {name: dict(sorted(counts.items())) for name, counts in class_counts.items()},
        "non_finite_replacements": dict(sorted(non_finite_replacements.items())),
    }
    (output_directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return PreparationSummary(
        output_directory=output_directory,
        split_counts=dict(sorted(split_counts.items())),
        class_counts={name: dict(sorted(counts.items())) for name, counts in class_counts.items()},
    )


def _split_for_group(group_key: str, ratios: SplitRatios, seed: int) -> str:
    bucket = int.from_bytes(hashlib.sha256(f"{seed}:{group_key}".encode("utf-8")).digest()[:8], "big") / 2**64
    if bucket < ratios.train:
        return "train"
    if bucket < ratios.train + ratios.validation:
        return "validation"
    return "test"


def _http_record(sample: HttpRequestSample) -> dict[str, object]:
    request = sample.request
    return {
        "request": {
            "method": request.method,
            "path": request.path,
            "query": request.query,
            "headers": dict(request.headers),
            "cookies": dict(request.cookies),
            "body": request.body,
        },
        "label": sample.label.value,
        "source": {"file": str(sample.source_file), "row": sample.source_row},
    }


def _network_record(sample: NetworkFlowSample) -> dict[str, object]:
    return {
        "features": dict(sample.features),
        "label": sample.label.value,
        "source": {"file": str(sample.source_file), "row": sample.source_row},
    }


def _source_metadata(path: Path) -> dict[str, object]:
    stat = path.stat()
    return {"path": str(path), "size_bytes": stat.st_size, "modified_ns": stat.st_mtime_ns}
