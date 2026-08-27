"""Sample the processed datasets into a small corpus the console can replay as traffic.

The processed splits are hundreds of megabytes and are not shipped in the service images, so this writes a
balanced, deterministic sample to ``datasets/samples``. The detection service serves that corpus to the console's
traffic generator, which means generated payloads are real labelled records rather than hand-written strings.

    python scripts/build_probe_corpus.py --http-per-class 60 --network-per-class 40
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from adaptive_waf.config import load_settings  # noqa: E402

HTTP_DATASET = "datasets/processed/atrdf/atrdf-dataset3-dataset4-v1/test.jsonl"
NETWORK_DATASET = "datasets/processed/cicids2018/cicids2018-flow-subset-v3/test.jsonl"
OUTPUT_DIRECTORY = "datasets/samples"
MAX_QUERY_LENGTH = 1024
MAX_BODY_LENGTH = 2048


def sample_http(source: Path, per_class: int, seed: int) -> list[dict]:
    """Reservoir-sample per label so rare attack classes are represented as strongly as benign traffic."""
    reservoirs: dict[str, list[dict]] = defaultdict(list)
    seen: dict[str, int] = defaultdict(int)
    rng = random.Random(seed)
    with source.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            label = str(record.get("label", "UNKNOWN"))
            request = record.get("request") or {}
            path = str(request.get("path") or "")
            if not path.startswith("/"):
                continue
            seen[label] += 1
            entry = {
                "label": label,
                "method": str(request.get("method") or "GET").upper(),
                "path": path[:512],
                "query": str(request.get("query") or "")[:MAX_QUERY_LENGTH],
                "body": str(request.get("body") or "")[:MAX_BODY_LENGTH],
                "cookies": {str(k): str(v)[:256] for k, v in (request.get("cookies") or {}).items()},
            }
            bucket = reservoirs[label]
            if len(bucket) < per_class:
                bucket.append(entry)
            else:
                index = rng.randrange(seen[label])
                if index < per_class:
                    bucket[index] = entry
    return [entry for bucket in reservoirs.values() for entry in bucket]


def sample_network(source: Path, per_class: int, seed: int) -> list[dict]:
    reservoirs: dict[str, list[dict]] = defaultdict(list)
    seen: dict[str, int] = defaultdict(int)
    rng = random.Random(seed)
    with source.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            features = record.get("features")
            if not isinstance(features, dict) or not features:
                continue
            label = str(record.get("label", "UNKNOWN"))
            seen[label] += 1
            entry = {"label": label, "features": {str(k): float(v) for k, v in features.items()}}
            bucket = reservoirs[label]
            if len(bucket) < per_class:
                bucket.append(entry)
            else:
                index = rng.randrange(seen[label])
                if index < per_class:
                    bucket[index] = entry
    return [entry for bucket in reservoirs.values() for entry in bucket]


def write(records: list[dict], target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--http-per-class", type=int, default=60)
    parser.add_argument("--network-per-class", type=int, default=40)
    parser.add_argument("--seed", type=int, default=641)
    arguments = parser.parse_args()

    root = load_settings().paths.project_root
    output = root / OUTPUT_DIRECTORY

    http_source = root / HTTP_DATASET
    network_source = root / NETWORK_DATASET

    if http_source.is_file():
        http_records = sample_http(http_source, arguments.http_per_class, arguments.seed)
        write(http_records, output / "http-corpus.jsonl")
        counts = defaultdict(int)
        for record in http_records:
            counts[record["label"]] += 1
        print(f"http-corpus.jsonl: {len(http_records)} records {dict(counts)}")
    else:
        print(f"skipped http corpus: {http_source} is not present")

    if network_source.is_file():
        network_records = sample_network(network_source, arguments.network_per_class, arguments.seed)
        write(network_records, output / "network-corpus.jsonl")
        counts = defaultdict(int)
        for record in network_records:
            counts[record["label"]] += 1
        print(f"network-corpus.jsonl: {len(network_records)} records {dict(counts)}")
    else:
        print(f"skipped network corpus: {network_source} is not present")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
