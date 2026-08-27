"""Serves the sampled dataset corpus used by the console's traffic generator.

Payloads replayed against the platform come from the same labelled datasets the models were trained and evaluated
on, so a generated batch exercises realistic traffic rather than a handful of hand-written strings. The corpus is
loaded once and sampled without replacement per request.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
import random
from threading import Lock
from typing import Any

from adaptive_waf.config import load_settings

HTTP_CORPUS = "datasets/samples/http-corpus.jsonl"
NETWORK_CORPUS = "datasets/samples/network-corpus.jsonl"


@dataclass(frozen=True, slots=True)
class Corpus:
    kind: str
    source: str
    records: tuple[dict[str, Any], ...]

    @property
    def labels(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for record in self.records:
            counts[str(record.get("label", "UNKNOWN"))] += 1
        return dict(sorted(counts.items()))

    def sample(self, count: int, labels: list[str] | None, seed: int | None) -> list[dict[str, Any]]:
        wanted = {label.upper() for label in labels} if labels else None
        pool = [record for record in self.records if wanted is None or str(record.get("label", "")).upper() in wanted]
        if not pool:
            return []
        rng = random.Random(seed)
        if count <= len(pool):
            return rng.sample(pool, count)
        # Asking for more than the pool holds repeats it, shuffled, so a large batch stays varied.
        drawn: list[dict[str, Any]] = []
        while len(drawn) < count:
            block = pool[:]
            rng.shuffle(block)
            drawn.extend(block[: count - len(drawn)])
        return drawn


class CorpusLibrary:
    def __init__(self, root: Path | None = None) -> None:
        self._root = root or load_settings().paths.project_root
        self._lock = Lock()
        self._loaded: dict[str, Corpus] = {}

    def http(self) -> Corpus:
        return self._load("http", HTTP_CORPUS)

    def network(self) -> Corpus:
        return self._load("network", NETWORK_CORPUS)

    def available(self) -> dict[str, Any]:
        http = self.http()
        network = self.network()
        return {
            "http": {"available": bool(http.records), "records": len(http.records), "labels": http.labels, "source": http.source},
            "network": {"available": bool(network.records), "records": len(network.records), "labels": network.labels, "source": network.source},
        }

    def _load(self, kind: str, relative: str) -> Corpus:
        with self._lock:
            cached = self._loaded.get(kind)
            if cached is not None:
                return cached
            path = self._root / relative
            records: list[dict[str, Any]] = []
            if path.is_file():
                with path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            corpus = Corpus(kind=kind, source=relative, records=tuple(records))
            self._loaded[kind] = corpus
            return corpus
