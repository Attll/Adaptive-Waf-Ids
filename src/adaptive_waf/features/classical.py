from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import math
import re
from types import MappingProxyType
from typing import Mapping

from adaptive_waf.contracts import HttpRequestRecord
from adaptive_waf.features.canonical import normalized_method, normalized_path, normalized_query, normalized_request_text


_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
_CONTENT_TYPES = ("application/json", "application/x-www-form-urlencoded", "multipart/form-data", "text/plain")
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_]+")
_PERCENT_SEQUENCE_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")
_SUSPICIOUS_CHARACTERS = frozenset("'\"<>;|&$`(){}[]\\")


@dataclass(frozen=True, slots=True)
class ClassicalFeatureVector:
    names: tuple[str, ...]
    values: tuple[float, ...]

    def as_dict(self) -> Mapping[str, float]:
        return MappingProxyType(dict(zip(self.names, self.values, strict=True)))


class ClassicalFeatureExtractor:
    version = "http-classical-v1"

    def extract(self, request: HttpRequestRecord) -> ClassicalFeatureVector:
        method = normalized_method(request)
        path = normalized_path(request)
        query = normalized_query(request)
        normalized_text = normalized_request_text(request)
        content_type = _content_type(request.headers)
        raw_text = "\n".join((request.path, request.query, request.body))
        lengths = {
            "request_length": float(len(normalized_text)),
            "path_length": float(len(path)),
            "path_depth": float(len([part for part in path.split("/") if part])),
            "query_length": float(len(query)),
            "body_length": float(len(request.body)),
            "header_count": float(len(request.headers)),
            "cookie_count": float(len(request.cookies)),
            "parameter_count": float(len(parse_query_pairs(query))),
            "token_count": float(len(_TOKEN_PATTERN.findall(normalized_text))),
            "percent_encoded_count": float(len(_PERCENT_SEQUENCE_PATTERN.findall(raw_text))),
            "percent_encoded_density": _ratio(len(_PERCENT_SEQUENCE_PATTERN.findall(raw_text)), len(raw_text)),
            "special_character_density": _ratio(
                sum(character in _SUSPICIOUS_CHARACTERS for character in normalized_text), len(normalized_text)
            ),
            "shannon_entropy": _shannon_entropy(normalized_text),
        }
        method_features = {f"method_{candidate.lower()}": float(method == candidate) for candidate in _METHODS}
        method_features["method_other"] = float(method not in _METHODS)
        content_type_features = {
            f"content_type_{_feature_slug(candidate)}": float(content_type == candidate) for candidate in _CONTENT_TYPES
        }
        content_type_features["content_type_other"] = float(content_type not in _CONTENT_TYPES)
        features = {**method_features, **content_type_features, **lengths}
        names = tuple(features)
        return ClassicalFeatureVector(names=names, values=tuple(features[name] for name in names))


def parse_query_pairs(query: str) -> tuple[tuple[str, str], ...]:
    if not query:
        return ()
    return tuple(tuple(pair.split("=", maxsplit=1)) if "=" in pair else (pair, "") for pair in query.split("&"))


def _content_type(headers: Mapping[str, str]) -> str:
    value = next((value for name, value in headers.items() if name.lower() == "content-type"), "")
    return value.split(";", maxsplit=1)[0].strip().lower()


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _feature_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
