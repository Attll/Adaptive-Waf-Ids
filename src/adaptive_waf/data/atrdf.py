from __future__ import annotations

import csv
from dataclasses import dataclass
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit

import ijson

from adaptive_waf.contracts import AttackClass, HttpRequestRecord


@dataclass(frozen=True, slots=True)
class AtrdfSchema:
    label_column: str
    method_column: str | None = None
    path_column: str | None = None
    query_column: str | None = None
    headers_column: str | None = None
    cookies_column: str | None = None
    body_column: str | None = None

    def required_columns(self) -> tuple[str, ...]:
        return tuple(column for column in (self.label_column, self.method_column, self.path_column) if column)


@dataclass(frozen=True, slots=True)
class AtrdfJsonSchema:
    request_key: str = "request"
    headers_key: str = "headers"
    method_key: str = "method"
    url_key: str = "url"
    body_key: str = "body"
    label_key: str = "Attack_Tag"


@dataclass(frozen=True, slots=True)
class HttpRequestSample:
    request: HttpRequestRecord
    label: AttackClass
    source_file: Path
    source_row: int


def normalize_atrdf_label(raw_label: str, aliases: Mapping[str, AttackClass] | None = None) -> AttackClass:
    normalized = _normalize_label(raw_label)
    known_labels = dict(_ATRDF_LABELS)
    if aliases:
        known_labels.update({_normalize_label(label): attack for label, attack in aliases.items()})
    try:
        return known_labels[normalized]
    except KeyError as error:
        raise ValueError(f"unrecognized ATRDF label: {raw_label!r}") from error


class AtrdfDatasetLoader:
    def __init__(
        self,
        schema: AtrdfSchema | None = None,
        label_aliases: Mapping[str, AttackClass] | None = None,
        json_schema: AtrdfJsonSchema = AtrdfJsonSchema(),
    ) -> None:
        self._schema = schema
        self._json_schema = json_schema
        self._label_aliases = MappingProxyType(dict(label_aliases or {}))

    def load_file(self, path: Path) -> list[HttpRequestSample]:
        return list(self.iter_file(path))

    def iter_file(self, path: Path):
        if path.suffix.lower() == ".json":
            yield from self._iter_json_file(path)
            return
        if self._schema is None:
            raise ValueError("a CSV schema is required for ATRDF CSV files")
        yield from self._iter_csv_file(path)

    def _iter_csv_file(self, path: Path):
        with path.open("r", encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            if reader.fieldnames is None:
                raise ValueError(f"CSV file has no header: {path}")
            missing = set(self._schema.required_columns()) - set(reader.fieldnames)
            if missing:
                raise ValueError(f"ATRDF schema mismatch in {path}: missing {sorted(missing)}")

            for row_number, row in enumerate(reader, start=2):
                yield HttpRequestSample(
                    request=HttpRequestRecord(
                        method=_read(row, self._schema.method_column, "GET"),
                        path=_read(row, self._schema.path_column, "/"),
                        query=_read(row, self._schema.query_column, ""),
                        headers={},
                        cookies={},
                        body=_read(row, self._schema.body_column, ""),
                    ),
                    label=normalize_atrdf_label(row[self._schema.label_column], self._label_aliases),
                    source_file=path,
                    source_row=row_number,
                )

    def _iter_json_file(self, path: Path):
        with path.open("rb") as source:
            for row_number, record in enumerate(ijson.items(source, "item"), start=1):
                request = record.get(self._json_schema.request_key)
                if not isinstance(request, dict):
                    raise ValueError(f"ATRDF record {row_number} has no request object")
                raw_label = request.get(self._json_schema.label_key)
                try:
                    label = normalize_atrdf_label(raw_label or AttackClass.BENIGN, self._label_aliases)
                except ValueError:
                    continue
                yield HttpRequestSample(
                    request=_request_from_json(request, self._json_schema),
                    label=label,
                    source_file=path,
                    source_row=row_number,
                )


def _read(row: Mapping[str, str | None], column: str | None, default: str) -> str:
    return row[column].strip() if column is not None and row.get(column) else default


def _request_from_json(record: Mapping[str, object], schema: AtrdfJsonSchema) -> HttpRequestRecord:
    raw_url = _string_value(record.get(schema.url_key), "http://localhost/")
    parsed_url = urlsplit(raw_url)
    headers = _string_mapping(record.get(schema.headers_key))
    return HttpRequestRecord(
        method=_string_value(record.get(schema.method_key), "GET"),
        path=parsed_url.path or "/",
        query=parsed_url.query,
        headers=headers,
        cookies=_cookies_from_headers(headers),
        body=_string_value(record.get(schema.body_key), ""),
    )


def _string_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): _string_value(item, "") for key, item in value.items()}


def _string_value(value: object, default: str) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else default


def _cookies_from_headers(headers: Mapping[str, str]) -> dict[str, str]:
    raw_cookie = next((value for key, value in headers.items() if key.lower() == "cookie"), "")
    return {
        key.strip(): value.strip()
        for item in raw_cookie.split(";")
        if "=" in item
        for key, value in (item.split("=", maxsplit=1),)
    }


def _normalize_label(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


_ATRDF_LABELS = MappingProxyType(
    {
        "benign": AttackClass.BENIGN,
        "normal": AttackClass.BENIGN,
        "sql_injection": AttackClass.SQL_INJECTION,
        "sqli": AttackClass.SQL_INJECTION,
        "xss": AttackClass.XSS,
        "cross_site_scripting": AttackClass.XSS,
        "cookie_injection": AttackClass.COOKIE_INJECTION,
        "directory_traversal": AttackClass.DIRECTORY_TRAVERSAL,
        "path_traversal": AttackClass.DIRECTORY_TRAVERSAL,
        "remote_code_execution": AttackClass.REMOTE_CODE_EXECUTION,
        "rce": AttackClass.REMOTE_CODE_EXECUTION,
    }
)
