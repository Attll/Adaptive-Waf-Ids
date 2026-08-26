from __future__ import annotations

import re
import unicodedata
from urllib.parse import parse_qsl, quote, unquote, urlencode

from adaptive_waf.contracts import HttpRequestRecord


def serialize_deep_request(request: HttpRequestRecord) -> str:
    headers = "\n".join(f"{name}: {value}" for name, value in _normalized_headers(request.headers))
    cookies = "\n".join(f"{name}={value}" for name, value in _normalized_cookies(request.cookies))
    sections = (
        ("METHOD", _normalize_text(request.method).upper()),
        ("PATH", _normalize_path(request.path)),
        ("QUERY", _normalize_query(request.query)),
        ("HEADERS", headers),
        ("COOKIES", cookies),
        ("BODY", _normalize_text(request.body)),
    )
    return "\n\n".join(f"[{name}]\n{value}" for name, value in sections)


def normalized_request_text(request: HttpRequestRecord) -> str:
    return "\n".join(
        (
            _normalize_path(request.path),
            _normalize_query(request.query),
            " ".join(value for _, value in _normalized_headers(request.headers)),
            " ".join(value for _, value in _normalized_cookies(request.cookies)),
            _normalize_text(request.body),
        )
    )


def normalized_method(request: HttpRequestRecord) -> str:
    return _normalize_text(request.method).upper()


def normalized_path(request: HttpRequestRecord) -> str:
    return _normalize_path(request.path)


def normalized_query(request: HttpRequestRecord) -> str:
    return _normalize_query(request.query)


def _normalized_headers(headers: object) -> tuple[tuple[str, str], ...]:
    if not hasattr(headers, "items"):
        return ()
    return tuple(
        sorted(
            (_normalize_text(str(name)).lower(), _normalize_text(str(value)))
            for name, value in headers.items()
        )
    )


def _normalized_cookies(cookies: object) -> tuple[tuple[str, str], ...]:
    if not hasattr(cookies, "items"):
        return ()
    return tuple(
        sorted((_normalize_text(str(name)), _normalize_text(str(value))) for name, value in cookies.items())
    )


def _normalize_path(path: str) -> str:
    return quote(unquote(_normalize_text(path)), safe="/%:@-._~!$&'()*+,;=") or "/"


def _normalize_query(query: str) -> str:
    pairs = parse_qsl(_normalize_text(query), keep_blank_values=True)
    return urlencode(sorted(pairs))


def _normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFC", value).replace("\r\n", "\n")).strip()
