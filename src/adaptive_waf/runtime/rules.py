"""Small versioned deterministic guard set, not an implementation of OWASP CRS."""
from dataclasses import dataclass
from html import unescape
import re
from urllib.parse import parse_qsl, unquote
import unicodedata

from adaptive_waf.contracts import AttackClass


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    attack: AttackClass
    field: str
    risk: float = .99


class SemanticRules:
    version = "semantic-guards-v1"
    _sql = re.compile(r"(?:['\"]\s*(?:or|and)\s+(?:\d+|'[^']*'|\"[^\"]*\")\s*=\s*(?:\d+|'[^']+'?|\"[^\"]+\"?)|\bunion\s+(?:all\s+)?select\b)", re.I)
    _xss = re.compile(r"(?:<\s*script\b|<\s*(?:img|svg|iframe|body|input)\b[^>]*\bon[a-z]+\s*=|(?:href|src)\s*=\s*['\"]?\s*javascript\s*:)", re.I)
    _traversal = re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|$)")
    _execution = re.compile(r"(?:[;|`]\s*(?:cat|curl|wget|bash|sh|powershell|cmd|nc|whoami|id)\b|\$\(\s*(?:cat|curl|wget|bash|sh|whoami|id)\b)", re.I)

    def inspect(self, request):
        fields = [("path", request.path), ("body", request.body)]
        fields += [("parameter", value) for _, value in parse_qsl(request.query, keep_blank_values=True, max_num_fields=512)]
        fields += [("cookie", value) for value in request.cookies.values()]
        fields += [("header", value) for key, value in request.headers.items()
                   if key.lower() not in {"authorization", "cookie", "x-waf-internal-token"}]
        matches = []
        for field, value in fields:
            text = unicodedata.normalize("NFKC", str(value))
            # Bounded inspection views; forwarding bytes and legacy feature contracts are unchanged.
            for _ in range(2):
                decoded = unquote(text)
                if decoded == text:
                    break
                text = decoded
            text = unescape(text).replace("\x00", "")
            for name, pattern, attack in (("SQL_BOOLEAN_OR_UNION", self._sql, AttackClass.SQL_INJECTION),
                                         ("ACTIVE_HTML", self._xss, AttackClass.XSS),
                                         ("PARENT_PATH", self._traversal, AttackClass.DIRECTORY_TRAVERSAL),
                                         ("SHELL_COMMAND", self._execution, AttackClass.REMOTE_CODE_EXECUTION)):
                if pattern.search(text):
                    if attack == AttackClass.SQL_INJECTION and field == "cookie":
                        attack = AttackClass.COOKIE_INJECTION
                    matches.append(RuleMatch(name, attack, field))
        return tuple(matches)
