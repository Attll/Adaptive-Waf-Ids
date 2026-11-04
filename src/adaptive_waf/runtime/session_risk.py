"""Bounded, expiring session evidence; detector evidence remains distinct from verified feedback."""
from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import hmac
import math
from threading import RLock
from time import monotonic


def private_session_key(secret, session_value):
    if len(secret) < 32 or not session_value:
        raise ValueError("session identity requires a configured secret and explicit session token")
    return hmac.new(secret.encode(), session_value.encode(), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class RiskRevision:
    request_id: str
    evidence_id: str
    model_version: str
    policy_version: str
    risk: float
    verified: bool
    at: float


class SessionRiskStore:
    def __init__(self, ttl_seconds=300, half_life_seconds=60, max_sessions=4096, history_limit=16, clock=monotonic):
        if min(ttl_seconds, half_life_seconds, max_sessions, history_limit) <= 0:
            raise ValueError("session bounds must be positive")
        self.ttl, self.half_life, self.maximum, self.history_limit = ttl_seconds, half_life_seconds, max_sessions, history_limit
        self.clock, self.sessions, self.lock = clock, OrderedDict(), RLock()

    def _purge(self):
        now = self.clock()
        for key, (expires, _) in list(self.sessions.items()):
            if expires <= now:
                del self.sessions[key]

    def revise(self, session_key, revision):
        if len(session_key) != 64 or any(c not in "0123456789abcdef" for c in session_key) or not 0 <= revision.risk <= 1:
            raise ValueError("invalid private session identity or risk")
        with self.lock:
            self._purge()
            _, history = self.sessions.pop(session_key, (0, []))
            # Retransmission cannot repeatedly amplify one detector result. Verified correction is a new evidence id.
            if not any(item.evidence_id == revision.evidence_id for item in history):
                history.append(revision)
            self.sessions[session_key] = (self.clock() + self.ttl, history[-self.history_limit:])
            while len(self.sessions) > self.maximum:
                self.sessions.popitem(last=False)
            return self.risk(session_key)

    def risk(self, session_key):
        with self.lock:
            self._purge()
            history = self.sessions.get(session_key, (0, []))[1]
            # Latest verified correction replaces detector evidence for the same request, without mutating history.
            corrections = {item.request_id: item for item in history if item.verified}
            latest = {item.request_id: item for item in history if not item.verified}
            latest.update(corrections)
            applicable = list(latest.values())
            return max((item.risk * math.exp(-math.log(2) * max(0, self.clock() - item.at) / self.half_life) for item in applicable), default=0.)

    def history(self, session_key):
        with self.lock:
            self._purge()
            return tuple(self.sessions.get(session_key, (0, []))[1])
