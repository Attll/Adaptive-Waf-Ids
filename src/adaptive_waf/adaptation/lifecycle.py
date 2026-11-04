"""Guarded policy lifecycle. Runtime activation is injected, never inferred from a registry DB status."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
from pathlib import Path
from threading import RLock
from uuid import uuid4
from collections import deque
from adaptive_waf.runtime.routing import empirical_gate
from adaptive_waf.runtime.strategies import STRATEGIES


@dataclass(frozen=True)
class PolicyCandidate:
    version: str
    strategy: str
    metrics: dict
    verification_reference: str
    shadow_only: bool = True


class PolicyLifecycle:
    def __init__(self, audit_root, activate, baseline, live_enabled=False):
        self.root = Path(audit_root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.activate, self.active, self.previous = activate, baseline, None
        self.live_enabled, self.candidates, self.lock = live_enabled, {}, RLock()
        self.events = deque(maxlen=50)

    def _audit(self, action, version, **details):
        value = {"id":str(uuid4()), "timestamp":datetime.now(timezone.utc).isoformat(), "action":action,"version":version, **details}
        with (self.root / (value["timestamp"].replace(":","-") + "-" + value["id"] + ".json")).open("x") as target:
            json.dump(value,target,indent=2,allow_nan=False)
        self.events.append({key:value[key] for key in ("timestamp","action","version")})

    def snapshot(self):
        with self.lock:
            return {"available":True,"activation_enabled":self.live_enabled,"registered_candidates":len(self.candidates),
                "active_version":getattr(self.active,"version","startup-baseline"),"events":list(self.events),
                "audit_persistence":"append-only local files; startup restores configured baseline"}

    def register(self, candidate):
        if not candidate.version or candidate.strategy not in STRATEGIES | {"fixed","guarded_fixed"} or not candidate.verification_reference:
            raise ValueError("invalid policy or missing verified evaluation reference")
        # Freeze values at registration; callers cannot later mutate the metrics through shared references.
        frozen = PolicyCandidate(**json.loads(json.dumps(asdict(candidate),allow_nan=False)))
        with self.lock:
            if candidate.version in self.candidates:
                raise ValueError("policy version already registered")
            self._audit("SHADOW_REGISTERED",candidate.version,metrics=frozen.metrics,reference=frozen.verification_reference)
            self.candidates[candidate.version] = frozen
        return "SHADOW"

    def promote(self, version, operator_approval_reference):
        with self.lock:
            candidate = self.candidates[version]
            if not self.live_enabled or candidate.shadow_only or not operator_approval_reference:
                raise PermissionError("live promotion disabled or explicit operator approval absent")
            if not empirical_gate(candidate.metrics):
                self._audit("GATE_REJECTED",version)
                raise ValueError("candidate failed empirical security/resource gates")
            old = self.active
            try:
                if self.activate(candidate) is not True:
                    raise RuntimeError("runtime did not acknowledge activation")
                self._audit("ACTIVATED",version,approval_reference=operator_approval_reference)
            except Exception as error:
                self.activate(old)
                self._audit("ACTIVATION_FAILED",version,error_type=type(error).__name__)
                raise
            self.previous, self.active = old, candidate

    def monitor(self, metrics):
        # Unlabeled operational errors can trigger rollback; they cannot train a supervised classifier.
        if metrics.get("observations",0) >= 20 and metrics.get("inference_error_rate",0) > .05 and self.previous is not None:
            self.rollback("operational_error_gate")
            return "ROLLED_BACK"
        return "MONITOR"

    def rollback(self, reason):
        with self.lock:
            if self.previous is None:
                raise ValueError("no acknowledged rollback target")
            if self.activate(self.previous) is not True:
                raise RuntimeError("runtime did not acknowledge rollback")
            old = self.active
            self.active, self.previous = self.previous, None
            self._audit("ROLLED_BACK",getattr(old,"version","unknown"),reason=reason)
