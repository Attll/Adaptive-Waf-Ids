from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import ipaddress
from typing import Mapping, Protocol

from adaptive_waf.contracts import NetworkContext


class NetworkDetector(Protocol):
    model_version: str

    def detect(self, features: Mapping[str, float]) -> NetworkContext: ...


class NetworkContextStore(Protocol):
    def put(self, source_ip: str, evidence: "NetworkEvidence", ttl_seconds: int) -> None: ...

    def ping(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class NetworkEvidence:
    source_ip: str
    destination_ip: str | None
    network_risk: float
    network_class: str | None
    confidence: float | None
    model_version: str
    observed_at: str
    observation_scope: str = "PROVIDED_FLOW"
    feature_contract: str = "PROVIDED_FLOW"

    def as_redis_value(self) -> dict[str, object]:
        return asdict(self)


class NetworkSensor:
    """Classifies a reproducible flow feature record and publishes contextual evidence."""

    def __init__(self, detector: NetworkDetector, store: NetworkContextStore, ttl_seconds: int) -> None:
        if ttl_seconds < 1:
            raise ValueError("network context TTL must be positive")
        self._detector = detector
        self._store = store
        self._ttl_seconds = ttl_seconds

    @property
    def model_version(self) -> str:
        return self._detector.model_version

    def process(self, source_ip: str, destination_ip: str | None, features: Mapping[str, float], observation_scope="PROVIDED_FLOW", feature_contract="PROVIDED_FLOW") -> NetworkEvidence:
        if feature_contract not in {'PROVIDED_FLOW','frame-population-v1','payload-sample-v2'}:
            raise ValueError('unsupported flow feature contract')
        normalized_source = str(ipaddress.ip_address(source_ip))
        normalized_destination = str(ipaddress.ip_address(destination_ip)) if destination_ip else None
        context = self._detector.detect(features)
        evidence = NetworkEvidence(
            source_ip=normalized_source,
            destination_ip=normalized_destination,
            network_risk=context.risk,
            network_class=context.network_class,
            confidence=context.confidence,
            model_version=self._detector.model_version,
            observed_at=datetime.now(timezone.utc).isoformat(),
            observation_scope=observation_scope,
            feature_contract=feature_contract,
        )
        self._store.put(normalized_source, evidence, self._ttl_seconds)
        return evidence
