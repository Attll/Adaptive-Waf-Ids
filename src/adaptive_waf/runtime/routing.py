"""Routing experiments use pre-action context. Live promotion requires external measured gates."""
from dataclasses import dataclass
import math
import numpy as np

ROUTES = ("FAST_ONLY", "BOTH", "SYNC_DEEP", "DEFERRED_DEEP", "RULES_ONLY")


@dataclass(frozen=True)
class RoutingContext:
    fast_risk: float
    entropy: float
    margin: float
    source_rate: float = 0
    session_risk: float = 0
    network_risk: float = 0
    endpoint_anomaly: float = 0
    load: float = 0
    queue_fraction: float = 0
    deadline_fraction: float = 1

    def vector(self):
        values = np.asarray(list(self.__dict__.values()), dtype=float)
        if not np.isfinite(values).all():
            raise ValueError("routing context must be finite")
        return np.r_[1., np.clip(values, 0, 1)]


class LinUCB:
    def __init__(self, dimension=11, exploration=.2, seed=641):
        if dimension!=11 or not np.isfinite(exploration) or exploration<0:
            raise ValueError("routing requires 11 features and finite nonnegative exploration")
        self.exploration = exploration
        self.a = {route: np.eye(dimension) for route in ROUTES}
        self.b = {route: np.zeros(dimension) for route in ROUTES}
        self.random = np.random.default_rng(seed)

    def select(self, context, available, conservative=False, minimum_cost_route="BOTH"):
        available = set(available).intersection(ROUTES)
        if context.queue_fraction >= 1:
            available.discard("DEFERRED_DEEP")
        if context.deadline_fraction <= 0:
            available.discard("SYNC_DEEP")
        if conservative and (context.fast_risk > .2 or context.entropy > .3 or context.session_risk > .2):
            available.discard("FAST_ONLY")
            available.discard("DEFERRED_DEEP")
            available.discard("RULES_ONLY")
        if not available:
            raise ValueError("no safe available route; explicit conservative fallback required")
        x = context.vector()
        scores = {}
        for route in sorted(available):
            solved = np.linalg.solve(self.a[route], x)
            scores[route] = float(self.b[route] @ solved + self.exploration * math.sqrt(max(0, x @ solved)))
        maximum = max(scores.values())
        tied = sorted(route for route, score in scores.items() if np.isclose(score, maximum))
        selected = self.random.choice(tied).item()
        # This is the actual tie-randomization propensity, not an invented exploration probability.
        return selected, {route: 1 / len(tied) if route in tied else 0. for route in ROUTES}

    def update(self, context, action, reward, label_source):
        if label_source != "VERIFIED" or action not in ROUTES or not np.isfinite(reward):
            raise ValueError("bandit updates require a finite reward from verified labels")
        x = context.vector()
        self.a[action] += np.outer(x, x)
        self.b[action] += reward * x

    def state(self):
        return {"schema_version":1,"exploration":self.exploration,"random_state":self.random.bit_generator.state,
            "a":{route:value.tolist() for route,value in self.a.items()},"b":{route:value.tolist() for route,value in self.b.items()}}

    @classmethod
    def from_state(cls, value):
        if value.get("schema_version")!=1 or set(value["a"])!=set(ROUTES) or set(value["b"])!=set(ROUTES):
            raise ValueError("invalid bandit state schema")
        policy=cls(exploration=value["exploration"])
        for route in ROUTES:
            a,b=np.asarray(value["a"][route],dtype=float),np.asarray(value["b"][route],dtype=float)
            if a.shape!=(11,11) or b.shape!=(11,) or not np.isfinite(a).all() or not np.isfinite(b).all() or not np.allclose(a,a.T):
                raise ValueError("invalid bandit matrices")
            try:
                np.linalg.cholesky(a)
            except np.linalg.LinAlgError as error:
                raise ValueError("bandit covariance must be positive definite") from error
            policy.a[route],policy.b[route]=a,b
        policy.random.bit_generator.state=value["random_state"]
        return policy


def labeled_reward(expected, predicted, latency_ms, compute_cost=0, queue_ms=0, fn_cost=10, fp_cost=2):
    if any(not np.isfinite(value) or value<0 for value in (latency_ms,compute_cost,queue_ms,fn_cost,fp_cost)):
        raise ValueError("reward costs and timings must be finite and nonnegative")
    missed = expected != "BENIGN" and predicted == "BENIGN"
    false_positive = expected == "BENIGN" and predicted != "BENIGN"
    return float(expected == predicted) - fn_cost * missed - fp_cost * false_positive - .001 * latency_ms - compute_cost - .001 * queue_ms


def empirical_gate(metrics, minimum_recall=.99, maximum_fpr=.01, maximum_p95_ms=250, maximum_queue=256):
    required = ("attack_recall", "benign_fpr", "p95_ms", "queue_depth", "verified_attack_count", "verified_benign_count")
    if any(key not in metrics or not np.isfinite(metrics[key]) for key in required):
        return False
    if (not 0<=metrics["attack_recall"]<=1 or not 0<=metrics["benign_fpr"]<=1
            or metrics["p95_ms"]<0 or metrics["queue_depth"]<0
            or any(metrics[key] != int(metrics[key]) for key in ("verified_attack_count","verified_benign_count"))):
        return False
    return (metrics["verified_attack_count"] >= 100 and metrics["verified_benign_count"] >= 100
            and metrics["attack_recall"] >= minimum_recall and metrics["benign_fpr"] <= maximum_fpr
            and metrics["p95_ms"] <= maximum_p95_ms and metrics["queue_depth"] <= maximum_queue)
