from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass
import math
from time import perf_counter_ns

from adaptive_waf.contracts import AttackClass, ExpertFamily, HttpRequestRecord


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    total_requests: int
    expected_attack_distribution: dict[str, int]
    predicted_attack_distribution: dict[str, int]
    action_distribution: dict[str, int]
    triage_exit_rate: float
    fast_expert_exit_rate: float
    ensemble_escalation_rate: float
    deep_escalation_rate: float
    router_accuracy: float | None
    top2_router_coverage: float | None
    attack_recall: float | None
    false_positive_rate: float | None
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    throughput_requests_per_second: float
    duration_ms: float

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def run_http_benchmark(pipeline, policy, samples: Iterable[tuple[HttpRequestRecord, str]]) -> tuple[BenchmarkReport, list[dict[str, object]]]:
    """Run prepared HTTP samples through the deployed pipeline and offline policy."""
    expected_counts: Counter[str] = Counter()
    predicted_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    rows: list[dict[str, object]] = []
    latencies: list[float] = []
    triage_exits = fast_exits = ensemble_escalations = deep_escalations = 0
    attack_samples = router_top1_correct = router_top2_covered = attack_correct = benign_samples = false_positives = 0
    start = perf_counter_ns()
    for request, expected_label in samples:
        result = pipeline.detect(request)
        policy_decision = policy.evaluate(result.overall_risk, result.explanation_evidence)
        total_latency = sum(result.latency_by_stage_ms.values())
        latencies.append(total_latency)
        expected_counts[expected_label] += 1
        predicted_counts[str(result.predicted_attack)] += 1
        action_counts[str(policy_decision.action)] += 1
        triage_exits += int("TRIAGE_EARLY_EXIT" in result.routing_path)
        fast_exits += int(bool(result.expert_outputs) and not result.ensemble_used and not result.deep_model_used)
        ensemble_escalations += int(result.ensemble_used)
        deep_escalations += int(result.deep_model_used)
        if expected_label == AttackClass.BENIGN:
            benign_samples += 1
            false_positives += int(result.predicted_attack != AttackClass.BENIGN)
        else:
            attack_samples += 1
            expected_family = _family_for_attack(expected_label)
            selected = result.router_output.selected_experts if result.router_output else ()
            router_top1_correct += int(bool(selected) and selected[0] == expected_family)
            router_top2_covered += int(expected_family in selected)
            attack_correct += int(str(result.predicted_attack) == expected_label)
        rows.append({
            "request_id": str(result.request_id),
            "expected_attack": expected_label,
            "predicted_attack": result.predicted_attack,
            "overall_risk": result.overall_risk,
            "action": policy_decision.action,
            "routing_path": result.routing_path,
            "total_latency_ms": total_latency,
        })
    duration_ms = (perf_counter_ns() - start) / 1_000_000
    total = len(rows)
    report = BenchmarkReport(
        total_requests=total,
        expected_attack_distribution=dict(sorted(expected_counts.items())),
        predicted_attack_distribution=dict(sorted(predicted_counts.items())),
        action_distribution=dict(sorted(action_counts.items())),
        triage_exit_rate=_rate(triage_exits, total),
        fast_expert_exit_rate=_rate(fast_exits, total),
        ensemble_escalation_rate=_rate(ensemble_escalations, total),
        deep_escalation_rate=_rate(deep_escalations, total),
        router_accuracy=_optional_rate(router_top1_correct, attack_samples),
        top2_router_coverage=_optional_rate(router_top2_covered, attack_samples),
        attack_recall=_optional_rate(attack_correct, attack_samples),
        false_positive_rate=_optional_rate(false_positives, benign_samples),
        latency_p50_ms=_percentile(latencies, 50),
        latency_p95_ms=_percentile(latencies, 95),
        latency_p99_ms=_percentile(latencies, 99),
        throughput_requests_per_second=total / (duration_ms / 1_000) if duration_ms else 0.0,
        duration_ms=duration_ms,
    )
    return report, rows


def _family_for_attack(label: str) -> ExpertFamily:
    if label in {AttackClass.SQL_INJECTION, AttackClass.XSS, AttackClass.COOKIE_INJECTION}:
        return ExpertFamily.INJECTION
    if label in {AttackClass.DIRECTORY_TRAVERSAL, AttackClass.REMOTE_CODE_EXECUTION}:
        return ExpertFamily.EXECUTION
    raise ValueError(f"unsupported HTTP attack label for router evaluation: {label}")


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _optional_rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile / 100
    lower = math.floor(position)
    upper = math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)
