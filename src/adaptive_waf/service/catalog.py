"""Read-only view of the trained artifacts backing each pipeline stage.

The console compares every candidate algorithm that was evaluated for a stage against the one actually deployed,
so this module reports the deployment selection alongside the full evaluation record written during training.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import tomllib
from typing import Any

from adaptive_waf.config import load_settings

_STAGE_DEFENDS: dict[str, tuple[str, ...]] = {
    "triage": ("Any suspicious HTTP request",),
    "router": ("Routes to the correct expert family",),
    "injection": ("SQL_INJECTION", "XSS", "COOKIE_INJECTION"),
    "execution": ("DIRECTORY_TRAVERSAL", "REMOTE_CODE_EXECUTION"),
    "deep": ("SQL_INJECTION", "XSS", "COOKIE_INJECTION", "DIRECTORY_TRAVERSAL", "REMOTE_CODE_EXECUTION"),
    "network": ("BRUTE_FORCE", "DOS_DDOS", "BOT_ANOMALY"),
}

_STAGE_DEFINITIONS: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "triage",
        "Triage",
        "http",
        "triage_deployment.toml",
        "First-pass binary screen that separates benign-like traffic from requests worth deeper analysis.",
    ),
    (
        "router",
        "Router",
        "http",
        "router_deployment.toml",
        "Chooses which expert families evaluate a suspicious request, and whether one or two of them run.",
    ),
    (
        "injection",
        "Injection expert",
        "http",
        "injection_expert_deployment.toml",
        "Fast classical classifier for SQL injection, cross-site scripting, and cookie injection.",
    ),
    (
        "execution",
        "Execution expert",
        "http",
        "execution_expert_deployment.toml",
        "Fast classical classifier for directory traversal and remote code execution.",
    ),
    (
        "deep",
        "Deep escalation",
        "http",
        "deep_deployment.toml",
        "Transformer that adjudicates requests the fast experts classify with low confidence.",
    ),
    (
        "network",
        "Network detector",
        "network",
        "network_deployment.toml",
        "Offline flow classifier that supplies network risk context from the sensor.",
    ),
)

_ALGORITHM_PROFILES: dict[str, dict[str, str]] = {
    "logistic_regression": {
        "family": "Linear model",
        "description": "Regularised linear classifier over the classical feature vector; cheapest to serve.",
    },
    "random_forest": {
        "family": "Bagged decision-tree ensemble",
        "description": "Bootstrap-aggregated trees with random feature subsets; strong on tabular features.",
    },
    "extra_trees": {
        "family": "Extremely randomised trees",
        "description": "Like a random forest but with randomised split thresholds, trading bias for variance.",
    },
    "distilbert": {
        "family": "Transformer (distilled BERT)",
        "description": "Six-layer transformer fine-tuned on the serialised request; reads the payload as text.",
    },
    "char_cnn": {
        "family": "Character convolutional network",
        "description": "Character-level CNN over the serialised request; cheaper than a transformer.",
    },
}

_METRIC_ORDER = (
    "accuracy",
    "f1_macro",
    "f1_weighted",
    "precision_macro",
    "recall_macro",
    "pr_auc",
    "roc_auc",
    "top1_accuracy",
    "top2_coverage",
    "false_positive_rate",
    "false_negative_rate",
    "multiclass_brier_score",
    "top_label_expected_calibration_error",
    "inference_p50_ms",
    "inference_p95_ms",
)


@dataclass(frozen=True, slots=True)
class CatalogPaths:
    root: Path

    @property
    def configs(self) -> Path:
        return self.root / "configs/models"

    @property
    def training(self) -> Path:
        return self.root / "artifacts/training"


def build_catalog(core_config: Path | None = None) -> dict[str, Any]:
    paths = CatalogPaths(load_settings(core_config).paths.project_root)
    calibration = _toml(paths.configs / "calibration_deployment.toml")
    pipeline = _toml(paths.configs / "pipeline.toml")
    fusion = _toml(paths.configs / "fusion.toml")
    stages = [_stage(paths, calibration, *definition) for definition in _STAGE_DEFINITIONS]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pipeline": {
            "name": "Adaptive hierarchy",
            "thresholds": pipeline,
            "fusion": fusion,
            "calibration_run": calibration.get("run_id"),
            "stage_order": [stage["stage"] for stage in stages],
        },
        "stages": stages,
        "ensembles": _ensembles(paths),
        "benchmark": _benchmark(paths),
    }


def _stage(paths: CatalogPaths, calibration: dict[str, Any], key: str, title: str, plane: str, config_name: str, purpose: str) -> dict[str, Any]:
    config = _toml(paths.configs / config_name)
    run_id = str(config.get("run_id", "unknown"))
    calibration_method = str(calibration.get(key, {}).get("method")) if key in calibration else None
    candidates, labels = _candidates(paths, key, run_id, config)
    selected = str(config.get("algorithm") or config.get("candidate") or "")
    training = _json(_run_directory(paths, key, run_id) / "config.json").get("config", {})
    hyperparameters = _hyperparameters(training)
    for candidate in candidates:
        name = candidate["algorithm"]
        candidate["deployed"] = name == selected
        candidate["hyperparameters"] = hyperparameters.get(name, {})
        candidate["profile"] = _ALGORITHM_PROFILES.get(name, {"family": "Unclassified", "description": ""})
    return {
        "stage": key,
        "title": title,
        "plane": plane,
        "purpose": purpose,
        "labels": labels,
        "defends_against": list(_STAGE_DEFENDS.get(key, ())),
        "training": {
            "dataset_version": training.get("dataset_version"),
            "feature_version": training.get("feature_version"),
            "evaluated_algorithms": training.get("algorithms") or list(training.get("candidates", {})),
        },
        "deployment": {
            "run_id": run_id,
            "algorithm": selected or "unknown",
            "artifact": str(config.get("artifact", "")),
            "dataset_version": config.get("dataset_version"),
            "feature_version": config.get("feature_version"),
            "calibration": calibration_method,
            "model_version": f"{run_id}:{calibration_method or selected or 'unknown'}",
            "device": config.get("device"),
            "profile": _ALGORITHM_PROFILES.get(selected, {"family": "Unclassified", "description": ""}),
            "hyperparameters": hyperparameters.get(selected, {}),
            "router_thresholds": {
                "minimum_top1_probability": config.get("minimum_top1_probability"),
                "minimum_top1_margin": config.get("minimum_top1_margin"),
            }
            if key == "router"
            else None,
        },
        "candidates": candidates,
    }


def _candidates(paths: CatalogPaths, key: str, run_id: str, config: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    metrics = _json(_metrics_path(paths, key, run_id))
    if not metrics:
        return [], []
    labels: list[str] = []
    candidates: list[dict[str, Any]] = []
    runs = metrics.get("runs")
    if isinstance(runs, list):
        for entry in runs:
            evaluation = entry.get("evaluation", {})
            labels = labels or list(evaluation.get("labels", []))
            candidates.append(
                {
                    "algorithm": str(entry.get("algorithm", "unknown")),
                    "model_size_bytes": entry.get("model_size_bytes"),
                    "metrics": _ordered_metrics(evaluation),
                    "confusion_matrix": evaluation.get("confusion_matrix"),
                }
            )
    elif "evaluation" in metrics:
        evaluation = metrics["evaluation"]
        labels = list(evaluation.get("labels", []))
        candidates.append(
            {
                "algorithm": str(metrics.get("candidate") or config.get("candidate") or "deep"),
                "model_size_bytes": None,
                "metrics": _ordered_metrics(evaluation),
                "confusion_matrix": evaluation.get("confusion_matrix"),
            }
        )
    return candidates, labels


def _run_directory(paths: CatalogPaths, key: str, run_id: str) -> Path:
    return {
        "triage": paths.training / "triage" / run_id,
        "router": paths.training / "router" / run_id,
        "injection": paths.training / "experts/injection" / run_id,
        "execution": paths.training / "experts/execution" / run_id,
        "deep": paths.training / "deep" / run_id,
        "network": paths.training / "network" / run_id,
    }[key]


def _metrics_path(paths: CatalogPaths, key: str, run_id: str) -> Path:
    return _run_directory(paths, key, run_id) / "metrics.json"


def _hyperparameters(training: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Training configs store classical parameters under `parameters` and deep ones under `candidates`."""
    for field in ("parameters", "candidates"):
        block = training.get(field)
        if isinstance(block, dict):
            return {str(name): value for name, value in block.items() if isinstance(value, dict)}
    return {}


def _ensembles(paths: CatalogPaths) -> list[dict[str, Any]]:
    directory = paths.training / "ensembles"
    if not directory.is_dir():
        return []
    runs = sorted((entry for entry in directory.iterdir() if entry.is_dir()), key=lambda entry: entry.name)
    for run in reversed(runs):
        metrics = _json(run / "metrics.json")
        if not metrics:
            continue
        families = []
        for family, payload in metrics.items():
            results = payload.get("results", []) if isinstance(payload, dict) else []
            families.append(
                {
                    "family": family,
                    "run_id": run.name,
                    "combinations": [
                        {
                            "members": result.get("members", []),
                            "retained": bool(result.get("retained")),
                            "metrics": _ordered_metrics(result.get("evaluation", {})),
                        }
                        for result in results
                    ],
                }
            )
        if families:
            return families
    return []


def _benchmark(paths: CatalogPaths) -> dict[str, Any]:
    summary = _json(paths.root / "artifacts/evaluations/phase10-summary.json")
    directory = paths.root / "artifacts/benchmarks"
    runs: list[dict[str, Any]] = []
    if directory.is_dir():
        for entry in sorted(entry for entry in directory.iterdir() if entry.is_dir()):
            metrics = _json(entry / "metrics.json")
            if metrics:
                runs.append({"run_id": entry.name, "metrics": metrics})
    return {"summary": summary, "runs": runs}


def _ordered_metrics(evaluation: dict[str, Any]) -> dict[str, float]:
    ordered = {name: evaluation[name] for name in _METRIC_ORDER if isinstance(evaluation.get(name), (int, float))}
    extra = {
        name: value
        for name, value in evaluation.items()
        if name not in ordered and name not in {"confusion_matrix", "labels"} and isinstance(value, (int, float))
    }
    return {**ordered, **extra}


def _toml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    with path.open("rb") as source:
        return tomllib.load(source)


def _json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
