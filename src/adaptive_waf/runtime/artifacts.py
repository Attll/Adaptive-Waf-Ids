from __future__ import annotations

import json
from pathlib import Path
import tomllib

import joblib
from threading import Lock

from adaptive_waf.config import load_settings
from adaptive_waf.contracts import AttackClass, ExpertFamily, HttpRequestRecord
from adaptive_waf.features.canonical import serialize_deep_request
from adaptive_waf.runtime.fusion import DeterministicRiskFusion
from adaptive_waf.runtime.network import OfflineNetworkDetector
from adaptive_waf.runtime.policy import OfflinePolicySimulator, PolicyThresholds
from adaptive_waf.runtime.pipeline import AdaptiveDetectionPipeline, PipelineThresholds


def load_adaptive_pipeline(core_config: Path | None = None, deep_scheduler=None) -> AdaptiveDetectionPipeline:
    settings = load_settings(core_config)
    root = settings.paths.project_root
    triage = _toml(root / "configs/models/triage_deployment.toml")
    router = _toml(root / "configs/models/router_deployment.toml")
    injection = _toml(root / "configs/models/injection_expert_deployment.toml")
    execution = _toml(root / "configs/models/execution_expert_deployment.toml")
    calibration = _toml(root / "configs/models/calibration_deployment.toml")
    pipeline_config = _toml(root / "configs/models/pipeline.toml")
    fusion_config = _toml(root / "configs/models/fusion.toml")
    deep = _toml(root / "configs/models/deep_deployment.toml")
    return AdaptiveDetectionPipeline(
        joblib.load(root / calibration["triage"]["artifact"]),
        joblib.load(root / router["artifact"]),
        {
            ExpertFamily.INJECTION: joblib.load(root / calibration["injection"]["artifact"]),
            ExpertFamily.EXECUTION: joblib.load(root / calibration["execution"]["artifact"]),
        },
        PipelineThresholds(
            float(pipeline_config["triage_benign_exit_max_suspicious_probability"]),
            bool(pipeline_config["triage_early_exit_enabled"]),
            float(pipeline_config["expert_minimum_confidence"]),
            float(router["minimum_top1_probability"]),
            float(router["minimum_top1_margin"]),
            bool(pipeline_config.get("asynchronous_deep_escalation_enabled", False)),
        ),
        {
            "triage": f"{triage['run_id']}:{calibration['triage']['method']}",
            "router": f"{router['run_id']}:{router['algorithm']}",
            "injection": f"{injection['run_id']}:{calibration['injection']['method']}",
            "execution": f"{execution['run_id']}:{calibration['execution']['method']}",
            "deep": f"{deep['run_id']}:{calibration['deep']['method']}",
        },
        DistilBertPredictor(root / deep["artifact"], root / calibration["deep"]["artifact"], str(deep["device"])),
        DeterministicRiskFusion(
            {name: float(value) for name, value in fusion_config["source_weights"].items()},
            float(fusion_config["supporting_evidence_minimum_risk"]),
        ),
        deep_scheduler,
    )


def load_pipeline_settings(core_config: Path | None = None) -> dict:
    """Runtime knobs the service layer needs before the pipeline itself is constructed."""
    settings = load_settings(core_config)
    config = _toml(settings.paths.project_root / "configs/models/pipeline.toml")
    return {
        "asynchronous_deep_escalation_enabled": bool(config.get("asynchronous_deep_escalation_enabled", False)),
        "deep_escalation_workers": int(config.get("deep_escalation_workers", 2)),
        "deep_escalation_queue_limit": int(config.get("deep_escalation_queue_limit", 256)),
        "expert_minimum_confidence": float(config.get("expert_minimum_confidence", 0.9)),
    }


def load_offline_network_detector(core_config: Path | None = None) -> OfflineNetworkDetector:
    """Load the selected offline flow classifier and its ordered feature schema."""
    settings = load_settings(core_config)
    root = settings.paths.project_root
    deployment = _toml(root / "configs/models/network_deployment.toml")
    manifest = json.loads((root / deployment["feature_manifest"]).read_text(encoding="utf-8"))
    feature_names = manifest.get("feature_names")
    if not isinstance(feature_names, list) or not all(isinstance(name, str) for name in feature_names):
        raise ValueError("network feature manifest does not contain a valid feature_names list")
    return OfflineNetworkDetector(
        joblib.load(root / deployment["artifact"]),
        feature_names,
        f"{deployment['run_id']}:{deployment['algorithm']}",
    )


def load_offline_policy_simulator(core_config: Path | None = None) -> OfflinePolicySimulator:
    settings = load_settings(core_config)
    policy = _toml(settings.paths.project_root / "configs/models/policy.toml")
    return OfflinePolicySimulator(
        str(policy["policy_version"]),
        PolicyThresholds(
            float(policy["allow_max_risk"]),
            float(policy["monitor_max_risk"]),
            float(policy["rate_limit_max_risk"]),
        ),
    )


class DistilBertPredictor:
    """Loads the transformer on first use. The load is guarded because escalation workers call this concurrently."""

    def __init__(self, artifact_directory: Path, temperature_path: Path, device_name: str) -> None:
        self._artifact_directory = artifact_directory
        self._temperature = float(json.loads(temperature_path.read_text(encoding="utf-8"))["temperature"])
        self._device_name = device_name
        self._model = None
        self._tokenizer = None
        self._load_lock = Lock()

    def warm(self) -> None:
        """Loads the artifact ahead of the first request so a cold start never sits in the escalation queue."""
        self._loaded()

    def __call__(self, request: HttpRequestRecord) -> dict[AttackClass, float]:
        torch, model, tokenizer, device = self._loaded()
        inputs = tokenizer(serialize_deep_request(request), truncation=True, max_length=256, return_tensors="pt")
        with torch.no_grad():
            probabilities = torch.softmax(model(**{name: value.to(device) for name, value in inputs.items()}).logits / self._temperature, dim=1)[0].cpu().tolist()
        return {AttackClass(model.config.id2label[index]): float(value) for index, value in enumerate(probabilities)}

    def _loaded(self):
        if self._model is None:
            with self._load_lock:
                if self._model is None:
                    import torch
                    from transformers import AutoModelForSequenceClassification, AutoTokenizer

                    device = _resolve_inference_device(torch, self._device_name)
                    tokenizer = AutoTokenizer.from_pretrained(self._artifact_directory / "tokenizer")
                    model = AutoModelForSequenceClassification.from_pretrained(self._artifact_directory / "model").to(device).eval()
                    self._tokenizer = tokenizer
                    self._device_name = str(device)
                    self._model = model  # published last: another thread never sees a half-initialised predictor
        import torch

        return torch, self._model, self._tokenizer, torch.device(self._device_name)


def _resolve_inference_device(torch, configured: str):
    if configured.startswith("cuda") and not torch.cuda.is_available():
        return torch.device("cpu")
    return torch.device(configured)


def _toml(path: Path) -> dict[str, object]:
    with path.open("rb") as source:
        return tomllib.load(source)
